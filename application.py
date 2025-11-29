from decimal import Decimal
import boto3
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import os
from dotenv import load_dotenv, find_dotenv
import json
from datetime import datetime 
import datetime as dt
from functools import wraps
import requests
from jose import jwt
from boto3.dynamodb.conditions import Attr
from botocore.exceptions import ClientError
import logging
from google.oauth2 import service_account
import google.auth.transport.requests
import uuid
import re

# --- Configuration ---
env_path = find_dotenv()
load_dotenv(env_path)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Flask Setup (Note the template_folder)
application = Flask(__name__, template_folder='templates', static_folder='static')
CORS(application)

# Env Vars
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
SQS_QUEUE_URL = os.getenv('ORDER_QUEUE_URL')
DYNAMODB_TABLE = os.getenv('DYNAMODB_TABLE_NAME', 'orders')
USERS_TABLE = os.getenv('USERS_TABLE_NAME', 'users')
COGNITO_POOL_ID = os.getenv('COGNITO_USER_POOL_ID')
COGNITO_CLIENT_ID = os.getenv('COGNITO_APP_CLIENT_ID')
COGNITO_REGION = os.getenv('COGNITO_REGION', AWS_REGION)

# SSM Keys
SSM_GOOGLE_CREDS = "/preethi-logistics/google-creds"

# Warehouse (Dublin)
WAREHOUSE_LOCATION = {"lat": Decimal("53.349242"), "lng": Decimal("-6.242983")}

# AWS Clients
try:
    cognito = boto3.client('cognito-idp', region_name=AWS_REGION)
    dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
    sns = boto3.client('sns', region_name=AWS_REGION)
    ssm = boto3.client('ssm', region_name=AWS_REGION)
    sqs = boto3.client('sqs', region_name=AWS_REGION)
    
    orders_table = dynamodb.Table(DYNAMODB_TABLE)
    users_table = dynamodb.Table(USERS_TABLE)
except Exception as e:
    logger.critical(f"AWS Client Error: {e}")

# --- HELPERS ---
def get_google_token():
    try:
        param = ssm.get_parameter(Name=SSM_GOOGLE_CREDS, WithDecryption=True)
        creds = service_account.Credentials.from_service_account_info(
            json.loads(param['Parameter']['Value']),
            scopes=['https://www.googleapis.com/auth/cloud-platform']
        )
        creds.refresh(google.auth.transport.requests.Request())
        return creds.token
    except Exception as e:
        logger.error(f"Google Auth Error: {e}")
        return None

def create_sns_topic(email):
    try:
        clean_mail = re.sub(r'[^a-zA-Z0-9]', '_', email)
        resp = sns.create_topic(Name=f"Preethi_Logistics_{clean_mail}")
        arn = resp['TopicArn']
        sns.subscribe(TopicArn=arn, Protocol='email', Endpoint=email)
        return arn
    except: return None

# --- AUTH DECORATOR ---
JWKS_URL = f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_POOL_ID}/.well-known/jwks.json"
jwks = requests.get(JWKS_URL).json() if requests.get(JWKS_URL).ok else {}

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token: return jsonify({'error': 'Missing token'}), 401
        try:
            token = token.split(" ")[1]
            header = jwt.get_unverified_header(token)
            key = next(k for k in jwks['keys'] if k['kid'] == header['kid'])
            payload = jwt.decode(token, key, algorithms=['RS256'], audience=COGNITO_CLIENT_ID, issuer=f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_POOL_ID}")
            request.user_id = payload['sub']
            request.user_email = payload.get('email')
        except Exception as e:
            return jsonify({'error': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated

# --- FRONTEND ROUTES ---
@application.route('/')
def index(): return render_template('index.html')

@application.route('/customer')
def customer(): return render_template('customer.html')

@application.route('/partner')
def partner(): return render_template('partner.html')

@application.route('/create_order')
def create_order_page(): return render_template('create_order.html')

@application.route('/track')
def track(): return render_template('track.html')

# --- API ROUTES (Auth) ---
@application.route('/api/signup', methods=['POST'])
def signup():
    d = request.json
    try:
        resp = cognito.sign_up(
            ClientId=COGNITO_CLIENT_ID, Username=d['email'], Password=d['password'],
            UserAttributes=[{'Name': 'email', 'Value': d['email']}, {'Name': 'name', 'Value': d['name']}]
        )
        try: cognito.admin_add_user_to_group(UserPoolId=COGNITO_POOL_ID, Username=d['email'], GroupName=d.get('role', 'customer'))
        except: pass
        
        topic_arn = create_sns_topic(d['email'])
        
        users_table.put_item(Item={
            'user_id': resp['UserSub'], 'email': d['email'], 'name': d['name'], 
            'role': d.get('role', 'customer'), 'sns_topic_arn': topic_arn,
            'created_at': datetime.now(dt.timezone.utc).isoformat()
        })
        return jsonify({'success': True})
    except Exception as e: return jsonify({'error': str(e)}), 400

@application.route('/api/login', methods=['POST'])
def login():
    d = request.json
    try:
        resp = cognito.initiate_auth(
            ClientId=COGNITO_CLIENT_ID, AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={'USERNAME': d['email'], 'PASSWORD': d['password']}
        )
        return jsonify(resp['AuthenticationResult'])
    except: return jsonify({'error': 'Invalid credentials'}), 401

@application.route('/api/confirm', methods=['POST'])
def confirm():
    d = request.json
    try:
        cognito.confirm_sign_up(ClientId=COGNITO_APP_CLIENT_ID, Username=d['email'], ConfirmationCode=d['code'])
        return jsonify({'success': True})
    except: return jsonify({'error': 'Failed'}), 400

# --- API ROUTES (Orders - CQRS) ---

@application.route('/api/orders', methods=['POST'])
@token_required
def create_order():
    """Async: Pushes to SQS"""
    try:
        d = request.json
        oid = str(uuid.uuid4())
        
        event = {
            "action": "CREATE_ORDER",
            "order_id": oid,
            "customer_id": request.user_id,
            "user_email": d.get('customerEmail') or request.user_email,
            "data": d,
            "timestamp": datetime.now(dt.timezone.utc).isoformat()
        }
        
        if SQS_QUEUE_URL:
            sqs.send_message(QueueUrl=SQS_QUEUE_URL, MessageBody=json.dumps(event))
            return jsonify({'success': True, 'order_id': oid, 'message': 'Processing'}), 202
        return jsonify({'error': 'Queue missing'}), 500
    except Exception as e: return jsonify({'error': str(e)}), 500

@application.route('/api/orders', methods=['GET'])
@token_required
def get_orders():
    """Sync: Reads DB"""
    try:
        role = users_table.get_item(Key={'user_id': request.user_id}).get('Item', {}).get('role', 'customer')
        if role == 'agent': resp = orders_table.scan()
        else: resp = orders_table.scan(FilterExpression=Attr('customer_id').eq(request.user_id))
        
        # Decimal fix
        items = resp.get('Items', [])
        for i in items:
            for k, v in i.items():
                if isinstance(v, Decimal): i[k] = float(v)
                
        return jsonify({'orders': items})
    except Exception as e: return jsonify({'error': str(e)}), 500

@application.route('/api/orders/<oid>', methods=['GET'])
@token_required
def get_one(oid):
    item = orders_table.get_item(Key={'order_id': oid}).get('Item')
    if item:
        for k, v in item.items():
            if isinstance(v, Decimal): item[k] = float(v)
        return jsonify({'order': item})
    return jsonify({'error': 'Not found'}), 404

@application.route('/api/orders/<oid>', methods=['DELETE'])
@token_required
def delete_order(oid):
    """Async: Pushes to SQS"""
    if SQS_QUEUE_URL:
        sqs.send_message(
            QueueUrl=SQS_QUEUE_URL,
            MessageBody=json.dumps({"action": "DELETE_ORDER", "order_id": oid})
        )
        return jsonify({'success': True}), 202
    return jsonify({'error': 'Queue error'}), 500

@application.route('/api/optimize-route', methods=['POST'])
def optimize():
    """Hybrid: Sync Google Calc + Async DB Update"""
    try:
        oids = request.json.get('order_ids', [])
        
        # 1. Fetch Order Details
        orders = []
        for oid in oids:
            item = orders_table.get_item(Key={'order_id': oid}).get('Item')
            if item: orders.append(item)

        if not orders: return jsonify({'error': 'No orders'}), 400

        # 2. Google API (Sync)
        token = get_google_token()
        shipments = [{
            "label": str(i), "penaltyCost": 1000,
            "deliveries": [{"arrivalWaypoint": {"location": {"latLng": {"latitude": float(o['delivery_lat']), "longitude": float(o['delivery_lng'])}}}}]
        } for i, o in enumerate(orders)]

        vehicle = {
            "label": "v1", "costPerKilometer": 1.0,
            "startWaypoint": {"location": {"latLng": {"latitude": float(WAREHOUSE_LOCATION['lat']), "longitude": float(WAREHOUSE_LOCATION['lng'])}}},
            "endWaypoint": {"location": {"latLng": {"latitude": float(WAREHOUSE_LOCATION['lat']), "longitude": float(WAREHOUSE_LOCATION['lng'])}}}
        }

        resp = requests.post(
            "https://routeoptimization.googleapis.com/v1/projects/semiotic-bloom-477113-n6:optimizeTours",
            headers={"Authorization": f"Bearer {token}"},
            json={"model": {"shipments": shipments, "vehicles": [vehicle]}, "populatePolylines": True}
        ).json()

        if "routes" not in resp: return jsonify({'error': 'Optimization failed'}), 400

        # 3. Push Results to SQS (Async DB Update & Notify)
        if SQS_QUEUE_URL:
            sqs.send_message(
                QueueUrl=SQS_QUEUE_URL,
                MessageBody=json.dumps({
                    "action": "ROUTE_OPTIMIZED",
                    "polyline": resp["routes"][0]["routePolyline"]["points"],
                    "visits": resp["routes"][0].get("visits", []),
                    "orders_map": {str(i): {"id": o['order_id'], "arn": o.get('sns_topic_arn')} for i, o in enumerate(orders)}
                })
            )

        return jsonify({
            "success": True, 
            "polyline": resp["routes"][0]["routePolyline"]["points"],
            "optimized_sequence": [{"order_id": orders[int(v['shipmentLabel'])]['order_id']} for v in resp["routes"][0].get("visits", [])]
        })

    except Exception as e: return jsonify({'error': str(e)}), 500

@application.route('/api/orders/mark-delivered', methods=['POST'])
def mark_delivered():
    """Async: Pushes to SQS"""
    if SQS_QUEUE_URL:
        sqs.send_message(
            QueueUrl=SQS_QUEUE_URL,
            MessageBody=json.dumps({
                "action": "MARK_DELIVERED",
                "order_id": request.json.get("order_id"),
                "timestamp": datetime.now(dt.timezone.utc).isoformat()
            })
        )
        return jsonify({'success': True}), 202
    return jsonify({'error': 'Queue error'}), 500

if __name__ == '__main__':
    application.run(debug=True, port=5001)