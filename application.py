from decimal import Decimal
import boto3
from flask import Flask, request, jsonify
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

# --- Configuration & Setup ---
env_path = find_dotenv()
load_dotenv(env_path)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

application = Flask(__name__)
CORS(application)

# --- Environment Variables ---
# REQUIRED_VARS = [
#     'AWS_REGION', 'COGNITO_USER_POOL_ID', 'COGNITO_APP_CLIENT_ID', 
#     'DYNAMODB_TABLE_NAME', 'USERS_TABLE_NAME', 'SQS_QUEUE_URL'
# ]
# Check optional vars to prevent crash on local dev
# missing = [v for v in REQUIRED_VARS if not os.getenv(v)]
# if missing: logger.warning(f"Missing vars: {missing}")

AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
COGNITO_USER_POOL_ID = os.getenv('COGNITO_USER_POOL_ID')
COGNITO_APP_CLIENT_ID = os.getenv('COGNITO_APP_CLIENT_ID')
COGNITO_REGION = os.getenv('COGNITO_REGION', AWS_REGION)
ORDERS_TABLE_NAME = os.getenv('DYNAMODB_TABLE_NAME', 'orders')
USERS_TABLE_NAME = os.getenv('USERS_TABLE_NAME', 'users')
SQS_QUEUE_URL = os.getenv('SQS_QUEUE_URL')

# SSM Keys
SSM_GOOGLE_CREDS = "/preethi-logistics/google-creds"
SSM_MAPS_KEY = "/preethi-logistics/google-maps-key"

# Warehouse (Dublin)
WAREHOUSE_LOCATION = {"lat": Decimal("53.349242"), "lng": Decimal("-6.242983")}

# --- AWS Clients ---
try:
    cognito_client = boto3.client('cognito-idp', region_name=AWS_REGION)
    dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
    sns_client = boto3.client('sns', region_name=AWS_REGION)
    ssm_client = boto3.client('ssm', region_name=AWS_REGION)
    sqs_client = boto3.client('sqs', region_name=AWS_REGION) # <--- SQS Client
    
    orders_table = dynamodb.Table(ORDERS_TABLE_NAME)
    users_table = dynamodb.Table(USERS_TABLE_NAME)
    logger.info("AWS Clients initialized")
except Exception as e:
    logger.critical(f"AWS Client Init Error: {e}")
    raise e

# --- HELPERS ---

def get_google_access_token():
    """Fetches Credentials from SSM and returns Token."""
    try:
        parameter = ssm_client.get_parameter(Name=SSM_GOOGLE_CREDS, WithDecryption=True)
        creds_dict = json.loads(parameter['Parameter']['Value'])
        creds = service_account.Credentials.from_service_account_info(
            creds_dict, scopes=['https://www.googleapis.com/auth/cloud-platform']
        )
        auth_req = google.auth.transport.requests.Request()
        creds.refresh(auth_req)
        return creds.token
    except Exception as e:
        logger.error(f"Google Auth Error: {e}")
        return None

def get_maps_api_key():
    try:
        parameter = ssm_client.get_parameter(Name=SSM_MAPS_KEY, WithDecryption=True)
        return parameter['Parameter']['Value']
    except: return None

def get_geo_data(address):
    key = get_maps_api_key()
    if not key: return None
    try:
        url = f"https://maps.googleapis.com/maps/api/geocode/json?address={address}&key={key}"
        resp = requests.get(url).json()
        if resp['status'] == 'OK':
            loc = resp['results'][0]['geometry']['location']
            return {"lat": loc['lat'], "lng": loc['lng']}
        return None
    except: return None

def create_user_topic(email):
    try:
        safe_name = re.sub(r'[^a-zA-Z0-9]', '_', email)
        topic_name = f"Preethi_Logistics_{safe_name}"
        resp = sns_client.create_topic(Name=topic_name)
        arn = resp['TopicArn']
        sns_client.subscribe(TopicArn=arn, Protocol='email', Endpoint=email)
        return arn
    except Exception as e:
        logger.error(f"SNS Error: {e}")
        return None

def send_sns_notification(topic_arn, subject, message):
    if not topic_arn: return
    try:
        sns_client.publish(TopicArn=topic_arn, Subject=subject, Message=message)
    except: pass

# --- AUTH UTILS ---
COGNITO_ISSUER = f'https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}'
JWKS_URL = f'{COGNITO_ISSUER}/.well-known/jwks.json'
try: jwks = requests.get(JWKS_URL).json()
except: jwks = {}

def verify_token(token):
    try:
        headers = jwt.get_unverified_header(token)
        kid = headers['kid']
        key = next(k for k in jwks.get('keys', []) if k['kid'] == kid)
        return jwt.decode(token, key, algorithms=['RS256'], audience=COGNITO_APP_CLIENT_ID, issuer=COGNITO_ISSUER)
    except: return None

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token or not token.startswith('Bearer '):
            request.user_id = 'guest_id'; request.user_email = 'guest'
            return f(*args, **kwargs)
        payload = verify_token(token[len('Bearer '):])
        if not payload: return jsonify({'error': 'Invalid token'}), 401
        request.user_id = payload.get('sub')
        request.user_email = payload.get('email')
        return f(*args, **kwargs)
    return decorated

def convert_decimal(obj):
    if isinstance(obj, list): return [convert_decimal(i) for i in obj]
    if isinstance(obj, dict): return {k: convert_decimal(v) for k, v in obj.items()}
    if isinstance(obj, float): return Decimal(str(obj))
    return obj

# --- ROUTES ---

@application.route('/')
def health(): return jsonify({"status": "online"}), 200

@application.route('/signup', methods=['POST'])
def signup():
    data = request.get_json() or {}
    email = data.get('email')
    password = data.get('password')
    name = data.get('name')
    role = data.get('role', 'customer')

    try:
        resp = cognito_client.sign_up(
            ClientId=COGNITO_APP_CLIENT_ID, Username=email, Password=password,
            UserAttributes=[{"Name": "email", "Value": email}, {"Name": "name", "Value": name}]
        )
        try: cognito_client.admin_add_user_to_group(UserPoolId=COGNITO_USER_POOL_ID, Username=email, GroupName=role)
        except: pass
        
        topic_arn = create_user_topic(email)
        
        users_table.put_item(Item={
            'user_id': resp['UserSub'], 'email': email, 'name': name, 'role': role,
            'sns_topic_arn': topic_arn, 'created_at': datetime.now(dt.timezone.utc).isoformat()
        })
        return jsonify({"success": True, "message": "User registered. Check email."}), 201
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

@application.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    try:
        resp = cognito_client.initiate_auth(
            ClientId=COGNITO_APP_CLIENT_ID, AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={'USERNAME': data.get('email'), 'PASSWORD': data.get('password')}
        )
        return jsonify(resp['AuthenticationResult']), 200
    except: return jsonify({'error': 'Invalid credentials'}), 401

@application.route('/confirm', methods=['POST'])
def confirm():
    data = request.get_json()
    try:
        cognito_client.confirm_sign_up(ClientId=COGNITO_APP_CLIENT_ID, Username=data.get('email'), ConfirmationCode=data.get('code'))
        return jsonify({"success": True}), 200
    except: return jsonify({'success': False}), 400

# --- EVENT-DRIVEN CREATE ORDER ---
@application.route('/api/orders', methods=['POST'])
@token_required
def create_order():
    try:
        data = request.get_json()
        
        # 1. Geocode immediately for DB (So user sees it in UI)
        geo = get_geo_data(data.get('deliveryAddress'))
        if not geo: return jsonify({'success': False, 'error': 'Invalid Address'}), 400

        user_id = request.user_id
        user_rec = users_table.get_item(Key={'user_id': user_id})
        topic_arn = user_rec.get('Item', {}).get('sns_topic_arn')
        order_id = str(uuid.uuid4())

        # 2. Save to DB (Synchronous)
        item = {
            'order_id': order_id, 'customer_id': user_id, 
            'sns_topic_arn': topic_arn,
            'delivery_locations': data['deliveryAddress'],
            'contact_num': data.get("contact"),
            'status': 'Pending',
            'package_size': data.get("packageSize"),
            "delivery_lat": Decimal(str(geo["lat"])), "delivery_lng": Decimal(str(geo["lng"])),
            'created_at': datetime.now(dt.timezone.utc).isoformat()
        }
        orders_table.put_item(Item=item)

        # 3. Push to SQS (Event-Driven Background Task)
        if SQS_QUEUE_URL:
            sqs_client.send_message(
                QueueUrl=SQS_QUEUE_URL,
                MessageBody=json.dumps({
                    "order_id": order_id,
                    "customer_id": user_id,
                    "action": "NOTIFY_CREATED"
                })
            )
            logger.info(f"Order {order_id} queued to SQS")

        return jsonify({'success': True, 'order_id': order_id}), 201
    except Exception as e:
        logger.error(e)
        return jsonify({'success': False, 'error': str(e)}), 500

# --- GET / DELETE / SINGLE ---
@application.route('/api/orders', methods=['GET'])
@token_required
def get_orders():
    try:
        user_id = request.user_id
        user_rec = users_table.get_item(Key={'user_id': user_id})
        role = user_rec.get('Item', {}).get('role', 'customer')
        
        if role == 'agent': resp = orders_table.scan()
        else: resp = orders_table.scan(FilterExpression=Attr('customer_id').eq(user_id))
        
        orders = resp.get('Items', [])
        for o in orders: 
            o['delivery_lat'] = float(o['delivery_lat'])
            o['delivery_lng'] = float(o['delivery_lng'])
        return jsonify({'success': True, 'orders': orders}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@application.route('/api/orders/<oid>', methods=['GET'])
@token_required
def get_one(oid):
    resp = orders_table.get_item(Key={'order_id': oid})
    if 'Item' not in resp: return jsonify({'error': 'Not found'}), 404
    item = resp['Item']
    item['delivery_lat'] = float(item['delivery_lat'])
    item['delivery_lng'] = float(item['delivery_lng'])
    return jsonify({'success': True, 'order': item}), 200

@application.route('/api/orders/<oid>', methods=['DELETE'])
@token_required
def delete(oid):
    orders_table.delete_item(Key={'order_id': oid})
    return jsonify({'success': True}), 200

# --- OPTIMIZE & DELIVER ---
@application.route('/api/optimize-route', methods=['POST'])
def optimize():
    try:
        data = request.get_json()
        oids = data.get("order_ids", [])
        
        orders_list = []
        for oid in oids:
            resp = orders_table.get_item(Key={'order_id': oid})
            if 'Item' in resp:
                i = resp['Item']
                orders_list.append({
                    "id": i["order_id"], "lat": float(i["delivery_lat"]), "lng": float(i["delivery_lng"]),
                    "arn": i.get("sns_topic_arn")
                })
        
        if not orders_list: return jsonify({"error": "No orders"}), 400

        # Google Payload
        shipments = []
        for idx, o in enumerate(orders_list):
            shipments.append({
                "label": str(idx), "penaltyCost": 1000.0,
                "deliveries": [{"arrivalWaypoint": {"location": {"latLng": {"latitude": o["lat"], "longitude": o["lng"]}}}}]
            })
        
        vehicle = {
            "label": "v1", "costPerKilometer": 1.0,
            "startWaypoint": {"location": {"latLng": {"latitude": float(WAREHOUSE_LOCATION["lat"]), "longitude": float(WAREHOUSE_LOCATION["lng"])}}},
            "endWaypoint": {"location": {"latLng": {"latitude": float(WAREHOUSE_LOCATION["lat"]), "longitude": float(WAREHOUSE_LOCATION["lng"])}}}
        }

        token = get_google_access_token()
        if not token: return jsonify({"error": "Auth Error"}), 500

        g_resp = requests.post(
            "https://routeoptimization.googleapis.com/v1/projects/semiotic-bloom-477113-n6:optimizeTours",
            headers={"Authorization": f"Bearer {token}"},
            json={"model": {"shipments": shipments, "vehicles": [vehicle]}, "populatePolylines": True}
        ).json()

        if "routes" not in g_resp: return jsonify({"error": "Opt failed"}), 400
        
        polyline = g_resp["routes"][0]["routePolyline"]["points"]
        visits = g_resp["routes"][0].get("visits", [])
        seq = []

        for v in visits:
            idx = int(v["shipmentLabel"])
            o = orders_list[idx]
            seq.append({"order_id": o["id"]})
            
            orders_table.update_item(
                Key={'order_id': o['id']},
                UpdateExpression="SET #s=:s, polyline=:p",
                ExpressionAttributeNames={'#s': 'status'},
                ExpressionAttributeValues={':s': 'In Transit', ':p': polyline}
            )
            if o['arn']:
                send_sns_notification(o['arn'], "Order Update", f"Preethi Logistics: Order {o['id'][:8]} is OUT FOR DELIVERY.")

        return jsonify({"success": True, "polyline": polyline, "optimized_sequence": seq}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

@application.route('/api/orders/mark-delivered', methods=['POST'])
def mark_delivered():
    try:
        oid = request.get_json().get("order_id")
        resp = orders_table.get_item(Key={'order_id': oid})
        item = resp.get('Item')
        
        orders_table.update_item(
            Key={'order_id': oid},
            UpdateExpression="SET #s=:s, delivered_at=:t",
            ExpressionAttributeNames={'#s': 'status'},
            ExpressionAttributeValues={':s': 'Delivered', ':t': datetime.now(dt.timezone.utc).isoformat()}
        )
        
        if item and item.get('sns_topic_arn'):
            send_sns_notification(item['sns_topic_arn'], "Delivered", f"Preethi Logistics: Order {oid[:8]} DELIVERED.")
            
        return jsonify({"success": True}), 200
    except Exception as e: return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    application.run(debug=True)