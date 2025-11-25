from decimal import Decimal
import boto3
from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import json
import logging
from datetime import datetime
import datetime as dt
from functools import wraps
import requests
from jose import jwt
from boto3.dynamodb.conditions import Attr
from botocore.exceptions import ClientError
from google.oauth2 import service_account
import google.auth.transport.requests
import uuid
import re

# -------------------------------------------------------
#  FLASK SETUP
# -------------------------------------------------------

application = Flask(__name__)
CORS(application)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# -------------------------------------------------------
#  REQUIRED ENV VARIABLES (from Elastic Beanstalk)
# -------------------------------------------------------

REQUIRED_ENV = [
    "AWS_REGION",
    "COGNITO_USER_POOL_ID",
    "COGNITO_APP_CLIENT_ID",
    "COGNITO_REGION",
    "DYNAMODB_TABLE_NAME",
    "USERS_TABLE_NAME",
    "ORDER_QUEUE_URL"
]

missing = [v for v in REQUIRED_ENV if not os.getenv(v)]
if missing:
    raise EnvironmentError(f"Missing EB environment variables: {missing}")

AWS_REGION = os.getenv("AWS_REGION")
COGNITO_USER_POOL_ID = os.getenv("COGNITO_USER_POOL_ID")
COGNITO_APP_CLIENT_ID = os.getenv("COGNITO_APP_CLIENT_ID")
COGNITO_REGION = os.getenv("COGNITO_REGION")
ORDERS_TABLE_NAME = os.getenv("DYNAMODB_TABLE_NAME")
USERS_TABLE_NAME = os.getenv("USERS_TABLE_NAME")
ORDER_QUEUE_URL = os.getenv("ORDER_QUEUE_URL")

# SSM Parameter names
SSM_GOOGLE_CREDS = "/preethi-logistics/google-creds"
SSM_MAPS_KEY = "/preethi-logistics/google-maps-key"

# Warehouse (Dublin)
WAREHOUSE_LOCATION = {"lat": Decimal("53.349242"), "lng": Decimal("-6.242983")}

# -------------------------------------------------------
#  AWS CLIENTS
# -------------------------------------------------------

cognito = boto3.client("cognito-idp", region_name=AWS_REGION)
dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
sns = boto3.client("sns", region_name=AWS_REGION)
ssm = boto3.client("ssm", region_name=AWS_REGION)
sqs = boto3.client("sqs", region_name=AWS_REGION)

orders_table = dynamodb.Table(ORDERS_TABLE_NAME)
users_table = dynamodb.Table(USERS_TABLE_NAME)

ORDER_QUEUE_URL = ORDER_QUEUE_URL  # from EB

# -------------------------------------------------------
#  GOOGLE AUTH HELPERS
# -------------------------------------------------------

def get_google_access_token():
    try:
        param = ssm.get_parameter(Name=SSM_GOOGLE_CREDS, WithDecryption=True)
        creds_dict = json.loads(param["Parameter"]["Value"])

        creds = service_account.Credentials.from_service_account_info(
            creds_dict,
            scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )
        req = google.auth.transport.requests.Request()
        creds.refresh(req)
        return creds.token

    except Exception as e:
        logger.error(f"Google OAuth failed: {e}")
        return None

def get_maps_key():
    try:
        param = ssm.get_parameter(Name=SSM_MAPS_KEY, WithDecryption=True)
        return param["Parameter"]["Value"]
    except:
        return None

# -------------------------------------------------------
#  GEOCODING
# -------------------------------------------------------

def geocode(address):
    api_key = get_maps_key()
    if not api_key:
        return None

    try:
        url = f"https://maps.googleapis.com/maps/api/geocode/json?address={address}&key={api_key}"
        resp = requests.get(url).json()

        if resp["status"] != "OK":
            logger.error("Geocode failed: " + resp["status"])
            return None

        loc = resp["results"][0]["geometry"]["location"]
        return {"lat": loc["lat"], "lng": loc["lng"]}
    except Exception as e:
        logger.error(f"Geocoding error: {e}")
        return None

# -------------------------------------------------------
#  SNS FUNCTIONS
# -------------------------------------------------------

def create_user_topic(email):
    safe = re.sub(r"[^a-zA-Z0-9]", "_", email)
    topic_name = f"PreethiLogistics_{safe}"

    try:
        resp = sns.create_topic(Name=topic_name)
        arn = resp["TopicArn"]
        sns.subscribe(TopicArn=arn, Protocol="email", Endpoint=email)
        return arn
    except Exception as e:
        logger.error(f"Failed to create SNS topic: {e}")
        return None

def send_notification(topic_arn, subject, msg):
    if not topic_arn:
        return False
    try:
        sns.publish(TopicArn=topic_arn, Subject=subject, Message=msg)
        return True
    except Exception as e:
        logger.error(f"SNS failed: {e}")
        return False

# -------------------------------------------------------
#  AUTH HELPERS (COGNITO JWT)
# -------------------------------------------------------

ISSUER = f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}"
JWKS_URL = f"{ISSUER}/.well-known/jwks.json"

try:
    jwks = requests.get(JWKS_URL).json()
except:
    jwks = {}

def get_key(token):
    try:
        headers = jwt.get_unverified_header(token)
        kid = headers["kid"]
        for key in jwks.get("keys", []):
            if key["kid"] == kid:
                return key
    except:
        return None

def verify_token(token):
    try:
        key = get_key(token)
        if not key:
            return None
        return jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            audience=COGNITO_APP_CLIENT_ID,
            issuer=ISSUER
        )
    except Exception:
        return None

def token_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization")
        if not auth or not auth.startswith("Bearer "):
            return jsonify({"success": False, "error": "Missing token"}), 401

        token = auth.split(" ")[1]
        decoded = verify_token(token)
        if not decoded:
            return jsonify({"success": False, "error": "Invalid token"}), 401

        request.user_id = decoded.get("sub")
        request.user_email = decoded.get("email")
        return fn(*args, **kwargs)
    return wrapper

# -------------------------------------------------------
#  ROUTES
# -------------------------------------------------------

@application.route("/")
def health():
    return {"status": "online"}

# ---------------------- SIGNUP ------------------------

@application.route("/signup", methods=["POST"])
def signup():
    data = request.json
    email = data.get("email")
    password = data.get("password")
    name = data.get("name")
    role = data.get("role", "customer")

    try:
        resp = cognito.sign_up(
            ClientId=COGNITO_APP_CLIENT_ID,
            Username=email,
            Password=password,
            UserAttributes=[{"Name": "email", "Value": email}, {"Name": "name", "Value": name}]
        )
        user_sub = resp["UserSub"]

        try:
            cognito.admin_add_user_to_group(
                UserPoolId=COGNITO_USER_POOL_ID,
                Username=email,
                GroupName=role
            )
        except:
            pass

        topic_arn = create_user_topic(email)

        users_table.put_item(Item={
            "user_id": user_sub,
            "email": email,
            "name": name,
            "role": role,
            "sns_topic_arn": topic_arn,
            "created_at": datetime.now(dt.timezone.utc).isoformat()
        })

        return {"success": True, "message": "Signup successful"}

    except cognito.exceptions.UsernameExistsException:
        return {"success": False, "error": "Email already exists"}, 409
    except Exception as e:
        logger.error(e)
        return {"success": False, "error": str(e)}, 500

# ---------------------- LOGIN -------------------------

@application.route("/login", methods=["POST"])
def login():
    data = request.json
    try:
        resp = cognito.initiate_auth(
            ClientId=COGNITO_APP_CLIENT_ID,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={
                "USERNAME": data.get("email"),
                "PASSWORD": data.get("password")
            }
        )
        return resp["AuthenticationResult"]
    except:
        return {"error": "Invalid credentials"}, 401

# ---------------------- CREATE ORDER ------------------

@application.route("/api/orders", methods=["POST"])
@token_required
def create_order():
    try:
        data = request.json
        geo = geocode(data.get("deliveryAddress"))

        if not geo:
            return {"success": False, "error": "Invalid address"}, 400

        user = users_table.get_item(Key={"user_id": request.user_id}).get("Item")
        topic_arn = user.get("sns_topic_arn")

        order_id = str(uuid.uuid4())

        item = {
            "order_id": order_id,
            "customer_id": request.user_id,
            "sns_topic_arn": topic_arn,
            "deliveryAddress": data.get("deliveryAddress"),
            "delivery_lat": Decimal(str(geo["lat"])),
            "delivery_lng": Decimal(str(geo["lng"])),
            "contact": data.get("contact"),
            "package_size": data.get("packageSize"),
            "status": "Pending",
            "created_at": datetime.now(dt.timezone.utc).isoformat()
        }

        orders_table.put_item(Item=item)

        # Push message to SQS → Lambda processes async
        sqs.send_message(
            QueueUrl=ORDER_QUEUE_URL,
            MessageBody=json.dumps({"order_id": order_id})
        )

        send_notification(topic_arn, "Order Received", f"Your order {order_id[:8]} is received")

        return {"success": True, "order_id": order_id}

    except Exception as e:
        logger.error(e)
        return {"success": False, "error": str(e)}, 500

# ---------------------- GET ORDER(S) ------------------

@application.route("/api/orders", methods=["GET"])
@token_required
def get_orders():
    try:
        user_id = request.user_id
        role = users_table.get_item(Key={"user_id": user_id}).get("Item", {}).get("role", "customer")

        if role == "agent":
            result = orders_table.scan()
        else:
            result = orders_table.scan(FilterExpression=Attr("customer_id").eq(user_id))

        items = result.get("Items", [])
        for i in items:
            i["delivery_lat"] = float(i["delivery_lat"])
            i["delivery_lng"] = float(i["delivery_lng"])

        return {"success": True, "orders": items}
    except Exception as e:
        return {"success": False, "error": str(e)}, 500

# ---------------------- GET SINGLE ORDER ---------------

@application.route("/api/orders/<oid>", methods=["GET"])
@token_required
def get_single(oid):
    try:
        item = orders_table.get_item(Key={"order_id": oid}).get("Item")
        if not item:
            return {"error": "Not found"}, 404

        item["delivery_lat"] = float(item["delivery_lat"])
        item["delivery_lng"] = float(item["delivery_lng"])
        return {"success": True, "order": item}
    except Exception as e:
        return {"success": False, "error": str(e)}, 500

# ---------------------- DELETE ORDER --------------------

@application.route("/api/orders/<oid>", methods=["DELETE"])
@token_required
def delete_order(oid):
    try:
        item = orders_table.get_item(Key={"order_id": oid}).get("Item")
        if not item:
            return {"error": "Not found"}, 404

        if item["customer_id"] != request.user_id:
            return {"error": "Unauthorized"}, 403

        if item["status"] != "Pending":
            return {"error": "Cannot delete order that is already processed"}, 400

        orders_table.delete_item(Key={"order_id": oid})

        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}, 500

# -------------------------------------------------------
# RUN APP
# -------------------------------------------------------
if __name__ == "__main__":
    application.run(debug=True)
