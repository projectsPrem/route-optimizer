import json
import boto3
import os
import urllib.request
import urllib.parse
from decimal import Decimal

DYNAMODB_TABLE = os.environ.get('DYNAMODB_TABLE_NAME', 'orders')
USERS_TABLE = os.environ.get('USERS_TABLE_NAME', 'users')
SSM_MAPS_KEY = "/preethi-logistics/google-maps-key"
REGION = os.environ.get('AWS_REGION', 'us-east-1')

dynamodb = boto3.resource('dynamodb', region_name=REGION)
sns = boto3.client('sns', region_name=REGION)
ssm = boto3.client('ssm', region_name=REGION)
table = dynamodb.Table(DYNAMODB_TABLE)
users = dynamodb.Table(USERS_TABLE)

def get_geo(address):
    try:
        key = ssm.get_parameter(Name=SSM_MAPS_KEY, WithDecryption=True)['Parameter']['Value']
        url = f"https://maps.googleapis.com/maps/api/geocode/json?address={urllib.parse.quote(address)}&key={key}"
        with urllib.request.urlopen(url) as r:
            data = json.loads(r.read().decode())
            if data['status'] == 'OK':
                loc = data['results'][0]['geometry']['location']
                return Decimal(str(loc['lat'])), Decimal(str(loc['lng']))
    except: pass
    return Decimal("53.3498"), Decimal("-6.2603")

def lambda_handler(event, context):
    for record in event['Records']:
        try:
            payload = json.loads(record['body'])
            action = payload.get('action')
            print(f"Processing: {action}")

            if action == "CREATE_ORDER":
                data = payload['data']
                lat, lng = get_geo(data['deliveryAddress'])
                
                # Get Topic ARN
                arn = None
                try: arn = users.get_item(Key={'user_id': payload['customer_id']}).get('Item', {}).get('sns_topic_arn')
                except: pass

                table.put_item(Item={
                    'order_id': payload['order_id'],
                    'customer_id': payload['customer_id'],
                    'user_email': payload['user_email'],
                    'contact_num': data.get('contact'),
                    'delivery_locations': data['deliveryAddress'],
                    'package_size': data.get('packageSize'),
                    'status': 'Pending',
                    'delivery_lat': lat,
                    'delivery_lng': lng,
                    'sns_topic_arn': arn,
                    'created_at': payload['timestamp']
                })
                
                if arn: sns.publish(TopicArn=arn, Subject="Order Received", Message=f"Order {payload['order_id'][:8]} received.")

            elif action == "MARK_DELIVERED":
                oid = payload['order_id']
                table.update_item(
                    Key={'order_id': oid},
                    UpdateExpression="SET #s=:s, delivered_at=:t",
                    ExpressionAttributeNames={'#s': 'status'},
                    ExpressionAttributeValues={':s': 'Delivered', ':t': payload['timestamp']}
                )
                item = table.get_item(Key={'order_id': oid}).get('Item', {})
                if item.get('sns_topic_arn'):
                    sns.publish(TopicArn=item['sns_topic_arn'], Subject="Delivered", Message=f"Order {oid[:8]} Delivered.")

            elif action == "DELETE_ORDER":
                table.delete_item(Key={'order_id': payload['order_id']})

            elif action == "ROUTE_OPTIMIZED":
                poly = payload['polyline']
                for label, order_info in payload['orders_map'].items():
                    oid = order_info['id']
                    table.update_item(
                        Key={'order_id': oid},
                        UpdateExpression="SET #s=:s, polyline=:p",
                        ExpressionAttributeNames={'#s': 'status'},
                        ExpressionAttributeValues={':s': 'In Transit', ':p': poly}
                    )
                    if order_info.get('arn'):
                        sns.publish(TopicArn=order_info['arn'], Subject="Out for Delivery", Message=f"Order {oid[:8]} is Out for Delivery.")

        except Exception as e:
            print(f"Error: {e}")

    return {"statusCode": 200}