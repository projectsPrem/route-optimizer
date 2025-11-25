#!/usr/bin/env python3
import json
import boto3
import os
from datetime import datetime, timezone

AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
ORDERS_TABLE = os.getenv("DYNAMODB_TABLE_NAME", "orders")

dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
sns = boto3.client("sns", region_name=AWS_REGION)
orders_table = dynamodb.Table(ORDERS_TABLE)

def update_status(order_id, new_status):
    try:
        return orders_table.update_item(
            Key={"order_id": order_id},
            UpdateExpression="SET #s = :s, updated_at = :t",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":s": new_status, ":t": datetime.now(timezone.utc).isoformat()},
            ReturnValues="UPDATED_NEW"
        )
    except Exception as e:
        print("Error updating status:", e)
        raise

def send_notification(topic_arn, subject, message):
    if not topic_arn:
        print("No topic ARN; skipping notification.")
        return
    try:
        sns.publish(TopicArn=topic_arn, Subject=subject, Message=message)
        print(f"Notified {topic_arn}")
    except Exception as e:
        print("SNS publish failed:", e)

def lambda_handler(event, context):
    print("Received event:", json.dumps(event))
    for record in event.get("Records", []):
        try:
            body = json.loads(record.get("body", "{}"))
            order_id = body.get("order_id")
            if not order_id:
                print("No order_id in message; skipping.")
                continue

            resp = orders_table.get_item(Key={"order_id": order_id})
            if "Item" not in resp:
                print("Order not found:", order_id)
                continue

            order = resp["Item"]
            topic = order.get("sns_topic_arn")

            print(f"Processing order {order_id}")

            # 1. mark Processing
            update_status(order_id, "Processing")
            send_notification(topic, "Order Processing", f"Your order {order_id[:8]} is being processed.")

            # (Heavy async work would be here — e.g., routing, 3rd-party calls)
            # For Option 1 we simulate processing quickly.

            # 2. mark In Transit
            update_status(order_id, "In Transit")
            send_notification(topic, "Order In Transit", f"Your order {order_id[:8]} is now In Transit.")

            print(f"Finished processing {order_id}")

        except Exception as e:
            print("Error handling record:", e)
            # Do not raise — let SQS retry via visibility timeout / DLQ
            continue

    return {"status": "ok"}
