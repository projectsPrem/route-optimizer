#!/usr/bin/env python3
import os
import boto3
from botocore.exceptions import ClientError

REGION = os.getenv("AWS_REGION", "us-east-1")

def create_tables():
    dynamodb = boto3.client("dynamodb", region_name=REGION)

    tables = {
        "users": {
            "AttributeDefinitions": [
                {"AttributeName": "user_id", "AttributeType": "S"}
            ],
            "KeySchema": [
                {"AttributeName": "user_id", "KeyType": "HASH"}
            ],
            "BillingMode": "PAY_PER_REQUEST"
        },
        "orders": {
            "AttributeDefinitions": [
                {"AttributeName": "order_id", "AttributeType": "S"},
                {"AttributeName": "customer_id", "AttributeType": "S"}
            ],
            "KeySchema": [
                {"AttributeName": "order_id", "KeyType": "HASH"}
            ],
            "GlobalSecondaryIndexes": [
                {
                    "IndexName": "customer_id-index",
                    "KeySchema": [
                        {"AttributeName": "customer_id", "KeyType": "HASH"}
                    ],
                    "Projection": {"ProjectionType": "ALL"}
                }
            ],
            "BillingMode": "PAY_PER_REQUEST"
        }
    }

    print(f"🟦 DynamoDB setup (region={REGION})")
    for name, schema in tables.items():
        try:
            dynamodb.create_table(TableName=name, **schema)
            print(f"   ✔ Created table: {name}")
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            if code == "ResourceInUseException" or "AlreadyExistsException" in str(e):
                print(f"   ✔ Table exists: {name}")
            else:
                print(f"   ✖ Error creating table {name}: {e}")
                raise

if __name__ == "__main__":
    create_tables()
