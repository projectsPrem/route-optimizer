#!/usr/bin/env python3
import os
import json
import boto3
from botocore.exceptions import ClientError

REGION = os.getenv("AWS_REGION", "us-east-1")
QUEUE_NAME = os.getenv("ORDER_QUEUE_NAME", "route-orders-queue")
DLQ_NAME = os.getenv("ORDER_DLQ_NAME", "route-orders-dlq")

sqs = boto3.client("sqs", region_name=REGION)

def create_queue(name, attributes=None):
    try:
        args = {"QueueName": name}
        if attributes:
            args["Attributes"] = attributes
        resp = sqs.create_queue(**args)
        url = resp["QueueUrl"]
        print(f"   ✔ Created/Found queue: {name} -> {url}")
        return url
    except ClientError as e:
        # If create fails because exists, try to get url
        try:
            url = sqs.get_queue_url(QueueName=name)["QueueUrl"]
            print(f"   ✔ Queue exists: {name} -> {url}")
            return url
        except Exception as ex:
            print(f"   ✖ Failed to create/get queue {name}: {e} / {ex}")
            raise

def get_queue_arn(url):
    attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])
    return attrs["Attributes"]["QueueArn"]

def apply_redrive_policy(main_url, dlq_arn, max_receive=3):
    policy = {
        "deadLetterTargetArn": dlq_arn,
        "maxReceiveCount": str(max_receive)
    }
    sqs.set_queue_attributes(QueueUrl=main_url, Attributes={"RedrivePolicy": json.dumps(policy)})
    print("   ✔ Applied redrive policy (main -> dlq)")

if __name__ == "__main__":
    print(f"🟦 SQS setup (region={REGION})")

    dlq_url = create_queue(DLQ_NAME, attributes={"MessageRetentionPeriod":"1209600"})  # 14 days
    dlq_arn = get_queue_arn(dlq_url)

    main_url = create_queue(QUEUE_NAME, attributes={"VisibilityTimeout": "60", "MessageRetentionPeriod":"86400"})
    # Attach DLQ
    try:
        apply_redrive_policy(main_url, dlq_arn)
    except Exception as e:
        print(f"   ⚠ Could not apply redrive policy: {e}")

    # Print outputs for GitHub Actions
    print(f"OUTPUT_MAIN_QUEUE_URL={main_url}")
    print(f"OUTPUT_DLQ_URL={dlq_url}")
