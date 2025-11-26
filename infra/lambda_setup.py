#!/usr/bin/env python3
import os
import zipfile
import boto3
from botocore.exceptions import ClientError

AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
LAMBDA_NAME = os.getenv("LAMBDA_NAME", "OrderProcessorLambda")
ROLE_ARN = os.getenv("LAB_ROLE_ARN","arn:aws:iam::593793054391:role/data-processor-lambda-role")  # should be provided as secret
SOURCE_DIR = os.getenv("LAMBDA_SOURCE", "order_processor")
ZIP_NAME = "lambda_package.zip"
ORDER_QUEUE_URL = os.getenv("ORDER_QUEUE_URL","https://sqs.us-east-1.amazonaws.com/593793054391/route-orders-queue")  # expected from infra outputs

lambda_client = boto3.client("lambda", region_name=AWS_REGION)
sqs = boto3.client("sqs", region_name=AWS_REGION)

def zip_source():
    print("📦 Packaging Lambda code...")
    with zipfile.ZipFile(ZIP_NAME, "w", zipfile.ZIP_DEFLATED) as z:
        for root, dirs, files in __import__("os").walk(SOURCE_DIR):
            for f in files:
                path = __import__("os").path.join(root, f)
                arcname = __import__("os").path.relpath(path, SOURCE_DIR)
                z.write(path, arcname)
    print(f"   ✔ Created {ZIP_NAME}")

def lambda_exists(name):
    try:
        lambda_client.get_function(FunctionName=name)
        return True
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return False
        raise

def create_function():
    if not ROLE_ARN:
        raise RuntimeError("LAB_ROLE_ARN not provided in environment (cannot create function).")
    print(f"🚀 Creating Lambda function {LAMBDA_NAME} (role={ROLE_ARN})")
    with open(ZIP_NAME, "rb") as f:
        code = f.read()
    resp = lambda_client.create_function(
        FunctionName=LAMBDA_NAME,
        Runtime="python3.12",
        Role=ROLE_ARN,
        Handler="lambda_function.lambda_handler",
        Code={"ZipFile": code},
        Timeout=30,
        MemorySize=256,
        Publish=True
    )
    print("   ✔ Created Lambda")
    return resp

def update_function():
    print(f"🔁 Updating Lambda function {LAMBDA_NAME}")
    with open(ZIP_NAME, "rb") as f:
        lambda_client.update_function_code(FunctionName=LAMBDA_NAME, ZipFile=f.read(), Publish=True)
    print("   ✔ Lambda code updated")

def ensure_sqs_trigger():
    if not ORDER_QUEUE_URL:
        print("   ⚠ ORDER_QUEUE_URL not provided. Skipping trigger creation.")
        return
    # read queue arn
    attrs = sqs.get_queue_attributes(QueueUrl=ORDER_QUEUE_URL, AttributeNames=["QueueArn"])
    queue_arn = attrs["Attributes"]["QueueArn"]
    # list event source mappings
    mappings = lambda_client.list_event_source_mappings(FunctionName=LAMBDA_NAME)
    for m in mappings.get("EventSourceMappings", []):
        if m.get("EventSourceArn") == queue_arn:
            print("   ✔ SQS -> Lambda mapping already exists")
            return
    # create mapping
    lambda_client.create_event_source_mapping(EventSourceArn=queue_arn, FunctionName=LAMBDA_NAME, Enabled=True, BatchSize=1)
    print("   ✔ Created event source mapping (SQS -> Lambda)")

if __name__ == "__main__":
    print(f"🟦 Lambda setup (region={AWS_REGION})")
    zip_source()
    if lambda_exists(LAMBDA_NAME):
        update_function()
    else:
        create_function()
    try:
        ensure_sqs_trigger()
    except Exception as e:
        print(f"   ⚠ Warning setting up trigger: {e}")
    print("   ✔ Lambda setup complete")
