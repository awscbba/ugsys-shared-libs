"""
Shared pytest fixtures for ugsys services.
Import these in your conftest.py:

    from ugsys_testing_lib.fixtures import dynamodb_table, s3_bucket
"""

import os

import boto3
import pytest
from moto import mock_aws


@pytest.fixture(scope="function")
def aws_credentials():
    """Mocked AWS credentials so boto3 doesn't hit real AWS."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"


@pytest.fixture(scope="function")
def dynamodb_table(aws_credentials):
    """
    Provides a mocked DynamoDB table.
    Override table_name and key_schema in your service conftest.
    """
    with mock_aws():
        client = boto3.resource("dynamodb", region_name="us-east-1")
        table = client.create_table(
            TableName="test-table",
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        yield table


@pytest.fixture(scope="function")
def s3_bucket(aws_credentials):
    """Provides a mocked S3 bucket."""
    with mock_aws():
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket="test-bucket")
        yield client


@pytest.fixture(scope="function")
def eventbridge_bus(aws_credentials):
    """Provides a mocked EventBridge custom bus."""
    with mock_aws():
        client = boto3.client("events", region_name="us-east-1")
        client.create_event_bus(Name="ugsys-platform-bus")
        yield client
