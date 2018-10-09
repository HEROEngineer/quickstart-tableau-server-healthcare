from __future__ import print_function
from datetime import datetime
import json
import boto3

config = boto3.client('config')
s3 = boto3.client('s3')


def evaluate_compliance(rule_parameters):
    s3_bucket_name = rule_parameters['S3BucketName']
    bucket_list = rule_parameters['LogBuckets']

    non_compliant_list = []

    for bucket in bucket_list:
        bucket_logging_response = s3.get_bucket_logging(Bucket=bucket)

        if 'LoggingEnabled' not in bucket_logging_response:
            non_compliant_list.append(bucket)
            continue

        target_bucket = bucket_logging_response['LoggingEnabled']['TargetBucket']

        if target_bucket != s3_bucket_name:
            non_compliant_list.append(bucket)

    if len(non_compliant_list) > 0:
        return {
            'compliance_type': 'NON_COMPLIANT',
            'annotation': 'Invalid logging for the following buckets: (%s)' % ', '.join(non_compliant_list)
        }

    return {
        'compliance_type': 'COMPLIANT',
        'annotation': 'All buckets are logging to s3://%s' % s3_bucket_name
    }


def lambda_handler(event, context):
    today = datetime.today()

    rule_parameters = json.loads(event['ruleParameters'])

    evaluation = evaluate_compliance(rule_parameters)

    result_token = event['resultToken'] if 'resultToken' in event else 'No token found'

    config.put_evaluations(
        Evaluations=[
            {
                'ComplianceResourceType': 'AWS::::Account',
                'ComplianceResourceId': event['accountId'],
                'ComplianceType': evaluation['compliance_type'],
                'Annotation': evaluation['annotation'],
                'OrderingTimestamp': datetime(today.year, today.month, today.day, today.hour)
            },
        ],
        ResultToken=result_token
    )
