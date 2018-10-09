from __future__ import print_function
import json
import boto3
from datetime import datetime

cloudtrail = boto3.client('cloudtrail')
config = boto3.client('config')


def evaluate_compliance(rule_parameters):
    s3_bucket_name = rule_parameters['S3BucketName']
    s3_key_prefix = rule_parameters['S3KeyPrefix']

    trails_response = cloudtrail.describe_trails()

    if 'trailList' not in trails_response or len(trails_response['trailList']) == 0:
        return {
            'compliance_type': 'NON_COMPLIANT',
            'annotation': 'No trails were found. Check CloudTrail enabled'
        }

    for trail in trails_response['trailList']:
        if trail['S3BucketName'] == s3_bucket_name:
            if ('S3KeyPrefix' not in trail and s3_key_prefix in [None, '']) or trail['S3KeyPrefix'] == s3_key_prefix:
                continue
        return {
            'compliance_type': 'NON_COMPLIANT',
            'annotation': '%s is not writing to s3://%s/%s. Showing as s3://%s/%s' % (trail['TrailARN'],
                                                                                      s3_bucket_name,
                                                                                      s3_key_prefix,
                                                                                      trail['S3BucketName'],
                                                                                      trail['S3KeyPrefix'])
        }

    return {
        'compliance_type': 'COMPLIANT',
        'annotation': 'All trails writing to specified s3://%s/%s' % (s3_bucket_name, s3_key_prefix)
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
