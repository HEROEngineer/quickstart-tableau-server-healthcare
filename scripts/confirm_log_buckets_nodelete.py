from __future__ import print_function
from datetime import datetime
import json
import boto3

s3 = boto3.client('s3')


def validate_deny_delete_object(deny_statements, bucket):
    valid_resource = 'arn:aws:s3:::%s/*' % bucket

    for statement in deny_statements:
        if statement['Resource'] != valid_resource or statement['Principal'] != '*':
            continue

        if type(statement['Action']) is str:
            action = statement['Action']
            if action == '*' or action[-1] in 's3:DeleteObject':
                return 'COMPLIANT'
        else:
            for action in statement['Action']:
                if action == '*' or action[-1] in 's3:DeleteObject':
                    return 'COMPLIANT'

    return 'NON_COMPLIANT'


def validate_deny_delete_bucket(deny_statements, bucket):
    valid_resource = 'arn:aws:s3:::%s' % bucket

    for statement in deny_statements:
        if statement['Resource'] != valid_resource or statement['Principal'] != '*':
            continue

        if type(statement['Action']) is str:
            action = statement['Action']
            if action == '*' or action[-1] in 's3:DeleteBucket':
                return 'COMPLIANT'
        else:
            for action in statement['Action']:
                if action == '*' or action[-1] in 's3:DeleteBucket':
                    return 'COMPLIANT'

    return 'NON_COMPLIANT'


def validate_acceptable_allow_string(action):
    return action != 's3:*' and \
           not (action[-1] == '*' and (action[:-1] in 's3:DeleteObject' or action[:-1] not in 's3:DeleteBucket')) and \
           (action != 's3:DeleteObject' and action != 's3:DeleteBucket')


def validate_acceptable_allow(action):
    if type(action) is str:
        return validate_acceptable_allow_string(action)

    for action_string in action:
        valid_action = validate_acceptable_allow_string(action_string)
        if not valid_action:
            return False

    return True


# Verify compliance
def evaluate_compliance(rule_parameters):
    log_buckets = rule_parameters['LogBuckets']

    for bucket in log_buckets:
        response = s3.get_bucket_policy(Bucket=bucket)
        bucket_policy = json.loads(response['Policy'])

        deny_statements = [_ for _ in bucket_policy['Statement'] if _['Effect'] == 'Deny']
        allow_statements = [_ for _ in bucket_policy['Statement'] if _['Effect'] == 'Allow']

        # First verify denies for delete object and bucket are in place
        if validate_deny_delete_object(deny_statements, bucket) == 'NON_COMPLIANT':
            return {
                'compliance_type': 'NON_COMPLIANT',
                'annotation': '%s is missing explicit deny of DeleteObject' % bucket
            }

        if validate_deny_delete_bucket(deny_statements, bucket) == 'NON_COMPLIANT':
            return {
                'compliance_type': 'NON_COMPLIANT',
                'annotation': '%s is missing explicit deny of DeleteObject' % bucket
            }

        # Then ensure that none of the Allow Policies contradict
        for statement in allow_statements:
            if statement['Effect'] == 'Allow':
                if not validate_acceptable_allow(statement['Action']):
                    return {
                        'compliance_type': 'NON_COMPLIANT',
                        'annotation': 'Non-compliant S3 Bucket Policy for %s. Problematic statement is: %s' % (bucket,
                                                                                                               statement)
                    }

    return {
        'compliance_type': 'COMPLIANT',
        'annotation': 'Bucket policies disallow delete object and bucket'
    }


def lambda_handler(event, context):
    today = datetime.today()

    rule_parameters = json.loads(event['ruleParameters'])

    evaluation = evaluate_compliance(rule_parameters)
    config = boto3.client('config')

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
