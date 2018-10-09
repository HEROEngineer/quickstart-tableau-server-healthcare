from __future__ import print_function
import boto3
import json
from datetime import datetime

s3 = boto3.client('s3')
config = boto3.client('config')


def sort_rules(rules):
    # First sort all of the nested components
    # tags, transitions, noncurrent version transitions
    for rule in rules:
        if 'Filter' in rule and 'And' in rule['Filter'] and 'Tags' in rule['Filter']['And']:
            sorted_tags = sorted(rule['Filter']['And']['Tags'])
            rule['Filter']['And']['Tags'] = sorted_tags
        if 'Transitions' in rule:
            rule['Transitions'] = sorted(rule['Transitions'])
        if 'NoncurrentVersionTransitions' in rule:
            rule['NoncurrentVersionTransitions'] = sorted(rule['NoncurrentVersionTransitions'])

    return sorted(rules)


def evaluate_compliance(rule_parameters):
    log_buckets = rule_parameters['LogBuckets']
    for bucket in log_buckets:
        try:
            policy_response = s3.get_bucket_lifecycle_configuration(Bucket=bucket)
        except Exception as e:
            return {
                'compliance_type': 'NON_COMPLIANT',
                'annotation': 'Lifecycle Policy does not exist for %s' % bucket
            }

        policy_statement = sort_rules(policy_response['Rules'])
        policy_to_validate = sort_rules(rule_parameters['LifecyclePolicy']['Rules'])

        if len(policy_statement) != len(policy_to_validate):
            return {
                'compliance_type': 'NON_COMPLIANT',
                'annotation': 'Incorrect length of policy statement for %s' % bucket
            }

        # When we match, we look for Transitions, Filters, NoncurrentVersionTransitions, Status, Expiration
        for i in range(len(policy_statement)):
            if policy_statement[i]['Status'] != policy_to_validate[i]['Status'] and \
                policy_statement[i]['Transitions'] != policy_to_validate[i]['Transitions'] and \
                policy_statement[i]['NoncurrentVersionTransitions'] != policy_to_validate[i]['NoncurrentVersionTransitions'] and \
                policy_statement[i]['Filter'] != policy_to_validate[i]['Filter'] and \
                'Expiration' not in policy_statement[i]:

                return {
                    'compliance_type': 'NON_COMPLIANT',
                    'annotation': 'Invalid policy statement for %s. Should be %s' % (bucket, policy_to_validate[i])
                }

    return {
        'compliance_type': 'COMPLIANT',
        'annotation': 'All log buckets conform to correct lifecycle policy'
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
            }
        ],
        ResultToken=result_token
    )
