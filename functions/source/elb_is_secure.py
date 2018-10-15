from __future__ import print_function
from datetime import datetime
import json
import boto3

config = boto3.client('config')
elb = boto3.client('elbv2')


def evaluate_compliance(configuration_item, rule_parameters):
    load_balancer_arn = configuration_item['configuration']['loadBalancerArn']
    undesired_protocol = rule_parameters['undesiredProtocol']

    listeners_obj = elb.describe_listeners(LoadBalancerArn=load_balancer_arn)

    for listener in listeners_obj['Listeners']:
        if undesired_protocol == listener['Protocol']:
            return {
                'compliance_type': 'NON_COMPLIANT',
                'annotation': 'Insecure %s protocol being used for the load balancer' % undesired_protocol
    }

    return {
        'compliance_type': 'COMPLIANT',
        'annotation': 'Load balancer is secure'
    }


def lambda_handler(event, context):
    invoking_event = json.loads(event['invokingEvent'])
    rule_parameters = json.loads(event['ruleParameters'])

    configuration_item = invoking_event['configurationItem']

    evaluation = evaluate_compliance(configuration_item, rule_parameters)

    result_token = event['resultToken'] if 'resultToken' in event else 'No token found'

    config.put_evaluations(
        Evaluations=[
            {
                'ComplianceResourceType': configuration_item['resourceType'],
                'ComplianceResourceId': configuration_item['resourceId'],
                'ComplianceType': evaluation['compliance_type'],
                'Annotation': evaluation['annotation'],
                'OrderingTimestamp': configuration_item['configurationItemCaptureTime']
            },
        ],
        ResultToken=result_token
    )
