from __future__ import print_function
from datetime import datetime
import json
import boto3

config = boto3.client('config')
elb = boto3.client('elbv2')

def evaluate_compliance(configuration_item, rule_parameters):
    load_balancer_arn = configuration_item['configuration']['loadBalancerArn']
    desired_port = rule_parameters['DesiredPort']
    desired_protocol = rule_parameters['DesiredProtocol']

    listeners_obj = elb.describe_listeners(LoadBalancerArn=load_balancer_arn)

    for listener in listeners_obj['Listeners']:
        if desired_protocol != listener['Protocol']:
            return {
                'compliance_type': 'NON_COMPLIANT',
                'annotation': 'Listener %s on Load Balancer %s: Insecure %s protocol being used for the load balancer' % (listener['ListenerArn'], listener['LoadBalancerArn'], listener['Protocol'])
            }
        if desired_port != listener['Protocol']:
            return {
                'compliance_type': 'NON_COMPLIANT',
                'annotation': 'Listener %s on Load Balancer %s: %s port being used for the load balancer rather than %s' % (listener['ListenerArn'], listener['LoadBalancerArn'], listener['Port'], desired_port)
            }
        if len(listener['Certificates']) < 1:
            return {
                'compliance_type': 'NON_COMPLIANT',
                'annotation': 'Listener %s on Load Balancer %s: Does not have a SSL Cert installed' % (listener['ListenerArn'], listener['LoadBalancerArn'])
            }
        for cert in listener['Certificates']:
            if 'CertificateArn' not in cert:
                return {
                    'compliance_type': 'NON_COMPLIANT',
                    'annotation': 'Listener %s on Load Balancer %s: Invalid SSL Cert installed - no ARN found' % (listener['ListenerArn'], listener['LoadBalancerArn'])
                }

    return {
        'compliance_type': 'COMPLIANT',
        'annotation': 'Load balancer is configured with %s on port %s' % (desired_protocol, desired_port)
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
