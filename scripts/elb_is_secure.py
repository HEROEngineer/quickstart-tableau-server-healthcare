from __future__ import print_function
import json
import boto3

config = boto3.client('config')
elb = boto3.client('elbv2')


def evaluate_compliance(configuration_item, rule_parameters):
    load_balancer_arn = configuration_item['configuration']['loadBalancerArn']
    desired_port = rule_parameters['DesiredPort']
    desired_protocol = rule_parameters['DesiredProtocol']

    listeners_obj = elb.describe_listeners(LoadBalancerArn=load_balancer_arn)

    print(json.dumps(listeners_obj))

    for listener in listeners_obj['Listeners']:
        if desired_protocol != listener['Protocol']:
            return {
                'compliance_type': 'NON_COMPLIANT',
                'annotation': 'Insecure %s protocol being used for the load balancer' % listener['Protocol']
            }
        if int(desired_port) != listener['Port']:
            return {
                'compliance_type': 'NON_COMPLIANT',
                'annotation': '%s port being used for the load balancer rather than %s' % (listener['Port'], desired_port)
            }
        if len(listener['Certificates']) < 1:
            return {
                'compliance_type': 'NON_COMPLIANT',
                'annotation': 'Does not have a SSL Cert installed'
            }
        for cert in listener['Certificates']:
            if 'CertificateArn' not in cert:
                return {
                    'compliance_type': 'NON_COMPLIANT',
                    'annotation': 'Invalid SSL Cert installed - no ARN found'
                }

    return {
        'compliance_type': 'COMPLIANT',
        'annotation': 'Load balancer is secure'
    }


def lambda_handler(event, context):
    invoking_event = json.loads(event['invokingEvent'])
    rule_parameters = json.loads(event['ruleParameters'])

    print(json.dumps(invoking_event))
    print(json.dumps(rule_parameters))

    configuration_item = invoking_event['configurationItem']

    evaluation = evaluate_compliance(configuration_item, rule_parameters)

    print(json.dumps(evaluation))

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
