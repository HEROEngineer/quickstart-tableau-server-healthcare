from __future__ import print_function
import json
import boto3

config = boto3.client('config')
ec2 = boto3.client('ec2')


def evaluate_compliance(configuration_item, rule_parameters):
    undesired_port = int(rule_parameters['UndesiredPort'])

    configuration = configuration_item['configuration']

    for ip_permissions in configuration['ipPermissions']:
        if 'fromPort' not in ip_permissions and 'toPort' not in ip_permissions:
            return {
                'compliance_type': 'NON_COMPLIANT',
                'annotation': 'Security Group is open to all traffic so port %s is not blocked' % str(undesired_port)
            }
        if ip_permissions['fromPort'] <= undesired_port <= ip_permissions['toPort']:
            return {
                'compliance_type': 'NON_COMPLIANT',
                'annotation': 'Security Group port %s is not blocked' % str(undesired_port)
            }

    return {
        'compliance_type': 'COMPLIANT',
        'annotation': 'Port %s not open for ingress' % str(undesired_port)
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
