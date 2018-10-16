from __future__ import print_function
from datetime import datetime
import json
import boto3

config = boto3.client('config')
ec2 = boto3.client('ec2')

def evaluate_compliance(configuration_item, rule_parameters):
    undesired_port = int(rule_parameters['UndesiredPort'])
    undesired_protocol = rule_parameters['UndesiredProtocol']
    tag_key = rule_parameters['TagKey']
    tag_value = rule_parameters['TagValue']

    security_group_list = ec2.describe_security_groups(Filters=[{
        'Name': 'tag:%s' % tag_key,
        'Values': [ tag_value ]
    }])

    for security_group in security_group_list['SecurityGroups']:
        for port_range in security_group['IpPermissions']:
            if undesired_port >= port_range['FromPort'] and undesired_port <= port_range['ToPort']:
                return {
                    'compliance_type': 'NON_COMPLIANT',
                    'annotation': 'Security Group %s: Port %s is not blocked' % (security_group['GroupId'], str(undesired_port))
                }

    return {
        'compliance_type': 'COMPLIANT',
        'annotation': 'No security groups have port %s open for ingress' % str(undesired_port)
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
