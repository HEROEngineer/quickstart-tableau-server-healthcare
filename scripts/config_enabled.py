"""
Adapted from https://github.com/awslabs/aws-config-rules/blob/master/python/config-enabled.py
"""

#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Ensure Config is enabled
# Description: Checks that Config has been activated and if it logs to a specific bucket OR a send to a specifc SNS topic.
#
# Trigger Type: Periodic
# Scope of Changes: N/A
# Required Parameters: None
# Optional Parameter 1 name: s3BucketName
# Optional Parameter 1 value example: config-bucket-123456789012-ap-southeast-1
# Optional Parameter 2 name: snsTopicARN
# Optional Parameter 2 value example: arn:aws:sns:ap-southeast-1:123456789012:config-topic

from __future__ import print_function
import boto3
import json
from datetime import datetime

config = boto3.client('config')


def evaluate_compliance(rule_parameters):
    # First check configuration recorder is created
    config_recorder_response = config.describe_configuration_recorder_status()

    if 'ConfigurationRecordersStatus' not in config_recorder_response or \
                    len(config_recorder_response['ConfigurationRecordersStatus']) < 1:
        return {
            'compliance_type': 'NON_COMPLIANT',
            'annotation': 'Cannot find config recorder status'
        }

    for config_recorder in config_recorder_response['ConfigurationRecordersStatus']:
        if not config_recorder['recording']:
            return {
                'compliance_type': 'NON_COMPLIANT',
                'annotation': 'Config recorder is not recording'
            }

    # Check that there are delivery channels and that they're mapping to the appropriate buckets
    delivery_channels_response = config.describe_delivery_channels()

    if 'DeliveryChannels' not in delivery_channels_response or len(delivery_channels_response['DeliveryChannels']) < 1:
        return {
            'compliance_type': 'NON_COMPLIANT',
            'annotation': 'No delivery channel for config recorder'
        }

    if 's3BucketName' in rule_parameters:
        for channel in delivery_channels_response['DeliveryChannels']:
            if channel['s3BucketName'] != rule_parameters['s3BucketName']:
                return {
                    'compliance_type': 'NON_COMPLIANT',
                    'annotation': 'Config recorder writing to incorrect bucket'
                }

    if 'snsTopicARN' in rule_parameters:
        for channel in delivery_channels_response['DeliveryChannels']:
            if channel['snsTopicARN'] != rule_parameters['snsTopicARN']:
                return {
                    'compliance_type': 'NON_COMPLIANT',
                    'annotation': 'Config recording writing to incorrect SNS topic'
                }

    return {
        'compliance_type': 'COMPLIANT',
        'annotation': 'Config recorder enabled with appropriate delivery channel'
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
