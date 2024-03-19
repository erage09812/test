import json
import traceback

import boto3
import os

from silpyutils import LogHelper

# contants
LOGGER = LogHelper("Game Day Lambda", os.getenv("LOG_LEVEL"))
ECS = "ECS"
SSM = "SSM"
SECRET_MANAGER = "SECRET_MANAGER"
# clients
session = boto3.session.Session()
ECS_CLIENT = session.client('ecs')
SSM_CLIENT = session.client('ssm')
SECRET_MANAGER_CLIENT = session.client('secretsmanager')
SSM_CLIENT = session.client('ssm')
LAMBDA_CLIENT = session.client('lambda')
SQS_CLIENT = session.client('sqs')
ASG_CLIENT = boto3.client('autoscaling')
EC2_CLIENT = boto3.client('ec2')


def perform_ecs_operation(payload, context):
    try:
        # check for health check
        if context is not None and context.client_context is not None:
            if "InvocationType" in context.client_context.custom:
                if context.client_context.custom['InvocationType'] == 'HealthCheck':
                    LOGGER.info("Health Check Success!!")
                    return {"statusCode": 200, "body": {"status": "OK"}}

        LOGGER.info(f"Event received: {payload}")

        cluster_name = payload['ClusterName']
        service_name = payload['ServiceName']
        action = payload['Action']

        LOGGER.info(f"Cluster to be picked: {cluster_name}")
        LOGGER.info(f'Service to be modified: {service_name}')

        # check if the service exists
        service_response = ECS_CLIENT.describe_services(cluster=cluster_name, services=[service_name])
        if len(service_response['services']) == 0:
            return {
                "statusCode": 404,
                "message": f"Service name is wrong: {service_name}"
            }

        # get the desired count of the service
        desired_count = service_response['services'][0]['desiredCount']

        # check for valid action input
        if action != 'start' and action != 'stop':
            return {
                "statusCode": 400,
                "message": f"Allowed action is start, stop. Provided : {action}"
            }
        # start the service
        if action == 'start' and desired_count == 0:
            update_desired_count(cluster_name, service_name, 1 - desired_count)
            return {
                "statusCode": 202,
                "message": f"Service Start Request Issued for service: {service_name}"
            }
        elif action == 'start' and desired_count == 1:
            # service is already running
            return {
                "statusCode": 409,
                "message": f"Service: {service_name} is already running"
            }
        elif action == 'stop' and desired_count == 0:
            # service is already stopped
            return {
                "statusCode": 409,
                "message": f"Service: {service_name} is already stopped"
            }
        elif action == 'stop' and desired_count >= 1:
            # stop the service
            update_desired_count(cluster_name, service_name, 0)
            return {
                "statusCode": 202,
                "message": f"Service Stop Request Issued for service: {service_name}"
            }
        elif action == 'delete':
            ECS_CLIENT.delete_service(
                cluster=cluster_name,
                service=service_name,
                force=True
            )
            return {
                "statusCode": 200,
                "message": f"Service {service_name} deleted successfully"
            }

    except Exception as e:
        LOGGER.error(f"Error Updating Service {e}")
        traceback.print_exc()
        return {
            "statusCode": 500,
            "error": str(e)
        }


def update_desired_count(cluster_name, service_name, desired_count):
    ECS_CLIENT.update_service(
        cluster=cluster_name,
        service=service_name,
        desiredCount=desired_count,
        forceNewDeployment=False
    )


def convert_string_to_json(json_value):
    try:
        return json.loads(json_value)
    except Exception as e:
        raise ValueError(f"Invalid Payload Value : {str(e)}")


def perform_ssm_operation(payload, context):
    LOGGER.info("Performing SSM Operation")
    # declare variables
    actual_value = payload.get("Value")
    ssm_name = payload.get("Name")
    # update the existing ssm parameter value in JSON
    if payload.get("Type") is not None and payload.get("Type").upper() == "UPDATE":
        # get the existing values of the ssm
        ssm_response = SSM_CLIENT.get_parameter(
            Name=ssm_name
        )
        LOGGER.debug(f"SSM Value response : {ssm_response}")
        ssm_value_dict = ssm_response['Parameter']['Value']
        # convert the string to JSON, if not Json Raise exception
        ssm_value_dict = convert_string_to_json(ssm_value_dict)
        # iterate on the input and update the existing json
        for key, value in actual_value.items():
            ssm_value_dict[key] = value
        LOGGER.debug(f"Updated SSM Value : {ssm_response}")
        # perform an update with the new version
        return SSM_CLIENT.put_parameter(
            Name=ssm_name,
            Value=get_string_value(ssm_value_dict),
            Overwrite=True,
        )
    else:
        # update the ssm value with the new values
        return SSM_CLIENT.put_parameter(
            Name=ssm_name,
            Value=get_string_value(actual_value),
            Overwrite=True,
        )


def get_string_value(input):
    # check if the input is string or dict and convert to string if dict
    if isinstance(input, dict):
        return json.dumps(input)
    return input


def perform_secret_manager_operation(payload, context):
    LOGGER.info("Performing Secret Manager operation")
    if payload.get("Type").upper() == "SECRETSTRING":
        # update the secret string in the secret manager
        return SECRET_MANAGER_CLIENT.put_secret_value(
            SecretId=payload.get("Name"),
            SecretString=get_string_value(payload.get("Value"))
        )
    elif payload.get("Type").upper() == "SECRETBINARY":
        # update the secret binary in the secret manager
        return SECRET_MANAGER_CLIENT.put_secret_value(
            SecretId=payload.get("Name"),
            SecretBinary=bytes(get_string_value(payload.get("Value")), "utf8"),
        )



def perform_lambda_operation(payload, context):
    try:
        lambda_name = payload['LambdaName']
        queue_name = payload['QueueName']
        action = payload['Action']

        if action == 'disable':
            # Get the Lambda function's event source mappings
            mappings = LAMBDA_CLIENT.list_event_source_mappings(FunctionName=lambda_name)

            for mapping in mappings['EventSourceMappings']:
                # Find the mapping associated with the specified SQS queue
                if 'EventSourceArn' in mapping and queue_name in mapping['EventSourceArn']:
                    # Disable the event source mapping
                    LAMBDA_CLIENT.update_event_source_mapping(
                        UUID=mapping['UUID'],
                        FunctionName=lambda_name,
                        Enabled=False
                    )
                    return {
                        "statusCode": 200,
                        "message": f"SQS trigger for Lambda {lambda_name} with Queue {queue_name} disabled successfully"
                    }

        elif action == 'enable':
            # Get the Lambda function's event source mappings
            mappings = LAMBDA_CLIENT.list_event_source_mappings(FunctionName=lambda_name)

            for mapping in mappings['EventSourceMappings']:
                # Find the mapping associated with the specified SQS queue
                if 'EventSourceArn' in mapping and queue_name in mapping['EventSourceArn']:
                    # Enable the event source mapping
                    LAMBDA_CLIENT.update_event_source_mapping(
                        UUID=mapping['UUID'],
                        FunctionName=lambda_name,
                        Enabled=True
                    )
                    return {
                        "statusCode": 200,
                        "message": f"SQS trigger for Lambda {lambda_name} with Queue {queue_name} enabled successfully"
                    }

            return {
                "statusCode": 404,
                "message": f"No SQS trigger found for Lambda {lambda_name} with Queue {queue_name}"
            }

    except Exception as e:
        LOGGER.error(f"Error updating Lambda trigger {e}")
        traceback.print_exc()
        return {
            "statusCode": 500,
            "error": str(e)
        }

def perform_sqs_operation(payload, context):
    try:
        queue_name = payload['QueueName']
        action = payload['Action']

        if action == 'disable':
            # Get the queue URL
            queue_url = SQS_CLIENT.get_queue_url(QueueName=queue_name)['QueueUrl']

            # Get the current attributes of the queue
            queue_attributes = SQS_CLIENT.get_queue_attributes(QueueUrl=queue_url, AttributeNames=['RedrivePolicy'])

            # Check if RedrivePolicy (DLQ configuration) is present
            if 'RedrivePolicy' in queue_attributes['Attributes']:
                # Remove the RedrivePolicy attribute to disable the DLQ
                SQS_CLIENT.set_queue_attributes(QueueUrl=queue_url, Attributes={'RedrivePolicy': ''})
                return {
                    "statusCode": 200,
                    "message": f"DLQ disabled for SQS queue {queue_name}"
                }
            else:
                return {
                    "statusCode": 404,
                    "message": f"No Dead Letter Queue found for SQS queue {queue_name}"
                }

        elif action == 'update':
            # Get the queue URL
            queue_url = SQS_CLIENT.get_queue_url(QueueName=queue_name)['QueueUrl']

            # Update Visibility Timeout
            if 'VisibilityTimeout' in payload:
                visibility_timeout_seconds = int(payload['VisibilityTimeout'])
                SQS_CLIENT.set_queue_attributes(
                    QueueUrl=queue_url,
                    Attributes={'VisibilityTimeout': str(visibility_timeout_seconds)}
                )
                return {
                    "statusCode": 200,
                    "message": f"Visibility Timeout updated to {visibility_timeout_seconds} seconds for SQS queue {queue_name}"
                }

            # Update Message Retention Period
            if 'MessageRetentionPeriod' in payload:
                retention_period_seconds = int(payload['MessageRetentionPeriod']) * 24 * 60 * 60  # Convert to seconds
                SQS_CLIENT.set_queue_attributes(
                    QueueUrl=queue_url,
                    Attributes={'MessageRetentionPeriod': str(retention_period_seconds)}
                )
                return {
                    "statusCode": 200,
                    "message": f"Message Retention Period is updated to {retention_period_seconds} seconds for SQS queue {queue_name}"
                }

            # Update Delivery Delay
            if 'DeliveryDelay' in payload:
                delivery_delay_seconds = int(payload['DeliveryDelay'])
                SQS_CLIENT.set_queue_attributes(
                    QueueUrl=queue_url,
                    Attributes={'DelaySeconds': str(delivery_delay_seconds)}
                )
                return {
                    "statusCode": 200,
                    "message": f"Delivery Delay is updated to {delivery_delay_seconds} seconds for SQS queue {queue_name}"
                }

            # Update Maximum Message Size
            if 'MaximumMessageSizeKB' in payload:
                max_message_size_kb = int(payload['MaximumMessageSizeKB'])
                SQS_CLIENT.set_queue_attributes(
                    QueueUrl=queue_url,
                    # Attributes={'MaximumMessageSize': max_message_size_kb}
                    Attributes={'MaximumMessageSize': str(max_message_size_kb * 1024)}
                )
                return {
                    "statusCode": 200,
                    "message": f"Maximum Message Size updated to {max_message_size_kb} KB for SQS queue {queue_name}"
                }

            # Update Message Retention Period
            if 'MessageRetentionPeriodHours' in payload:
                retention_period_hours = int(payload['MessageRetentionPeriodHours'])
                SQS_CLIENT.set_queue_attributes(
                    QueueUrl=queue_url,
                    Attributes={'MessageRetentionPeriod': str(retention_period_hours * 3600)}
                )
                return {
                    "statusCode": 200,
                    "message": f"Message Retention Period updated to {retention_period_hours} hours for SQS queue {queue_name}"
                }

            return {
                "statusCode": 400,
                "message": "No valid attribute provided for update"
            }

    except Exception as e:
        LOGGER.error(f"Error updating SQS queue {e}")
        traceback.print_exc()
        return {
            "statusCode": 500,
            "error": str(e)
        }

def perform_asg_operation(payload, context):
    try:
        action = payload.get("Action", "").lower()
        asg_name = payload.get("AutoScalingGroupName")

        if action == 'stop':

            # Get the current attributes of the queue
            queue_attributes = ASG_CLIENT.update_auto_scaling_group(
                AutoScalingGroupName=asg_name,
                MinSize=0,
                MaxSize=0,
                DesiredCapacity=0
            )
            return {
                    "statusCode": 200,
                    "message": f"Auto Scaling Group {asg_name} stopped successfully."
                }

        elif action == 'start':
            # Scale up the Auto Scaling Group
            ASG_CLIENT.update_auto_scaling_group(
                AutoScalingGroupName=asg_name,
                MinSize=1,
                MaxSize=1,
                DesiredCapacity=1
            )
            return {
                    "statusCode": 200,
                    "message": f"Auto Scaling Group {asg_name} started successfully."
                }

    except Exception as e:
        LOGGER.error(f"Error updating ASG {e}")
        traceback.print_exc()
        return {
            "statusCode": 500,
            "error": f"Error stopping Auto Scaling Group: {str(e)}"
        }



def perform_ec2_operation(payload, context):
    try:
        action = payload.get("Action", "").lower()


        if action == 'ec2_stop':

            # Get the current attributes of the queue
            queue_attributes = EC2_CLIENT.stop_instances(
                InstanceIds=[payload.get("instance_id")]
                )

            return {
                    "statusCode": 200,
                    "message": f"ec2 instance {payload.get("instance_id")} stopped successfully."
                }

        elif action == 'ec2_start':

            EC2_CLIENT.start_instances(
                InstanceIds=[payload.get("instance_id")]
                )
            return {
                    "statusCode": 200,
                    "message": f"ec2 instance {payload.get("instance_id")} stopped successfully."
                }


        elif action == 'ebs_detach':

            EC2_CLIENT.detach_volume(
                VolumeId=payload.get("volume_id"),
                Force=True
            )
            return {
                    "statusCode": 200,
                    "message": f"ebs volume {payload.get("volume_id")} detached successfully."
                }

        elif action == 'ebs_attach':

            EC2_CLIENT.attach_volume(
                VolumeId=payload.get("volume_id"),
                InstanceId=payload.get("instance_id"),
                Force=True
            )
            return {
                    "statusCode": 200,
                    "message": f"ebs volume {payload.get("volume_id")} attched successfully."
                }
        elif action == 'sg_revoke':

            EC2_CLIENT.revoke_security_group_ingress(
                GroupId=payload.get("security_group_id"),
                IpPermissions=[]
            )
            return {
                    "statusCode": 200,
                    "message": f"ec2 security Group {payload.get("security_group_id")} access revoked successfully."
                }

    except Exception as e:
        LOGGER.error(f"Error updating EC2 {e}")
        traceback.print_exc()
        return {
            "statusCode": 500,
            "error": f"Error stopping EC2: {str(e)}"
        }

def lambda_handler(event, context):
    if event.get("Service").upper() == ECS:
        # If the service is ECS then perform ECS operation
        return perform_ecs_operation(event.get("PayLoad"), context)
    elif event.get("Service").upper() == ASG:
        # If the service is ECS then perform ECS operation
        return perform_asg_operation(event.get("PayLoad"), context)
    elif event.get("Service").upper() == SSM:
        # If the service is SSM then perform SSM operation
        return perform_ssm_operation(event.get("PayLoad"), context)
    elif event.get("Service").upper() == SECRET_MANAGER:
        # If the service is Secret Manager then perform Secret manager Operation operation
        return perform_secret_manager_operation(event.get("PayLoad"), context)
    elif event.get("Service").upper() == "LAMBDA":
        # If the service is Lambda then perform Lambda operation
        return perform_lambda_operation(event.get("PayLoad"), context)
    elif event.get("Service").upper() == "SQS":
        # If the service is SQS then perform SQS operation
        return perform_sqs_operation(event.get("PayLoad"), context)
    elif event.get("Service").upper() == "EC2":
        # If the service is SQS then perform EC2 operation
        return perform_ec2_operation(event.get("PayLoad"), context)
