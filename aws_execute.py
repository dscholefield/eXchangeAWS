#!/usr/bin/python3

# AWS devsecops function library
# Copyright (c) 2021, D. Scholefield
# All rights reserved.

# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree. 

import boto3
import botocore
from time import sleep
from aws_exceptions import AWSExecuteError

# funtion to try to execute command on EC2 instance using SSM
# requires a handle to an SSM client, an instance name, the
# command to execute and a boolean flag to indicate whether
# in debug mode or not
# may throw 'aws_exceptions.AWSExecuteError exception

def aws_execute_on_instance(
        ssm_handle: botocore.client,
        instance: str,
        command: str,
        debug_mode: bool,
    ):

    ssm_send_response = ssm_handle.send_command(
        InstanceIds=[instance],
        DocumentName="AWS-RunShellScript",
        Comment="AWS-RunShellScript",
        Parameters={'commands':[command]},
    )

    ssm_command_id = ssm_send_response['Command']['CommandId']

    # give the command time to execute before we query the results
    sleep(2)

    # will try a number of times if not yet completed or result
    # cant be found for the command execution
    fail_count = 1
    not_completed = True
    while fail_count < 3 and not_completed:
        try:
            ssm_get_details_response = ssm_handle.get_command_invocation(
                InstanceId=instance,
                CommandId=ssm_command_id,
            )
            not_completed = False
        except ssm_handle.exceptions.InvocationDoesNotExist as err:
            fail_count += 1
            if debug_mode: print("Failed to retrieve results from command, retrying ({0} of 3)...".format(fail_count))
        sleep(2) 
    if not_completed:
        raise AWSExecuteError()

    return ssm_get_details_response