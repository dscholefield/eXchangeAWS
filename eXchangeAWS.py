#!/usr/bin/python3

# Copyright (c) 2021, D. Scholefield
# All rights reserved.

# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree. 

# Execute bash command on given instance and check for
# changes in script files in specificed directory tree
# in previous 'x' days

# All results are writting to AWS log service, and emailed to
# specified email account 

# to-do list:
# add log group and stream name in config
# search on all web servers, exeception management,
# add 'no interact' config
# ensure PEP-8 compliance (flake8?)
# look for additional possible exception handling and manage
# add informational logging entries

import boto3
import json
import time

from datetime import datetime
import re
import colorama
import os
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate

from botocore.exceptions import ProfileNotFound

from aws_exceptions import AWSExecuteError
from aws_execute import aws_execute_on_instance
from aws_logging import log_me, get_log_stream_token, LogLevel


# globals for ANSI color changes and initialise ANSI output
colorama.init()
RED = '\033[31m'    # mode 31 = red forground
CYAN = '\033[36m'   # mode 36 = cyan foreground
GREEN = '\033[32m'  # mode 32 = green foreground
RESET = '\033[0m'   # mode 0  = reset

print("\neXchangeAWS - checking script file changes on AWS")
print("-----------------------------")
print(GREEN + "starting up" + RESET + "\n")


# we will define the profile for AWS connections using
# the environment variable 'AWS_PROFILE'
if "AWS_PROFILE" in os.environ:
    aws_profile = os.environ['AWS_PROFILE']
else:
    aws_profile = "default [no AWS_PROFILE env var set]"

print("using profile {0}".format(aws_profile))

# define the default number of days to check for changes within
# and the default mode (debug or not)
# these defaults may be overwritten by the config file
check_change_days = 1
is_debug = False
log_group = ''
log_stream = ''

# read the credentials file
with open("eXchangeAWS_credentials.json") as credentials_file:
    credentials = json.load(credentials_file)
    if 'email_passwd' not in credentials:
        print("No email password value in credentials file, bailing...")
        quit()
    else:
        password_entered = credentials['email_passwd']

# read the config file
with open("eXchangeAWS_config.json") as config_file:
    config = json.load(config_file)
    if 'change_days' in config:
        check_change_days = config['change_days']
        # this should be checked for an int to avoid injection
        if not type(check_change_days) == type(int()):
            print("change_days in config file not an int, is type {0}, bailing...".format(type(check_change_days)))
            quit()
    if 'web_tag_name' in config:
        if 'web_tag_value' in config:
            web_tag_name = config['web_tag_name']
            web_tag_value = config['web_tag_value']
        else:
            print("no web tag value given... bailing")
            quit()
    else:
        print("no web tag name given... bailing")
        quit()
    if 'log_group' not in config:
        print("no log group given... bailing")
        quit()
    else:
        log_group = config['log_group']
    if 'log_stream' not in config:
        print("no log stream given... bailing")
        quit()
    else:
        log_stream = config['log_stream']
    if 'debug' in config:
        is_debug = True

print("checking for file changes in previous {0} days".format(str(check_change_days)))


# version control reporting
__version = "1.0"

# define the function to send the alert email(s)


def send_mail(
    send_from,
    send_to,
    subject,
    text,
    files=[],
    server="localhost",
    ssl=False,
    username=None,
    password=None
):
    msg = MIMEMultipart('alternative')
    msg.set_charset('utf-8')
    msg['From'] = send_from
    msg['To'] = send_to
    msg['Date'] = formatdate(localtime=True)
    msg['Subject'] = subject
    part = MIMEText(text)
    part.set_charset('utf-8')
    msg.attach(part)
    if ssl:
        smtp = smtplib.SMTP_SSL(server)
    else:
        smtp = smtplib.SMTP(server)
    if username:
        smtp.login(username, password)
    smtp.sendmail(send_from, send_to, msg.as_string())
    smtp.close()

# define the command to run on discovered and running instances

command = 'find /var/www/html/current/app/pub/ -type f -not -path "./media/*" \( -iname \*.js -o -iname \*.php \) -mtime -' + str(check_change_days) + ' | wc'
# start with list of running EC2 instances

# define the find | wc regex capture groups in
# number of lines, word count, and char count format
find_pattern = '^\s*(\d+)\s*(\d+)\s*(\d+)\s*$'

try:
    ec2 = boto3.resource('ec2')
    ssm = boto3.client('ssm')
    logs = boto3.client('logs')
except ProfileNotFound as pnf:
    print("{0}, bailing...".format(pnf))
    exit()

print("Type of ssm is {0}".format(type(ssm)))

# collect running instance IDs
instance_ids = []
web_instances = []

today = datetime.now()

# normally we care about web instances but could be any type of instance based on the tag name/value pair
print("started on {0}-{1}-{2} at {3}:{4}:{5}".format(today.day, today.month, today.year, today.hour, today.minute, today.second))
print("discovering running EC2 Instances:")
for instance in ec2.instances.all():
    is_web_instance = False
    for tag in instance.tags:
        if tag["Key"] == web_tag_name and tag["Value"] == web_tag_value:
            # print("Instance %s is a detected instance based on tags" % instance.id)
            test_id = instance.id
            is_web_instance = True
    # state_dict = json.loads(instance.state)
    if instance.state['Name'] == 'running':
        if is_web_instance:
            print("\tinstance: {0}, running [".format(instance.id), end='')
            print(CYAN, end='')
            print("web instance", end='')
            print(RESET, end='')
            print("]")
            instance_ids.append(instance.id)
            web_instances.append(instance.id)
        else:
            print("\tinstance: {0}, running".format(instance.id))

print("\tweb instances discovered are: ", web_instances)

# we need somewhere where we can collect the report on all instances
# and an overall flag to indicate whether we need to cause an alert
instance_report = []
need_to_alert = False

# now to check each web instance in turn
for instance_id in web_instances:

    print("\nexecuting file change check on instance %s..." % test_id)

    # if checking an instance fails then we can just exit
    # the AWS log checking system should detect the lack of a heartbeat
    # anyway and alert the watcher
    try:
        command_response = aws_execute_on_instance(ssm_handle=ssm, instance=test_id, command=command, debug_mode=is_debug)
    except AWSExecuteError as err:
        print("Could not complete search for changed files on {0}, baling with error {1}".format(test_id, err))
        exit()

    # we now have a response so we can parse the 'wc' command
    # output into line count, word count, and char count, we care about
    # the line count most (group 0) as it tells us how many files were found
    check_response = re.search(find_pattern, command_response['StandardOutputContent'])

    # the re may not have matched to a group so we need to check or it will
    # raise an exception
    if check_response is not None and len(check_response.groups()) > 1:
        if int(check_response.group(1)) > 0:
            changed_message = "instance {0} has {1} changed script files found within previous {2} days".format(instance_id, check_response.group(1), check_change_days)
            instance_report.append(changed_message)
            need_to_alert = True
            print(RED + "\t" + u'\u2573' + RESET + changed_message)
    else:
        print("could not detect file change report in find result on instance {0}".format(instance_id))


# if any changed file was found on any web instance
# then send email and also log the alert
timestamp = int(round(time.time() * 1000))
if need_to_alert:
    print("\tSending email to NAME OF RECIPIENT...", end='')
    text_of_email = "eXchangeAWS has detected file changes on " \
                    + aws_profile \
                    + "\n"
    text_of_email += text_of_email.join(instance_report)

    send_mail(
            send_from='from email address',
            send_to='to email address',
            subject="AWS M2 file change alert",
            text=text_of_email,
            server='SMTP server address',
            ssl=True,
            username='email account username',
            password=password_entered,
    )
    print(GREEN + " sent" + RESET)

    # log alert to CloudWatch log trail
    print("\tLogging alert to CloudWatch logs")
    # we need a stream token
    stream_token = get_log_stream_token(logs, log_group, log_stream)

    # and now log the change alert (uses LogLevel enum from aws_logging)
    log_me(logs, LogLevel.Alert, log_group, log_stream, stream_token,
        [
            {
                'timestamp': timestamp,
                'message': 'eXchange\t' + text_of_email
            }
        ]
    )
else:
    print(GREEN)
    print("\t" + u'\u221A' + RESET + " no changed script files have changed within previous %s days" % check_change_days)


# and send the heartbeat to say that the checking script has
# run and therefore no alert on failed script is required

if need_to_alert:
    heartbeat_message = "changed scripts found"
else:
    heartbeat_message = "no changed scripts found"

stream_token = get_log_stream_token(logs, log_group, log_stream)
log_me(logs, LogLevel.Heartbeat, log_group, log_stream, stream_token,
        [
            {
                'timestamp' : timestamp,
                'message' : 'eXchange\t' + heartbeat_message
            }
        ]
    )
print("\nterminating\n")
exit()