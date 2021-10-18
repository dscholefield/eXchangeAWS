#!/usr/bin/python3

# Copyright (c) 2021, D. Scholefield
# All rights reserved.

# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree. 

from enum import Enum

# we need to create common structures for log entries in CloudWatch
# and will use an enum type for criticality
class LogLevel(Enum):
    Alert = "ALERT"
    Warn = "WARN"
    Error = "ERROR"
    Info = "INFO"
    Heartbeat = "HEARTBEAT"
    Debug = "DEBUG"

# log_me will write a log entry for the log stream and log group named
# in the input: this assumes a 'log' service has been created 
# NOTE: the CloudWatch service is the one for the CURRENT profile

def log_me(logs, level, lgn, lsn, lst, le):
    # we need to add the level string into the message(s) 
    le_with_level = []
    for entry in le:
        entry['message'] = level.value + "\t " + entry['message']
        le_with_level.append(entry)

    # in the (unique) incident that the CloudWatch log is new
    # there'll be no sequence token
    if not lst == '':
        logs.put_log_events(logGroupName=lgn, logStreamName=lsn, sequenceToken=lst, logEvents=le_with_level)
    else:
        logs.put_log_events(logGroupName=lgn, logStreamName=lsn, logEvents=le_with_level)

# for each log stream we need the 'next write token' so we don't clash
def get_log_stream_token(logs, lgn, lsn):
    stream_description_response = logs.describe_log_streams(logGroupName=lgn, logStreamNamePrefix=lsn)
    stream_token = ''
    for stream in stream_description_response['logStreams']:
        if stream['logStreamName'] == lsn:
            if 'uploadSequenceToken' in stream.keys():
                stream_token=stream['uploadSequenceToken']
    return stream_token

