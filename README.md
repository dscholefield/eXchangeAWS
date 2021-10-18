# eXchangeAWS
Tool to use Python/Boto3 for detecting file changes on AWS

Connects to remote AWS instance using Python3/boto3 and:
1. finds specific running EC2 instances with a given tag name=value pair
2. executes a predefined command remotely and waits for the result (asynchronous)
3. compares the result with a given regex
4. logs the script execution and results in AWS cloudwatch log
5. emails a given email address with a report if the command was successful (the find command succeeded)

The script is hard-wired to look for .php and .js file changes within a given number of days prior.

The reason for creating this script is that if the AWS instance is using EFS then the inotify() *nix kernel call 
will not work (as with any NFS based file system and so file change staples such as tripwire(tm) etc. can't be
used to detect file changes to scripts/config/executable files. 

This script can be cron-d to detect file changes to key files in place of a more efficient on-cloud solution
should inotify() have functioned.
