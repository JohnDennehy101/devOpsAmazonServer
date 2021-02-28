#!/usr/bin/env python3
import sys
import boto3

serverCommands = """#!/bin/bash 
yum update -y 
yum install httpd -y 
systemctl enable httpd 
systemctl start httpd"""
ec2 = boto3.resource('ec2')
new_instance = ec2.create_instances(
                                    ImageId='ami-0fc970315c2d38f01',
                                    MinCount=1,
                                    MaxCount=1,
                                    InstanceType='t2.nano',
                                    SecurityGroups=['httpssh'],
                                    KeyName='credentials',
                                    UserData=serverCommands,
                                    TagSpecifications=[
                                       {
            'ResourceType': 'instance',
            'Tags': [
                {
                    'Key': 'Name',
                    'Value': 'My web server'
                },
            ]
        },
    ],)
print (new_instance[0].id)