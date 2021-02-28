#!/usr/bin/env python3
import sys
import boto3
import requests

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

imageUrl = 'http://devops.witdemo.net/image.jpg'
imageContent = requests.get(imageUrl).content

with open('./imageToBeUploaded.jpg', 'wb') as handleImageData:
    handleImageData.write(imageContent)