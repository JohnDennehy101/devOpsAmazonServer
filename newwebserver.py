#!/usr/bin/env python3
import sys
import boto3
from botocore.exceptions import ClientError
import logging
import requests
from time import gmtime

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


currentTime = gmtime()
s3BucketName = 'imagebucket.' + str(currentTime.tm_mday) + '-' + str(currentTime.tm_mon) + '-' + str(currentTime.tm_year) + '.' + str(currentTime.tm_hour) + '.' + str(currentTime.tm_min) + '.' + str(currentTime.tm_sec)



def create_bucket(bucket_name, region=None):

    # Create bucket
    try:
        if region is None:
            s3_client = boto3.client('s3')
            s3_client.create_bucket(Bucket=bucket_name)
        else:
            s3_client = boto3.client('s3', region_name=region)
            location = {'LocationConstraint': region}
            s3_client.create_bucket(Bucket=bucket_name,
                                    CreateBucketConfiguration=location)
    except ClientError as e:
        logging.error(e)
        return False
    return True

create_bucket(s3BucketName, 'eu-west-1')