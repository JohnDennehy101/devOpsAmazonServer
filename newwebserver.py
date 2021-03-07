#!/usr/bin/env python3
import sys
import boto3
from botocore.exceptions import ClientError
import logging
import requests
from time import gmtime
import time
import paramiko

serverCommands = """#!/bin/bash 
yum update -y 
yum install httpd -y 
systemctl enable httpd 
systemctl start httpd"""
ec2 = boto3.resource('ec2')

ec2Client = boto3.client('ec2')
s3_Client = boto3.client('s3')

# filters = [ {
#     'Name': 'name',
#     'Values': ['amzn-ami-hvm-*']
# },{
#     'Name': 'description',
#     'Values': ['Amazon Linux AMI*']
# },{
#     'Name': 'architecture',
#     'Values': ['x86_64']
# },{
#     'Name': 'owner-alias',
#     'Values': ['amazon']
# },{
#     'Name': 'owner-id',
#     'Values': ['137112412989']
# },{
#     'Name': 'state',
#     'Values': ['available']
# },{
#     'Name': 'root-device-type',
#     'Values': ['ebs']
# },{
#     'Name': 'virtualization-type',
#     'Values': ['hvm']
# },{
#     'Name': 'hypervisor',
#     'Values': ['xen']
# },{
#     'Name': 'image-type',
#     'Values': ['machine']
# } ]


# response = ec2Client.describe_images(
#     Filters=filters,
#      Owners=[
#       'amazon'
#   ]
# )

# print(response)

#instance_type= response['InstanceTypes'][0]['InstanceType']

# responseTest= ec2Client.describe_images(
#    Filters=[{'Name': 'name', 'Values': [instance_type]},],
  
# )

#print(responseTest)



print("Starting instance")
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

new_instance[0].wait_until_running()
print (new_instance[0].id)




while True:
    allInstances = ec2.meta.client.describe_instance_status()['InstanceStatuses']
    instanceJustCreated = allInstances[len(allInstances) - 1]
    print(instanceJustCreated)
    instanceStatus = instanceJustCreated['InstanceStatus']['Details'][0]['Status']
    print(instanceJustCreated['InstanceStatus']['Details'][0]['Status'])
    if instanceStatus != 'passed':
        time.sleep(15)
    else:
        break



new_instance[0].reload()

print(new_instance[0].public_ip_address)
instanceIpAddress = new_instance[0].public_ip_address

imageUrl = 'http://devops.witdemo.net/image.jpg'
imageContent = requests.get(imageUrl).content

with open('./imageToBeUploaded.jpg', 'wb') as handleImageData:
    handleImageData.write(imageContent)






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


def upload_file(file_name, bucket, object_name=None):

    # If S3 object_name was not specified, use file_name
    if object_name is None:
        object_name = file_name

    # Upload the file
    s3_client = boto3.client('s3')
    try:
        response = s3_client.upload_file(file_name, bucket, object_name, ExtraArgs={
        'ACL':'public-read',
        'ContentType': "image/jpeg",
    })
    except ClientError as e:
        logging.error(e)
        return False
    return True



existingS3Buckets = s3_Client.list_buckets()
s3BucketsList = existingS3Buckets['Buckets']

s3BucketAlreadyCreated = False
s3BucketName = ''

for bucket in s3BucketsList:
    if 'imagebucket' in bucket['Name']:
        s3BucketAlreadyCreated = True
        s3BucketName = bucket['Name']
        break

print(s3BucketAlreadyCreated)

if s3BucketAlreadyCreated != True:
    currentTime = gmtime()
    s3BucketName = 'imagebucket.' + str(currentTime.tm_mday) + '-' + str(currentTime.tm_mon) + '-' + str(currentTime.tm_year) + '.' + str(currentTime.tm_hour) + '.' + str(currentTime.tm_min) + '.' + str(currentTime.tm_sec)
    create_bucket(s3BucketName, 'eu-west-1')


upload_file('./imageToBeUploaded.jpg', s3BucketName, 'webSiteImage.jpg')

#sshCommand = "ssh -o StrictHostKeyChecking=no -i ~/aws/credentials/credentials.pem ec2-user@" + instanceIpAddress
print(sshCommand)
sshClient = paramiko.SSHClient()
sshClient.set_missing_host_key_policy(paramiko.AutoAddPolicy())
sshPrivateKey = paramiko.RSAKey.from_private_key_file('./credentials.pem')
#time.sleep(60)


def sshConnection(ssh, ip, numberOfAttempts):
    if numberOfAttempts > 3:
        return False
    sshPrivateKey = paramiko.RSAKey.from_private_key_file('./credentials.pem')
    interval = 20
    try:
        numberOfAttempts += 1
        print('SSH into the instance: {}'.format(ip))
        ssh.connect(hostname=ip,
                    username='ec2-user', pkey=sshPrivateKey)
        return True
    except Exception as e:
        print(e)
        time.sleep(interval)
        print('Retrying SSH connection to {}'.format(ip))
        sshConnection(ssh, ip, numberOfAttempts)


sshConnection(sshClient, instanceIpAddress, 0)
       



#sshClient.connect(hostname=instanceIpAddress, username='ec2-user', pkey=sshPrivateKey)
shellCommand = """
echo "Hello World" > index.html
ls
sudo mv index.html /var/www/html
 """

stdin, stdout, stderr = sshClient.exec_command(shellCommand)
print(stdout.read())
print(stderr.read())


sshClient.close()

