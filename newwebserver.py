#!/usr/bin/env python3
import sys
import boto3
from botocore.exceptions import ClientError
import logging
import requests
from time import gmtime
import time
import paramiko
import subprocess
from datetime import datetime, timedelta

serverCommands = """#!/bin/bash 
yum update -y 
yum install httpd -y 
systemctl enable httpd 
systemctl start httpd"""
ec2 = boto3.resource('ec2')

ec2Client = boto3.client('ec2')
s3_Client = boto3.client('s3')
s3_Resource = boto3.resource('s3')
cloudwatch = boto3.resource('cloudwatch')

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






def ensureNumberInput(input):
    try:
        val = int(input)
        return True
    except ValueError:
        print("Invalid Input")
        return False



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


def sshConnection(ssh, ip, numberOfAttempts):
    if numberOfAttempts > 3:
        return False
    sshPrivateKey = paramiko.RSAKey.from_private_key_file('credentials.pem')
    interval = 30
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

def userMenu():
    print("AWS Automation Project")
    print("-------------------------")
    print("1. Create new EC2 instance on AWS with Apache Server, image and metadata displayed on site")
    print("2. Monitor an existing instance")
    print("3. Exit")

    checkInput = False

    
    while checkInput == False:
        userInput = input("Please input the option number you want to execute: ")
        checkInput = ensureNumberInput(userInput)
    
    if checkInput == True:
        return userInput





userInput = userMenu()


# checkInput = False
# while checkInput == False:
  
#     userInput = input("Please input the option number you want to execute: ")
#     checkInput = ensureNumberInput(userInput)


optionSelected = int(userInput)

if optionSelected == 1:
    print("Starting instance")
    new_instance = ec2.create_instances(
                                    ImageId='ami-079d9017cb651564d',
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

    waiter = ec2Client.get_waiter('instance_status_ok')

    # while True:
    #     allInstances = ec2.meta.client.describe_instance_status()['InstanceStatuses']
    #     instanceJustCreated = allInstances[len(allInstances) - 1]
    #     print(instanceJustCreated)
    #     instanceStatus = instanceJustCreated['InstanceStatus']['Details'][0]['Status']
    #     print(instanceJustCreated['InstanceStatus']['Details'][0]['Status'])
    #     if instanceStatus != 'passed':
    #         time.sleep(15)
    #     else:
    #         break

    print('Waiting until instance status ok (to ensure web server is available)...')
    waiter.wait(
    InstanceIds=[
        new_instance[0].id,
    ],
)
        
    new_instance[0].reload()
    instanceIpAddress = new_instance[0].public_ip_address
    imageUrl = 'http://devops.witdemo.net/image.jpg'
    imageContent = requests.get(imageUrl).content
    with open('./imageToBeUploaded.jpg', 'wb') as handleImageData:
        handleImageData.write(imageContent)
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
    s3ImageBucketContents = s3_Resource.Bucket(s3BucketName).objects.all()
    testUrl = ''
    bucketName = ''
    objectName = ''
    
    for image in s3ImageBucketContents:
        bucketName = image.bucket_name
        objectName = image.key
    
    imageUrl = 'https://s3-eu-west-1.amazonaws.com/' + str(bucketName) + '/' + str(objectName)
    metadataUrl = 'http://{}/latest/meta-data/local-ipv4'.format(instanceIpAddress)
    metadataShellCommand = """
    ssh -o StrictHostKeyChecking=no -i credentials.pem ec2-user@{}
    echo '<html>' > index.html
    echo '<b>Private IP address: </b>' >> index.html
    curl http://169.254.169.254/latest/meta-data/local-ipv4 >> index.html
    echo '<br>' >> index.html
    echo '<b>Availability Zone: </b>' >> index.html
    curl http://169.254.169.254/latest/meta-data/placement/availability-zone >> index.html
    echo '<br>' >> index.html
    echo '<b>MAC Address: </b>' >> index.html
    curl http://169.254.169.254/latest/meta-data/mac >> index.html
    echo '<br>' >> index.html
    echo '<b>HostName: </b>' >> index.html
    curl http://169.254.169.254/latest/meta-data/hostname >> index.html
    echo '<br>' >> index.html
    """.format(instanceIpAddress)

    sshClient = paramiko.SSHClient()
    sshClient.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    sshPrivateKey = paramiko.RSAKey.from_private_key_file('credentials.pem')


    sshConnection(sshClient, instanceIpAddress, 0)
    configureServerShellCommand = """
    echo "<hr>Here is an image that I have stored on S3: <br>
    <img src={}>" >> index.html
    ls
    sudo mv index.html /var/www/html
    """.format(imageUrl)
  
    uploadMonitorFileCommand = 'scp -o StrictHostKeyChecking=no -i credentials.pem monitor.sh ec2-user@{}:.'.format(instanceIpAddress)
    adjustPermissionsMonitorFileCommand = 'ssh -o StrictHostKeyChecking=no -i credentials.pem ec2-user@{} "chmod 700 monitor.sh"'.format(instanceIpAddress)
    runMonitorFileCommand = 'ssh -o StrictHostKeyChecking=no -i credentials.pem ec2-user@{} "./monitor.sh"'.format(instanceIpAddress)
   
    stdin, stdout, stderr = sshClient.exec_command(metadataShellCommand)
    print(stdout.read())
    print(stderr.read())
    
    time.sleep(10)
    stdin, stdout, stderr = sshClient.exec_command(configureServerShellCommand)
    print(stdout.read())
    print(stderr.read())
    sshClient.close()
    
    monitorFileUploadResponse = subprocess.run(uploadMonitorFileCommand, shell=True)
    adjustPermissionsFileUpload = subprocess.run(adjustPermissionsMonitorFileCommand, shell=True)
    executeMonitorFile = subprocess.run(runMonitorFileCommand, shell=True)
    print(monitorFileUploadResponse)
    new_instance[0].monitor()  # Enables detailed monitoring on instance (1-minute intervals)

    time.sleep(60) 

  
    
    cpuMetricIterator = cloudwatch.metrics.filter(Namespace='AWS/EC2',
                                            MetricName='CPUUtilization',
                                            Dimensions=[{'Name':'InstanceId', 'Value':  new_instance[0].id}])
    
    print(cpuMetricIterator)
    cpuMetric = list(cpuMetricIterator)[0]    # extract first (only) element

    
    cloudwatchCpuResponse = cpuMetric.get_statistics(StartTime = datetime.utcnow() - timedelta(minutes=1),
                                 EndTime=datetime.utcnow(),                              # now
                                 Period=300,                                             # 5 min intervals
                                 Statistics=['Average'])
    
    cpuNetworkOutIterator = cloudwatch.metrics.filter(Namespace='AWS/EC2',
                                            MetricName='NetworkOut',
                                            Dimensions=[{'Name':'InstanceId', 'Value':  new_instance[0].id}])
    
    
    cpuNetworkOutMetric = list(cpuNetworkOutIterator)[0]    # extract first (only) element
    cloudwatchNetworkOutResponse = cpuNetworkOutMetric.get_statistics(StartTime = datetime.utcnow() - timedelta(minutes=1),   # 1 minute ago
                                 EndTime=datetime.utcnow(),                              # now
                                 Period=60,                                             # 1 min intervals
                                 Statistics=['Average'])


    print("Monitoring of New Instance (Last 60 Seconds)")
    print("--------------------------")
    print ("Average CPU utilisation:", cloudwatchCpuResponse['Datapoints'][0]['Average'], cloudwatchCpuResponse['Datapoints'][0]['Unit'])
    print("Average Network Out:", cloudwatchNetworkOutResponse['Datapoints'][0]['Average'], cloudwatchNetworkOutResponse['Datapoints'][0]['Unit'])

elif optionSelected == 2:
    print('2')
    existingInstanceId = input("Please input the instance number of the instance you are looking to monitor: ")
    allInstances = ec2.meta.client.describe_instance_status()['InstanceStatuses']

    validExistingInstanceId = False
    for instance in allInstances:
        if instance['InstanceId'] == existingInstanceId:
            print('valid instance id')
            validExistingInstanceId = True
            break
            
    if validExistingInstanceId:
        print('You can continue')  


    else:
        print("No live instance found with that id. Please try again.") 
        subprocess.run('python3 newwebserver.py',shell=True) 
    # cpuMetricIterator = cloudwatch.metrics.filter(Namespace='AWS/EC2',
    #                                         MetricName='CPUUtilization',
    #                                         Dimensions=[{'Name':'InstanceId', 'Value':  'i-0a77e96b4a5de8b46'}])
                                            
    # cpuMetric = list(cpuMetricIterator)[0]    # extract first (only) element
   
    # cloudwatchCpuResponse = cpuMetric.get_statistics(StartTime = datetime.utcnow() - timedelta(**{'minutes': minutesInt}),   # 1 minute ago
    #                              EndTime=datetime.utcnow(),                              # now
    #                              Period=int(period),                                             # 1 min intervals
    #                              Statistics=['Average', 'Sum', 'Minimum', 'Maximum'],
    #                              Unit=['Bytes'])



else:
    print('Exiting Programme....')
    exit()





# print(int(minutes))
# if int(minutes):
#     minutesInt = int(minutes)
#     print(minutesInt)
#     print(type(minutesInt))
#     period = minutesInt * 60
# else:
#     print("Invalid input. Please enter a number.")
#     exit()




# cloudwatchCpuResponse = cpuMetric.get_statistics(StartTime = datetime.utcnow() - timedelta(**{'minutes': minutesInt}),   # 1 minute ago
#                                  EndTime=datetime.utcnow(),                              # now
#                                  Period=int(period),                                             # 1 min intervals
#                                  Statistics=['Average', 'Sum', 'Minimum', 'Maximum'],
#                                  Unit=['Bytes'])


# cloudwatchCpuResponse = cpuMetric.get_statistics(StartTime = datetime.utcnow() - timedelta(**{'minutes': minutesInt}),   # 1 minute ago
#                                  EndTime=datetime.utcnow(),                              # now
#                                  Period=int(period),                                             # 1 min intervals
#                                  Statistics=['Average', 'Sum', 'Minimum', 'Maximum'],
#                                  Unit=['Bytes'])





