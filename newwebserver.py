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
import os.path

# Command passed to ec2 instance on launch. Implements server on instance.
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


# This function returns True if the input parameter is of type number. Otherwise, False is returned
def ensureNumberInput(input):
    try:
        val = int(input)
        return True
    except ValueError:
        print("Invalid Input")
        return False


# This function creates an s3 bucket.
# The bucket name is set via the value passed in the bucket_name parameter (I have configured this to be a combination of date and time to ensure unique value).
# Standard implementation based on boto3 documentation: https://boto3.amazonaws.com/v1/documentation/api/latest/guide/s3-example-creating-buckets.html
def create_bucket(bucket_name, region=None):

    
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


# This function uploads a file to the s3 bucket.
# ExtraArgs used for upload_file method to enable public access for newly uploaded image ('ACL': 'public-read').
# Content type set to image/jpeg to indicate that file type is image.
def upload_file(file_name, bucket, object_name=None):

    # If s3 object_name is not specified, use file_name
    if object_name is None:
        object_name = file_name

    # File is uploaded
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


# This function uses the paramiko library to initiate a ssh connection with the newly created ec2 instance.
# sshPrivateKey is created based on name of credentials file used in creation of ec2 instance.
# If unsuccessful on first attempt, function increments numberOfAttempts, waits 30 seconds and re-attempts connection (should't be required as waiter in place until ec2 status is running).
# If numberOfAttempts is greater than 3, False is returned with exception.
def sshConnection(ssh, ip, numberOfAttempts, credentials):
    if numberOfAttempts > 3:
        return False
    sshPrivateKey = paramiko.RSAKey.from_private_key_file('{}.pem'.format(credentials))
    interval = 30
    try:
        numberOfAttempts += 1
        print('SSHing into instance: {}'.format(ip))
        ssh.connect(hostname=ip,
                    username='ec2-user', pkey=sshPrivateKey)
        return True
    except Exception as e:
        print(e)
        time.sleep(interval)
        print('Retrying SSH connection to instance {}'.format(ip))
        sshConnection(ssh, ip, numberOfAttempts)


# Function to show basic menu on launch of programme.
# While loop in place to ask user for input until valid input provided (number).
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




# Calling userMenu function to display menu and capturing user response in userInput variable
userInput = userMenu()


# Converting string to integer
optionSelected = int(userInput)


# If user has entered 1, ec2 instance and s3 bucket flow are initiated.
if optionSelected == 1:

    # Declaring empty string for keyPairName
    keyPairName = ''

    # User is asked if they want to create a new keypair or use an existing key pair
    createSecurityGroup = input("Do you want to create a new keypair for the instance (Y / N): ")

    # If user enters 'Y' or 'y', they are indicating they do want to create a new key pair
    if createSecurityGroup.upper() == 'Y':
        
        # Setting validKeyPair variable to False on declaration
        validKeyPair = False
        
        # While loop in place until validKeyPair is True
        while not validKeyPair:
            
            # User is prompted for name of new key pair

            keyPairName = input("Please input the name of the keypair to be created: ")

            # Declaring keyPairAlreadyCreated variable and setting initial value to False
            keyPairAlreadyCreated = False
            
            try:
                # A check is made to see if there is an existing key pair with the input provided by the user
                existingKeyPair = ec2Client.describe_key_pairs(KeyNames=[keyPairName])

                # If result found, an existing key pair already has the name provided by the user
                keyPairAlreadyCreated = True
                print('Key Pair already found for that input....')
                print("-----------------------------------------")
            except ClientError as e:

                # If no result found, no existing key pair has the name provided by the user and can be used.
                existingKeyPair = False


            # If an existing file in the folder does not have the same title as the user input and keyPairAlreadyCreated is False:
            # Key Pair is created, contents written into local file.
            # Subprocess command is used to edit permissions on newly created file.
            # validKeyPair variable set to True, breaking out of loop

            if not os.path.isfile('{}.pem'.format(keyPairName)) and not keyPairAlreadyCreated:
                print ("File does not exist")
                outfile = open('{}.pem'.format(keyPairName), 'w')
                key_pair = ec2.create_key_pair(KeyName=keyPairName)
                KeyPairOut = str(key_pair.key_material)
                outfile.write(KeyPairOut)
                outfile.close()
                editFilePermissions = 'chmod 700 ./{}.pem'.format(keyPairName)
                subprocess.run(editFilePermissions, shell=True)
                
                validKeyPair = True
        else:
            # User is informed that credentials have been successfully created
            print ("Valid credentials provided...")
            print("------------------------------")


    # If user enters 'N' or 'n', they are indicating they do not want to create a new key pair
    elif createSecurityGroup.upper() == 'N':

        # validKeyPairProvided is set to False

        validKeyPairProvided = False

        # Loop in place until validKeyPairProvided is True
        while not validKeyPairProvided:

            # User is prompted for name of existing key pair that user wishes to use
            existingKeyPairName = input("Please input the name of the existing keypair file that you wish to use: ")
            try:
                # Call made to describe_key_pairs to see if existing key pair is present for input provided by user.
                existingKeyPair = ec2Client.describe_key_pairs(KeyNames=[existingKeyPairName])

                # If result found, validKeyPairProvided is set to True, breaking out of loop
                validKeyPairProvided = True

                # keyPairName variable value is set to existingKeyPairName (inputted by user)
                keyPairName = existingKeyPairName

                # User is informed that valid key pair was found
                print('Valid Key Pair Found....')
                print("------------------------")

            except ClientError as e:

                # If error on describe_key_pairs call: existingKeyPair is set to False
                existingKeyPair = False

                # User informed that no existing key pair was found.
                print('No Key Pair Found for that input. Please try again.')
                print("----------------------------------------------------")

    # If user inputs anything other than 'Y' or 'y' or 'N' or 'n' then the user is informed invalid input has been provided and the programme exits
    else:
        print("Invalid input. Exiting Programme...")
        exit()
    

    # securityGroupName variable initialised as empty string
    securityGroupName = ''

    # User is prompted for input on whether they wish to use an existing security group or create a new one
    newSecurityGroupOption = input("Do you want to create a new security group (Y / N): ")


    # If user enters 'Y' or 'y', they are indicating they want to create a new security group
    if newSecurityGroupOption.upper() == 'Y':

        # validNewSecurityGroup variable set to False
        validNewSecurityGroup = False

        # while loop until validNewSecurityGroup is True
        while not validNewSecurityGroup:

            # User is prompted for name of new security group
            securityGroupName = input("Please enter the name of the new security group: ")
            try:
                # Check is made with describe_security_groups method to see if security group exists with the name provided by the user
                response = ec2Client.describe_security_groups(GroupNames=[securityGroupName])
                print("A security group already exists with that name. Please try again...")
                print("-------------------------------------------------------------------")
            except ClientError as e:
                # If error, no existing security group with the name provided by the user so validNewSecurityGroup set to True to break out of the while loop.
                validNewSecurityGroup = True

                # User is informed that valid security group name has been provided.
                print("Valid new security group name...")
                print("--------------------------------")
        
        # User is prompted for description of new security group
        newSecurityGroupDescription = input("Please enter the description for the new security group: ")

        try:
            # New security group is created with description and name provided by user
            newSecurityGroup = ec2Client.create_security_group( Description=newSecurityGroupDescription,GroupName=securityGroupName)


            # Permissions for ssh and http are added to newly created security group.
            addingPermissionsSecurityGroupResponse = ec2Client.authorize_security_group_ingress(
                GroupName=securityGroupName,IpPermissions=[
                    {
                        'FromPort': 80,
                        'IpProtocol': 'tcp',
                        'IpRanges': [
                            {
                                'CidrIp': '0.0.0.0/0',
                                'Description': 'HTTP'
                                },
                                ],
                                'ToPort': 80
                                },
                    {
                        'FromPort': 22,
                        'IpProtocol': 'tcp',
                        'IpRanges': [
                            {
                                'CidrIp': '0.0.0.0/0',
                                'Description': 'SSH'
                                },
                                ],
                                'ToPort': 22
                                }
                                ])
            # User is informed that security group has been created
            print("Security Group Created...")
            print("-------------------------")

        except ClientError as e:
            # If error in creation of security group, user is informed and programme exits.
            print("Error creating new security group. Exiting programme....")
            exit()
        

    
    # If user inputs 'N' or 'n', they are indicating that they do not want to create a new security group
    elif newSecurityGroupOption.upper() == 'N':

        # User is prompted for name of existing security group they want to use
        securityGroupName = input("Please enter the name of the existing security group to use: ")
        try:
            # Call made to describe_security_groups method to check if security group exists with name provided by user
            response = ec2Client.describe_security_groups(GroupNames=[securityGroupName])

            # If valid, user informed that valid security group found
            print('Valid Security Group Found....')
            print("-------------------------------")
      
        except ClientError as e:
            # Otherwise, user informed that no security group was found for the name they provided.
            print("No security group found for that input. Exiting programme....")

            # Programme exits
            exit()


    
    # If user inputs anything other than 'Y' or 'y' or 'N' or 'n', user is informed that invalid input has been provided. Programme exits
    else:
        print("Invalid Input provided. Exiting Programme....")
        exit()

    

    # User is informed that instance is about to be launched
    print("Starting instance")
    print("-----------------")

    # Call made to create_instances (securityGroupName variable passed for SecurityGroups paramater, keyPairName variable passed for KeyName parameter, serverCommands variable passed in UserData parameter)
    new_instance = ec2.create_instances(
                                    ImageId='ami-079d9017cb651564d',
                                    MinCount=1,
                                    MaxCount=1,
                                    InstanceType='t2.nano',
                                    SecurityGroups=[securityGroupName],
                                    KeyName=keyPairName,
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

    # Wait until instance is running
    new_instance[0].wait_until_running()

    # Print out newly created instance id
    print (new_instance[0].id)

    # Another waiter declared to wait until instance status is ok (to ensure that server has launched before sshing in.)
    waiter = ec2Client.get_waiter('instance_status_ok')

   
    # User is informed that waiter is firing (and that it is not an error in the programme)
    print('Waiting until instance status ok (to ensure web server is available)...')
    print("-----------------------------------------------------------------------")
    waiter.wait(
    InstanceIds=[
        new_instance[0].id,
    ],
)
    
    # Instance is reloaded to ensure that public ip address can be obtained
    new_instance[0].reload()

    # Initiating monitoring on new instance
    new_instance[0].monitor()

    # instance ip address stored in instanceIpAddress variable
    instanceIpAddress = new_instance[0].public_ip_address

    # url from which to fetch the image
    imageUrl = 'http://devops.witdemo.net/image.jpg'

    # Request made to obtain image from url
    imageContent = requests.get(imageUrl).content

    # Response content written to './imageToBeUploaded.jpg' file
    with open('./imageToBeUploaded.jpg', 'wb') as handleImageData:
        handleImageData.write(imageContent)

    
    #Commenting out (ran out of time to add functionality for asking user for bucket name)
    # call made to s3
    # existingS3Buckets = s3_Client.list_buckets()
    # s3BucketsList = existingS3Buckets['Buckets']
    s3BucketAlreadyCreated = False
    # s3BucketName = ''
    # for bucket in s3BucketsList:
    #     if 'imagebucket' in bucket['Name']:
    #         s3BucketAlreadyCreated = True
    #         s3BucketName = bucket['Name']
    #         break
    if s3BucketAlreadyCreated != True:

        # Obtain current time
        currentTime = gmtime()

        # Create unique bucket name by concatenating various elements of the current date with 'imagebucket'
        s3BucketName = 'imagebucket.' + str(currentTime.tm_mday) + '-' + str(currentTime.tm_mon) + '-' + str(currentTime.tm_year) + '.' + str(currentTime.tm_hour) + '.' + str(currentTime.tm_min) + '.' + str(currentTime.tm_sec)

        # create_bucket function called with bucket name and region passed as parameters
        create_bucket(s3BucketName, 'eu-west-1')
    

    # Upload file function called with image, bucket name and name of image to be created passed as parameters
    upload_file('./imageToBeUploaded.jpg', s3BucketName, 'webSiteImage.jpg')

    # calling Bucket.(bucketName).objects.all() to obtain contents of newly created bucket
    s3ImageBucketContents = s3_Resource.Bucket(s3BucketName).objects.all()
    bucketName = ''
    objectName = ''
    

    # Pulling out bucketName and objectName from bucket contents response
    for image in s3ImageBucketContents:
        bucketName = image.bucket_name
        objectName = image.key
    

    # Constructing url for newly uploaded image to s3
    imageUrl = 'https://s3-eu-west-1.amazonaws.com/' + str(bucketName) + '/' + str(objectName)

    # Defining metadataUrl (passing instanceIpAddress in via .format method)
    metadataUrl = 'http://{}/latest/meta-data/local-ipv4'.format(instanceIpAddress)

    # shell command to obtain various pieces of metadata about the newly created instance
    metadataShellCommand = """
    ssh -o StrictHostKeyChecking=no -i {}.pem ec2-user@{}
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
    """.format(keyPairName, instanceIpAddress)


    # creating paramiko ssh client, setting credentials
    sshClient = paramiko.SSHClient()
    sshClient.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    sshPrivateKey = paramiko.RSAKey.from_private_key_file('{}.pem'.format(keyPairName))


    # sshConnection function call with value of sshClient, instanceIpAddress, initiating number of attempts as 0 and keyPairName as values for each parameter
    sshConnection(sshClient, instanceIpAddress, 0, keyPairName)

    # Shell command for redirecting image tag into index.html file on instance.
    # Sudo used to then move this file to the server file location on the instance.
    configureServerShellCommand = """
    echo "<hr>Here is an image that I have stored on S3: <br>
    <img src={}>" >> index.html
    ls
    sudo mv index.html /var/www/html
    """.format(imageUrl)
  
    # Shell command for sshing into instance, securely copying the monitor.sh file from the local device up onto the newly created instance
    uploadMonitorFileCommand = 'scp -o StrictHostKeyChecking=no -i {}.pem monitor.sh ec2-user@{}:.'.format(keyPairName, instanceIpAddress)

    # Shell command for sshing into instance, editing permissions on newly uploaded monitor.sh file on the ec2 instance
    adjustPermissionsMonitorFileCommand = 'ssh -o StrictHostKeyChecking=no -i {}.pem ec2-user@{} "chmod 700 monitor.sh"'.format(keyPairName, instanceIpAddress)

    # Shell command for sshing into instance and executing the monitor.sh file
    runMonitorFileCommand = 'ssh -o StrictHostKeyChecking=no -i {}.pem ec2-user@{} "./monitor.sh"'.format(keyPairName, instanceIpAddress)
    

    # Using paramiko sshClient instance to ssh into ec2 instance and execute initial command
    stdin, stdout, stderr = sshClient.exec_command(metadataShellCommand)
    
    # Giving a gap here between execution of ssh commands
    time.sleep(10)

    # Using paramiko sshClient instance to ssh into ec2 instance and execute server configuration command
    stdin, stdout, stderr = sshClient.exec_command(configureServerShellCommand)
   
    
    # sshClient session closed
    sshClient.close()
    
    # using subprocess to run latter shell commands (firstly sshing into instance)
    # Securely copying up monitor.sh file
    monitorFileUploadResponse = subprocess.run(uploadMonitorFileCommand, shell=True)

    # Adjusting permissions on monitor.sh file so that it can be executed on instance
    adjustPermissionsFileUpload = subprocess.run(adjustPermissionsMonitorFileCommand, shell=True)

    # Executing monitor.sh file
    executeMonitorFile = subprocess.run(runMonitorFileCommand, shell=True)
  

    # Informing user that monitoring is commencing.
    print("Commencing monitoring...")
    print("------------------------")
    time.sleep(60) 
  

  
    # Setting up cpUUtilization cloudwatch monitoring (note instance id passed as value in Dimensions)
    cpuMetricIterator = cloudwatch.metrics.filter(Namespace='AWS/EC2',
                                            MetricName='CPUUtilization',
                                            Dimensions=[{'Name':'InstanceId', 'Value':  new_instance[0].id}])
    
    
    # First element extracted from newly created cpuMetricIterator list
    cpuMetric = list(cpuMetricIterator)[0]    

    
    # cloudwatch cpu utilization data obtained using .get_statistics method (using delta of 1 minute). Average value returned.
    cloudwatchCpuResponse = cpuMetric.get_statistics(StartTime = datetime.utcnow() - timedelta(minutes=1),
                                 EndTime=datetime.utcnow(),                              # now
                                 Period=60,                                             # 5 min intervals
                                 Statistics=['Average'])
    

    # Setting up NetworkOut cloudwatch monitoring (note instance id passed as value in Dimensions)
    cpuNetworkOutIterator = cloudwatch.metrics.filter(Namespace='AWS/EC2',
                                            MetricName='NetworkOut',
                                            Dimensions=[{'Name':'InstanceId', 'Value':  new_instance[0].id}])
    

    # First element extracted from newly created cpuNetworkOutIterator list
    cpuNetworkOutMetric = list(cpuNetworkOutIterator)[0]


     # cloudwatch network out data obtained using .get_statistics method (using delta of 1 minute). Average value returned.
    cloudwatchNetworkOutResponse = cpuNetworkOutMetric.get_statistics(StartTime = datetime.utcnow() - timedelta(minutes=1),  
                                 EndTime=datetime.utcnow(),                              # now
                                 Period=60,                                             # 1 min intervals
                                 Statistics=['Average'])



    # Monitoring results outputted to user
    print("Monitoring of New Instance (Last 60 Seconds)")
    print("--------------------------")
    print ("Average CPU utilisation:", cloudwatchCpuResponse['Datapoints'][0]['Average'], cloudwatchCpuResponse['Datapoints'][0]['Unit'])
    print("Average Network Out:", cloudwatchNetworkOutResponse['Datapoints'][0]['Average'], cloudwatchNetworkOutResponse['Datapoints'][0]['Unit'])


# If user has chosen 2 from main menu, they want to monitor an existing ec2 instance
elif optionSelected == 2:


    # User is prompted for instance id they want to monitor
    userInputInstanceId = input("Please enter the instance ID you wish to monitor: ")
    validInstanceId = ''

    try:
        # .describe_instances method called with user input passed as value for InstanceIds parameter to check if valid instance
        validInstanceId = ec2Client.describe_instances(InstanceIds=[userInputInstanceId])
        print("Instance found")
    except ClientError as e:
        # If error, no instances found with that id
        print("No live instance found with that id. Exiting programme...")
        exit()
    


    # configuring cloudwatch CPUUtilization (note user input passed as value in dimensions after checking above that it was a valid instance)
    cpuMetricIterator = cloudwatch.metrics.filter(Namespace='AWS/EC2',
                                            MetricName='CPUUtilization',
                                            Dimensions=[{'Name':'InstanceId', 'Value':  userInputInstanceId}])


    # First element extracted from newly created cpuMetricIterator list     
    cpuMetric = list(cpuMetricIterator)[0]    # extract first (only) element


    # configuring cloudwatch NetworkOut (note user input passed as value in dimensions after checking above that it was a valid instance)
    cpuNetworkOutIterator = cloudwatch.metrics.filter(Namespace='AWS/EC2',
                                            MetricName='NetworkOut',
                                            Dimensions=[{'Name':'InstanceId', 'Value':  userInputInstanceId}])

    
    # First element extracted from newly created cpuNetworkOutIterator list    
    cpuNetworkOutMetric = list(cpuNetworkOutIterator)[0]  


    # Submenu for monitoring existing instance displayed to user
    print("SubMenu")
    print("-------")


    # User prompted for monitoring type they wish to complete
    monitorType = input("Enter 1 for Historical Monitoring or 2 to start monitoring an instance: ")


    # If they enter '1' they want historical monitoring
    if monitorType == '1':

        # Prompted for number of minutes to go back in monitoring data
        duration = input("Please input the number of minutes that you want to monitor: ")

        # Checking if valid input (number)
        numberInputProvided = ensureNumberInput(duration)
        
        # If valid number
        if numberInputProvided:

            # minutesInt set to integer of duration variable
            minutesInt = int(duration)

            # Period is minutes multipled by 60
            period = minutesInt * 60
            
       

            try:
                # .get_statistics method called with timedelta of minutes passed by user and period set to number of minutes entered by user * 60  (Average, sum, minimum, maximum statistics sought)
                cloudwatchCpuResponse = cpuMetric.get_statistics(StartTime = datetime.utcnow() - timedelta(**{'minutes': minutesInt}),  
                                 EndTime=datetime.utcnow(),                            
                                 Period=int(period),                                            
                                 Statistics=['Average', 'Sum', 'Minimum', 'Maximum'])

                cpuDataReturned = cloudwatchCpuResponse['Datapoints']

                if cpuDataReturned:
                    print("CPU Cloudwatch Data")
                    print("--------")
                    print ("Average CPU utilisation:", cloudwatchCpuResponse['Datapoints'][0]['Average'], cloudwatchCpuResponse['Datapoints'][0]['Unit'])
                    print("CPU Utilization Sum:", cloudwatchCpuResponse['Datapoints'][0]['Sum'], cloudwatchCpuResponse['Datapoints'][0]['Unit'])
                    print("CPU Utilization Max:", cloudwatchCpuResponse['Datapoints'][0]['Maximum'], cloudwatchCpuResponse['Datapoints'][0]['Unit'])
                    print("CPU Utilization Min:", cloudwatchCpuResponse['Datapoints'][0]['Minimum'], cloudwatchCpuResponse['Datapoints'][0]['Unit'])
                    print("--------")
                else:
                    print("No cpu data returned")


                

                
                # .get_statistics method called with timedelta of minutes passed by user and period set to number of minutes entered by user * 60 (Average, sum, minimum, maximum statistics sought)
                cloudwatchNetworkOutResponse = cpuNetworkOutMetric.get_statistics(StartTime = datetime.utcnow() - timedelta(**{'minutes': minutesInt}), 
                                 EndTime=datetime.utcnow(),                             
                                 Period=int(period),                                            
                                 Statistics=['Average', 'Sum', 'Minimum', 'Maximum'])

                networkDataReturned = cloudwatchNetworkOutResponse['Datapoints']

                if networkDataReturned:
                    print("Network Out Cloudwatch Data")
                    print("--------")
                    print ("Average Network Out:", cloudwatchNetworkOutResponse['Datapoints'][0]['Average'], cloudwatchNetworkOutResponse['Datapoints'][0]['Unit'])
                    print("Network Out Sum:", cloudwatchNetworkOutResponse['Datapoints'][0]['Sum'], cloudwatchNetworkOutResponse['Datapoints'][0]['Unit'])
                    print("Network Out Max:", cloudwatchNetworkOutResponse['Datapoints'][0]['Maximum'], cloudwatchNetworkOutResponse['Datapoints'][0]['Unit'])
                    print("Network Out Min:", cloudwatchNetworkOutResponse['Datapoints'][0]['Minimum'], cloudwatchNetworkOutResponse['Datapoints'][0]['Unit'])
                    print("--------")
                else:
                    print("No network out data returned")
            
               
            
           
        
            except ClientError as e:
                # If error thrown for obtaining either statistics metric, user informed of error and programme exits
                print('No data found for that timeframe. Exiting programme....')
                exit()
        
        else:
            # If user has not provided a number for minutes, user informed of invalid input and programme exits
            print("Invalid option. Exiting programme....")
            exit()

    
    # If user has entered '2', they are indicating they want to begin monitring an instance now
    elif monitorType == '2':

        # ec2 instance instantiated by passed userInput instanceid
        instance = ec2.Instance(userInputInstanceId)

        # User prompted for number of minutes they want to monitor
        duration = input("Please input the number of minutes that you want to monitor: ")

        # Checking that user has provided number
        numberInputProvided = ensureNumberInput(duration)


        # If number provided
        if numberInputProvided:

            # minutesInt set to integer of duration variable
            minutesInt = int(duration)
           
           
            # Period set to value of minutesInt multipied by 60
            period = minutesInt * 60
            try:

                # An attempt made to start monitoring on the instance
                instance.monitor()
            
            except ClientError as e:
                # If error thown, instance cannot be monitored. User informed, programme exits.
                print("Instance not in monitorable state (terminated / unavailable). Exiting programme...")
                exit()
            
            # If no error thrown, user informed that monitoring has commenced and informed of monitoring end time.
            print("Monitoring starting. Completion Time: " +  str(datetime.utcnow() + timedelta(**{'minutes': minutesInt})))

            # time.sleep called for the period variable set above to enable monitoring
            time.sleep(period)
            
       

            try:

                 # .get_statistics method called with timedelta of minutes passed by user and period set to number of minutes entered by user * 60 (Average, sum, minimum, maximum statistics sought)
                cloudwatchCpuResponse = cpuMetric.get_statistics(StartTime = datetime.utcnow() - timedelta(**{'minutes': minutesInt}),  
                                 EndTime=datetime.utcnow(),                            
                                 Period=int(period),                                            
                                 Statistics=['Average', 'Sum', 'Minimum', 'Maximum'])

                
                # Checking if cpu data returned.
                cpuDataReturned = cloudwatchCpuResponse['Datapoints']

                if cpuDataReturned:
                    print("Cpu data returned.")
                    print("------------------")
                    print("CPU Cloudwatch Data")
                    print("--------")
                    print ("Average CPU utilisation:", cloudwatchCpuResponse['Datapoints'][0]['Average'], cloudwatchCpuResponse['Datapoints'][0]['Unit'])
                    print("CPU Utilization Sum:", cloudwatchCpuResponse['Datapoints'][0]['Sum'], cloudwatchCpuResponse['Datapoints'][0]['Unit'])
                    print("CPU Utilization Max:", cloudwatchCpuResponse['Datapoints'][0]['Maximum'], cloudwatchCpuResponse['Datapoints'][0]['Unit'])
                    print("CPU Utilization Min:", cloudwatchCpuResponse['Datapoints'][0]['Minimum'], cloudwatchCpuResponse['Datapoints'][0]['Unit'])
                    print("--------")
                else:
                    print("Cpu data not returned.")


                 # .get_statistics method called with timedelta of minutes passed by user and period set to number of minutes entered by user * 60 (Average, sum, minimum, maximum statistics sought)
                cloudwatchNetworkOutResponse = cpuNetworkOutMetric.get_statistics(StartTime = datetime.utcnow() - timedelta(**{'minutes': minutesInt}),  
                                 EndTime=datetime.utcnow(),                             
                                 Period=int(period),                                          
                                 Statistics=['Average', 'Sum', 'Minimum', 'Maximum'])
            
              
                # Checking if network data returned
                networkDataReturned = cloudwatchNetworkOutResponse['Datapoints']
               

                if networkDataReturned:
                    print("Network data returned.")
                    print("----------------------")
                    print("Network Out Cloudwatch Data")
                    print("--------")
                    print ("Average Network Out:", cloudwatchNetworkOutResponse['Datapoints'][0]['Average'], cloudwatchNetworkOutResponse['Datapoints'][0]['Unit'])
                    print("Sum Network Out:", cloudwatchNetworkOutResponse['Datapoints'][0]['Sum'], cloudwatchNetworkOutResponse['Datapoints'][0]['Unit'])
                    print("Max Network Out:", cloudwatchNetworkOutResponse['Datapoints'][0]['Maximum'], cloudwatchNetworkOutResponse['Datapoints'][0]['Unit'])
                    print("Min Network Out:", cloudwatchNetworkOutResponse['Datapoints'][0]['Minimum'], cloudwatchNetworkOutResponse['Datapoints'][0]['Unit'])
                    print("--------")
                    
                else:
                    print("Network data not returned.")
                


            
           
        
            except ClientError as e:
                # If error, user informed that no data available for that period, programme exits
                print('No data found for that timeframe. Exiting programme....')
                exit()
        
        else:
            # If user has not provided number, informed of invalid input, programme exits
            print("Invalid option. Exiting programme....")
            exit()


    
    else:
        # If user has not provided number, informed of invalid input, programme exits
        print("Invalid option. Exiting programme....")



else:
    # If user has not provided valid input at menu screen, programme exits
    print('Exiting Programme....')
    
    exit()
  
    



   
        



















