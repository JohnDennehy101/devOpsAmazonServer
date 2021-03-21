#!/usr/bin/bash
#
# Sample basic monitoring functionality; Tested on Amazon Linux 2
#
INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
MEMORYUSAGE=$(free -m | awk 'NR==2{printf "%.2f%%", $3*100/$2 }')
UPTIME=$(uptime |awk '{ print $3 $4 }')
PROCESSES=$(expr $(ps -A | grep -c .) - 1)
HTTPD_PROCESSES=$(ps -A | grep -c httpd)
TOTAL_PACKETS_RECEIVED=$(netstat -s | grep 'total packets received')
TOTAL_PACKETS_DISCARDED=$(netstat -s | grep 'incoming packets discarded')
PACKET_RECEIVE_ERROR=$(netstat -s | grep 'packet receive errors')



echo "Instance ID: $INSTANCE_ID"
echo "Uptime: $UPTIME"
echo "Memory utilisation: $MEMORYUSAGE"
echo "No of processes: $PROCESSES"
echo "Received packets: $TOTAL_PACKETS_RECEIVED"
echo "Packets discarded: $TOTAL_PACKETS_DISCARDED"
echo "Packet Receive Errors: $PACKET_RECEIVE_ERROR"
if [ $HTTPD_PROCESSES -ge 1 ]
then
    echo "Web server is running"
else
    echo "Web server is NOT running"
fi

