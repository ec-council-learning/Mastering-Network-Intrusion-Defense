#!/bin/bash
#EC2 parameters
INSTANCE_ID="your-instance-id"
NEW_INSTANCE_TYPE="t3.2xlarge"
#1Gbps throughput
THRESHOLD=1000000000

#Poll tshark output
THROUGHPUT=$(tshark -q -a duration:60 -z io,stat,0 | awk '/\|[ ]+All[ ]+\|/ {print $6}')
echo "Current throughput: $THROUGHPUT bps"

#compare the sample and resize as needed
THROUGHPUT_NUM=$(echo $THROUGHPUT | sed 's/[^0-9]*//g')
if [ "$THROUGHPUT_NUM" -gt "$THRESHOLD" ]; then
    echo "Throughput exceeds 1 Gbps. Resizing instance..." 
    aws ec2 stop-instances --instance-ids $INSTANCE_ID
    #have to use a wait instead of sleep
    aws ec2 wait instance-stopped --instance-ids $INSTANCE_ID
    aws ec2 modify-instance-attribute --instance-id $INSTANCE_ID --instance-type "{\"Value\": \"$NEW_INSTANCE_TYPE\"}"
    aws ec2 start-instances --instance-ids $INSTANCE_ID
    echo "Instance $INSTANCE_ID resized to $NEW_INSTANCE_TYPE"
else
    echo "No resize needed"
fi