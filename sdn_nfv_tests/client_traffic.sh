#! usr/bin/bash

echo "Started" 

# Parameters
start_time="$(date -u +%s)"
echo "Time out in seconds: "
read TIMEOUT_SEC
current_time="$(date -u +%s)"
elapsed_seconds=$(($current_time-$start_time))
# Loop until TIMEOUT
while  [ $elapsed_seconds -lt $TIMEOUT_SEC ]; 
do 
echo "connect to server"
remaining_seconds=$(($TIMEOUT_SEC-$elapsed_seconds))
echo "******** Remaining time: " $remaining_seconds
iperf -c 10.0.0.250 -t $remaining_seconds -b 10M
current_time="$(date -u +%s)"
elapsed_seconds=$(($current_time-$start_time))
done
# end traffic
echo "Done"
