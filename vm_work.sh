VM_IP="192.168.56.101"
USER=mininet
VM_PATH=pox/ext/
CONN=$USER@$VM_IP
DATA=$CONN:$VM_PATH

ping -c 1 $VM_IP > /dev/null
if [ ! $? -eq 0 ]
then
    echo "Host down"
    exit 1
fi

FILE1=SimpleLoadBalancer.py
FILE2=SimpleLoadBalancer_conf.json
scp $FILE1 $DATA$FILE1
scp $FILE2 $DATA$FILE2

COMMAND="cd pox && ./pox.py log.level --DEBUG SimpleLoadBalancer --configuration_json_file=ext/SimpleLoadBalancer_conf.json"
ssh -t  $CONN command $COMMAND
