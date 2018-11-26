#!/bin/bash


EXT_INT=""

Lo="lo"

if [[ $EXT_INT ]];then
  EXT_IP=`ifconfig ${EXT_INT} | grep "inet addr" | awk -F: '{ print $2}' | awk '{print $1}'`
fi

denied=""

SECONDS=100
BLOCKCOUNT=20

REMOTE_SERVER=""

IPS_SSH=""
SSH_PORT=""

SPOOF_IPS="0.0.0.0/8 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 224.0.0.0/3"
IPT="/sbin/iptables" # path to iptables 

ACTION_DROP="DROP"
ACTION_ACCEPT="ACCEPT"

## Failsafe - die if /sbin/iptables not found 
[ ! -x "$IPT" ] && { echo "$0: \"${ipt}\" command not found."; exit 1; }

###   FLUSH ALLL IPTABlE RULES AND ALLOW CHAINS

$IPT -P INPUT ACCEPT
$IPT -P FORWARD ACCEPT
$IPT -P OUTPUT ACCEPT
$IPT -F
$IPT -X
$IPT -t nat -F
$IPT -t nat -X
$IPT -t mangle -F
$IPT -t mangle -X
$IPT -t raw -X

$IPT -A INPUT -i lo -j ACCEPT


$IPT -N syn-flood
$IPT -A INPUT -p tcp --syn -j syn-flood

$IPT -t mangle -I PREROUTING -p tcp -m tcp --dport 80 -m state --state NEW -m tcpmss ! --mss 536:65535 -j DROP
#$IPT -A INPUT -i $EXT_INT -p tcp -m tcp --dport 80 -m state --state UNTRACKED -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460

#$IPT -A INPUT -p tcp --syn --dport 80 -m connlimit --connlimit-above 20 --connlimit-mask 24 -j REJECT --reject-with tcp-reset
$IPT -A INPUT -i $EXT_INT -m state --state ESTABLISHED,RELATED -j ACCEPT

$IPT -A INPUT -m state --state INVALID -s 127.0.0.1 -j ACCEPT


for spoof in ${SPOOF_IPS[@]};do
   $IPT -A INPUT -i $EXT_INT -s $spoof -j $ACTION
   $IPT -A OUTPUT -o $EXT_INT -s $spoof -j $ACTION
done


#Force SYN packets check
$IPT -A INPUT -p tcp ! --syn -m state --state NEW -s ${REMOTE_SERVER} -j ACCEPT
$IPT -A INPUT -p tcp ! --syn -m state --state NEW -j $ACTION
#Force Fragments packets check
$IPT -A INPUT -f -j $ACTION
#XMAS packets
$IPT -A INPUT -p tcp --tcp-flags ALL ALL -j $ACTION
#Drop all NULL packets
$IPT -A INPUT -p tcp --tcp-flags ALL NONE -j $ACTION

# SALT STACK ALLOW INCOMING REQUEST ONLY FROM SQL SERVER AND LOGGING ####################################################

$IPT -A INPUT -i $EXT_INT -m state --state new -m tcp -p tcp --dport 4505 -s $LEMANOIR_SQL -j ACCEPT
$IPT -A INPUT -i $EXT_INT -m state --state new -m tcp -p tcp --dport 4506 -s $LEMANOIR_SQL -j ACCEPT
$IPT -A INPUT -i $EXT_INT -m state --state NEW -m tcp -p tcp --dport 4505 -j LOG --log-prefix "LOG SALT PORT 4505"
$IPT -A INPUT -i $EXT_INT -m state --state NEW -m tcp -p tcp --dport 4506 -j LOG --log-prefix "LOG SALT PORT 4506"
$IPT -A INPUT -i lo -p tcp -m multiport --dports 4505,4506 -j ACCEPT
$IPT -A INPUT -i $EXT_INT -m state --state NEW -m tcp -p tcp --dport 4505 -j $ACTION
$IPT -A INPUT -i $EXT_INT -m state --state NEW -m tcp -p tcp --dport 4506 -j $ACTION

#########################################################################################################################

for ssh in ${IPS_SSH[@]};do
   $IPT -A INPUT -i $EXT_INT -m state --state NEW -p tcp --dport 22 -s $ssh -j ACCEPT
done
# LOG SSH TRAFFIC
$IPT -A INPUT -i $EXT_INT -p tcp --dport ${SSH_PORT} -m state --state NEW -m limit --limit 3/min --limit-burst 3 -j ACCEPT
$IPT -A INPUT -i $EXT_INT -m state --state NEW -p tcp --dport ${SSH_PORT} -j LOG --log-prefix "LOG PORT 22"
#DENY ALL SSH TRAFIC
$IPT -A INPUT -i $EXT_INT -p tcp --dport ${SSH_PORT} -j $ACTION


for sshsql in ${IPS_SQL[@]};do
   $IPT -A INPUT -i $EXT_INT -m state --state NEW -p tcp --dport 3307 -s $sshsql -j ACCEPT
done



$IPT -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j RETURN

$IPT -A INPUT -p tcp --syn --dport 80 -m state --state NEW -m connlimit --connlimit-above 20 -j REJECT --reject-with tcp-reset

$IPT -A INPUT -p tcp -m conntrack --ctstate NEW -m limit --limit 60/s --limit-burst 20 -j ACCEPT
$IPT -A INPUT -p tcp -m conntrack --ctstate NEW -j DROP

$IPT -A INPUT -p tcp --dport 80 -m state --state NEW -m recent --set
$IPT -A INPUT -p tcp --dport 80 -m state --state NEW -m recent --update --seconds ${SECONDS} --hitcount ${BLOCKCOUNT} -j LOG --log-prefix "Limit port 80"
$IPT -A INPUT -p tcp --dport 80 -m state --state NEW -m recent --update --seconds ${SECONDS} --hitcount ${BLOCKCOUNT} -j DROP

for china in ${denied[@]};do
 $IPT -A INPUT -s $china -j $ACTION 
done



service iptables save
service iptables restart










