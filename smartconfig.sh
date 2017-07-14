echo "start get passwd and bssid from APP"
cp config/monitor.config /etc/config/wireless
wifi up
./mydump

if [ $? != 0 ];then
	echo "ERROR: get passwd and bssid"
	exit(-1)
fi


BSSID=`head -1 password.txt`
PASSWD=`tail -1 password.txt`

cp config/sta.config /etc/config/wireless
sed -i "s/replace-bssid/$BSSID/g" /etc/config/wireless
sed -i "s/replace-passwd/$PASSWD/g" /etc/config/wireless
sed -i "s/replace-sec/psk2/g" /etc/config/wireless

wifi up

