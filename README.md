
# Setup
Setup of wireless network and bluetooth adapters (wlan setup can be done using `interface_manager.py`).

## Set wireless network adapter to monitor mode
```
ifconfig wlan0 down
airmon-ng check kill
iwconfig wlan0 mode monitor
ifconfig wlan0 up
iwconfig
```


## Set wireless network adapter to managed mode
```
ifconfig wlan0 down
airmon-ng check kill
iwconfig wlan0 mode managed
ifconfig wlan0 up
service NetworkManager start 
iwconfig
```

## Turn bluetooth adapter on
```
hciconfig hci0 up
hciconfig
```