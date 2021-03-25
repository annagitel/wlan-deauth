### WLAN DeAuthentication attack
pre requirments:
* linux environment
* external network card (can be switched to monitor mode)
* python 3
* scapy ```pip install scapy```
* netifaces ```pip install netifaces```

to run:
```buildoutcfg
sudo python3 wlanDeAuth.py
```

#####please make sure you select the right interface - if not, the monitor command will get into infi loop !

###Do not panic if: 
* you cant see your iphone in the devices list - Iphones spoof their MAC address. If you see a "special" MAC, its him

* your WIN10 computer was not disconnected, just a bit interrupted - most resent versions have defence rules against deauth attacks. to see if the attack is sucessful run ```ping -t 8.8.8.8``` on the attacked computer and see the interruptions!