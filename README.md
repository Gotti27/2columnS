# 2columnS
2columnS is a Network Intrusion Detection System (NIDS) and basic firewall on the IN traffic chain, developed for Network Security project 2023.
To detect an anomaly in the incoming traffic flow a dummy one-class SVM was trained on unlabeled data recorded from our system.

## Summary
The tool is composed of a kernel module and a user space daemon.
## Installation
To install this tool, you have to make the intall script executable:
```
$ sudo chmod +x install
```
And then just invoke it as follows:
```
$ ./install
```
### Fire it up!
Finally, to start-up the user daemon you have to use the systemctl:
```
$ sudo systemctl start 2columnS.service
```
You can then observe the log from the journalctl:
```
$ sudo journalctl -f -u 2columnS.service
```
