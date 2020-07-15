# USB logs analysis

## USBrip

 **usbrip** is a small piece of software written in pure Python 3 which parses Linux log files \(`/var/log/syslog*` or `/var/log/messages*` depending on the distro\) for constructing USB event history tables.

It is interesting to know all the USBs that have been used and it will be more usefull if you have an authorized list of USB to find "violation events" \(the use of USBs that aren't inside that list\).

### Installation

```text
pip3 install usbrip
usbrip ids download #Downloal USB ID database
```

### Examples

```text
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```

More examples and info inside the github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

