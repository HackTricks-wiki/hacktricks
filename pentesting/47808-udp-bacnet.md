# 47808/udp - Pentesting BACNet

## Protocol Information

**BACnet** is a [communications protocol](https://en.wikipedia.org/wiki/Communications_protocol) for Building Automation and Control \(BAC\) networks that leverage the [ASHRAE](https://en.wikipedia.org/wiki/ASHRAE), [ANSI](https://en.wikipedia.org/wiki/ANSI), and [ISO](https://en.wikipedia.org/wiki/International_Organization_for_Standardization) 16484-5 standard[\[1\]](https://en.wikipedia.org/wiki/BACnet#cite_note-1) protocol.

BACnet was designed to allow communication of [building automation](https://en.wikipedia.org/wiki/Building_automation) and control systems for applications such as heating, ventilating, and air-conditioning control \([HVAC](https://en.wikipedia.org/wiki/HVAC)\), lighting control, access control, and fire detection systems and their associated equipment. The BACnet protocol provides mechanisms for computerized building automation devices to exchange information, regardless of the particular building service they perform.  
From [Wikipedia](https://en.wikipedia.org/wiki/BACnet)

**Default port:** 47808

```text
PORT      STATE SERVICE
47808/udp open  BACNet -- Building Automation and Control NetworksEnumerate
```

## Enumeration

### Manual

```bash
pip3 install BAC0
import BAC0
bbmdIP = '<IP>:47808'
bbmdTTL = 900
bacnet = BAC0.connect(bbmdAddress=bbmdIP, bbmdTTL=bbmdTTL) #Connect
bacnet.vendorName.strValue
#I couldn't find how to obtain the same data as nmap with this library or any other
#talk me if you know how please
```

### Automatic

```bash
nmap --script bacnet-info --script-args full=yes -sU -n -sV -p 47808 <IP>
```

This script does not attempt to join a BACnet network as a foreign device, it simply sends BACnet requests directly to an IP addressable device.

### Shodan

* `port:47808 instance`
* `"Instance ID" "Vendor Name"`

