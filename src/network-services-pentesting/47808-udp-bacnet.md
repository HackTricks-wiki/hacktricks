# 47808/udp - BACnet

{{#include ../banners/hacktricks-training.md}}

## Protocol Information

**BACnet** is a vendor-independent data-communications protocol for building automation and control networks. It is standardized as ANSI/ASHRAE 135 and ISO 16484-5 and supports systems such as HVAC, lighting, access control, elevators, security, and fire detection.<sup>[[1]](#references)</sup>

**Default port:** 47808

```text
PORT      STATE SERVICE
47808/udp open  bacnet  Building Automation and Control Networks
```

## Enumeration

### BAC0

The BAC0 Python library can issue a `Who-Is` broadcast and read properties from discovered devices. The host generally needs network reachability to the target BACnet/IP network.<sup>[[2]](#references)</sup>

```bash
pip3 install BAC0
pip3 install netifaces
```

```python
import BAC0
import time

myIP = '<YOUR_IP>/<MASK>'  # Example: '192.168.1.4/24'
bacnet = BAC0.connect(ip=myIP)
bacnet.whois()  # Broadcast a BACnet Who-Is request
time.sleep(5)   # Wait for devices to respond
for i, (deviceId, companyId, devIp, numDeviceId) in enumerate(bacnet.devices):
    print(f"-------- Device #{numDeviceId} --------")
    print(f"Device:     {deviceId}")
    print(f"IP:         {devIp}")
    print(f"Company:    {companyId}")
    readDevice = bacnet.readMultiple(f"{devIp} device {numDeviceId} all")
    print(f"Model Name: {readDevice[11]}")
    print(f"Version:    {readDevice[2]}")
    # print(readDevice)  # List all available device information
```

### Automatic

```bash
nmap --script bacnet-info --script-args full=yes -sU -n -sV -p 47808 <IP>
```

The Nmap script does not register as a BACnet foreign device. It sends standard BACnet requests directly to an IP-addressable device and reports properties such as its vendor, instance number, firmware, model, and description.<sup>[[3]](#references)</sup>

### Shodan

- `port:47808 instance`
- `"Instance ID" "Vendor Name"`

## References

- [1] [BACnet Committee: About the BACnet Standard](https://bacnet.org/about-bacnet-standard/)
- [2] [BAC0 documentation: Getting Started](https://bac0.readthedocs.io/en/latest/getstarted.html)
- [3] [Nmap NSE documentation: `bacnet-info`](https://nmap.org/nsedoc/scripts/bacnet-info.html)

{{#include ../banners/hacktricks-training.md}}
