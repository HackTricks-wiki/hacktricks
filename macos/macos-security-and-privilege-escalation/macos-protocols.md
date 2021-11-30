# MacOS Protocols

## Bonjour

**Bonjour** is an Apple-designed technology that enables computers and **devices located on the same network to learn about services offered **by other computers and devices. It is designed such that any Bonjour-aware device can be plugged into a TCP/IP network and it will **pick an IP address** and make other computers on that network** aware of the services it offers**. Bonjour is sometimes referred to as Rendezvous, **Zero Configuration**, or Zeroconf.\
Zero Configuration Networking, such as Bonjour provides:

* Must be able to **obtain an IP Address** (even without a DHCP server)
* Must be able to do **name-to-address translation** (even without a DNS server)
* Must be able to **discover services on the network**

The device will get an **IP address in the range 169.254/16** and will check if any other device is using that IP address. If not, it will keep the IP address. Macs keeps an entry in their routing table for this subnet: `netstat -rn | grep 169`

For DNS the **Multicast DNS (mDNS) protocol is used**. [**mDNS** **services** listen in port **5353/UDP**](../../pentesting/5353-udp-multicast-dns-mdns.md), use **regular DNS queries** and use the **multicast address 224.0.0.251** instead of sending the request just to an IP address. Any machine listening these request will respond, usually to a multicast address, so all the devices can update their tables.\
Each device will **select its own name** when accessing the network, the device will choose a name **ended in .local** (might be based on the hostname or a completely random one). 

For **discovering services DNS Service Discovery (DNS-SD)** is used.

The final requirement of Zero Configuration Networking is met by **DNS Service Discovery (DNS-SD)**. DNS Service Discovery uses the syntax from DNS SRV records, but uses **DNS PTR records so that multiple results can be returned** if more than one host offers a particular service. A client requests the PTR lookup for the name `<Service>.<Domain>` and **receives** a list of zero or more PTR records of the form `<Instance>.<Service>.<Domain>`.

The `dns-sd` binary can be used to **advertise services and perform lookups** for services:

```bash
#Search ssh services
dns-sd -B _ssh._tcp

Browsing for _ssh._tcp
DATE: ---Tue 27 Jul 2021---
12:23:20.361  ...STARTING...
Timestamp     A/R    Flags  if Domain               Service Type         Instance Name
12:23:20.362  Add        3   1 local.               _ssh._tcp.           M-C02C934RMD6R
12:23:20.362  Add        3  10 local.               _ssh._tcp.           M-C02C934RMD6R
12:23:20.362  Add        2  16 local.               _ssh._tcp.           M-C02C934RMD6R
```

```bash
#Announce HTTP service
dns-sd -R "Index" _http._tcp . 80 path=/index.html

#Search HTTP services
dns-sd -B _http._tcp
```

When a new service is started the **new service mulitcasts its presence to everyone** on the subnet. The listener didn’t have to ask; it just had to be listening.

You ca use [**this tool**](https://apps.apple.com/us/app/discovery-dns-sd-browser/id1381004916?mt=12) to see the **offered services** in your current local network.\
Or you can write your own scripts in python with [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf):

```python
from zeroconf import ServiceBrowser, Zeroconf


class MyListener:

    def remove_service(self, zeroconf, type, name):
        print("Service %s removed" % (name,))

    def add_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        print("Service %s added, service info: %s" % (name, info))


zeroconf = Zeroconf()
listener = MyListener()
browser = ServiceBrowser(zeroconf, "_http._tcp.local.", listener)
try:
    input("Press enter to exit...\n\n")
finally:
    zeroconf.close()
```

If you feel like Bonjour might be more secured **disabled**, you can do so with:

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```

## References

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?\_encoding=UTF8\&me=\&qid=)****
* ****[**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)****
