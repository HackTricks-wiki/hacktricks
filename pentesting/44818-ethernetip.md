# 44818/UDP/TCP - Pentesting EthernetIP

## **Protocol Information**

From Wikipedia article on EtherNet/IP [http://en.wikipedia.org/wiki/EtherNet/IP](http://en.wikipedia.org/wiki/EtherNet/IP)

> EtherNet/IP was developed in the late 1990s by Rockwell Automation as part of Rockwell's industrial Ethernet networking solutions. Rockwell gave EtherNet/IP its moniker and handed it over to ODVA, which now manages the protocol and assures multi-vendor system interoperability by requiring adherence to established standards whenever new products that utilize the protocol are developed today.

> EtherNet/IP is most commonly used in industrial automation control systems, such as for water processing plants, manufacturing facilities and utilities. Several control system vendors have developed programmable automation controllers and I/O capable of communicating via EtherNet/IP.

An EtherNet/IP device is positively identified by querying TCP/44818 with a list Identities Message \(0x63\). The response messages will determine if it is a EtherNet/IP device and parse the information to enumerate the device.  
From [here](https://github.com/digitalbond/Redpoint)

**Default port:** 44818 UDP/TCP

```text
PORT      STATE SERVICE
44818/tcp open  EtherNet/IP
```

## **Enumeration**

```bash
nmap -n -sV --script enip-info -p 44818 <IP>
pip3 install cpppo
python3 -m cpppo.server.enip.list_services [--udp] [--broadcast] --list-identity -a <IP>
```

## Shodan

* `port:44818 "product name"`

