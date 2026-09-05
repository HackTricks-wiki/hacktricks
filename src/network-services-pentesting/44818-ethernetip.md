# 44818 Pentesting EtherNet/IP

{{#include ../banners/hacktricks-training.md}}

## Protocol information

EtherNet/IP carries the Common Industrial Protocol (CIP) over standard Ethernet and is maintained by ODVA. Its common object model and conformance framework are intended to let devices from different vendors interoperate. It is used across industrial automation environments such as manufacturing, utilities, and water or process-control systems. Its encapsulation protocol uses TCP and UDP port 44818 for explicit messaging and discovery. The `ListIdentity` command (`0x0063`) can be sent directly over TCP or UDP with a zero session handle; a UDP broadcast is commonly used to discover every EtherNet/IP device on the local network.<sup>[[1]](#references)</sup>

**Default ports:**

- **44818/TCP:** encapsulation sessions, discovery commands, and explicit CIP messaging.<sup>[[1]](#references)</sup>
- **44818/UDP:** connectionless encapsulation discovery, especially `ListIdentity` broadcasts.<sup>[[1]](#references)</sup>
- **2222/UDP:** time-critical implicit (Class 0/1) I/O after a connection is negotiated. This traffic can be cyclic or change-of-state, unicast or multicast, and is especially useful when mapping controller-to-adapter relationships.<sup>[[1]](#references)</sup>

```
PORT      STATE SERVICE
44818/tcp open  EtherNet/IP
```

### Encapsulation and CIP request anatomy

Recognizing the normal sequence makes captures and custom probes much easier:<sup>[[1]](#references)</sup>

1. Discovery commands such as `ListIdentity`, `ListServices`, and `ListInterfaces` do not require a registered session.
2. A TCP originator normally sends `RegisterSession` (`0x0065`) and receives a 32-bit session handle.
3. `SendRRData` (`0x006f`) carries unconnected CIP requests. A `Forward_Open` request to the Connection Manager creates a connected explicit or I/O connection; connected explicit traffic is then normally carried by `SendUnitData` (`0x0070`).
4. A CIP request selects a **service** and an encoded path. Object paths commonly identify class, instance, and attribute; Logix symbolic paths instead address controller/program tags. Read-only assessment usually starts with `Get_Attributes_All` (`0x01`) and `Get_Attribute_Single` (`0x0e`). Treat `Set_Attribute_Single` (`0x10`), `Reset` (`0x05`), vendor-specific services, and tag writes as state-changing operations.

## Enumeration

Nmap's `enip-info` script sends a request-identity packet and can return the vendor ID, device type, product name, revision, serial number, and IP address.<sup>[[2]](#references)</sup>

```bash
nmap -n -sV --script enip-info -p 44818 <IP>
nmap -n -sU --script enip-info -p 44818 <IP>
pip3 install cpppo
python3 -m cpppo.server.enip.list_services [--udp] [--broadcast] --list-identity -a <IP>
```

The complete unicast UDP `ListIdentity` request is only the 24-byte encapsulation header below. This is useful where NSE is unavailable and also confirms whether UDP discovery is filtered differently from TCP.<sup>[[1]](#references)</sup>

```bash
IP=192.0.2.10
printf '630000000000000000000000000000000000000000000000' | xxd -r -p | \
  timeout 3 socat -T2 - UDP-DATAGRAM:$IP:44818 | xxd
```

For local-segment discovery and Rockwell/Allen-Bradley rack or tag inventory, `pycomm3` exposes both the encapsulation discovery calls and routed CIP operations. A route such as `<gateway-IP>/backplane/<slot>` reaches a controller behind an EtherNet/IP bridge. Opening `LogixDriver` uploads tag definitions by default, so do this slowly on production controllers; `external_access` immediately highlights tags exposed as `Read Only` or `Read/Write`.<sup>[[3]](#references)</sup>

```bash
pip3 install pycomm3
```

```python
from pycomm3 import CIPDriver, LogixDriver

for identity in CIPDriver.discover():
    print(identity)

target = "192.0.2.10/backplane/0"
with LogixDriver(target, init_program_tags=False) as plc:
    print(plc.info)
    for name, meta in plc.tags.items():
        print(name, meta["data_type_name"], meta["external_access"])
    print(plc.read("KnownSafeTag"))
    # plc.write("AuthorizedTestTag", 1)  # physical/process impact possible
```

### Packet capture

Capture both explicit and I/O planes. A connection setup on 44818/TCP followed by high-rate 2222/UDP flows is a quick way to associate an originator with adapters and multicast groups.<sup>[[1]](#references)</sup>

```bash
sudo tcpdump -ni eth0 -s0 -w enip.pcap \
  'tcp port 44818 or udp port 44818 or udp port 2222'
tshark -r enip.pcap -Y 'enip || cip' -T fields \
  -e frame.time -e ip.src -e ip.dst -e enip.command -e cip.service
```

## Attack primitives

### Exposed object and tag operations

Do not equate a successful `ListIdentity` response with write access. After fingerprinting the product and revision, test progressively: standard Identity/TCP-IP object reads, rack-slot identity, tag metadata, individual tag reads, and only then an explicitly authorized sacrificial write. Whether a service is accepted depends on the target object, controller mode, tag `external_access`, vendor implementation, and whether CIP Security or another access-control layer is actually enforced.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

### `Forward_Open` connection exhaustion

Connected CIP requires the target and intermediate routing devices to reserve resources. Research presented at ACSAC 2024 showed that repeatedly issuing `Forward_Open` with changing originator serial values could allocate many distinct connections inside one TCP stream. On the tested ControlLogix 1756-EN4T setup, roughly 32–128 outstanding connections were enough to prevent legitimate connections; this threshold and recovery behavior are implementation-dependent. This is a disruptive availability test, not routine enumeration.<sup>[[4]](#references)</sup>

Useful evidence during an authorized resilience test includes the number of accepted `Forward_Open` replies, unique originator/connection identifiers, `Forward_Close` balance, module resource/error counters, controller state, and the point at which a known-good client fails. Defensively, alert on bursts of connection opens, rapidly changing originator identities, or sustained opens without matching closes; restrict 44818/2222 reachability and validate that protected CIP transport and authentication are actually required rather than merely supported.<sup>[[4]](#references)</sup>

## Shodan

`port:44818 "product name"`

## References

- [1] [ODVA - EtherNet/IP Developers Guide](https://www.odva.org/wp-content/uploads/2020/05/PUB00213R0_EtherNetIP_Developers_Guide.pdf)
- [2] [Nmap NSE documentation - `enip-info`](https://nmap.org/nsedoc/scripts/enip-info.html)
- [3] [`pycomm3` documentation](https://pycomm3.readthedocs.io/en/latest/)
- [4] [Gebhard and Perouli - Attacks on EtherNet/IP and Migrations through CIP Security (ACSAC 2024)](https://www.acsac.org/2024/workshops/icss/Alex-Gebhard-Attacks-on-EtherNetIP-and-Migrations-through-CIP-Security.pdf)

{{#include ../banners/hacktricks-training.md}}
