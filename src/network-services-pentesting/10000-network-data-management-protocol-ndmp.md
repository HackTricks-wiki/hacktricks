# 10000/tcp - Network Data Management Protocol (NDMP)

{{#include ../banners/hacktricks-training.md}}

## Protocol information

The Network Data Management Protocol (NDMP) coordinates backup and recovery between network-attached storage (NAS) and backup systems. Its architecture separates control from the data path, allowing backup data to move directly between an NDMP data server and a tape or backup data server instead of passing through the application that controls the job. This avoids turning the controlling backup application into the data-transfer bottleneck and reduces the processing and network load placed on it.<sup>[[4]](#references)</sup> IANA registers the service name `ndmp` on port 10000 for both TCP and UDP; the Nmap discovery scripts below target the TCP service.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

**Default port:** 10000/TCP

```text
PORT      STATE SERVICE REASON  VERSION
10000/tcp open  ndmp    syn-ack Symantec/Veritas Backup Exec ndmp
```

## Enumeration

Nmap's `ndmp-version` and `ndmp-fs-info` scripts are in the `default`, `discovery`, and `safe` categories. They can identify the NDMP version and, when the service permits it, list remote file systems.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

```bash
nmap -n -sV --script "ndmp-fs-info or ndmp-version" -p 10000 <IP>
```

## Shodan

`port:10000 ndmp`

## References

- [1] [IANA - Service Name and Transport Protocol Port Number Registry](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=ndmp)
- [2] [Nmap NSE documentation - `ndmp-version`](https://nmap.org/nsedoc/scripts/ndmp-version.html)
- [3] [Nmap NSE documentation - `ndmp-fs-info`](https://nmap.org/nsedoc/scripts/ndmp-fs-info.html)
- [4] [SNIA - Network Data Management Protocol White Paper](https://www.snia.org/sites/default/files/technical-work/whitepapers/SNIA-NDMP-White-Paper.pdf)

{{#include ../banners/hacktricks-training.md}}
