# Impacket

{{#include ../banners/hacktricks-training.md}}

## Overview

**Impacket** is a Python toolkit for crafting and parsing network packets with an object-oriented API that lets you stack protocol layers and fully control fields. Beyond raw packet work, it ships complete client-side implementations for **SMB1/2/3** and **MSRPC (DCE/RPC v5)** over **TCP**, **SMB/TCP**, **SMB/NetBIOS**, and **HTTP**, plus support for **LDAP** and **TDS (MSSQL)**. Operators can automate complex Windows/AD interactions (SMB file ops, RPC calls, directory queries) without GUI tools.

## Protocol and authentication coverage

- **Link/network/transport:** Ethernet, Linux “Cooked” capture, ARP, IPv4/IPv6, IP, TCP, UDP, ICMP, IGMP.
- **Windows-focused protocols:** NMB, SMB1/SMB2/SMB3, MSRPC v5 over multiple transports, LDAP, MSSQL TDS.
- **MSRPC interfaces implemented (partial list):** EPM, DTYPES, LSAD, LSAT, NRPC, RRP, SAMR, SRVS, WKST, SCMR, BKRP, DHCPM, EVEN6, MGMT, SASEC, TSCH, DCOM, WMI, OXABREF, NSPI, OXNSPI.
- **Authentication:** Plain/NTLM/Kerberos using **passwords**, **NT/LM hashes**, **Kerberos tickets**, or **Kerberos keys**, enabling hash/ticket/key-based auth against SMB/MSRPC/LDAP/Kerberos-aware services.

## Typical offensive use cases

- Build custom clients/fuzzers by composing protocol layers and manipulating individual fields.
- Automate **SMB** operations and **RPC** calls directly from Python (e.g., SCMR/ATSVC for service or scheduled task creation, SAMR/LSA for account/secret interaction).
- Script **Kerberos** and **NTLM** auth flows with non-cleartext material (hashes/tickets/keys) to test credential re-use and relay-like scenarios.
- Reuse the shipped `examples/` scripts as ready-made tools or as templates for bespoke workflows.

## Installation (pipx recommended)

- Install latest stable release (v0.13.0):

```bash
python3 -m pipx install impacket
```

- Install development version from a checked-out source tree (v0.14.0-dev/master):

```bash
python3 -m pipx install .
```

`pipx` is recommended for isolated, system-wide installs without polluting the global Python site-packages.

## Docker usage

```bash
# Build image
$ docker build -t "impacket:latest" .

# Run container interactively and clean up on exit
$ docker run -it --rm "impacket:latest"
```

## References

- [Impacket repository](https://github.com/durck/impacket)

{{#include ../banners/hacktricks-training.md}}
