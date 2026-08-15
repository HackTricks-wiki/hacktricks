# 69 - UDP TFTP

{{#include ../banners/hacktricks-training.md}}

## Basic Information

**Trivial File Transfer Protocol (TFTP)** is a small UDP-based file-transfer protocol. A client sends its initial read or write request to UDP port 69, after which the transfer uses negotiated transfer identifiers (UDP ports). TFTP provides neither user authentication nor directory listing, so server-side file permissions and path restrictions are its primary access controls.<sup>[[1]](#references)</sup>

TFTP is still commonly encountered on internal networks for bootstrapping devices—including VoIP handsets—and transferring firmware, ROM images, or configuration files. Those files can reveal credentials and network topology, so test both readable and writable paths within the authorized scope.<sup>[[1]](#references)</sup>

**Default Port:** 69/UDP

```
PORT   STATE SERVICE REASON
69/udp open  tftp    script-set
```

## Enumeration

Because TFTP does not provide directory listings, Nmap's `tftp-enum` script requests names from a list of common files. It is categorized as intrusive; use it only against systems you are authorized to test.<sup>[[2]](#references)</sup>

```bash
nmap -n -Pn -sU -p69 -sV --script tftp-enum <IP>
```

The NSE script also generates Cisco-style `A.B.C.X-confg` candidates from the target address. Supply a target-specific list built from observed boot filenames, device models and provisioning conventions instead of relying only on its generic list.<sup>[[2]](#references)</sup>

```bash
nmap -n -Pn -sU -p69 --script tftp-enum \
  --script-args tftp-enum.filelist=./tftp-files.txt <IP>
```

TFTP error packets distinguish conditions such as **file not found** (code 1), **access violation** (2), **file already exists** (6) and an **unknown transfer ID** (5). Treat the exact mapping as implementation-specific, but preserve responses while enumerating because a policy rejection is more informative than a timeout.<sup>[[1]](#references)</sup>

The server's first response comes from a new UDP source port, not necessarily 69. If a scanner finds port 69 but transfers time out, capture all UDP traffic to the host and check whether a firewall/NAT is dropping the negotiated flow.<sup>[[1]](#references)[[3]](#references)</sup>

```bash
sudo tcpdump -ni any "udp and host <IP>"
```

### Download/Upload

Use Metasploit's transfer utility or a TFTP client to test explicitly authorized reads and writes. Uploads succeed only when the server permits writing to the requested location.<sup>[[1]](#references)[[3]](#references)</sup>

```text
msfconsole -q
use auxiliary/admin/tftp/tftp_transfer_util
set ACTION Download
set RHOST <IP>
set REMOTE_FILENAME <remote-file>
run
```

A native client is useful for sending an exact remote pathname. Always use binary (`octet`) mode for firmware, archives and other non-text files.<sup>[[1]](#references)[[3]](#references)</sup>

```text
tftp <IP>
tftp> mode binary
tftp> verbose
tftp> get <remote-file> /tmp/downloaded-file
tftp> put /tmp/local-canary <unique-remote-name>
tftp> quit
```

Or automate exact filenames with `tftpy`:

```python
import tftpy
client = tftpy.TftpClient("192.0.2.10", 69)
client.download("filename in server", "/tmp/filename", timeout=5)
client.upload("remote-filename", "/local/path/file", timeout=5)
```

A failed new-file upload does **not** prove that the service is entirely read-only. For example, `tftpd-hpa` normally permits writes only to files that already exist and are publicly writable; its `--create` option enables creation. Test a unique new name first and, only with the system owner's coordination, an existing disposable canary. TFTP has no delete request, so plan cleanup separately.<sup>[[1]](#references)[[5]](#references)</sup>

If writable provisioning, boot or firmware files are found, determine which client consumes each file and whether it verifies authenticity before modifying anything. For protocol-specific pivots, see [Cisco SNMP configuration copy abuse](pentesting-snmp/cisco-snmp.md), [SCCM PXE boot artifacts](../windows-hardening/active-directory-methodology/sccm-management-point-relay-sql-policy-secrets.md) and [bootloader testing](../hardware-physical-access/firmware-analysis/bootloader-testing.md).

### Path traversal and root confinement

Do not assume a configured TFTP root is a security boundary. Test canonicalization with a harmless, known file outside the intended root using OS-appropriate separators (for example `../` versus `..\`) and both relative and absolute names. The 2026 Erlang/OTP advisory is a recent example: its `root_dir` handling concatenated attacker-controlled filenames without preventing `..` components, allowing unauthenticated reads or writes with the TFTP process privileges.<sup>[[4]](#references)</sup>

```text
tftp <IP>
tftp> mode binary
tftp> get ../../etc/hostname /tmp/tftp-hostname
```

A secure implementation should canonicalize the requested path and reject any result outside its export. Server-side containment such as `tftpd-hpa --secure` (chroot), a dedicated low-privilege account, read-only exports and network allowlisting limit the impact if validation fails.<sup>[[4]](#references)[[5]](#references)</sup>

### Shodan

- `port:69`



## References

- [1] [RFC 1350 - The TFTP Protocol (Revision 2)](https://www.rfc-editor.org/rfc/rfc1350.html)
- [2] [Nmap NSE documentation - tftp-enum](https://nmap.org/nsedoc/scripts/tftp-enum.html)
- [3] [Rapid7 Metasploit - TFTP file transfer utility](https://www.rapid7.com/db/modules/auxiliary/admin/tftp/tftp_transfer_util/)
- [4] [Erlang/OTP security advisory - TFTP Path Traversal](https://github.com/erlang/otp/security/advisories/GHSA-hmrc-prh3-rpvp)
- [5] [Debian manpages - tftpd-hpa](https://manpages.debian.org/trixie/tftpd-hpa/in.tftpd.8.en.html)
{{#include ../banners/hacktricks-training.md}}
