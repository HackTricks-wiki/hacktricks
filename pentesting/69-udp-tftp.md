# 69/UDP TFTP/Bittorrent-tracker

## Basic Information

**TFTP** uses UDP port 69 and **requires no authentication**—clients read from, and write to servers using the datagram format outlined in RFC 1350. Due to deficiencies within the protocol \(namely lack of authentication and no transport security\), it is uncommon to find servers on the public Internet. Within large internal networks, however, TFTP is used to serve configuration files and ROM images to VoIP handsets and other devices.

**TODO**: Provide information about what is a Bittorrent-tracker \(Shodan identifies this port with that name\). PLEASE, LET ME KNOW IF YOU HAVE SOME INFORMATION ABOUT THIS IN THE [**HackTricks telegram group**](https://t.me/peass) ****\(or in a github issue in [PEASS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)\).

**Default Port:** 69/UDP

```text
PORT   STATE SERVICE REASON
69/udp open  tftp    script-set
```

## Enumeration

TFTP doesn't provide directory listing so the script `tftp-enum` from `nmap` will try to brute-force default paths.

```bash
nmap -n -Pn -sU -p69 -sV --script tftp-enum <IP>
```

### Download/Upload

You can use Metasploit or Python to check if you can download/upload files:

```bash
msf5> auxiliary/admin/tftp/tftp_transfer_util
```

```bash
import tftpy
client = tftpy.TftpClient(<ip>, <port>)
client.download("filename in server", "/tmp/filename", timeout=5)
client.upload("filename to upload", "/local/path/file", timeout=5)
```

### Shodan

* `port:69`

