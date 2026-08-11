# macOS Network Services & Protocols

{{#include ../../banners/hacktricks-training.md}}

## Remote Access Services

These are common services for remote access to macOS systems.<sup>[[11]](#references)</sup>\
You can enable/disable these services in `System Settings` --> `Sharing`<sup>[[1]](#references)</sup>

- **VNC**, known as “Screen Sharing” (tcp:5900)
- **SSH**, called “Remote Login” (tcp:22)
- **Apple Remote Desktop** (ARD), or “Remote Management” (tcp:3283, tcp:5900)
- **AppleEvent**, known as “Remote Apple Event” (tcp:3031)

Check if any is enabled running:

```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\\*.88|\\*.445|\\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```

### Enumerating sharing configuration locally

When you already have local code execution on a Mac, **check the configured state**, not just the listening sockets. `systemsetup` and `launchctl` usually tell you whether the service is administratively enabled, while `kickstart` and `system_profiler` help confirm the effective ARD/Sharing configuration:

```bash
system_profiler SPSharingDataType
sudo /usr/sbin/systemsetup -getremotelogin
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status
sudo launchctl print-disabled system | egrep 'com.apple.screensharing|com.apple.AEServer|ssh'
```

### Pentesting ARD

Apple Remote Desktop (ARD) is an enhanced version of [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) tailored for macOS, offering additional features. A notable vulnerability in ARD is its authentication method for the control screen password, which only uses the first 8 characters of the password, making it prone to [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) with tools like Hydra or [GoRedShell](https://github.com/ahhh/GoRedShell/), as there are no default rate limits.<sup>[[2]](#references)</sup>

Vulnerable instances can be identified using **nmap**'s `vnc-info` script. Services supporting `VNC Authentication (2)` are especially susceptible to brute force attacks due to the 8-character password truncation.

To enable ARD for various administrative tasks like privilege escalation, GUI access, or user monitoring, use the following command:

```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```

ARD provides versatile control levels, including observation, shared control, and full control, with sessions persisting even after user password changes. It allows sending Unix commands directly, executing them as root for administrative users. Task scheduling and Remote Spotlight search are notable features, facilitating remote, low-impact searches for sensitive files across multiple machines.

From an operator perspective, **Monterey 12.1+ changed remote-enablement workflows** in managed fleets. If you already control the victim's MDM, Apple's `EnableRemoteDesktop` command is often the cleanest way to activate remote desktop functionality on newer systems. If you already have a foothold on the host, `kickstart` is still useful to inspect or reconfigure ARD privileges from the command line.

#### Apple Screen Sharing (RFB 003.889 / security type 36) pre-auth file-copy abuse

Recent `screensharingd` research showed that Apple Screen Sharing is not always just classic VNC auth: newer builds speak **RFB `003.889`** and advertise **security type `36`**, where **SRP** authenticates first and **ChaCha20-Poly1305** is only installed after `ccsrp_server_verify_session` succeeds. The public write-up reports the bug as fixed in **macOS Tahoe 26.6** (**July 27, 2026**).<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup>

A useful pattern to remember is the **stale-status parser bypass**: after a successful 4-byte length read, every oversized/error branch must return a fresh error. On affected builds, a big-endian SRP frame length **`>= 32768`** makes the rejection path reuse the previous `NetBufferRead` success (`0`), so the caller sets the session as authenticated even though no password proof ran and no transport crypto was installed. Because unread bytes stay in the shared socket buffer, an attacker can **pipeline malformed SRP data and post-auth RFB messages in the same TCP burst** and get them parsed as **cleartext authenticated traffic**.<sup>[[8]](#references)</sup>

After the bypass, Apple's proprietary **file-copy** message **`0x22`** becomes a **root file read/write primitive** because `screensharingd` runs as root:<sup>[[8]](#references)</sup>

```text
[u8 0x22][u8 sub][be32 L]
[be16 ver][be16 kind][be32 sid][be32 arg]
[L-12 bytes payload]
```

- `kind=1` / `StartFileSend`: arbitrary file read
- `kind=2` / `StartFileReceive`: arbitrary file write
- Different `sid` values let you pipeline several transactions in one connection
- In `kind=101` (`NewItem`), set byte `14` / `arg[0]` to `0x01` for a regular file, payload offset `+42` to a **non-zero** big-endian file size, and payload offset `+0x5a` to the desired Unix mode (`0600` if targeting a crontab)

Interesting post-write pivots on writable paths include **`/etc/sudoers.d/`**, **`/etc/zshenv`**, **`/Library/LaunchDaemons/`**, and **`/var/root/.ssh/authorized_keys`**. **SIP does not stop the auth bypass or root file read**, but it does block some write targets such as **`/var/at`**, so cron-based execution only works with SIP disabled. On default SIP-enabled hosts, think in terms of **"root file write into privileged auto-consumed files"** rather than immediate code execution.<sup>[[8]](#references)</sup>

Another SRP pitfall from the same research: servers must validate **`A mod N != 0`** (per RFC 5054), not just `A > 0`. Accepting **`A = N`** can force the shared secret to zero and undermine password verification.<sup>[[8]](#references)</sup><sup>[[10]](#references)</sup>

**Detection ideas**

- Security type `36` sessions where the first SRP frame length is **`>= 32768`**
- Sessions that start processing cleartext **`0x22`** file-copy traffic before any successful SRP proof / cipher install
- Repeated short-lived retries against **TCP/5900** plus multiple file-copy `sid` values in one burst
- Unexpected creation of **`/etc/zshenv`**, **`/etc/sudoers.d/*`**, **`/Library/LaunchDaemons/*.plist`**, or **`/var/root/.ssh/authorized_keys`** after Screen Sharing exposure

### Pentesting Remote Apple Events (RAE / EPPC)

Apple calls this feature **Remote Application Scripting** in modern System Settings. Under the hood it exposes the **Apple Event Manager** remotely over **EPPC** on **TCP/3031** via the `com.apple.AEServer` service. Palo Alto Unit 42 highlighted it again as a practical **macOS lateral movement** primitive because valid credentials plus an enabled RAE service allow an operator to drive scriptable applications on a remote Mac.<sup>[[6]](#references)</sup>

Useful checks:

```bash
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo launchctl print-disabled system | grep AEServer
lsof -nP -iTCP:3031 -sTCP:LISTEN
```

If you already have admin/root on the target and want to enable it:

```bash
sudo /usr/sbin/systemsetup -setremoteappleevents on
```

Basic connectivity test from another Mac:

```bash
osascript -e 'tell application "Finder" of machine "eppc://user:pass@192.0.2.10" to get name of startup disk'
```

In practice, the abuse case is not limited to Finder. Any **scriptable application** that accepts the required Apple events becomes a remote attack surface, which makes RAE especially interesting after credential theft on internal macOS networks.

#### Recent Screen-Sharing / ARD vulnerabilities (2023-2025)

| Year | CVE | Component | Impact | Fixed in |
|------|-----|-----------|--------|----------|
|2023|CVE-2023-42940|Screen Sharing|Incorrect session rendering could cause the *wrong* desktop or window to be transmitted, resulting in leakage of sensitive information|macOS Sonoma 14.2.1 (Dec 2023) <sup>[[3]](#references)</sup>|
|2024|CVE-2024-44248|Screen Sharing Server|A user with screen sharing access may be able to view **another user's screen** because of a state-management issue|macOS Ventura 13.7.2 / Sonoma 14.7.2 / Sequoia 15.1 (Oct-Dec 2024) <sup>[[7]](#references)</sup>|

**Hardening tips**

* Disable *Screen Sharing*/*Remote Management* when not strictly required.
* Keep macOS fully patched (Apple generally ships security fixes for the last three major releases).
* Use a **Strong Password** *and* enforce the *“VNC viewers may control screen with password”* option **disabled** when possible.
* Put the service behind a VPN instead of exposing TCP 5900/3283 to the Internet.
* Add an Application Firewall rule to limit `ARDAgent` to the local subnet:

  ```bash
  sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
  sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
  ```

---

## Bonjour Protocol

Bonjour, an Apple-designed technology, allows **devices on the same network to detect each other's offered services**. Known also as Rendezvous, **Zero Configuration**, or Zeroconf, it enables a device to join a TCP/IP network, **automatically choose an IP address**, and broadcast its services to other network devices.

Zero Configuration Networking, provided by Bonjour, ensures that devices can:

- **Automatically obtain an IP Address** even in the absence of a DHCP server.
- Perform **name-to-address translation** without requiring a DNS server.
- **Discover services** available on the network.

Devices using Bonjour will assign themselves an **IP address from the 169.254/16 range** and verify its uniqueness on the network. Macs maintain a routing table entry for this subnet, verifiable via `netstat -rn | grep 169`.

For DNS, Bonjour utilizes the **Multicast DNS (mDNS) protocol**. mDNS operates over **port 5353/UDP**, employing **standard DNS queries** but targeting the **multicast address 224.0.0.251**. This approach ensures that all listening devices on the network can receive and respond to the queries, facilitating the update of their records.

Upon joining the network, each device self-selects a name, typically ending in **.local**, which may be derived from the hostname or randomly generated.

Service discovery within the network is facilitated by **DNS Service Discovery (DNS-SD)**. Leveraging the format of DNS SRV records, DNS-SD uses **DNS PTR records** to enable the listing of multiple services. A client seeking a specific service will request a PTR record for `<Service>.<Domain>`, receiving in return a list of PTR records formatted as `<Instance>.<Service>.<Domain>` if the service is available from multiple hosts.

The `dns-sd` utility can be employed for **discovering and advertising network services**. Here are some examples of its usage:

### Searching for SSH Services

To search for SSH services on the network, the following command is used:

```bash
dns-sd -B _ssh._tcp
```

This command initiates browsing for \_ssh.\_tcp services and outputs details such as timestamp, flags, interface, domain, service type, and instance name.

### Advertising an HTTP Service

To advertise an HTTP service, you can use:

```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```

This command registers an HTTP service named "Index" on port 80 with a path of `/index.html`.

To then search for HTTP services on the network:

```bash
dns-sd -B _http._tcp
```

When a service starts, it announces its availability to all devices on the subnet by multicasting its presence. Devices interested in these services don't need to send requests but simply listen for these announcements.

For a more user-friendly interface, the **Discovery - DNS-SD Browser** app available on the Apple App Store can visualize the services offered on your local network.

Alternatively, custom scripts can be written to browse and discover services using the `python-zeroconf` library. The [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) script demonstrates creating a service browser for `_http._tcp.local.` services, printing added or removed services:

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

### macOS-specific Bonjour hunting

On macOS networks, Bonjour is frequently the easiest way to find **remote administration surfaces** without touching the target directly. Apple Remote Desktop itself can discover clients through Bonjour, so the same discovery data is useful to an attacker.

```bash
# Enumerate every advertised service type first
dns-sd -B _services._dns-sd._udp local

# Then look for common macOS admin surfaces
dns-sd -B _rfb._tcp local      # Screen Sharing / VNC
dns-sd -B _ssh._tcp local      # Remote Login
dns-sd -B _eppc._tcp local     # Remote Apple Events / EPPC

# Resolve a specific instance to hostname, port and TXT data
dns-sd -L "<Instance>" _rfb._tcp local
dns-sd -L "<Instance>" _eppc._tcp local
```

For broader **mDNS spoofing, impersonation, and cross-subnet discovery** techniques, check the dedicated page:

{{#ref}}
../../network-services-pentesting/5353-udp-multicast-dns-mdns.md
{{#endref}}

### Enumerating Bonjour over the network

* **Nmap NSE** – discover services advertised by a single host:

  ```bash
  nmap -sU -p 5353 --script=dns-service-discovery <target>
  ```

  The `dns-service-discovery` script sends a `_services._dns-sd._udp.local` query and then enumerates each advertised service type. 

* **mdns_recon** – Python tool that scans entire ranges looking for *misconfigured* mDNS responders that answer unicast queries (useful to find devices reachable across subnets/WAN):

  ```bash
  git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
  python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
  ```

  This will return hosts exposing SSH via Bonjour outside the local link. 

### Security considerations & recent vulnerabilities (2024-2025)

| Year | CVE | Severity | Issue | Patched in |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Medium|A logic error in *mDNSResponder* allowed a crafted packet to trigger a **denial-of-service**|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (Sep 2024) <sup>[[4]](#references)</sup>|
|2025|CVE-2025-31222|High|A correctness issue in *mDNSResponder* could be abused for **local privilege escalation**|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (May 2025) <sup>[[5]](#references)</sup>|

**Mitigation guidance**

1. Restrict UDP 5353 to *link-local* scope – block or rate-limit it on wireless controllers, routers, and host-based firewalls.
2. Disable Bonjour entirely on systems that do not require service discovery:

   ```bash
   sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
   ```
3. For environments where Bonjour is required internally but must never cross network boundaries, use *AirPlay Receiver* profile restrictions (MDM) or an mDNS proxy.
4. Enable **System Integrity Protection (SIP)** and keep macOS up to date – both vulnerabilities above were patched quickly but relied on SIP being enabled for full protection.

### Disabling Bonjour

If there are concerns about security or other reasons to disable Bonjour, it can be turned off using the following command:

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```

## References

- [1] [The Mac Hacker's Handbook](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [LockBoxx - macOS Red Teaming 206: ARD (Apple Remote Desktop Protocol)](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [3] [NVD – CVE-2023-42940](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [4] [NVD – CVE-2024-44183](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)
- [5] [NVD – CVE-2025-31222](https://nvd.nist.gov/vuln/detail/CVE-2025-31222)
- [6] [Palo Alto Unit 42 - Lateral Movement on macOS: Unique and Popular Techniques and In-the-Wild Examples](https://unit42.paloaltonetworks.com/unique-popular-techniques-lateral-movement-macos/)
- [7] [Apple Support - About the security content of macOS Sonoma 14.7.2](https://support.apple.com/en-us/121840)
- [8] [Apple Screen Sharing Pre-Auth RCE](https://warez.sl0p.foo/apple-screensharing-rce/)
- [9] [Apple Support - About the security content of macOS Tahoe 26.6](https://support.apple.com/en-us/128067)
- [10] [RFC 5054 - Using the Secure Remote Password (SRP) Protocol for TLS Authentication](https://www.rfc-editor.org/rfc/rfc5054)
- [11] [The Art of Mac Malware, Volume I: Analysis - Patrick Wardle](https://taomm.org/)

{{#include ../../banners/hacktricks-training.md}}
