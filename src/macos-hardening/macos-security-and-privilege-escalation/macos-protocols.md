# macOS Network Services & Protocols

{{#include ../../banners/hacktricks-training.md}}

## Remote Access Services

These are the common macOS services to access them remotely.\
You can enable/disable these services in `System Settings` --> `Sharing`

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

### Pentesting ARD

Apple Remote Desktop (ARD) is an enhanced version of [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) tailored for macOS, offering additional features. A notable vulnerability in ARD is its authentication method for the control screen password, which only uses the first 8 characters of the password, making it prone to [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) with tools like Hydra or [GoRedShell](https://github.com/ahhh/GoRedShell/), as there are no default rate limits.

Vulnerable instances can be identified using **nmap**'s `vnc-info` script. Services supporting `VNC Authentication (2)` are especially susceptible to brute force attacks due to the 8-character password truncation.

To enable ARD for various administrative tasks like privilege escalation, GUI access, or user monitoring, use the following command:

```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```

ARD provides versatile control levels, including observation, shared control, and full control, with sessions persisting even after user password changes. It allows sending Unix commands directly, executing them as root for administrative users. Task scheduling and Remote Spotlight search are notable features, facilitating remote, low-impact searches for sensitive files across multiple machines.

#### Recent Screen-Sharing / ARD vulnerabilities (2023-2025)

| Year | CVE | Component | Impact | Fixed in |
|------|-----|-----------|--------|----------|
|2023|CVE-2023-42940|Screen Sharing|Incorrect session rendering could cause the *wrong* desktop or window to be transmitted, resulting in leakage of sensitive information|macOS Sonoma 14.2.1 (Dec 2023) |
|2024|CVE-2024-23296|launchservicesd / login|Kernel memory-protection bypass that can be chained after a successful remote login (actively exploited in the wild)|macOS Ventura 13.6.4 / Sonoma 14.4 (Mar 2024) |

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
|2024|CVE-2024-44183|Medium|A logic error in *mDNSResponder* allowed a crafted packet to trigger a **denial-of-service**|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (Sep 2024) |
|2025|CVE-2025-31222|High|A correctness issue in *mDNSResponder* could be abused for **local privilege escalation**|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (May 2025) |

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

- [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [**NVD – CVE-2023-42940**](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [**NVD – CVE-2024-44183**](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)

{{#include ../../banners/hacktricks-training.md}}
