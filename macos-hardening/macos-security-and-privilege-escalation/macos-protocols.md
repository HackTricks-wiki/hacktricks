# macOS Network Services & Protocols

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Remote Access Services

These are the common macOS services to access them remotely.\
You can enable/disable these services in `System Settings` --> `Sharing`

* **VNC**, known as “Screen Sharing” (tcp:5900)
* **SSH**, called “Remote Login” (tcp:22)
* **Apple Remote Desktop** (ARD), or “Remote Management” (tcp:3283, tcp:5900)
* **AppleEvent**, known as “Remote Apple Event” (tcp:3031)

Check if any is enabled running:

```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\*.88|\*.445|\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```

### Pentesting ARD

(This part was [**taken from this blog post**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html))

It's essentially a bastardized [VNC](https://en.wikipedia.org/wiki/Virtual\_Network\_Computing) with some **extra macOS specific features**.\
However, the **Screen Sharing option** is just a **basic VNC** server. There is also an advanced ARD or Remote Management option to **set a control screen password** which will make ARD backwards **compatible for VNC clients**. However there is a weakness to this authentication method that **limits** this **password** to an **8 character auth buffer**, making it very easy to **brute force** with a tool like [Hydra](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) or [GoRedShell](https://github.com/ahhh/GoRedShell/) (there are also **no rate limits by default**).\
You can identify **vulnerable instances of Screen Sharing** or Remote Management with **nmap**, using the script `vnc-info`, and if the service supports `VNC Authentication (2)` then they are likely **vulnerable to brute force**. The service will truncate all passwords sent on the wire down to 8 characters, such that if you set the VNC auth to "password", both "passwords" and "password123" will authenticate.

<figure><img src="../../.gitbook/assets/image (9).png" alt=""><figcaption></figcaption></figure>

If you want to enable it to escalate privileges (accept TCC prompts), access with a GUI or spy the user, it's possible to enable it with:

{% code overflow="wrap" %}
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
{% endcode %}

You can switch between **observation** mode, **shared control**, and **full control**, going from spying on a user to taking over their desktop at the click of a button. Moreover, If you do get access to an ARD session, that session will remain open until the session is terminated, even if the user's password is changed during the session.

You can also **send unix commands directly** over ARD and you can specify the root user to execute things as root if your an administrative user. You can even use this unix command method to schedule remote tasks to run at a specific time, however this occurs as a network connection at the specified time (vs being stored and executing on the target server). Finally, remote Spotlight is one of my favorite features. It's really neat because you can run a low impact, indexed search quickly and remotely. This is gold for searching for sensitive files because it's quick, lets you run searches concurrently across multiple machines, and won't spike the CPU.

## Bonjour Protocol

**Bonjour** is an Apple-designed technology that enables computers and **devices located on the same network to learn about services offered** by other computers and devices. It is designed such that any Bonjour-aware device can be plugged into a TCP/IP network and it will **pick an IP address** and make other computers on that network **aware of the services it offers**. Bonjour is sometimes referred to as Rendezvous, **Zero Configuration**, or Zeroconf.\
Zero Configuration Networking, such as Bonjour provides:

* Must be able to **obtain an IP Address** (even without a DHCP server)
* Must be able to do **name-to-address translation** (even without a DNS server)
* Must be able to **discover services on the network**

The device will get an **IP address in the range 169.254/16** and will check if any other device is using that IP address. If not, it will keep the IP address. Macs keeps an entry in their routing table for this subnet: `netstat -rn | grep 169`

For DNS the **Multicast DNS (mDNS) protocol is used**. [**mDNS** **services** listen in port **5353/UDP**](../../network-services-pentesting/5353-udp-multicast-dns-mdns.md), use **regular DNS queries** and use the **multicast address 224.0.0.251** instead of sending the request just to an IP address. Any machine listening these request will respond, usually to a multicast address, so all the devices can update their tables.\
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

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
