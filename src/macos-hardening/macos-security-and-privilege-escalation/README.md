# macOS Security & Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Basic macOS

If you are not familiar with macOS, start with the basics and the incident-response, malware-analysis, and command references listed below.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup><sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

- Special macOS **files & permissions:**


{{#ref}}
macos-files-folders-and-binaries/
{{#endref}}

- Common macOS **users**


{{#ref}}
macos-users.md
{{#endref}}

- **AppleFS**


{{#ref}}
macos-applefs.md
{{#endref}}

- The **architecture** of the **kernel**


{{#ref}}
mac-os-architecture/
{{#endref}}

- Common macOS **network services and protocols**


{{#ref}}
macos-protocols.md
{{#endref}}

- **Opensource** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
  - To download a `tar.gz` change a URL such as [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) to [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### macOS MDM

In corporate environments, macOS systems are often managed with mobile device management (MDM). From an attacker's perspective, it is therefore useful to understand how MDM works:


{{#ref}}
../macos-red-teaming/macos-mdm/
{{#endref}}

### macOS - Inspecting, Debugging And Fuzzing


{{#ref}}
macos-apps-inspecting-debugging-and-fuzzing/
{{#endref}}

## macOS Security Protections


{{#ref}}
macos-security-protections/
{{#endref}}

## Attack Surface

### File Permissions

If a **process running as root writes** a file that can be controlled by a user, the user could abuse this to **escalate privileges**.\
This could occur in the following situations:

- File used was already created by a user (owned by the user)
- File used is writable by the user because of a group
- File used is inside a directory owned by the user (the user could create the file)
- File used is inside a directory owned by root but user has write access over it because of a group (the user could create the file)

Being able to **create a file** that is going to be **used by root**, allows a user to **take advantage of its content** or even create **symlinks/hardlinks** to point it to another place.

For this kind of vulnerabilities don't forget to **check vulnerable `.pkg` installers**:


{{#ref}}
macos-files-folders-and-binaries/macos-installers-abuse.md
{{#endref}}

### File Extension & URL scheme app handlers

Unexpected applications registered for file extensions or URL schemes may expose useful attack surfaces or handler-hijacking opportunities.


{{#ref}}
macos-file-extension-apps.md
{{#endref}}

## macOS TCC / SIP Privilege Escalation

In macOS **applications and binaries can have permissions** to access folders or settings that make them more privileged than others.

Therefore, an attacker that wants to successfully compromise a macOS machine will need to **escalate its TCC privileges** (or even **bypass SIP**, depending on his needs).

These privileges are usually granted through code-signing **entitlements** or through user-approved access recorded in the **TCC databases**. Some privileges may also be inherited from a parent process, depending on the protection and execution chain.<sup>[[5]](#references)</sup>

Follow these links for ways to [**escalate TCC privileges**](macos-security-protections/macos-tcc/index.html#tcc-privesc-and-bypasses), [**bypass TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/index.html), and understand how [**SIP has been bypassed**](macos-security-protections/macos-sip.md#sip-bypasses) in the past.

## macOS Traditional Privilege Escalation

From a red-team perspective, escalation to root is another important objective. The following page covers common approaches:


{{#ref}}
macos-privilege-escalation.md
{{#endref}}

## macOS Compliance

- [https://github.com/usnistgov/macos_security](https://github.com/usnistgov/macos_security)

## References

- [1] [OS X Incident Response: Scripting and Analysis](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [The Art of Mac Malware, Vol. 1 - Analysis](https://taomm.org/)
- [3] [NicolasGrimonpont/Cheatsheet - macOS/Linux/Windows commands and security tools](https://github.com/NicolasGrimonpont/Cheatsheet)
- [4] [SentinelOne - macOS Security Resource](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
- [5] [2022 - macOS local security: escaping the sandbox and bypassing TCC (YouTube)](https://www.youtube.com/watch?v=vMGiplQtjTY)

{{#include ../../banners/hacktricks-training.md}}
