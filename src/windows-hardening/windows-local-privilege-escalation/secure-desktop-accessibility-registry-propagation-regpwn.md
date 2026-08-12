# Secure Desktop Accessibility Registry Propagation LPE (RegPwn)

{{#include ../../banners/hacktricks-training.md}}

## Overview

Windows Accessibility features user configuration को HKCU के अंतर्गत persist करती हैं और उसे per-session HKLM locations में propagate करती हैं। **Secure Desktop** transition (lock screen या UAC prompt) के दौरान, **SYSTEM** components इन values को दोबारा copy करते हैं। यदि **per-session HKLM key user द्वारा writable** है, तो यह एक privileged write choke point बन जाती है, जिसे **registry symbolic links** से redirect किया जा सकता है और इससे **arbitrary SYSTEM registry write** प्राप्त होता है।<sup>[[1]](#references)</sup>

RegPwn technique इस propagation chain का abuse करती है और `osk.exe` द्वारा उपयोग की जाने वाली file पर **opportunistic lock (oplock)** के माध्यम से एक छोटी race window को stabilize करती है।<sup>[[1]](#references)</sup>

## Registry Propagation Chain (Accessibility -> Secure Desktop)

Example feature: **On-Screen Keyboard** (`osk`). Relevant locations ये हैं:

- **System-wide feature list**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`
- **Per-user configuration (user-writable)**:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
- **Per-session HKLM config (created by `winlogon.exe`, user-writable)**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- **Secure desktop/default user hive (SYSTEM context)**:
- `HKU\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`

Secure desktop transition के दौरान propagation (सरलीकृत रूप में):

1. **User `atbroker.exe`**, `HKCU\...\ATConfig\osk` को `HKLM\...\Session<session id>\ATConfig\osk` में copy करता है।
2. **SYSTEM `atbroker.exe`**, `HKLM\...\Session<session id>\ATConfig\osk` को `HKU\.DEFAULT\...\ATConfig\osk` में copy करता है।
3. **SYSTEM `osk.exe`**, `HKU\.DEFAULT\...\ATConfig\osk` को वापस `HKLM\...\Session<session id>\ATConfig\osk` में copy करता है।

यदि session HKLM subtree user द्वारा writable है, तो step 2/3 ऐसी location के माध्यम से SYSTEM write प्रदान करते हैं जिसे user replace कर सकता है।<sup>[[1]](#references)</sup>

## Primitive: Arbitrary SYSTEM Registry Write via Registry Links

User-writable per-session key को एक **registry symbolic link** से replace करें, जो attacker द्वारा चुनी गई destination की ओर point करता हो। जब SYSTEM copy होती है, तो वह link को follow करती है और attacker-controlled values को arbitrary target key में write करती है।

मुख्य विचार:

- Victim write target (user-writable):
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- Attacker उस key को किसी अन्य key की ओर point करने वाले **registry link** से replace करता है।
- SYSTEM copy perform करता है और attacker द्वारा चुनी गई key में SYSTEM permissions के साथ write करता है।

इससे **arbitrary SYSTEM registry write** primitive प्राप्त होती है।<sup>[[1]](#references)</sup>

## Winning the Race Window with Oplocks

**SYSTEM `osk.exe`** के start होने और per-session key में write करने के बीच एक छोटी timing window होती है। इसे reliable बनाने के लिए exploit निम्न पर एक **oplock** लगाता है:
```
C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml
```
जब oplock trigger होता है, attacker per-session HKLM key को registry link से बदल देता है, SYSTEM write को पूरा होने देता है, फिर link हटा देता है।<sup>[[1]](#references)</sup>

## Example Exploitation Flow (High Level)

1. Access token से वर्तमान **session ID** प्राप्त करें।
2. एक hidden `osk.exe` instance शुरू करें और थोड़ी देर sleep करें (यह सुनिश्चित करने के लिए कि oplock trigger होगा)।
3. Attacker-controlled values को यहां write करें:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
4. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` पर एक **oplock** सेट करें।
5. **Secure Desktop** (`LockWorkstation()`) को trigger करें, जिससे SYSTEM के रूप में `atbroker.exe` / `osk.exe` शुरू हों।
6. Oplock trigger होने पर `HKLM\...\Session<session id>\ATConfig\osk` को किसी arbitrary target की ओर संकेत करने वाले **registry link** से बदल दें।
7. SYSTEM copy पूरी होने के लिए थोड़ी देर प्रतीक्षा करें, फिर link हटा दें।<sup>[[1]](#references)</sup>

## Primitive को SYSTEM Execution में बदलना

एक सीधा chain यह है कि **service configuration** value (जैसे, `ImagePath`) को overwrite करें और फिर service शुरू करें। RegPwn PoC **`msiserver`** के `ImagePath` को overwrite करता है और **MSI COM object** को instantiate करके इसे trigger करता है, जिसके परिणामस्वरूप **SYSTEM** code execution होता है।<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

## Related

अन्य Secure Desktop / UIAccess behaviors के लिए देखें:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## References

- [1] [RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [2] [RegPwn PoC](https://github.com/mdsecactivebreach/RegPwn)
{{#include ../../banners/hacktricks-training.md}}
