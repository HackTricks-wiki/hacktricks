# Secure Desktop Accessibility Registry Propagation LPE (RegPwn)

{{#include ../../banners/hacktricks-training.md}}

## अवलोकन

Windows Accessibility फीचर्स उपयोगकर्ता कॉन्फ़िगरेशन को HKCU के अंतर्गत बनाए रखते हैं और इसे प्रति-सेशन HKLM स्थानों में propagate करते हैं। एक **Secure Desktop** transition (लॉक स्क्रीन या UAC प्रॉम्प्ट) के दौरान, **SYSTEM** कंपोनेंट्स इन मानों को फिर से कॉपी करते हैं। यदि **per-session HKLM key user द्वारा लिखने योग्य है**, तो यह एक privileged write choke point बन जाता है जिसे **registry symbolic links** के साथ रीडायरेक्ट किया जा सकता है, जिससे एक **arbitrary SYSTEM registry write** हासिल होता है।

RegPwn तकनीक उस propagation chain का दुरुपयोग करती है जिसमें एक छोटा race window होता है जिसे `osk.exe` द्वारा उपयोग की जाने वाली फाइल पर एक **opportunistic lock (oplock)** के जरिए स्थिर किया जाता है।

## Registry Propagation Chain (Accessibility -> Secure Desktop)

Example feature: **On-Screen Keyboard** (`osk`). The relevant locations are:

- **System-wide feature list**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`
- **Per-user configuration (user-writable)**:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
- **Per-session HKLM config (created by `winlogon.exe`, user-writable)**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- **Secure desktop/default user hive (SYSTEM context)**:
- `HKU\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`

Propagation during a secure desktop transition (simplified):

1. **User `atbroker.exe`** copies `HKCU\...\ATConfig\osk` to `HKLM\...\Session<session id>\ATConfig\osk`.
2. **SYSTEM `atbroker.exe`** copies `HKLM\...\Session<session id>\ATConfig\osk` to `HKU\.DEFAULT\...\ATConfig\osk`.
3. **SYSTEM `osk.exe`** copies `HKU\.DEFAULT\...\ATConfig\osk` back to `HKLM\...\Session<session id>\ATConfig\osk`.

यदि session HKLM subtree user द्वारा writable है, तो step 2/3 एक SYSTEM write प्रदान करते हैं जिसके माध्यम से user उस स्थान को बदल सकता है।

## Primitive: Arbitrary SYSTEM Registry Write via Registry Links

उपयोगकर्ता-लिखने योग्य per-session key को एक **registry symbolic link** से बदलें जो attacker-चयनित destination की ओर इशारा करता है। जब SYSTEM copy करता है, तो वह लिंक का अनुसरण करता है और attacker-नियंत्रित मान arbitrary target key में लिख देता है।

मुख्य विचार:

- Victim write target (user-writable):
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- Attacker replaces that key with a **registry link** to any other key.
- SYSTEM performs the copy and writes into the attacker-chosen key with SYSTEM permissions.

यह एक **arbitrary SYSTEM registry write** primitive देता है।

## Winning the Race Window with Oplocks

SYSTEM `osk.exe` के शुरू होने और per-session key लिखने के बीच एक छोटा timing window होता है। इसे भरोसेमंद बनाने के लिए, exploit एक **oplock** लगाता है जो:
```
C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml
```
When the oplock triggers, the attacker swaps the per-session HKLM key for a registry link, lets the SYSTEM write land, then removes the link.

## उदाहरण शोषण प्रवाह (उच्च स्तर)

1. access token से वर्तमान **session ID** प्राप्त करें।
2. एक छिपा हुआ `osk.exe` इंस्टेंस शुरू करें और थोड़ी देर रुकें (सुनिश्चित करें कि oplock ट्रिगर होगा)।
3. हमलावर द्वारा नियंत्रित मानों को निम्न स्थान पर लिखें:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
4. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` पर एक **oplock** सेट करें।
5. **Secure Desktop** (`LockWorkstation()` ) को ट्रिगर करें, जिससे SYSTEM `atbroker.exe` / `osk.exe` शुरू हो जाते हैं।
6. oplock ट्रिगर होने पर, `HKLM\...\Session<session id>\ATConfig\osk` को किसी मनमाने लक्ष्य की ओर एक **registry link** से बदल दें।
7. SYSTEM की कॉपी पूरी होने के लिए थोड़ी देर प्रतीक्षा करें, फिर लिंक हटा दें।

## Primitive को SYSTEM निष्पादन में परिवर्तित करना

एक सीधा तरीका है किसी **service configuration** मान (उदा., `ImagePath`) को ओवरराइट करना और फिर सेवा को शुरू करना। The RegPwn PoC `ImagePath` को **`msiserver`** के लिए ओवरराइट करता है और इसे **MSI COM object** को इंस्टेंटिएट करके ट्रिगर करता है, जिससे **SYSTEM** कोड निष्पादन होता है।

## संबंधित

अन्य Secure Desktop / UIAccess व्यवहारों के लिए देखें:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## संदर्भ

- [RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn PoC](https://github.com/mdsecactivebreach/RegPwn)

{{#include ../../banners/hacktricks-training.md}}
