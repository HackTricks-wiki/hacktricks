# WinRM

{{#include ../../banners/hacktricks-training.md}}

Το WinRM είναι ένα από τα πιο βολικά transports για **lateral movement** σε Windows environments, επειδή σου παρέχει remote shell μέσω **WS-Man/HTTP(S)** χωρίς να χρειάζονται τεχνικές δημιουργίας SMB service. Αν ο στόχος εκθέτει τις θύρες **5985/5986** και το principal σου επιτρέπεται να χρησιμοποιεί remoting, συχνά μπορείς να μεταβείς πολύ γρήγορα από "valid creds" σε "interactive shell".

Για το **protocol/service enumeration**, τους listeners, την ενεργοποίηση του WinRM, το `Invoke-Command` και τη γενική χρήση client, δες:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Γιατί αρέσει το WinRM στους operators

- Χρησιμοποιεί **HTTP/HTTPS** αντί για SMB/RPC, επομένως συχνά λειτουργεί σε περιπτώσεις όπου το PsExec-style execution είναι αποκλεισμένο.
- Με **Kerberos**, αποφεύγει την αποστολή reusable credentials στον στόχο.
- Λειτουργεί ομαλά από **Windows**, **Linux** και εργαλεία **Python** (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Η interactive PowerShell remoting διαδρομή εκκινεί το **`wsmprovhost.exe`** στον στόχο, στο context του authenticated user, κάτι που λειτουργικά διαφέρει από το service-based exec.

## Μοντέλο πρόσβασης και προαπαιτούμενα

Στην πράξη, το επιτυχές WinRM lateral movement εξαρτάται από **τρία** πράγματα:

1. Ο στόχος διαθέτει **WinRM listener** (`5985`/`5986`) και firewall rules που επιτρέπουν την πρόσβαση.
2. Ο λογαριασμός μπορεί να κάνει **authenticate** στο endpoint.
3. Ο λογαριασμός επιτρέπεται να **ανοίξει remoting session**.

Συνηθισμένοι τρόποι απόκτησης αυτής της πρόσβασης:

- **Local Administrator** στον στόχο.
- Membership στο **Remote Management Users** σε νεότερα systems ή στο **WinRMRemoteWMIUsers__** σε systems/components που εξακολουθούν να αναγνωρίζουν αυτό το group.
- Explicit remoting rights που έχουν γίνει delegated μέσω local security descriptors / αλλαγών στα PowerShell remoting ACLs.

Αν έχεις ήδη τον έλεγχο ενός box με admin rights, θυμήσου ότι μπορείς επίσης να κάνεις **delegate WinRM access χωρίς πλήρες membership σε admin group**, χρησιμοποιώντας τις τεχνικές που περιγράφονται εδώ:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Authentication gotchas που έχουν σημασία κατά το lateral movement

- Το **Kerberos απαιτεί hostname/FQDN**. Αν συνδεθείς μέσω IP, ο client συνήθως κάνει fallback σε **NTLM/Negotiate**.
- Σε **workgroup** ή cross-trust edge cases, το NTLM συνήθως απαιτεί είτε **HTTPS** είτε την προσθήκη του στόχου στο **TrustedHosts** στον client.
- Με **local accounts** μέσω Negotiate σε workgroup, οι UAC remote restrictions ενδέχεται να εμποδίσουν την πρόσβαση, εκτός αν χρησιμοποιηθεί ο built-in Administrator account ή οριστεί `LocalAccountTokenFilterPolicy=1`.
- Το PowerShell remoting χρησιμοποιεί από προεπιλογή το **`HTTP/<host>` SPN**. Σε environments όπου το **`HTTP/<host>`** είναι ήδη registered σε κάποιο άλλο service account, το WinRM Kerberos ενδέχεται να αποτύχει με `0x80090322`. Χρησιμοποίησε port-qualified SPN ή κάνε switch σε **`WSMAN/<host>`**, όπου υπάρχει αυτό το SPN.<sup>[[3]](#references)</sup>

Αν αποκτήσεις valid credentials κατά το password spraying, η επικύρωσή τους μέσω WinRM είναι συχνά ο ταχύτερος τρόπος να ελέγξεις αν μπορούν να μετατραπούν σε shell:

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

Το `evil-winrm` παραμένει η πιο βολική επιλογή για interactive shells από Linux, επειδή υποστηρίζει **κωδικούς πρόσβασης**, **NT hashes**, **Kerberos tickets**, **client certificates**, μεταφορά αρχείων και φόρτωση PowerShell/.NET στη μνήμη.
```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```
### Ειδική περίπτωση Kerberos SPN: `HTTP` vs `WSMAN`

Όταν το προεπιλεγμένο **`HTTP/<host>`** SPN προκαλεί αποτυχίες Kerberos, δοκιμάστε να ζητήσετε/χρησιμοποιήσετε ένα ticket **`WSMAN/<host>`**. Αυτό εμφανίζεται σε ενισχυμένα ή ασυνήθιστα enterprise setups, όπου το **`HTTP/<host>`** είναι ήδη συνδεδεμένο με άλλο service account.<sup>[[3]](#references)</sup>
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
Αυτό είναι επίσης χρήσιμο μετά από abuse των **RBCD / S4U**, όταν συγκεκριμένα έχετε forged ή ζητήσει ένα **WSMAN** service ticket αντί για ένα generic `HTTP` ticket.

### Authentication με βάση certificate

Το WinRM υποστηρίζει επίσης **client certificate authentication**, αλλά το certificate πρέπει να έχει γίνει map στον target σε έναν **local account**. Από offensive perspective, αυτό έχει σημασία όταν:

- έχετε κλέψει/exported ένα έγκυρο client certificate και private key που έχουν ήδη γίνει map για WinRM·
- έχετε κάνει abuse των **AD CS / Pass-the-Certificate** για να αποκτήσετε certificate για έναν principal και στη συνέχεια να κάνετε pivot σε άλλη authentication path·
- λειτουργείτε σε environments που αποφεύγουν σκόπιμα το password-based remoting.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Το WinRM με client-certificate είναι πολύ λιγότερο συνηθισμένο από το password/hash/Kerberos auth, αλλά όταν υπάρχει μπορεί να παρέχει μια διαδρομή **passwordless lateral movement** που επιβιώνει από την αλλαγή κωδικού πρόσβασης.

### Python / automation με `pypsrp`

Αν χρειάζεστε automation αντί για shell χειριστή, το `pypsrp` παρέχει WinRM/PSRP από Python με υποστήριξη για **NTLM**, **certificate auth**, **Kerberos** και **CredSSP**.<sup>[[2]](#references)</sup>
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
Αν χρειάζεστε πιο λεπτομερή έλεγχο από αυτόν που προσφέρει το wrapper υψηλού επιπέδου `Client`, τα API χαμηλότερου επιπέδου `WSMan` + `RunspacePool` είναι χρήσιμα για δύο συνηθισμένα προβλήματα των operators:

- την επιβολή του **`WSMAN`** ως υπηρεσίας/SPN του Kerberos, αντί για την προεπιλεγμένη προσδοκία **`HTTP`** που χρησιμοποιούν πολλοί PowerShell clients·
- τη σύνδεση σε ένα **μη προεπιλεγμένο PSRP endpoint**, όπως ένα **JEA** / custom session configuration, αντί για το `Microsoft.PowerShell`.
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

Ένα επιτυχές WinRM authentication **δεν** σημαίνει πάντα ότι καταλήγετε στο προεπιλεγμένο, unrestricted `Microsoft.PowerShell` endpoint. Τα ώριμα περιβάλλοντα ενδέχεται να εκθέτουν **custom session configurations** ή **JEA** endpoints με τα δικά τους ACLs και run-as behavior.<sup>[[1]](#references)</sup>

Αν έχετε ήδη code execution σε έναν Windows host και θέλετε να κατανοήσετε ποιες remoting επιφάνειες υπάρχουν, απαριθμήστε τα registered endpoints:
```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```
Όταν υπάρχει ένα χρήσιμο endpoint, στόχευσέ το ρητά αντί για το προεπιλεγμένο shell:
```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```
Πρακτικές offensive επιπτώσεις:

- Ένα **περιορισμένο** endpoint μπορεί και πάλι να επαρκεί για lateral movement, εάν εκθέτει μόνο τα κατάλληλα cmdlets/functions για service control, file access, process creation ή αυθαίρετη εκτέλεση εντολών .NET / external.
- Ένας **λανθασμένα ρυθμισμένος JEA** ρόλος είναι ιδιαίτερα πολύτιμος όταν εκθέτει επικίνδυνες εντολές όπως `Start-Process`, ευρέα wildcards, writable providers ή custom proxy functions που σας επιτρέπουν να ξεφύγετε από τους προβλεπόμενους περιορισμούς.
- Τα endpoints που υποστηρίζονται από **RunAs virtual accounts** ή **gMSAs** αλλάζουν το effective security context των εντολών που εκτελείτε. Ειδικότερα, ένα endpoint που υποστηρίζεται από gMSA μπορεί να παρέχει **network identity στο second hop**, ακόμη και όταν μια κανονική WinRM συνεδρία θα αντιμετώπιζε το κλασικό πρόβλημα delegation.

## Windows-native lateral movement μέσω WinRM

### `winrs.exe`

Το `winrs.exe` είναι ενσωματωμένο και χρήσιμο όταν θέλετε **native WinRM command execution** χωρίς να ανοίξετε μια interactive PowerShell remoting session:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
Δύο flags ξεχνιούνται εύκολα και είναι σημαντικά στην πράξη:

- Το `/noprofile` απαιτείται συχνά όταν ο remote principal **δεν** είναι local administrator.
- Το `/allowdelegate` επιτρέπει στο remote shell να χρησιμοποιεί τα credentials σας σε έναν **τρίτο host** (για παράδειγμα, όταν η εντολή χρειάζεται το `\\fileserver\share`).
```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```
Σε επιχειρησιακό επίπεδο, το `winrs.exe` συνήθως καταλήγει σε μια απομακρυσμένη αλυσίδα διεργασιών παρόμοια με:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
Αξίζει να το θυμάστε, επειδή διαφέρει από το service-based exec και από τις interactive PSRP sessions.

### `winrm.cmd` / WS-Man COM αντί για PowerShell remoting

Μπορείτε επίσης να εκτελέσετε εντολές μέσω του **WinRM transport** χωρίς `Enter-PSSession`, καλώντας WMI classes μέσω WS-Man. Έτσι, το transport παραμένει WinRM, ενώ το remote execution primitive γίνεται **WMI `Win32_Process.Create`**:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
Αυτή η προσέγγιση είναι χρήσιμη όταν:

- Η καταγραφή του PowerShell παρακολουθείται στενά.
- Θέλετε **WinRM transport**, αλλά όχι μια κλασική ροή εργασίας PS remoting.
- Δημιουργείτε ή χρησιμοποιείτε custom tooling γύρω από το **`WSMan.Automation`** COM object.

## NTLM relay to WinRM (WS-Man)

Όταν το SMB relay μπλοκάρεται λόγω signing και το LDAP relay περιορίζεται, το **WS-Man/WinRM** μπορεί να παραμένει ένας ελκυστικός στόχος για relay. Το σύγχρονο `ntlmrelayx.py` περιλαμβάνει **WinRM relay servers** και μπορεί να κάνει relay σε στόχους **`wsman://`** ή **`winrms://`**.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
Δύο πρακτικές σημειώσεις:

- Το Relay είναι πιο χρήσιμο όταν ο στόχος αποδέχεται **NTLM** και το principal που γίνεται relay επιτρέπεται να χρησιμοποιεί WinRM.
- Ο πρόσφατος κώδικας του Impacket χειρίζεται ειδικά αιτήματα **`WSMANIDENTIFY: unauthenticated`**, ώστε τα probes τύπου `Test-WSMan` να μην διακόπτουν τη ροή του relay.

Για περιορισμούς multi-hop μετά την απόκτηση της πρώτης συνεδρίας WinRM, δείτε:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## Σημειώσεις OPSEC και εντοπισμού

- Το **Interactive PowerShell remoting** συνήθως δημιουργεί το **`wsmprovhost.exe`** στον στόχο.
- Το **`winrs.exe`** συνήθως δημιουργεί το **`winrshost.exe`** και στη συνέχεια την ζητούμενη child process.
- Τα προσαρμοσμένα endpoints **JEA** ενδέχεται να εκτελούν ενέργειες ως virtual accounts **`WinRM_VA_*`** ή ως ρυθμισμένο **gMSA**, γεγονός που αλλάζει τόσο τα telemetry δεδομένα όσο και τη συμπεριφορά του second-hop σε σύγκριση με ένα shell σε κανονικό user context.<sup>[[1]](#references)</sup>
- Αναμένετε telemetry για **network logon**, events της υπηρεσίας WinRM και PowerShell operational/script-block logging αν χρησιμοποιείτε PSRP αντί για raw `cmd.exe`.
- Αν χρειάζεστε μόνο μία εντολή, το `winrs.exe` ή η one-shot εκτέλεση μέσω WinRM μπορεί να είναι πιο αθόρυβα από μια μακρόβια interactive remoting συνεδρία.
- Αν είναι διαθέσιμο το Kerberos, προτιμήστε **FQDN + Kerberos** αντί για IP + NTLM, ώστε να μειώσετε τόσο τα προβλήματα εμπιστοσύνης όσο και τις άβολες αλλαγές στο client-side `TrustedHosts`.

## Αναφορές

- [1] [Microsoft: Ζητήματα ασφάλειας του JEA](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [2] [pypsrp README](https://github.com/jborean93/pypsrp)
- [3] [Microsoft: Σφάλμα `0x80090322` κατά τη σύνδεση του PowerShell σε απομακρυσμένο server μέσω WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)


{{#include ../../banners/hacktricks-training.md}}
