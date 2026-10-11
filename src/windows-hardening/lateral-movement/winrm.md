# WinRM

{{#include ../../banners/hacktricks-training.md}}

Το WinRM είναι ένα από τα πιο βολικά transport για **lateral movement** σε περιβάλλοντα Windows, επειδή παρέχει remote shell μέσω **WS-Man/HTTP(S)** χωρίς να χρειάζονται τεχνάσματα δημιουργίας υπηρεσιών SMB. Αν ο στόχος εκθέτει τις θύρες **5985/5986** και ο principal σας έχει δικαίωμα χρήσης του remoting, συχνά μπορείτε να περάσετε πολύ γρήγορα από «έγκυρα creds» σε «interactive shell».

Για **protocol/service enumeration**, listeners, ενεργοποίηση του WinRM, `Invoke-Command` και γενική χρήση client, δείτε:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Γιατί οι operators προτιμούν το WinRM

- Χρησιμοποιεί **HTTP/HTTPS** αντί για SMB/RPC, οπότε συχνά λειτουργεί εκεί όπου είναι αποκλεισμένη η εκτέλεση τύπου PsExec.
- Με **Kerberos**, αποφεύγει την αποστολή επαναχρησιμοποιήσιμων credentials στον στόχο.
- Λειτουργεί ομαλά από **Windows**, **Linux** και εργαλεία **Python** (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Η interactive διαδρομή PowerShell remoting εκκινεί το **`wsmprovhost.exe`** στον στόχο, στο context του authenticated user, κάτι που διαφέρει λειτουργικά από την εκτέλεση μέσω υπηρεσίας.

## Μοντέλο πρόσβασης και προαπαιτούμενα

Στην πράξη, το επιτυχές WinRM lateral movement εξαρτάται από **τρία** πράγματα:

1. Ο στόχος διαθέτει **WinRM listener** (`5985`/`5986`) και κανόνες firewall που επιτρέπουν την πρόσβαση.
2. Ο λογαριασμός μπορεί να κάνει **authenticate** στο endpoint.
3. Ο λογαριασμός έχει δικαίωμα να **ανοίξει remoting session**.

Συνήθεις τρόποι απόκτησης αυτής της πρόσβασης:

- **Local Administrator** στον στόχο.
- Συμμετοχή στην ομάδα **Remote Management Users** σε νεότερα συστήματα ή στην **WinRMRemoteWMIUsers__** σε συστήματα/συστατικά που εξακολουθούν να αναγνωρίζουν αυτή την ομάδα.
- Ρητά δικαιώματα remoting που έχουν ανατεθεί μέσω local security descriptors / αλλαγών στα ACL του PowerShell remoting.

Αν έχετε ήδη αποκτήσει έλεγχο σε ένα μηχάνημα με δικαιώματα admin, θυμηθείτε ότι μπορείτε επίσης να **αναθέσετε πρόσβαση WinRM χωρίς πλήρη συμμετοχή σε ομάδα admin**, χρησιμοποιώντας τις τεχνικές που περιγράφονται εδώ:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Σημεία προσοχής στο authentication που έχουν σημασία κατά το lateral movement

- Το **Kerberos απαιτεί hostname/FQDN**. Αν συνδεθείτε μέσω IP, ο client συνήθως κάνει fallback σε **NTLM/Negotiate**.
- Σε **workgroup** ή οριακές περιπτώσεις cross-trust, το NTLM συνήθως απαιτεί είτε **HTTPS** είτε την προσθήκη του στόχου στο **TrustedHosts** του client.
- Με **local accounts** μέσω Negotiate σε workgroup, οι απομακρυσμένοι περιορισμοί UAC ενδέχεται να εμποδίσουν την πρόσβαση, εκτός αν χρησιμοποιείται ο ενσωματωμένος λογαριασμός Administrator ή έχει οριστεί `LocalAccountTokenFilterPolicy=1`.
- Το PowerShell remoting χρησιμοποιεί από προεπιλογή το **`HTTP/<host>` SPN**. Σε περιβάλλοντα όπου το **`HTTP/<host>`** είναι ήδη καταχωρισμένο σε κάποιον άλλο service account, το WinRM Kerberos μπορεί να αποτύχει με `0x80090322`. Χρησιμοποιήστε SPN με προσδιορισμένη θύρα ή αλλάξτε σε **`WSMAN/<host>`**, εφόσον υπάρχει αυτό το SPN.<sup>[[3]](#references)</sup>

Αν αποκτήσετε έγκυρα credentials κατά το password spraying, η επικύρωσή τους μέσω WinRM είναι συχνά ο ταχύτερος τρόπος να ελέγξετε αν σας δίνουν shell:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Lateral movement από Linux προς Windows

### NetExec / CrackMapExec για επικύρωση και εκτέλεση μίας εντολής

```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```

### Evil-WinRM για διαδραστικά shells

Το `evil-winrm` παραμένει η πιο βολική επιλογή για διαδραστική χρήση από Linux, καθώς υποστηρίζει **passwords**, **NT hashes**, **Kerberos tickets**, **client certificates**, μεταφορά αρχείων και φόρτωση PowerShell/.NET στη μνήμη.

```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```

### Οριακή περίπτωση Kerberos SPN: `HTTP` έναντι `WSMAN`

Όταν το προεπιλεγμένο SPN **`HTTP/<host>`** προκαλεί αποτυχίες Kerberos, δοκιμάστε να ζητήσετε/χρησιμοποιήσετε ένα ticket **`WSMAN/<host>`** αντί γι’ αυτό. Αυτό εμφανίζεται σε ενισχυμένα ή ασυνήθιστα εταιρικά περιβάλλοντα, όπου το **`HTTP/<host>`** είναι ήδη συνδεδεμένο με άλλον λογαριασμό υπηρεσίας.<sup>[[3]](#references)</sup>

```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```

Αυτό είναι επίσης χρήσιμο μετά από κατάχρηση **RBCD / S4U**, όταν συγκεκριμένα πλαστογραφήσατε ή ζητήσατε ένα service ticket **WSMAN** αντί για ένα γενικό ticket `HTTP`.

### Πιστοποίηση βάσει πιστοποιητικού

Το WinRM υποστηρίζει επίσης **client certificate authentication**, αλλά το πιστοποιητικό πρέπει να αντιστοιχιστεί στον στόχο με έναν **local account**. Από επιθετική σκοπιά, αυτό έχει σημασία όταν:

- έχετε ήδη κλέψει/εξαγάγει ένα έγκυρο client certificate και private key που είναι αντιστοιχισμένα για WinRM·
- καταχραστήκατε το **AD CS / Pass-the-Certificate** για να αποκτήσετε ένα πιστοποιητικό για μια principal και στη συνέχεια να κάνετε pivot σε μια άλλη διαδρομή πιστοποίησης·
- δραστηριοποιείστε σε περιβάλλοντα που αποφεύγουν σκόπιμα την απομακρυσμένη πρόσβαση βάσει κωδικού πρόσβασης.

```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```

Το WinRM με πιστοποιητικό πελάτη είναι πολύ λιγότερο συνηθισμένο από το authentication με password/hash/Kerberos, αλλά όταν υπάρχει, μπορεί να προσφέρει μια διαδρομή για **lateral movement χωρίς password**, η οποία παραμένει διαθέσιμη μετά την αλλαγή του password.

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


Αν χρειάζεστε πιο λεπτομερή έλεγχο από αυτόν που προσφέρει το wrapper υψηλού επιπέδου `Client`, τα API χαμηλότερου επιπέδου `WSMan` + `RunspacePool` είναι χρήσιμα για δύο συνηθισμένα προβλήματα χειριστών:

- να επιβάλετε το **`WSMAN`** ως υπηρεσία/SPN Kerberos αντί για την προεπιλεγμένη προσδοκία **`HTTP`** που χρησιμοποιούν πολλοί clients PowerShell·
- να συνδεθείτε σε ένα **μη προεπιλεγμένο endpoint PSRP**, όπως μια διαμόρφωση περιόδου λειτουργίας **JEA** / προσαρμοσμένη, αντί για το `Microsoft.PowerShell`.

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

Η επιτυχής αυθεντικοποίηση WinRM **δεν** σημαίνει πάντα ότι αποκτάτε πρόσβαση στο προεπιλεγμένο, χωρίς περιορισμούς endpoint `Microsoft.PowerShell`. Τα ώριμα περιβάλλοντα μπορεί να εκθέτουν **custom session configurations** ή endpoints **JEA** με δικά τους ACL και συμπεριφορά run-as.<sup>[[1]](#references)</sup>

Αν έχετε ήδη εκτέλεση κώδικα σε έναν host Windows και θέλετε να μάθετε ποιες επιφάνειες remoting υπάρχουν, απαριθμήστε τα καταχωρισμένα endpoints:

```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```

Όταν υπάρχει ένα χρήσιμο endpoint, στόχευσέ το ρητά αντί για το προεπιλεγμένο shell:

```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```

Πρακτικές επιθετικές επιπτώσεις:

- Ένα **περιορισμένο** endpoint μπορεί και πάλι να αρκεί για lateral movement, αν εκθέτει ακριβώς τα κατάλληλα cmdlets/functions για έλεγχο υπηρεσιών, πρόσβαση σε αρχεία, δημιουργία διεργασιών ή αυθαίρετη εκτέλεση .NET / εξωτερικών εντολών.
- Ένας **εσφαλμένα ρυθμισμένος JEA** ρόλος είναι ιδιαίτερα πολύτιμος όταν εκθέτει επικίνδυνες εντολές, όπως `Start-Process`, ευρείας αντιστοίχισης wildcards, εγγράψιμους providers ή custom proxy functions που επιτρέπουν τη διαφυγή από τους προβλεπόμενους περιορισμούς.
- Τα endpoints που βασίζονται σε **εικονικούς λογαριασμούς RunAs** ή **gMSAs** αλλάζουν το ενεργό πλαίσιο ασφαλείας των εντολών που εκτελείτε. Ειδικότερα, ένα endpoint που βασίζεται σε gMSA μπορεί να παρέχει **ταυτότητα δικτύου στο δεύτερο hop**, ακόμη κι όταν μια συνηθισμένη συνεδρία WinRM θα αντιμετώπιζε το κλασικό πρόβλημα delegation.

Για ένα custom restricted endpoint, εξετάστε χωριστά τα δικαιώματα εντολών και script που ισχύουν: μια σύντομη λίστα `Get-Command` από μόνη της δεν αποδεικνύει ότι δεν μπορεί να εκτελεστεί ένα υπάρχον `.ps1`. Οι [δυνατότητες ρόλων JEA](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) καθορίζουν ρητά ποιες διαδρομές script μπορούν να κληθούν· άλλα custom endpoints ενδέχεται να εφαρμόζουν διαφορετικούς κανόνες συνεδρίας. Αν ένα επιτρεπόμενο script χρησιμοποιεί αποθηκευμένο `SecureString` για να δημιουργήσει διαπιστευτήρια για άλλον host, ένα blob που δημιουργήθηκε χωρίς ρητό κλειδί χρησιμοποιεί [Windows DPAPI](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) και γενικά απαιτεί το πλαίσιο χρήστη και μηχανήματος που το προστάτευσε για να αποκρυπτογραφηθεί. Εξετάστε το ACL του script, την επιτρεπόμενη κλήση, την ταυτότητα run-as και τα δικαιώματα διαπιστευτηρίων στα επόμενα συστήματα, προτού θεωρήσετε τον εγγράψιμο κώδικα ή ένα αντιγραμμένο blob διαδρομή κλιμάκωσης σε άλλο host. Μην εκτυπώνετε την προστατευμένη τιμή κατά την παθητική απαρίθμηση.

Για μια custom function JEA που δέχεται διαδρομή αρχείου, εξετάστε μαζί το ACL του καταχωρισμένου endpoint, την αντιστοιχισμένη δυνατότητα ρόλου και την ενεργή ταυτότητα run-as. Ο καλών μπορεί να έχει `NoLanguage`, ενώ το σώμα της function εκτελείται στην προεπιλεγμένη λειτουργία γλώσσας του συστήματος· ένας εικονικός λογαριασμός μπορεί επίσης να έχει δικαιώματα τοπικού διαχειριστή. Αν η function ελέγχει έναν επιτρεπόμενο κατάλογο με ακατέργαστο string prefix και στη συνέχεια διαβάζει τη δοθείσα διαδρομή, τα στοιχεία `..` μπορεί να οδηγήσουν εκτός αυτού του καταλόγου. Το όριο καθορίζεται από την επιλυμένη διαδρομή υπό την ταυτότητα της function, όχι από τη λειτουργία γλώσσας του καλούντος ή το φαινομενικό πρόθεμα. Επιβεβαιώστε την προσβάσιμη function και την επικύρωση της τελικής διαδρομής προτού θεωρήσετε ένα αναγνώσιμο αρχείο `.psrc` ή `.pssc` εύρημα προνομιακής ανάγνωσης αρχείου. Δείτε τις οδηγίες της Microsoft για τις [δυνατότητες ρόλων JEA](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) και τις [παραμέτρους ασφαλείας](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations).

## Εγγενές στα Windows WinRM lateral movement

### `winrs.exe`

Το `winrs.exe` είναι ενσωματωμένο και χρήσιμο όταν θέλετε **εγγενή εκτέλεση εντολών WinRM** χωρίς να ανοίξετε μια διαδραστική συνεδρία απομακρυσμένης εκτέλεσης PowerShell:

```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```

Δύο flags ξεχνιούνται εύκολα και έχουν πρακτική σημασία:

- Το `/noprofile` συχνά είναι απαραίτητο όταν το remote principal **δεν** είναι local administrator.
- Το `/allowdelegate` επιτρέπει στο remote shell να χρησιμοποιεί τα credentials σου σε έναν **τρίτο host** (για παράδειγμα, όταν η εντολή χρειάζεται `\\fileserver\share`).

```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```

Στην πράξη, το `winrs.exe` συνήθως δημιουργεί μια απομακρυσμένη αλυσίδα διεργασιών παρόμοια με:

```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```

Αξίζει να το θυμάστε, επειδή διαφέρει από το service-based exec και από τις διαδραστικές συνεδρίες PSRP.

### `winrm.cmd` / WS-Man COM αντί για PowerShell remoting

Μπορείτε επίσης να εκτελέσετε εντολές μέσω του **WinRM transport** χωρίς `Enter-PSSession`, καλώντας WMI classes μέσω WS-Man. Έτσι, το transport παραμένει WinRM, ενώ το primitive απομακρυσμένης εκτέλεσης γίνεται **WMI `Win32_Process.Create`**:

```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```

Αυτή η προσέγγιση είναι χρήσιμη όταν:

- Η καταγραφή PowerShell παρακολουθείται στενά.
- Θέλετε **WinRM transport**, αλλά όχι μια κλασική ροή εργασίας PS remoting.
- Δημιουργείτε ή χρησιμοποιείτε προσαρμοσμένα εργαλεία γύρω από το αντικείμενο COM **`WSMan.Automation`**.

## NTLM relay προς WinRM (WS-Man)

Όταν το SMB relay αποκλείεται λόγω υπογραφής και το LDAP relay περιορίζεται, το **WS-Man/WinRM** μπορεί και πάλι να αποτελεί ελκυστικό στόχο relay. Το σύγχρονο `ntlmrelayx.py` περιλαμβάνει **WinRM relay servers** και μπορεί να πραγματοποιήσει relay σε στόχους **`wsman://`** ή **`winrms://`**.

```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```

Δύο πρακτικές σημειώσεις:

- Το Relay είναι πιο χρήσιμο όταν ο στόχος δέχεται **NTLM** και επιτρέπεται στο principal που γίνεται relay να χρησιμοποιεί WinRM.
- Ο πρόσφατος κώδικας του Impacket χειρίζεται ειδικά αιτήματα **`WSMANIDENTIFY: unauthenticated`**, ώστε τα probes τύπου `Test-WSMan` να μη διακόπτουν τη ροή του relay.

Για περιορισμούς multi-hop αφού αποκτήσετε την πρώτη συνεδρία WinRM, δείτε:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## Σημειώσεις OPSEC και ανίχνευσης

- Το **Interactive PowerShell remoting** συνήθως δημιουργεί το **`wsmprovhost.exe`** στον στόχο.
- Το **`winrs.exe`** συνήθως δημιουργεί το **`winrshost.exe`** και στη συνέχεια τη ζητούμενη θυγατρική διεργασία.
- Προσαρμοσμένα endpoints **JEA** μπορεί να εκτελούν ενέργειες ως virtual accounts **`WinRM_VA_*`** ή ως ρυθμισμένο **gMSA**, κάτι που αλλάζει τόσο τα telemetry στοιχεία όσο και τη συμπεριφορά του second-hop σε σύγκριση με ένα shell στο πλαίσιο κανονικού χρήστη.<sup>[[1]](#references)</sup>
- Αν χρησιμοποιείτε PSRP αντί για raw `cmd.exe`, αναμένετε telemetry για **network logon**, συμβάντα της υπηρεσίας WinRM και καταγραφή PowerShell operational/script-block.
- Αν χρειάζεστε μόνο μία εντολή, το `winrs.exe` ή η εκτέλεση WinRM μίας χρήσης μπορεί να είναι πιο διακριτική από μια διαδραστική συνεδρία remoting μεγάλης διάρκειας.
- Αν είναι διαθέσιμο το Kerberos, προτιμήστε **FQDN + Kerberos** αντί για IP + NTLM, για να μειώσετε τόσο τα προβλήματα εμπιστοσύνης όσο και τις άβολες αλλαγές στο `TrustedHosts` από την πλευρά του client.

## References

- [1] [Microsoft: Ζητήματα ασφάλειας JEA](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [2] [README του pypsrp](https://github.com/jborean93/pypsrp)
- [3] [Microsoft: Σφάλμα `0x80090322` κατά τη σύνδεση του PowerShell σε απομακρυσμένο server μέσω WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)
{{#include ../../banners/hacktricks-training.md}}
