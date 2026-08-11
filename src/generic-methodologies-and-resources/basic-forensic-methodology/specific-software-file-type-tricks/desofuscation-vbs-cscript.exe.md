# Τεχνικές Αποσυσκότισης για αρχεία VBS

{{#include ../../../banners/hacktricks-training.md}}

Μερικά πράγματα που θα μπορούσαν να φανούν χρήσιμα για τον εντοπισμό σφαλμάτων/την αποσυσκότιση ενός κακόβουλου αρχείου VBS:

## echo

Το `WScript.Echo` μπορεί να χρησιμοποιηθεί για διαγνωστική έξοδο· στο `cscript.exe`, αυτή εγγράφεται στην κονσόλα.<sup>[[1]](#references)</sup>
```bash
Wscript.Echo "Like this?"
```
## Σχόλια

Μία μόνο απόστροφος ξεκινά ένα σχόλιο VBScript.<sup>[[2]](#references)</sup>
```bash
' this is a comment
```
## Δοκιμή

Εκτελέστε το αρχείο VBS στο command-line host με:<sup>[[3]](#references)</sup>
```bash
cscript.exe file.vbs
```
## Εγγραφή δεδομένων σε αρχείο

Αυτό το helper είναι προσαρμοσμένο από μια απάντηση στο Stack Overflow και χρησιμοποιεί ένα text stream του `FileSystemObject`. Η `CreateTextFile` επιστρέφει ένα `TextStream`, ενώ οι `Write`/`Close` λειτουργούν σε δεδομένα κειμένου· αντιμετωπίστε το ως παράδειγμα εγγραφής κειμένου και όχι ως writer γενικής χρήσης που είναι ασφαλής για binary δεδομένα.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>
```js
Function writeBinary(strBinary, strPath)

Dim oFSO: Set oFSO = CreateObject("Scripting.FileSystemObject")

' below lines purpose: checks that write access is possible!
Dim oTxtStream

On Error Resume Next
Set oTxtStream = oFSO.createTextFile(strPath)

If Err.number <> 0 Then MsgBox(Err.message) : Exit Function
On Error GoTo 0

Set oTxtStream = Nothing
' end check of write access

With oFSO.createTextFile(strPath)
.Write(strBinary)
.Close
End With

End Function
```
## References

- [1] [Εκτέλεση ερωτήματος Visual Basic Scripting Edition (Microsoft Learn)](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/indexsrv/running-a-visual-basic-scripting-edition-query)
- [2] [Εργασία με γλώσσες scripting (Microsoft Learn)](https://learn.microsoft.com/en-us/previous-versions/iis/6.0-sdk/ms525153%28v%3Dvs.90%29)
- [3] [cscript (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cscript)
- [4] [Ανάγνωση και εγγραφή binary αρχείου σε VBScript (Stack Overflow)](https://stackoverflow.com/questions/6060529/read-and-write-binary-file-in-vbscript/6087783)
- [5] [Μέθοδος CreateTextFile (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/createtextfile-method)
- [6] [Αντικείμενο TextStream (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/textstream-object)
{{#include ../../../banners/hacktricks-training.md}}
