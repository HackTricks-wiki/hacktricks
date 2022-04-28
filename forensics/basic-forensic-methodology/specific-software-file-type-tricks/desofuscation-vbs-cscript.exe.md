<details> <summary><strong>Support HackTricks and get benefits!</strong></summary> Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)! Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family) Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com) **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.** **Share your hacking tricks submitting PRs to the** [**hacktricks github repo**](https://github.com/carlospolop/hacktricks)**.** </details>
# Desofuscation vbs \(cscript.exe\)

Some things that could be useful to debug/desofuscate a malicious vbs file:

### echo

```bash
Wscript.Echo "Like this?"
```

### Commnets

```text
' this is a comment
```

### Test

```text
cscript.exe file.vbs
```

### Write data to a file

```aspnet
Function writeBinary(strBinary, strPath)

    Dim oFSO: Set oFSO = CreateObject("Scripting.FileSystemObject")

    ' below lines pupose: checks that write access is possible!
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

<details> <summary><strong>Support HackTricks and get benefits!</strong></summary> Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)! Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family) Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com) **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.** **Share your hacking tricks submitting PRs to the** [**hacktricks github repo**](https://github.com/carlospolop/hacktricks)**.** </details>
