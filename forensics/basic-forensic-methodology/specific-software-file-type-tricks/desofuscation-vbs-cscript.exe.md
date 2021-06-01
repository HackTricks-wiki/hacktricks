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

