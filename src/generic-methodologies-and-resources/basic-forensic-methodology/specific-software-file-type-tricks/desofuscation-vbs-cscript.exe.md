# Desobfuscation Techniques for VBS Files

{{#include ../../../banners/hacktricks-training.md}}

Some things that could be useful to debug/deobfuscate a malicious VBS file:

## echo

`WScript.Echo` can be used for diagnostic output; under `cscript.exe`, it is written to the console.<sup>[[1]](#references)</sup>

```bash
Wscript.Echo "Like this?"
```

## Comments

A single apostrophe starts a VBScript comment.<sup>[[2]](#references)</sup>

```bash
' this is a comment
```

## Test

Run the VBS file in the command-line host with:<sup>[[3]](#references)</sup>

```bash
cscript.exe file.vbs
```

## Write data to a file

This helper is adapted from a Stack Overflow answer and uses a `FileSystemObject` text stream. `CreateTextFile` returns a `TextStream`, and `Write`/`Close` operate on text data; treat it as a text-writing example rather than a general binary-safe writer.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

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

- [1] [Running a Visual Basic Scripting Edition Query (Microsoft Learn)](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/indexsrv/running-a-visual-basic-scripting-edition-query)
- [2] [Working with Scripting Languages (Microsoft Learn)](https://learn.microsoft.com/en-us/previous-versions/iis/6.0-sdk/ms525153%28v%3Dvs.90%29)
- [3] [cscript (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cscript)
- [4] [Read and write binary file in VBScript (Stack Overflow)](https://stackoverflow.com/questions/6060529/read-and-write-binary-file-in-vbscript/6087783)
- [5] [CreateTextFile method (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/createtextfile-method)
- [6] [TextStream object (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/textstream-object)

{{#include ../../../banners/hacktricks-training.md}}
