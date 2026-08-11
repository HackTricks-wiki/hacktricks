# Методи деобфускації VBS-файлів

{{#include ../../../banners/hacktricks-training.md}}

Деякі речі, які можуть бути корисними для налагодження/деобфускації шкідливого VBS-файлу:

## echo

`WScript.Echo` можна використовувати для діагностичного виведення; у `cscript.exe` воно записується в консоль.<sup>[[1]](#references)</sup>
```bash
Wscript.Echo "Like this?"
```
## Коментарі

Одинарний апостроф розпочинає коментар VBScript.<sup>[[2]](#references)</sup>
```bash
' this is a comment
```
## Тест

Запустіть VBS-файл у хості командного рядка за допомогою:<sup>[[3]](#references)</sup>
```bash
cscript.exe file.vbs
```
## Запис даних у файл

Цей helper адаптовано з відповіді на Stack Overflow; він використовує текстовий потік `FileSystemObject`. `CreateTextFile` повертає `TextStream`, а `Write`/`Close` працюють із текстовими даними; розглядайте це як приклад запису тексту, а не як універсальний writer, безпечний для довільних бінарних даних.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>
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

- [1] [Запуск запиту Visual Basic Scripting Edition (Microsoft Learn)](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/indexsrv/running-a-visual-basic-scripting-edition-query)
- [2] [Робота зі скриптовими мовами (Microsoft Learn)](https://learn.microsoft.com/en-us/previous-versions/iis/6.0-sdk/ms525153%28v%3Dvs.90%29)
- [3] [cscript (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cscript)
- [4] [Читання та запис бінарного файлу у VBScript (Stack Overflow)](https://stackoverflow.com/questions/6060529/read-and-write-binary-file-in-vbscript/6087783)
- [5] [Метод CreateTextFile (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/createtextfile-method)
- [6] [Об'єкт TextStream (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/textstream-object)
{{#include ../../../banners/hacktricks-training.md}}
