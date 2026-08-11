# Techniques de désobfuscation des fichiers VBS

{{#include ../../../banners/hacktricks-training.md}}

Quelques éléments utiles pour déboguer/désobfusquer un fichier VBS malveillant :

## echo

`WScript.Echo` peut être utilisé pour afficher des informations de diagnostic ; avec `cscript.exe`, celles-ci sont écrites dans la console.<sup>[[1]](#references)</sup>
```bash
Wscript.Echo "Like this?"
```
## Commentaires

Une apostrophe simple commence un commentaire VBScript.<sup>[[2]](#references)</sup>
```bash
' this is a comment
```
## Test

Exécutez le fichier VBS dans l’hôte de ligne de commande avec :<sup>[[3]](#references)</sup>
```bash
cscript.exe file.vbs
```
## Écrire des données dans un fichier

Cet utilitaire est adapté d'une réponse Stack Overflow et utilise un flux de texte `FileSystemObject`. `CreateTextFile` renvoie un `TextStream`, et `Write`/`Close` opèrent sur des données textuelles ; considérez-le comme un exemple d'écriture de texte plutôt que comme un writer général compatible avec les données binaires.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>
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

- [1] [Exécuter une requête Visual Basic Scripting Edition (Microsoft Learn)](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/indexsrv/running-a-visual-basic-scripting-edition-query)
- [2] [Utiliser les langages de script (Microsoft Learn)](https://learn.microsoft.com/en-us/previous-versions/iis/6.0-sdk/ms525153%28v%3Dvs.90%29)
- [3] [cscript (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cscript)
- [4] [Lire et écrire un fichier binaire en VBScript (Stack Overflow)](https://stackoverflow.com/questions/6060529/read-and-write-binary-file-in-vbscript/6087783)
- [5] [Méthode CreateTextFile (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/createtextfile-method)
- [6] [Objet TextStream (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/textstream-object)
{{#include ../../../banners/hacktricks-training.md}}
