# Phishing Documents

Microsoft Word performs file data validation prior to opening a file. Data validation is performed in the form of data structure identification, against the OfficeOpenXML standard. If any error occurs during the data structure identification, the file being analysed will not be opened.

Usually Word files containing macros uses the `.docm` extension. However, it's possible to rename the file changing the file extension and still keep their macro executing capabilities.  
For example, an RTF file does not support macros, by design, but a DOCM file renamed to RTF will be handled by Microsoft Word and will be capable of macro execution.  
The same internals and mechanisms apply to all software of the Microsoft Office Suite \(Excel, PowerPoint etc.\).

You can use the following command to check which extensions are going to be executed by some Office programs:

```bash
assoc | findstr /i "word excel powerp"
```

DOCX files referencing a remote template \(File –Options –Add-ins –Manage: Templates –Go\) that includes macros can “execute” macros as well.

### Word with external image

Go to: _Insert --&gt; Quick Parts --&gt; Field_  
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ [http://&lt;ip&gt;/whatever](http://<ip>/whatever)

![](../.gitbook/assets/image%20%28347%29.png)

### Macros Code

```bash
Dim author As String
author = oWB.BuiltinDocumentProperties("Author")
With objWshell1.Exec("powershell.exe -nop -Windowsstyle hidden -Command-")
 .StdIn.WriteLine author
 .StdIn.WriteBlackLines 1
```

## Autoload functions

The more common they are, the more probable the AV will detect it.

* AutoOpen\(\)
* Document\_Open\(\)

