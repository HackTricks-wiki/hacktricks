# Office file analysis

{{#include ../../../banners/hacktricks-training.md}}

For further information check [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). This is just a sumary:<sup>[[2]](#references)</sup>

Microsoft Office documents commonly appear as legacy formats such as RTF and OLE/CFBF-based DOC, XLS, and PPT, or as newer **Office Open XML (OOXML)** formats such as DOCX, XLSX, and PPTX. Office documents may contain active content such as macros, making them common phishing and malware carriers. OOXML files are ZIP containers whose file hierarchy and XML contents can be inspected by unzipping them.<sup>[[1]](#references)[[2]](#references)</sup>

To explore OOXML file structures, the command to unzip a document and the output structure are given. Techniques for hiding data in these files have been documented, indicating ongoing innovation in data concealment within CTF challenges.<sup>[[2]](#references)</sup>

For analysis, **oletools** and **OfficeDissector** offer comprehensive toolsets for examining both OLE and OOXML documents. These tools help in identifying and analyzing embedded macros, which often serve as vectors for malware delivery, typically downloading and executing additional malicious payloads. Analysis of VBA macros can be conducted without Microsoft Office by utilizing Libre Office, which allows for debugging with breakpoints and watch variables.<sup>[[2]](#references)</sup>

Installation and usage of **oletools** are straightforward, with commands provided for installing via pip and extracting macros from documents. In Word, automatic macros include `AutoExec` and `AutoOpen`, while `Document_Open` is an open-event procedure.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```

## VBA macro analysis: junk code and UserForms

## Junk Code

Macros may contain **unreachable or irrelevant code** intended to slow analysis. Identify constant conditions and trace reachable behavior before spending time reversing a branch. The example below uses an `If` condition that can never be true to conceal junk code.

![A Word macro containing an unreachable conditional branch with junk code](<../../../images/image (369).png>)

## Macro Forms

VBA UserForms can store data in controls such as text boxes. Because forms, frames, and pages can each expose a `Controls` collection, analysts should enumerate the entire control hierarchy rather than relying only on what the form displays. The example below stores concealed data in overlapping text boxes.<sup>[[6]](#references)</sup>

During dynamic analysis, VBA's `GetObject` function can retrieve an Automation object from a file or attach to an already-running Automation server. Macros may use that object access to reach data that is not obvious in the visible document; inspect both the returned object and the UserForm control tree.<sup>[[7]](#references)</sup>

![A macro UserForm with data concealed in overlapping text boxes](<../../../images/image (344).png>)

For password-encrypted Office documents, see the [grammar-driven offline recovery workflow](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example).

---

For Revit RFA files that use OLE/CFBF, see [ECC recomputation, controlled gzip, and deserializer exploitation](../../../binary-exploitation/revit-rfa-ole-compound-file-exploitation.md); that parser-exploitation workflow is separate from Office document triage.

## References

- [1] [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [2] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
- [3] [olevba documentation (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [4] [Auto Macros (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [5] [Document.Open event (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
- [6] [Microsoft Learn - Collections, controls, and objects (Microsoft Forms)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
- [7] [Microsoft Learn - `GetObject` function](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/getobject-function)

{{#include ../../../banners/hacktricks-training.md}}
