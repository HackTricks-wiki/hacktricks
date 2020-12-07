# Phising Documents

Microsoft Word performs file data validation prior to opening a file. Data validation is performed in the form of data structure identification, against the OfficeOpenXML standard. If any error occurs during the data structure identification, the file being analysed will not be opened.

Usually Word files containing macros uses the `.docm` extension. However, it's possible to rename the file changing the file extension and still keep their macro executing capabilities.  
For example, an RTF file does not support macros, by design, but a DOCM file renamed to RTF will be handled by Microsoft Word and will be capable of macro execution.  
The same internals and mechanisms apply to all software of the Microsoft Office Suite \(Excel, PowerPoint etc.\).

You can use the following command to check with extensions are going to be executed by some Office programs:

```bash
assoc | findstr /i "word excel powerp"
```

DOCX files referencing a remote template \(File –Options –Add-ins –Manage: Templates –Go\) that includes macros can “execute” macros as well.

### Word with external image

Go to: _Insert --&gt; Quick Parts --&gt; Field_  
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**: http://&lt;ip&gt;/whatever_

![](.gitbook/assets/image%20%28347%29.png)

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

## Generate similar domain names

### Domain Name Variation Techniques

* **Keyword**: The domain name **contains** an important **keyword** of the original domain \(e.g., zelster.com-management.com\).
* **hypened subdomain**: Change the **dot for a hyphen** of a subdomain \(e.g., www-zelster.com\).
* **New TLD**: Same domain using a **new TLD** \(e.g., zelster.org\)
* **Homoglyph**: It **replaces** a letter in the domain name with **letters that look similar** \(e.g., zelfser.com\).
* **Transposition:** It **swaps two letters** within the domain name \(e.g., zelster.com\).
* **Singularization/Pluralization**: Adds or removes “s” at the end of the domain name \(e.g., zeltsers.com\).
* **Omission**: It **removes one** of the letters from the domain name \(e.g., zelser.com\).
* **Repetition:** It **repeats one** of the letters in the domain name \(e.g., zeltsser.com\).
* **Replacement**: Like homoglyph but less stealthy. It replaces one of the letters in the domain name, perhaps with a letter in proximity of the original letter on the keyboard \(e.g, zektser.com\).
* **Subdomained**: Introduce a **dot** inside the domain name \(e.g., ze.lster.com\).
* **Insertion**: It **inserts a letter** into the domain name \(e.g., zerltser.com\).
* **Bitsquatting:** It anticipates a small portion of systems encountering hardware errors, resulting in the mutation of the resolved domain name by 1 bit. \(e.g., xeltser.com\).
* **Missing dot**: Append the TLD to the domain name. \(e.g., zelstercom.com\)

### Automatic Tools

* \*\*\*\*[**dnstwist**](https://github.com/elceef/dnstwist)\*\*\*\*
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)\*\*\*\*

### **Websites**

* [https://dnstwist.it/](https://dnstwist.it/)
* [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

## References

* [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
* [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)

