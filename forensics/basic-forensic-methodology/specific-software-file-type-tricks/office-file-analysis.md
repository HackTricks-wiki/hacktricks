

<details>

<summary><strong>Support HackTricks and get benefits!</strong></summary>

Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

**Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**

**Share your hacking tricks submitting PRs to the** [**hacktricks github repo**](https://github.com/carlospolop/hacktricks)**.**

</details>


# Office file analysis

## Introduction

Microsoft has created **dozens of office document file formats**, many of which are popular for the distribution of phishing attacks and malware because of their ability to **include macros** (VBA scripts).

Broadly speaking, there are two generations of Office file format: the **OLE formats** (file extensions like RTF, DOC, XLS, PPT), and the "**Office Open XML**" formats (file extensions that include DOCX, XLSX, PPTX). **Both** formats are structured, compound file binary formats that **enable Linked or Embedded content** (Objects). OOXML files are actually zip file containers, meaning that one of the easiest ways to check for hidden data is to simply `unzip` the document:

```
$ unzip example.docx 
Archive:  example.docx
  inflating: [Content_Types].xml     
  inflating: _rels/.rels             
  inflating: word/_rels/document.xml.rels  
  inflating: word/document.xml       
  inflating: word/theme/theme1.xml   
 extracting: docProps/thumbnail.jpeg  
  inflating: word/comments.xml       
  inflating: word/settings.xml       
  inflating: word/fontTable.xml      
  inflating: word/styles.xml         
  inflating: word/stylesWithEffects.xml  
  inflating: docProps/app.xml        
  inflating: docProps/core.xml       
  inflating: word/webSettings.xml    
  inflating: word/numbering.xml
$ tree
.
├── [Content_Types].xml
├── _rels
├── docProps
│   ├── app.xml
│   ├── core.xml
│   └── thumbnail.jpeg
└── word
    ├── _rels
    │   └── document.xml.rels
    ├── comments.xml
    ├── document.xml
    ├── fontTable.xml
    ├── numbering.xml
    ├── settings.xml
    ├── styles.xml
    ├── stylesWithEffects.xml
    ├── theme
    │   └── theme1.xml
    └── webSettings.xml
```

As you can see, some of the structure is created by the file and folder hierarchy. The rest is specified inside the XML files. [_New Steganographic Techniques for the OOXML File Format_, 2011](http://download.springer.com/static/pdf/713/chp%3A10.1007%2F978-3-642-23300-5\_27.pdf?originUrl=http%3A%2F%2Flink.springer.com%2Fchapter%2F10.1007%2F978-3-642-23300-5\_27\&token2=exp=1497911340\~acl=%2Fstatic%2Fpdf%2F713%2Fchp%25253A10.1007%25252F978-3-642-23300-5\_27.pdf%3ForiginUrl%3Dhttp%253A%252F%252Flink.springer.com%252Fchapter%252F10.1007%252F978-3-642-23300-5\_27\*\~hmac=aca7e2655354b656ca7d699e8e68ceb19a95bcf64e1ac67354d8bca04146fd3d) details some ideas for data hiding techniques, but CTF challenge authors will always be coming up with new ones.

Once again, a Python toolset exists for the examination and **analysis of OLE and OOXML documents**: [oletools](http://www.decalage.info/python/oletools). For OOXML documents in particular, [OfficeDissector](https://www.officedissector.com) is a very powerful analysis framework (and Python library). The latter includes a [quick guide to its usage](https://github.com/grierforensics/officedissector/blob/master/doc/html/\_sources/txt/ANALYZING\_OOXML.txt).

Sometimes the challenge is not to find hidden static data, but to **analyze a VBA macro** to determine its behavior. This is a more realistic scenario, and one that analysts in the field perform every day. The aforementioned dissector tools can indicate whether a macro is present, and probably extract it for you. A typical VBA macro in an Office document, on Windows, will download a PowerShell script to %TEMP% and attempt to execute it, in which case you now have a PowerShell script analysis task too. But malicious VBA macros are rarely complicated, since VBA is [typically just used as a jumping-off platform to bootstrap code execution](https://www.lastline.com/labsblog/party-like-its-1999-comeback-of-vba-malware-downloaders-part-3/). In the case where you do need to understand a complicated VBA macro, or if the macro is obfuscated and has an unpacker routine, you don't need to own a license to Microsoft Office to debug this. You can use [Libre Office](http://libreoffice.org): [its interface](http://www.debugpoint.com/2014/09/debugging-libreoffice-macro-basic-using-breakpoint-and-watch/) will be familiar to anyone who has debugged a program; you can set breakpoints and create watch variables and capture values after they have been unpacked but before whatever payload behavior has executed. You can even start a macro of a specific document from a command line:

```
$ soffice path/to/test.docx macro://./standard.module1.mymacro
```

## [oletools](https://github.com/decalage2/oletools)

```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```

## Automatic Execution

Macro functions like `AutoOpen`, `AutoExec` or `Document_Open` will be **automatically** **executed**.

## References

* [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)


<details>

<summary><strong>Support HackTricks and get benefits!</strong></summary>

Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

**Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**

**Share your hacking tricks submitting PRs to the** [**hacktricks github repo**](https://github.com/carlospolop/hacktricks)**.**

</details>


