# Domain Escalation

<details>

<summary><strong>Support HackTricks and get benefits!</strong></summary>

Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

**Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**

**Share your hacking tricks submitting PRs to the** [**hacktricks github repo**](https://github.com/carlospolop/hacktricks)**.**

</details>

## Misconfigured Certificate Templates - ESC1

* The **Enterprise CA** grants **low-privileged users enrolment rights**
* **Manager approval is disabled**
* **No authorized signatures are required**
* An overly permissive **certificate template** security descriptor **grants certificate enrolment rights to low-privileged users**
* The **certificate template defines EKUs that enable authentication**:&#x20;
  * _Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), or no EKU (SubCA)._
* The **certificate template allows requesters to specify a subjectAltName in the CSR:**
  * **AD** will **use** the identity specified by a certificate’s **subjectAltName** (SAN) field **if** it is **present**. Consequently, if a requester can specify the SAN in a CSR, the requester can **request a certificate as anyone** (e.g., a domain admin user). The certificate template’s AD object **specifies** if the requester **can specify the SAN** in its **`mspki-certificate-name-`**`flag` property. The `mspki-certificate-name-flag` property is a **bitmask** and if the **`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`** flag is **present**, a **requester can specify the SAN.**

{% hint style="danger" %}
These settings allow a **low-privileged user to request a certificate with an arbitrary SAN**, allowing the low-privileged user to authenticate as any principal in the domain via Kerberos or SChannel.
{% endhint %}

This is often enabled, for example, to allow products or deployment services to generate HTTPS certificates or host certificates on the fly. Or because of lack of knowledge.

Note that when a certificate with this last option is created a **warning appears**, but it doesn't appear if a **certificate template** with this configuration is **duplicated** (like the `WebServer` template which has `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` enabled and then the admin might add an authentication OID).

To **find vulnerable certificate templates** you can run:

```bash
Certify.exe find /vulnerable
```

To **abuse this vulnerability to impersonate an administrator** one could run:

```bash
Certify.exe request /ca:dc.theshire.local-DC-CA /template:VulnTemplate /altname:localadmin
```

Then you can transform the generated **certificate to `.pfx`** format and use it to **authenticate using Rubeus**:

```
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
```

Moreover, the following LDAP query when run against the AD Forest’s configuration schema can be used to **enumerate** **certificate templates** that do **not require approval/signatures**, that have a **Client Authentication or Smart Card Logon EKU**, and have the **`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`** flag enabled:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```

## Misconfigured Certificate Templates - ESC2

The second abuse scenario is a variation of the first one:

1. The Enterprise CA grants low-privileged users enrollment rights.
2. Manager approval is disabled.
3. No authorized signatures are required.
4. An overly permissive certificate template security descriptor grants certificate enrollment rights to low-privileged users.
5. **The certificate template defines the Any Purpose EKU or no EKU.**

The **Any Purpose EKU** allows an attacker to get a **certificate** for **any purpose** like client authentication, server authentication, code signing, etc.

A **certificate with no EKUs** — a subordinate CA certificate —  can be abused for **any purpose** as well but could **also use it to sign new certificates**. As such, using a subordinate CA certificate, an attacker could **specify arbitrary EKUs or fields in the new certificates.**

However, if the **subordinate CA is not trusted** by the **`NTAuthCertificates`** object (which it won’t be by default), the attacker **cannot create new certificates** that will work for **domain authentication**. Still, the attacker can create **new certificates with any EKU** and arbitrary certificate values, of which there’s **plenty** the attacker could potentially **abuse** (e.g., code signing, server authentication, etc.) and might have large implications for other applications in the network like SAML, AD FS, or IPSec.

The following LDAP query when run against the AD Forest’s configuration schema can be used to enumerate templates matching this scenario:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```

## Misconfigured Enrolment Agent Templates - ESC3

This scenario is like the first and second one but **abusing** a **different EKU** (Certificate Request Agent) and **2 different templates** (therefore it has 2 sets of requirements),

The **Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), known as **Enrollment Agent** in Microsoft documentation, allows a principal to **enroll** for a **certificate** on **behalf of another user**.

The **“enrollment agent”** enrolls in such a **template** and uses the resulting **certificate to co-sign a CSR on behalf of the other user**. It then **sends** the **co-signed CSR** to the CA, enrolling in a **template** that **permits “enroll on behalf of”**, and the CA responds with a **certificate belong to the “other” user**.

**Requirements 1:**

1. The Enterprise CA allows low-privileged users enrollment rights.
2. Manager approval is disabled.
3. No authorized signatures are required.
4. An overly permissive certificate template security descriptor allows certificate enrollment rights to low-privileged users.
5. The **certificate template defines the Certificate Request Agent EKU**. The Certificate Request Agent OID (1.3.6.1.4.1.311.20.2.1) allows for requesting other certificate templates on behalf of other principals.

**Requirements 2:**

1. The Enterprise CA allows low-privileged users enrollment rights.
2. Manager approval is disabled.
3. **The template schema version 1 or is greater than 2 and specifies an Application Policy Issuance Requirement requiring the Certificate Request Agent EKU.**
4. The certificate template defines an EKU that allows for domain authentication.
5. Enrollment agent restrictions are not implemented on the CA.

You can use [**Certify**](https://github.com/GhostPack/Certify) to abuse this scenario:

```bash
# Request an enrollment agent certificate
Certify.exe request /ca:CORPDC01.CORP.LOCAL\CORP-CORPDC01-CA /template:Vuln-EnrollmentAgent

# Enrollment agent certificate to issue a certificate request on behalf of
# another user to a template that allow for domain authentication
Certify.exe request /ca:CORPDC01.CORP.LOCAL\CORP-CORPDC01-CA /template:User /onbehalfof:CORP\itadmin /enrollment:enrollmentcert.pfx /enrollcertpwd:asdf

# Use Rubeus with the certificate to authenticate as the other user
Certify.exe asktgt /user:CORP\itadmin /certificate:itadminenrollment.pfx /password:asdf
```

Enterprise CAs can **constrain** the **users** who can **obtain** an **enrollment agent certificate**, the templates enrollment **agents can enroll in**, and which **accounts** the enrollment agent can **act on behalf of** by opening `certsrc.msc` `snap-in -> right clicking on the CA -> clicking Properties -> navigating` to the “Enrollment Agents” tab.

However, the **default** CA setting is “**Do not restrict enrollment agents”.** Even when administrators enable “Restrict enrollment agents”, the default setting is extremely permissive, allowing Everyone access enroll in all templates as anyone.

## Vulnerable Certificate Template Access Control - ESC4

**Certificate templates** have a **security descriptor** that specifies which AD **principals** have specific **permissions over the template**.

If an **attacker** has enough **permissions** to **modify** a **template** and **create** any of the exploitable **misconfigurations** from the **previous sections**, he will be able to exploit it and **escalate privileges**.

Interesting rights over certificate templates:

* **Owner:** Implicit full control of the object, can edit any properties.
* **FullControl:** Full control of the object, can edit any properties.
* **WriteOwner:** Can modify the owner to an attacker-controlled principal.
* **WriteDacl**: Can modify access control to grant an attacker FullControl.
* **WriteProperty:** Can edit any properties

## Vulnerable PKI Object Access Control - ESC5

The web of interconnected ACL based relationships that can affect the security of AD CS is extensive. Several **objects outside of certificate** templates and the certificate authority itself can have a **security impact on the entire AD CS system**. These possibilities include (but are not limited to):

* The **CA server’s AD computer object** (i.e., compromise through S4U2Self or S4U2Proxy)
* The **CA server’s RPC/DCOM server**
* Any **descendant AD object or container in the container** `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` (e.g., the Certificate Templates container, Certification Authorities container, the NTAuthCertificates object, the Enrollment Services Container, etc.)

If a low-privileged attacker can gain **control over any of these**, the attack can likely **compromise the PKI system**.

## EDITF\_ATTRIBUTESUBJECTALTNAME2 - ESC6

There is another similar issue, described in the [**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage), which involves the **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag. As Microsoft describes, “**If** this flag is **set** on the CA, **any request** (including when the subject is built from Active Directory®) can have **user defined values** in the **subject alternative name**.”\
This means that an **attacker** can enroll in **ANY template** configured for domain **authentication** that also **allows unprivileged** users to enroll (e.g., the default User template) and **obtain a certificate** that allows us to **authenticate** as a domain admin (or **any other active user/machine**).

**Note**: the **alternative names** here are **included** in a CSR via the `-attrib "SAN:"` argument to `certreq.exe` (i.e., “Name Value Pairs”). This is **different** than the method for **abusing SANs** in ESC1 as it **stores account information in a certificate attribute vs a certificate extension**.

Organizations can **check if the setting is enabled** using the following `certutil.exe` command:

```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```

Underneath, this just uses **remote** **registry**, so the following command may work as well:

```
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags 
```

****[**Certify**](https://github.com/GhostPack/Certify) also checks for this and can be used to abuse this misconfiguration:

```bash
# Check for vulns, including this one
Certify.exe find

# Abuse vuln
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:User /altname:localadmin
```

These settings can be **set**, assuming **domain administrative** (or equivalent) rights, from any system:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```

If you find this setting in your environment, you can **remove this flag** with:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```

<details>

<summary><strong>Support HackTricks and get benefits!</strong></summary>

Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

**Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**

**Share your hacking tricks submitting PRs to the** [**hacktricks github repo**](https://github.com/carlospolop/hacktricks)**.**

</details>
