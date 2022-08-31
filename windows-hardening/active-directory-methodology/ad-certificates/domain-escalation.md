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

<details>

<summary><strong>Support HackTricks and get benefits!</strong></summary>

Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

**Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**

**Share your hacking tricks submitting PRs to the** [**hacktricks github repo**](https://github.com/carlospolop/hacktricks)**.**

</details>
