# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#3f17" id="3f17"></a>

**Check the original post for [all the information about this technique](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**<sup>[[1]](#references)</sup>

In summary, control of a user's or computer's **`msDS-KeyCredentialLink`** can let an attacker add a key credential, authenticate as that object with PKINIT, and—when the KDC and account support the necessary flows—use the resulting ticket with `S4U2Self`/user-to-user to recover the object's NT hash.<sup>[[1]](#references)</sup>

In the post, a method is outlined for setting up **public-private key authentication credentials** to acquire a unique **Service Ticket** that includes the target's NTLM hash. This process involves the encrypted NTLM_SUPPLEMENTAL_CREDENTIAL within the Privilege Attribute Certificate (PAC), which can be decrypted.<sup>[[1]](#references)</sup>

### Requirements

To apply this technique, certain conditions must be met:<sup>[[1]](#references)</sup>

- A minimum of one Windows Server 2016 Domain Controller is needed.
- The Domain Controller must have a server authentication digital certificate installed.
- The directory schema must contain `msDS-KeyCredentialLink`; a Windows Server 2016 or newer DC and a PKINIT-capable certificate on the KDC are the practical platform requirements described by the research. Verify the domain's schema/DC mix rather than assuming the domain functional-level label alone decides exploitability.
- An account with delegated rights to modify the msDS-KeyCredentialLink attribute of the target object is required.

## Abuse

The abuse of Key Trust for computer objects encompasses steps beyond obtaining a Ticket Granting Ticket (TGT) and the NTLM hash. The options include:<sup>[[1]](#references)</sup>

1. Creating an **RC4 silver ticket** to act as privileged users on the intended host.
2. Using the TGT with **S4U2Self** for impersonation of **privileged users**, necessitating alterations to the Service Ticket to add a service class to the service name.

A significant advantage of Key Trust abuse is its limitation to the attacker-generated private key, avoiding delegation to potentially vulnerable accounts and not requiring the creation of a computer account, which could be challenging to remove.<sup>[[1]](#references)</sup>

## Tools

### [**Whisker**](https://github.com/eladshamir/Whisker)

Whisker uses DSInternals to manipulate `msDS-KeyCredentialLink` from C#. Whisker and its Python counterpart **pyWhisker** support adding, listing, removing, and clearing key credentials.<sup>[[2]](#references)[[4]](#references)</sup>

**Whisker** functions include:

- **Add**: Generates a key pair and adds a key credential.
- **List**: Displays all key credential entries.
- **Remove**: Deletes a specified key credential.
- **Clear**: Erases all key credentials, potentially disrupting legitimate WHfB usage.

```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```

### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

pyWhisker brings the workflow to **UNIX-like systems** with Impacket and PyDSInternals, including list/add/remove and JSON import/export operations.<sup>[[4]](#references)</sup>

```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```

### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray enumerates domain objects over which the operator has rights such as `GenericWrite`/`GenericAll`, attempts to add key credentials broadly, and includes cleanup/recursive modes. Broad spraying is disruptive and conspicuous; use explicit targets and retain each added DeviceID for precise removal.<sup>[[3]](#references)</sup>

## References

- [1] [Shadow Credentials: Abusing Key Trust Account Mapping for Account Takeover](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker - Tool for taking over AD accounts by manipulating msDS-KeyCredentialLink](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray - Tool to spray Shadow Credentials across a domain](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker - Python version of the Shadow Credentials tool](https://github.com/ShutdownRepo/pywhisker)

{{#include ../../../banners/hacktricks-training.md}}
