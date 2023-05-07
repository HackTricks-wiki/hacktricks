# Kerberos Authentication

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

**This information was extracted from the post:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## Kerberos (I): How does Kerberos work? – Theory

20 - MAR - 2019 - ELOY PÉREZ

The objective of this series of posts is to clarify how Kerberos works, more than just introduce the attacks. This due to the fact that in many occasions it is not clear why some techniques works or not. Having this knowledge allows to know when to use any of those attacks in a pentest.

Therefore, after a long journey of diving into the documentation and several posts about the topic, we’ve tried to write in this post all the important details which an auditor should know in order to understand how take advantage of Kerberos protocol.

In this first post only basic functionality will be discussed. In later posts it will see how perform the attacks and how the more complex aspects works, as delegation.

If you have any doubt about the topic which it is not well explained, do not be afraid on leave a comment or question about it. Now, onto the topic.

### What is Kerberos?

Firstly, Kerberos is an authentication protocol, not authorization. In other words, it allows to identify each user, who provides a secret password, however, it does not validates to which resources or services can this user access.

Kerberos is used in Active Directory. In this platform, Kerberos provides information about the privileges of each user, but it is the responsibility of each service to determine if the user has access to its resources.

### Kerberos items

In this section several components of Kerberos environment will be studied.

**Transport layer**

Kerberos uses either UDP or TCP as transport protocol, which sends data in cleartext. Due to this Kerberos is responsible for providing encryption.

Ports used by Kerberos are UDP/88 and TCP/88, which should be listen in KDC (explained in next section).

**Agents**

Several agents work together to provide authentication in Kerberos. These are the following:

* **Client or user** who wants to access to the service.
* **AP** (Application Server) which offers the service required by the user.
* **KDC** (Key Distribution Center), the main service of Kerberos, responsible of issuing the tickets, installed on the DC (Domain Controller). It is supported by the **AS** (Authentication Service), which issues the TGTs.

**Encryption keys**

There are several structures handled by Kerberos, as tickets. Many of those structures are encrypted or signed in order to prevent being tampered by third parties. These keys are the following:

* **KDC or krbtgt key** which is derivate from krbtgt account NTLM hash.
* **User key** which is derivate from user NTLM hash.
* **Service key** which is derivate from the NTLM hash of service owner, which can be a user or computer account.
* **Session key** which is negotiated between the user and KDC.
* **Service session key** to be use between user and service.

**Tickets**

The main structures handled by Kerberos are the tickets. These tickets are delivered to the users in order to be used by them to perform several actions in the Kerberos realm. There are 2 types:

* The **TGS** (Ticket Granting Service) is the ticket which user can use to authenticate against a service. It is encrypted with the service key.
* The **TGT** (Ticket Granting Ticket) is the ticket presented to the KDC to request for TGSs. It is encrypted with the KDC key.

**PAC**

The **PAC** (Privilege Attribute Certificate) is a structure included in almost every ticket. This structure contains the privileges of the user and it is signed with the KDC key.

It is possible to services to verify the PAC by communicating with the KDC, although this does not happen often. Nevertheless, the PAC verification consists of checking only its signature, without inspecting if privileges inside of PAC are correct.

Furthermore, a client can avoid the inclusion of the PAC inside the ticket by specifying it in _KERB-PA-PAC-REQUEST_ field of ticket request.

**Messages**

Kerberos uses differents kinds of messages. The most interesting are the following:

* **KRB\_AS\_REQ**: Used to request the TGT to KDC.
* **KRB\_AS\_REP**: Used to deliver the TGT by KDC.
* **KRB\_TGS\_REQ**: Used to request the TGS to KDC, using the TGT.
* **KRB\_TGS\_REP**: Used to deliver the TGS by KDC.
* **KRB\_AP\_REQ**: Used to authenticate a user against a service, using the TGS.
* **KRB\_AP\_REP**: (Optional) Used by service to identify itself against the user.
* **KRB\_ERROR**: Message to communicate error conditions.

Additionally, even if it is not part of Kerberos, but NRPC, the AP optionally could use the **KERB\_VERIFY\_PAC\_REQUEST** message to send to KDC the signature of PAC, and verify if it is correct.

Below is shown a summary of message sequency to perform authentication

![Kerberos messages summary](<../../.gitbook/assets/image (174) (1).png>)

### Authentication process

In this section, the sequency of messages to perform authentication will be studied, starting from a user without tickets, up to being authenticated against the desired service.

**KRB\_AS\_REQ**

Firstly, user must get a TGT from KDC. To achieve this, a KRB\_AS\_REQ must be sent:

![KRB\_AS\_REQ schema message](<../../.gitbook/assets/image (175) (1).png>)

_KRB\_AS\_REQ_ has, among others, the following fields:

* A encrypted **timestamp** with client key, to authenticate user and prevent replay attacks
* **Username** of authenticated user
* The service **SPN** asociated with **krbtgt** account
* A **Nonce** generated by the user

Note: the encrypted timestamp is only necessary if user requires preauthentication, which is common, except if [_DONT\_REQ\_PREAUTH_](https://support.microsoft.com/en-us/help/305144/how-to-use-the-useraccountcontrol-flags-to-manipulate-user-account-pro) \_\_ flag is set in user account.

**KRB\_AS\_REP**

After receiving the request, the KDC verifies the user identity by decrypting the timestamp. If the message is correct, then it must respond with a _KRB\_AS\_REP_:

![KRB\_AS\_REP schema message](<../../.gitbook/assets/image (176) (1).png>)

_KRB\_AS\_REP_ includes the next information:

* **Username**
* **TGT**, which includes:
  * **Username**
  * **Session key**
  * **Expiration date** of TGT
  * **PAC** with user privileges, signed by KDC
* Some **encrypted data** with user key, which includes:
  * **Session key**
  * **Expiration date** of TGT
  * User **nonce**, to prevent replay attacks

Once finished, user already has the TGT, which can be used to request TGSs, and afterwards access to the services.

**KRB\_TGS\_REQ**

In order to request a TGS, a _KRB\_TGS\_REQ_ message must be sent to KDC:

![KRB\_TGS\_REQ schema message](<../../.gitbook/assets/image (177).png>)

_KRB\_TGS\_REQ_ includes:

* **Encrypted data** with session key:
  * **Username**
  * **Timestamp**
* **TGT**
* **SPN** of requested service
* **Nonce** generated by user

**KRB\_TGS\_REP**

After receiving the _KRB\_TGS\_REQ_ message, the KDC returns a TGS inside of _KRB\_TGS\_REP_:

![KRB\_TGS\_REP schema message](<../../.gitbook/assets/image (178) (1).png>)

_KRB\_TGS\_REP_ includes:

* **Username**
* **TGS**, which contains:
  * **Service session key**
  * **Username**
  * **Expiration date** of TGS
  * **PAC** with user privileges, signed by KDC
* **Encrypted data** with session key:
  * **Service session key**
  * **Expiration date** of TGS
  * User **nonce**, to prevent replay attacks

**KRB\_AP\_REQ**

To finish, if everything went well, the user already has a valid TGS to interact with service. In order to use it, user must send to the AP a _KRB\_AP\_REQ_ message:

![KRB\_AP\_REQ schema message](<../../.gitbook/assets/image (179) (1).png>)

_KRB\_AP\_REQ_ includes:

* **TGS**
* **Encrypted data** with service session key:
  * **Username**
  * **Timestamp**, to avoid replay attacks

After that, if user privileges are rigth, this can access to service. If is the case, which not usually happens, the AP will verify the PAC against the KDC. And also, if mutual authentication is needed it will respond to user with a _KRB\_AP\_REP_ message.

### References

* Kerberos v5 RFC: [https://tools.ietf.org/html/rfc4120](https://tools.ietf.org/html/rfc4120)
* \[MS-KILE] – Kerberos extension: [https://msdn.microsoft.com/en-us/library/cc233855.aspx](https://msdn.microsoft.com/en-us/library/cc233855.aspx)
* \[MS-APDS] – Authentication Protocol Domain Support: [https://msdn.microsoft.com/en-us/library/cc223948.aspx](https://msdn.microsoft.com/en-us/library/cc223948.aspx)
* Mimikatz and Active Directory Kerberos Attacks: [https://adsecurity.org/?p=556](https://adsecurity.org/?p=556)
* Explain like I’m 5: Kerberos: [https://www.roguelynn.com/words/explain-like-im-5-kerberos/](https://www.roguelynn.com/words/explain-like-im-5-kerberos/)
* Kerberos & KRBTGT: [https://adsecurity.org/?p=483](https://adsecurity.org/?p=483)
* Mastering Windows Network Forensics and Investigation, 2 Edition . Autores: S. Anson , S. Bunting, R. Johnson y S. Pearson. Editorial Sibex.
* Active Directory , 5 Edition. Autores: B. Desmond, J. Richards, R. Allen y A.G. Lowe-Norris
* Service Principal Names: [https://msdn.microsoft.com/en-us/library/ms677949(v=vs.85).aspx](https://msdn.microsoft.com/en-us/library/ms677949\(v=vs.85\).aspx)
* Niveles funcionales de Active Directory: [https://technet.microsoft.com/en-us/library/dbf0cdec-d72f-4ba3-bc7a-46410e02abb0](https://technet.microsoft.com/en-us/library/dbf0cdec-d72f-4ba3-bc7a-46410e02abb0)
* OverPass The Hash – Gentilkiwi Blog: [https://blog.gentilkiwi.com/securite/mimikatz/overpass-the-hash](https://blog.gentilkiwi.com/securite/mimikatz/overpass-the-hash)
* Pass The Ticket – Gentilkiwi Blog: [https://blog.gentilkiwi.com/securite/mimikatz/pass-the-ticket-kerberos](https://blog.gentilkiwi.com/securite/mimikatz/pass-the-ticket-kerberos)
* Golden Ticket – Gentilkiwi Blog: [https://blog.gentilkiwi.com/securite/mimikatz/golden-ticket-kerberos](https://blog.gentilkiwi.com/securite/mimikatz/golden-ticket-kerberos)
* Mimikatz Golden Ticket Walkthrough: [https://www.beneaththewaves.net/Projects/Mimikatz\_20\_-\_Golden\_Ticket\_Walkthrough.html](https://www.beneaththewaves.net/Projects/Mimikatz\_20\_-\_Golden\_Ticket\_Walkthrough.html)
* Attacking Kerberos: Kicking the Guard Dog of Hades: [https://files.sans.org/summit/hackfest2014/PDFs/Kicking%20the%20Guard%20Dog%20of%20Hades%20-%20Attacking%20Microsoft%20Kerberos%20%20-%20Tim%20Medin(1).pdf](https://files.sans.org/summit/hackfest2014/PDFs/Kicking%20the%20Guard%20Dog%20of%20Hades%20-%20Attacking%20Microsoft%20Kerberos%20%20-%20Tim%20Medin\(1\).pdf)
* Kerberoasting – Part 1: [https://room362.com/post/2016/kerberoast-pt1/](https://room362.com/post/2016/kerberoast-pt1/)
* Kerberoasting – Part 2: [https://room362.com/post/2016/kerberoast-pt2/](https://room362.com/post/2016/kerberoast-pt2/)
* Roasting AS-REPs: [https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/](https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/)
* PAC Validation: [https://passing-the-hash.blogspot.com.es/2014/09/pac-validation-20-minute-rule-and.html](https://passing-the-hash.blogspot.com.es/2014/09/pac-validation-20-minute-rule-and.html)
* Understanding PAC Validation: [https://blogs.msdn.microsoft.com/openspecification/2009/04/24/understanding-microsoft-kerberos-pac-validation/](https://blogs.msdn.microsoft.com/openspecification/2009/04/24/understanding-microsoft-kerberos-pac-validation/)
* Reset the krbtgt acoount password/keys: [https://gallery.technet.microsoft.com/Reset-the-krbtgt-account-581a9e51](https://gallery.technet.microsoft.com/Reset-the-krbtgt-account-581a9e51)
* Mitigating Pass-the-Hash (PtH) Attacks and Other Credential Theft: [https://www.microsoft.com/en-us/download/details.aspx?id=36036](https://www.microsoft.com/en-us/download/details.aspx?id=36036)
* Fun with LDAP, Kerberos (and MSRPC) in AD Environments: [https://speakerdeck.com/ropnop/fun-with-ldap-kerberos-and-msrpc-in-ad-environments?slide=58](https://speakerdeck.com/ropnop/fun-with-ldap-kerberos-and-msrpc-in-ad-environments?slide=58)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
