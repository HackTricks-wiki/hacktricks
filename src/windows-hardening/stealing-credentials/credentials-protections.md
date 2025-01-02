# Windows Credentials Protections

## Credentials Protections

{{#include ../../banners/hacktricks-training.md}}

## WDigest

[WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>) プロトコルは、Windows XP と共に導入され、HTTP プロトコルを介した認証のために設計されており、**Windows XP から Windows 8.0 および Windows Server 2003 から Windows Server 2012 までデフォルトで有効**です。このデフォルト設定により、**LSASS にプレーンテキストのパスワードが保存されます**（ローカル セキュリティ認証局サブシステムサービス）。攻撃者は Mimikatz を使用して、次のコマンドを実行することで **これらの資格情報を抽出**できます:
```bash
sekurlsa::wdigest
```
この機能を**オフまたはオンに切り替える**には、_**UseLogonCredential**_ および _**Negotiate**_ レジストリキーを _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ 内で "1" に設定する必要があります。これらのキーが**存在しないか "0" に設定されている**場合、WDigestは**無効**になります。
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA保護

**Windows 8.1**以降、MicrosoftはLSAのセキュリティを強化し、**信頼されていないプロセスによる不正なメモリ読み取りやコード注入をブロック**するようにしました。この強化により、`mimikatz.exe sekurlsa:logonpasswords`のようなコマンドの通常の機能が妨げられます。この**強化された保護を有効にする**には、_**HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**_内の_**RunAsPPL**_値を1に調整する必要があります。
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### バイパス

この保護をバイパスすることは、Mimikatzドライバーmimidrv.sysを使用して可能です：

![](../../images/mimidrv.png)

## Credential Guard

**Credential Guard**は、**Windows 10 (EnterpriseおよびEducationエディション)**専用の機能で、**Virtual Secure Mode (VSM)**と**Virtualization Based Security (VBS)**を使用してマシンの資格情報のセキュリティを強化します。これは、CPUの仮想化拡張を利用して、主要なプロセスを保護されたメモリ空間内に隔離し、メインオペレーティングシステムのアクセスから遠ざけます。この隔離により、カーネルでさえVSM内のメモリにアクセスできず、**pass-the-hash**のような攻撃から資格情報を効果的に保護します。**Local Security Authority (LSA)**は、この安全な環境内でトラストレットとして動作し、メインOSの**LSASS**プロセスはVSMのLSAとの通信者としてのみ機能します。

デフォルトでは、**Credential Guard**はアクティブではなく、組織内で手動での有効化が必要です。これは、資格情報を抽出する能力が制限されるため、**Mimikatz**のようなツールに対するセキュリティを強化するために重要です。ただし、カスタム**Security Support Providers (SSP)**を追加することで、ログイン試行中に平文で資格情報をキャプチャするために脆弱性が悪用される可能性があります。

**Credential Guard**の有効化状態を確認するには、_**HKLM\System\CurrentControlSet\Control\LSA**_の下にあるレジストリキー_**LsaCfgFlags**_を検査できます。値が"**1**"の場合は**UEFIロック**で有効化されており、"**2**"はロックなし、"**0**"は無効を示します。このレジストリチェックは強力な指標ですが、Credential Guardを有効にするための唯一のステップではありません。この機能を有効にするための詳細なガイダンスとPowerShellスクリプトはオンラインで入手可能です。
```powershell
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
包括**Credential Guard**をWindows 10で有効にし、**Windows 11 Enterprise and Education (version 22H2)**の互換性のあるシステムでの自動アクティベーションに関する包括的な理解と指示については、[Microsoftのドキュメント](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage)を参照してください。

資格情報キャプチャのためのカスタムSSPの実装に関する詳細は、[このガイド](../active-directory-methodology/custom-ssp.md)に記載されています。

## RDP RestrictedAdmin Mode

**Windows 8.1とWindows Server 2012 R2**は、_**RDPのRestricted Adminモード**_を含むいくつかの新しいセキュリティ機能を導入しました。このモードは、[**パス・ザ・ハッシュ**](https://blog.ahasayen.com/pass-the-hash/)攻撃に関連するリスクを軽減することでセキュリティを強化することを目的としています。

従来、RDPを介してリモートコンピュータに接続する際、資格情報はターゲットマシンに保存されます。これは、特に特権のあるアカウントを使用する場合に重大なセキュリティリスクをもたらします。しかし、_**Restricted Adminモード**_の導入により、このリスクは大幅に軽減されます。

**mstsc.exe /RestrictedAdmin**コマンドを使用してRDP接続を開始すると、リモートコンピュータへの認証は、資格情報をその上に保存することなく行われます。このアプローチにより、マルウェア感染や悪意のあるユーザーがリモートサーバーにアクセスした場合でも、資格情報がサーバーに保存されていないため、危険にさらされることはありません。

**Restricted Adminモード**では、RDPセッションからネットワークリソースにアクセスしようとする試みは、個人の資格情報を使用せず、代わりに**マシンのアイデンティティ**が使用されることに注意が必要です。

この機能は、リモートデスクトップ接続のセキュリティを強化し、セキュリティ侵害が発生した場合に機密情報が露出するのを防ぐための重要なステップです。

![](../../images/RAM.png)

詳細情報については、[このリソース](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/)を参照してください。

## Cached Credentials

Windowsは、**Local Security Authority (LSA)**を通じて**ドメイン資格情報**を保護し、**Kerberos**や**NTLM**などのセキュリティプロトコルを使用してログオンプロセスをサポートします。Windowsの重要な機能の一つは、**最後の10回のドメインログイン**をキャッシュする能力であり、これにより**ドメインコントローラーがオフライン**の場合でもユーザーがコンピュータにアクセスできるようになります。これは、会社のネットワークから離れていることが多いノートパソコンユーザーにとって大きな利点です。

キャッシュされたログインの数は、特定の**レジストリキーまたはグループポリシー**を介して調整可能です。この設定を表示または変更するには、次のコマンドが使用されます：
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
これらのキャッシュされた資格情報へのアクセスは厳しく制御されており、**SYSTEM** アカウントのみがそれらを表示するための必要な権限を持っています。情報にアクセスする必要がある管理者は、SYSTEM ユーザー権限で行う必要があります。資格情報は次の場所に保存されています: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** は、コマンド `lsadump::cache` を使用してこれらのキャッシュされた資格情報を抽出するために使用できます。

詳細については、元の [source](http://juggernaut.wikidot.com/cached-credentials) が包括的な情報を提供しています。

## 保護されたユーザー

**Protected Users group** へのメンバーシップは、ユーザーに対していくつかのセキュリティ強化を導入し、資格情報の盗難や悪用に対するより高い保護レベルを確保します：

- **Credential Delegation (CredSSP)**: **Allow delegating default credentials** のグループポリシー設定が有効であっても、Protected Users の平文資格情報はキャッシュされません。
- **Windows Digest**: **Windows 8.1 および Windows Server 2012 R2** 以降、システムは Protected Users の平文資格情報をキャッシュしません。Windows Digest の状態に関係なく。
- **NTLM**: システムは Protected Users の平文資格情報や NT 一方向関数 (NTOWF) をキャッシュしません。
- **Kerberos**: Protected Users に対して、Kerberos 認証は **DES** または **RC4 keys** を生成せず、平文資格情報や初期 Ticket-Granting Ticket (TGT) 取得を超える長期キーをキャッシュしません。
- **Offline Sign-In**: Protected Users はサインインまたはロック解除時にキャッシュされた検証子が作成されないため、これらのアカウントではオフラインサインインはサポートされていません。

これらの保護は、**Protected Users group** のメンバーであるユーザーがデバイスにサインインした瞬間に有効になります。これにより、資格情報の侵害に対するさまざまな方法から保護するための重要なセキュリティ対策が講じられます。

詳細な情報については、公式の [documentation](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group) を参照してください。

**Table from** [**the docs**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators           | Administrators                                                                | Administrators               |
| Backup Operators        | Backup Operators         | Backup Operators                                                              | Backup Operators             |
| Cert Publishers         |                          |                                                                               |                              |
| Domain Admins           | Domain Admins            | Domain Admins                                                                 | Domain Admins                |
| Domain Controllers      | Domain Controllers       | Domain Controllers                                                            | Domain Controllers           |
| Enterprise Admins       | Enterprise Admins        | Enterprise Admins                                                             | Enterprise Admins            |
|                         |                          |                                                                               | Enterprise Key Admins        |
|                         |                          |                                                                               | Key Admins                   |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Print Operators         | Print Operators          | Print Operators                                                               | Print Operators              |
|                         |                          | Read-only Domain Controllers                                                  | Read-only Domain Controllers |
| Replicator              | Replicator               | Replicator                                                                    | Replicator                   |
| Schema Admins           | Schema Admins            | Schema Admins                                                                 | Schema Admins                |
| Server Operators        | Server Operators         | Server Operators                                                              | Server Operators             |

{{#include ../../banners/hacktricks-training.md}}
