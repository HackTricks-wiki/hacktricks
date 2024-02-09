# Windows Credentials Protections

## 資格情報の保護

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい** または **HackTricks をPDFでダウンロードしたい** 場合は [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションを見つける
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)** に参加するか、[telegramグループ](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live) をフォローする
* **ハッキングテクニックを共有するために、PRを** [**HackTricks**](https://github.com/carlospolop/hacktricks) **と** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **のGitHubリポジトリに提出してください。**

</details>

## WDigest

[WDigest](https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396) プロトコルは、Windows XPで導入され、HTTPプロトコルを介した認証用に設計されており、**Windows XPからWindows 8.0、Windows Server 2003からWindows Server 2012までのデフォルトで有効**です。このデフォルト設定により、**LSASS（Local Security Authority Subsystem Service）に平文パスワードが保存**されます。攻撃者はMimikatzを使用して、次のコマンドを実行することで、これらの資格情報を**抽出**することができます：
```bash
sekurlsa::wdigest
```
**この機能をオンまたはオフに切り替える**には、_**HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ 内の _**UseLogonCredential**_ および _**Negotiate**_ レジストリキーを "1" に設定する必要があります。これらのキーが**存在しないか "0" に設定されている**場合、WDigest は**無効**になります。
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA保護

**Windows 8.1**からは、MicrosoftはLSAのセキュリティを強化し、**信頼されていないプロセスによる許可されていないメモリ読み取りやコードインジェクションをブロック**するようにしました。この強化により、`mimikatz.exe sekurlsa:logonpasswords`のようなコマンドの通常の機能が妨げられます。この強化された保護を**有効にする**には、_**HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**_内の_RunAsPPL_値を1に調整する必要があります：
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### バイパス

Mimikatzドライバーmimidrv.sysを使用して、この保護をバイパスすることが可能です：

![](../../.gitbook/assets/mimidrv.png)

## 資格情報ガード

**資格情報ガード**は、**Windows 10（エンタープライズおよび教育エディション）**にのみ存在する機能で、**仮想セキュアモード（VSM）**と**仮想化ベースセキュリティ（VBS）**を使用してマシンの資格情報のセキュリティを強化します。CPU仮想化拡張を活用して、主要なオペレーティングシステムから離れた保護されたメモリ空間内で重要なプロセスを分離します。この分離により、カーネルでさえVSM内のメモリにアクセスできないため、**パスザハッシュ**などの攻撃から資格情報を効果的に保護します。**ローカルセキュリティ機関（LSA）**は、この安全な環境内で信頼性を持って動作し、メインOS内の**LSASS**プロセスは、VSMのLSAとの通信者としてのみ機能します。

**資格情報ガード**はデフォルトではアクティブではなく、組織内での手動アクティベーションが必要です。これは、**Mimikatz**などのツールに対するセキュリティを強化するために重要です。ただし、カスタム**セキュリティサポートプロバイダ（SSP）**の追加により、ログイン試行中にクリアテキストで資格情報を取得する脆弱性が依然として悪用される可能性があります。

**資格情報ガード**のアクティベーション状態を確認するには、**_HKLM\System\CurrentControlSet\Control\LSA_**の下にある**_LsaCfgFlags_**レジストリキーを調査できます。値が「**1**」の場合は、**UEFIロック**でのアクティベーションを示し、「**2**」はロックなし、そして「**0**」は無効であることを示します。このレジストリチェックは強力な指標でありながら、資格情報ガードを有効にするための唯一の手順ではありません。この機能を有効にするための詳細なガイダンスとPowerShellスクリプトがオンラインで利用可能です。
```powershell
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Windows 10 で **Credential Guard** を有効にする手順や、**Windows 11 Enterprise および Education (バージョン 22H2)** における互換システムでの自動有効化についての包括的な理解と手順については、[Microsoft のドキュメント](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage) を参照してください。

資格情報キャプチャ用のカスタム SSP の実装の詳細については、[このガイド](../active-directory-methodology/custom-ssp.md) で提供されています。


## RDP RestrictedAdmin モード

**Windows 8.1 および Windows Server 2012 R2** では、**_RDP の Restricted Admin モード_** など、複数の新しいセキュリティ機能が導入されました。このモードは、**[パスザハッシュ](https://blog.ahasayen.com/pass-the-hash/)** 攻撃に関連するリスクを軽減することを目的として設計されました。

従来、RDP を介してリモートコンピュータに接続すると、資格情報がターゲットマシンに保存されます。これは、特権の昇格アカウントを使用する場合など、重大なセキュリティリスクを引き起こす可能性があります。しかし、**_Restricted Admin モード_** の導入により、このリスクは大幅に軽減されます。

コマンド **mstsc.exe /RestrictedAdmin** を使用して RDP 接続を開始すると、リモートコンピュータへの認証が資格情報を保存せずに行われます。このアプローチにより、マルウェア感染や悪意のあるユーザがリモートサーバにアクセスした場合でも、資格情報がサーバに保存されていないため、情報漏洩のリスクが軽減されます。

**Restricted Admin モード** では、RDP セッションからネットワークリソースにアクセスしようとする試みは、個人の資格情報ではなく、**マシンの識別子** が使用されます。

この機能は、リモートデスクトップ接続のセキュリティを向上させ、セキュリティ侵害の際に機密情報が露出するのを防ぐ点で重要な進歩と言えます。

![](../../.gitbook/assets/ram.png)

詳細については、[このリソース](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/) を参照してください。


## キャッシュされた資格情報

Windows は **Local Security Authority (LSA)** を介して **ドメイン資格情報** を保護し、**Kerberos** や **NTLM** のようなセキュリティプロトコルをサポートしています。Windows の重要な機能の1つは、**最後の 10 つのドメインログイン** をキャッシュしており、**ドメインコントローラがオフライン** の場合でもユーザがコンピュータにアクセスできるようにしています。これは、企業のネットワークから離れていることが多いノートパソコンユーザにとって便利です。

キャッシュされるログイン数は、特定の **レジストリキーまたはグループポリシー** を介して調整できます。この設定を表示または変更するには、次のコマンドを使用します：
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
これらのキャッシュされた資格情報へのアクセスは厳密に制御されており、**SYSTEM**アカウントだけがそれらを表示するために必要な権限を持っています。この情報にアクセスする必要がある管理者は、SYSTEMユーザー権限で行う必要があります。資格情報は以下に保存されています：`HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz**を使用して、`lsadump::cache`コマンドを使ってこれらのキャッシュされた資格情報を抽出することができます。

詳細については、元の[ソース](http://juggernaut.wikidot.com/cached-credentials)が包括的な情報を提供しています。


## 保護されたユーザー

**Protected Usersグループ**へのメンバーシップにより、ユーザーのセキュリティが向上し、資格情報の盗難や誤用に対する保護レベルが向上します：

- **資格情報委任（CredSSP）**：**デフォルトの資格情報の委任を許可**するグループポリシー設定が有効になっていても、Protected Usersの平文資格情報はキャッシュされません。
- **Windows Digest**：**Windows 8.1およびWindows Server 2012 R2**から、Protected Usersの平文資格情報はWindows Digestの状態に関係なくキャッシュされません。
- **NTLM**：システムはProtected Usersの平文資格情報やNTワンウェイ関数（NTOWF）をキャッシュしません。
- **Kerberos**：Protected Usersに対して、Kerberos認証は**DES**または**RC4キー**を生成せず、平文資格情報や初期のTicket-Granting Ticket（TGT）取得を超えた長期キーをキャッシュしません。
- **オフラインサインイン**：Protected Usersはサインインやロック解除時にキャッシュされた検証子を作成しないため、これらのアカウントではオフラインサインインはサポートされません。

これらの保護機能は、**Protected Usersグループ**のメンバーであるユーザーがデバイスにサインインするとすぐに有効になります。これにより、さまざまな資格情報の侵害手法に対する保護が確保されます。

詳細な情報については、公式[ドキュメント](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)を参照してください。

**ドキュメント**からの**表** [**の表**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

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
