# Windows Credentials Protections

{{#include ../../banners/hacktricks-training.md}}

## WDigest

[WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>) プロトコルは、Windows XP と共に導入され、HTTP プロトコルを介した認証のために設計されており、**Windows XP から Windows 8.0 および Windows Server 2003 から Windows Server 2012 までデフォルトで有効**です。このデフォルト設定により、**LSASS にプレーンテキストのパスワードが保存されます**（ローカル セキュリティ認証局サブシステムサービス）。攻撃者は Mimikatz を使用して、次のコマンドを実行することで**これらの資格情報を抽出**できます:
```bash
sekurlsa::wdigest
```
この機能を**オフまたはオンに切り替える**には、_**UseLogonCredential**_ および _**Negotiate**_ レジストリキーを _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ 内で "1" に設定する必要があります。これらのキーが**存在しないか "0" に設定されている**場合、WDigestは**無効**になります。
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA保護 (PPおよびPPL保護プロセス)

**保護プロセス (PP)** および **保護プロセスライト (PPL)** は、**LSASS** のような機密プロセスへの不正アクセスを防ぐために設計された **Windowsカーネルレベルの保護** です。**Windows Vista** で導入された **PPモデル** は、元々 **DRM** の施行のために作成され、**特別なメディア証明書** で署名されたバイナリのみが保護されることを許可していました。**PP** としてマークされたプロセスは、**同じくPP** で **同等またはそれ以上の保護レベル** を持つ他のプロセスからのみアクセス可能であり、その場合でも **特に許可されない限り、制限されたアクセス権** でのみアクセスできます。

**PPL** は **Windows 8.1** で導入され、PPのより柔軟なバージョンです。**デジタル署名のEKU (Enhanced Key Usage)** フィールドに基づいて **「保護レベル」** を導入することで、**より広範なユースケース** (例: LSASS, Defender) を可能にします。保護レベルは `EPROCESS.Protection` フィールドに格納されており、これは以下を持つ `PS_PROTECTION` 構造体です：
- **タイプ** (`Protected` または `ProtectedLight`)
- **署名者** (例: `WinTcb`, `Lsa`, `Antimalware` など)

この構造体は1バイトにパックされ、**誰が誰にアクセスできるか** を決定します：
- **高い署名者値は低いものにアクセスできる**
- **PPLはPPにアクセスできない**
- **保護されていないプロセスはPPL/PPにアクセスできない**

### 攻撃的な視点から知っておくべきこと

- **LSASSがPPLとして実行されている場合**、通常の管理者コンテキストから `OpenProcess(PROCESS_VM_READ | QUERY_INFORMATION)` を使用して開こうとすると、**`0x5 (アクセス拒否)`** で失敗します。たとえ `SeDebugPrivilege` が有効でもです。
- **Process Hacker** のようなツールを使用するか、プログラム的に `EPROCESS.Protection` 値を読み取ることで **LSASSの保護レベルを確認**できます。
- LSASSは通常、`PsProtectedSignerLsa-Light` (`0x41`) を持ち、**より高いレベルの署名者で署名されたプロセス**（例: `WinTcb` (`0x61` または `0x62`））のみがアクセスできます。
- PPLは **ユーザーランド専用の制限** であり、**カーネルレベルのコードは完全にバイパスできます**。
- LSASSがPPLであることは、**カーネルシェルコードを実行できる場合**や **適切なアクセス権を持つ高特権プロセスを利用できる場合** の資格情報ダンプを防ぎません。
- **PPLの設定または削除** には再起動または **Secure Boot/UEFI設定** が必要で、これによりレジストリの変更が元に戻された後でもPPL設定が持続することがあります。

**PPL保護をバイパスするオプション：**

PPLにもかかわらずLSASSをダンプしたい場合、主に3つのオプションがあります：
1. **署名されたカーネルドライバ (例: Mimikatz + mimidrv.sys)** を使用して **LSASSの保護フラグを削除**します：

![](../../images/mimidrv.png)

2. **自分の脆弱なドライバ (BYOVD)** を持ち込んでカスタムカーネルコードを実行し、保護を無効にします。**PPLKiller**、**gdrv-loader**、または **kdmapper** のようなツールを使用することでこれが可能になります。
3. **別のプロセスから既存のLSASSハンドルを盗む**（例: AVプロセス）し、それを **自分のプロセスに複製**します。これは `pypykatz live lsa --method handledup` テクニックの基礎です。
4. **任意のコードをそのアドレス空間にロードできる特権プロセスを悪用する**か、別の特権プロセス内にロードすることで、実質的にPPL制限をバイパスします。これに関する例は [bypassing-lsa-protection-in-userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/) または [https://github.com/itm4n/PPLdump](https://github.com/itm4n/PPLdump) で確認できます。

**LSASSのLSA保護 (PPL/PP) の現在の状態を確認**：
```bash
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
**`mimikatz privilege::debug sekurlsa::logonpasswords`** を実行すると、これによりエラーコード `0x00000005` で失敗する可能性があります。

- この件についての詳細は [https://itm4n.github.io/lsass-runasppl/](https://itm4n.github.io/lsass-runasppl/) を確認してください。


## Credential Guard

**Credential Guard** は **Windows 10 (Enterprise および Education エディション)** 専用の機能で、**Virtual Secure Mode (VSM)** と **Virtualization Based Security (VBS)** を使用してマシンの資格情報のセキュリティを強化します。これは、CPUの仮想化拡張を利用して、主要なプロセスを保護されたメモリ空間内に隔離し、メインオペレーティングシステムのアクセスから守ります。この隔離により、カーネルでさえもVSM内のメモリにアクセスできず、**pass-the-hash** のような攻撃から資格情報を効果的に保護します。**Local Security Authority (LSA)** はこの安全な環境内でトラストレットとして動作し、メインOSの**LSASS**プロセスはVSMのLSAとの通信を行うだけです。

デフォルトでは、**Credential Guard** はアクティブではなく、組織内で手動での有効化が必要です。これは、資格情報を抽出する能力が制限されるため、**Mimikatz** のようなツールに対するセキュリティを強化するために重要です。ただし、カスタム **Security Support Providers (SSP)** を追加することで、ログイン試行中に資格情報を平文でキャプチャする脆弱性が依然として悪用される可能性があります。

**Credential Guard** の有効化状態を確認するには、_**HKLM\System\CurrentControlSet\Control\LSA**_ の下にあるレジストリキー _**LsaCfgFlags**_ を調べることができます。値が "**1**" の場合は **UEFIロック** が有効で、"**2**" はロックなし、"**0**" は無効を示します。このレジストリチェックは強力な指標ですが、Credential Guardを有効にするための唯一のステップではありません。この機能を有効にするための詳細なガイダンスとPowerShellスクリプトはオンラインで入手可能です。
```bash
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
包括**Credential Guard**をWindows 10で有効にし、**Windows 11 Enterprise and Education (version 22H2)**の互換性のあるシステムでの自動アクティベーションに関する包括的な理解と指示については、[Microsoftのドキュメント](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage)を参照してください。

資格情報キャプチャのためのカスタムSSPの実装に関する詳細は、[このガイド](../active-directory-methodology/custom-ssp.md)に記載されています。

## RDP RestrictedAdmin Mode

**Windows 8.1とWindows Server 2012 R2**は、_**RDPのRestricted Adminモード**_を含むいくつかの新しいセキュリティ機能を導入しました。このモードは、[**パス・ザ・ハッシュ**](https://blog.ahasayen.com/pass-the-hash/)攻撃に関連するリスクを軽減することで、セキュリティを強化することを目的としています。

従来、RDPを介してリモートコンピュータに接続する際、資格情報はターゲットマシンに保存されます。これは、特に特権のあるアカウントを使用する場合に、重大なセキュリティリスクをもたらします。しかし、_**Restricted Adminモード**_の導入により、このリスクは大幅に軽減されます。

**mstsc.exe /RestrictedAdmin**コマンドを使用してRDP接続を開始すると、リモートコンピュータへの認証は、資格情報を保存することなく行われます。このアプローチにより、マルウェア感染や悪意のあるユーザーがリモートサーバーにアクセスした場合でも、資格情報がサーバーに保存されていないため、危険にさらされることはありません。

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

**保護されたユーザーグループ**へのメンバーシップは、資格情報の盗難や悪用に対するより高い保護レベルを確保するために、ユーザーにいくつかのセキュリティ強化を導入します。

- **資格情報の委任 (CredSSP)**: **デフォルトの資格情報を委任することを許可**するグループポリシー設定が有効であっても、保護されたユーザーのプレーンテキスト資格情報はキャッシュされません。
- **Windows Digest**: **Windows 8.1 および Windows Server 2012 R2** 以降、システムは保護されたユーザーのプレーンテキスト資格情報をキャッシュしません。Windows Digest の状態に関係なく。
- **NTLM**: システムは保護されたユーザーのプレーンテキスト資格情報や NT 一方向関数 (NTOWF) をキャッシュしません。
- **Kerberos**: 保護されたユーザーに対して、Kerberos 認証は **DES** または **RC4 キー** を生成せず、プレーンテキスト資格情報や初回のチケット授与チケット (TGT) 取得を超える長期キーをキャッシュしません。
- **オフラインサインイン**: 保護されたユーザーはサインインまたはロック解除時にキャッシュされた検証子が作成されないため、これらのアカウントではオフラインサインインはサポートされません。

これらの保護は、**保護されたユーザーグループ**のメンバーであるユーザーがデバイスにサインインした瞬間に有効になります。これにより、資格情報の侵害に対するさまざまな方法から保護するための重要なセキュリティ対策が講じられます。

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
