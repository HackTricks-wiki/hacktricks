# Windows クレデンシャル保護

## クレデンシャル保護

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert) で AWS ハッキングをゼロからヒーローまで学ぶ</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks にあなたの会社を広告掲載したい場合**や**HackTricks を PDF でダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式 PEASS & HackTricks グッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)コレクションをチェックする
* 💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f)や [**telegram グループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) の GitHub リポジトリに PR を提出して、あなたのハッキングテクニックを共有する。

</details>

## WDigest

[WDigest](https://technet.microsoft.com/pt-pt/library/cc778868\(v=ws.10\).aspx?f=255\&MSPPError=-2147217396) プロトコルは Windows XP で導入され、HTTP プロトコルでの認証に使用されるように設計されました。Microsoft はこのプロトコルを**デフォルトで複数の Windows バージョンで有効にしています**（Windows XP — Windows 8.0 および Windows Server 2003 — Windows Server 2012）、これは **平文のパスワードが LSASS**（Local Security Authority Subsystem Service）に保存されていることを意味します。**Mimikatz** は LSASS とやり取りすることができ、攻撃者が以下のコマンドを通じてこれらのクレデンシャルを**取得する**ことを可能にします：
```
sekurlsa::wdigest
```
この動作は _**HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ 内の _**UseLogonCredential**_ と _**Negotiate**_ の値を **1に設定することで** **無効化/有効化** できます。\
これらのレジストリキーが **存在しない**、または値が **"0"** の場合、WDigestは **無効化** されます。
```
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA 保護

Microsoftは、**Windows 8.1 以降**で、信頼できないプロセスがLSAのメモリを**読み取る**ことやコードを注入することを**防ぐ**ために、LSAに追加の保護を提供しています。これにより、通常の `mimikatz.exe sekurlsa:logonpasswords` が適切に機能することを防ぎます。\
この保護を**有効にする**には、_**HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**_ の _**RunAsPPL**_ の値を1に設定する必要があります。
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### バイパス

この保護をバイパスする方法として、Mimikatzのドライバーmimidrv.sysがあります：

![](../../.gitbook/assets/mimidrv.png)

## Credential Guard

**Credential Guard**はWindows 10（EnterpriseおよびEducationエディション）の新機能で、パスハッシュなどの脅威からマシン上の資格情報を保護するのに役立ちます。これはVirtual Secure Mode（VSM）と呼ばれる技術を通じて機能し、CPUの仮想化拡張を利用します（実際の仮想マシンではありません）が、**メモリの保護領域**に**保護**を提供します（Virtualization Based SecurityまたはVBSとして言及されることがあります）。VSMは、通常の**オペレーティングシステム**のプロセス、カーネルでさえも、**分離された**重要な**プロセス**のための別の「バブル」を作成し、**特定の信頼されたプロセスのみがVSM内のプロセス**（**trustlets**として知られています）と通信できます。これは、メインOSのプロセスがVSMのメモリを読み取ることができないことを意味します。**Local Security Authority（LSA）はVSM内のtrustletsの一つ**であり、既存のプロセスとの互換性を保つためにメインOSで引き続き実行される標準の**LSASS**プロセスもありますが、実際にはVSM内のバージョンと通信するためのプロキシまたはスタブとして機能し、実際の資格情報はVSMのバージョンで実行され、攻撃から保護されます。Windows 10の場合、Credential Guardはデフォルトでは**有効になっていません**ので、組織でオンにして展開する必要があります。
[https://www.itprotoday.com/windows-10/what-credential-guard](https://www.itprotoday.com/windows-10/what-credential-guard)からの情報。Credential Guardを有効にするPS1スクリプトについての詳細は[こちらで見つけることができます](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage)。ただし、Windows 11 Enterprise、バージョン22H2およびWindows 11 Education、バージョン22H2では、互換性のあるシステムにはWindows Defender Credential Guardが[デフォルトでオンになっています](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage#Default%20Enablement)。

この場合、**MimikatzはLSASSからハッシュを抽出するためのバイパスはほとんどできません**。しかし、**カスタムSSP**を追加して、ユーザーがログインしようとするときに**クリアテキスト**で**資格情報をキャプチャ**することはできます。\
[**SSPとこれを行う方法についての詳細はこちら**](../active-directory-methodology/custom-ssp.md)。

Credentials Guardは**異なる方法で有効にすることができます**。レジストリを使用して有効にされたかどうかを確認するには、_**HKLM\System\CurrentControlSet\Control\LSA**_のキー_**LsaCfgFlags**_の値を確認できます。値が**"1"**ならUEFIロック付きでアクティブ、**"2"**ならロックなしでアクティブ、**"0"**なら有効ではありません。\
これだけではCredentials Guardを有効にするには**十分ではありません**（しかし、強い指標です）。\
Credential Guardを有効にするPS1スクリプトについての詳細は[こちらで見つけることができます](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage)。
```
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
## RDP RestrictedAdmin モード

Windows 8.1とWindows Server 2012 R2では、新しいセキュリティ機能が導入されました。そのセキュリティ機能の一つが_RDPのRestricted Adminモード_です。この新しいセキュリティ機能は、[pass the hash](https://blog.ahasayen.com/pass-the-hash/)攻撃のリスクを軽減するために導入されました。

RDPを使用してリモートコンピュータに接続すると、接続先のリモートコンピュータにあなたの資格情報が保存されます。通常、リモートサーバーに接続するために強力なアカウントを使用しており、これらのコンピュータすべてに資格情報が保存されることは、確かにセキュリティ上の脅威です。

_RDPのRestricted Adminモード_を使用すると、コマンド **mstsc.exe /RestrictedAdmin** を使用してリモートコンピュータに接続する際、リモートコンピュータに認証されますが、**あなたの資格情報はそのリモートコンピュータに保存されません**。つまり、そのリモートサーバー上でマルウェアや悪意のあるユーザーが活動していても、リモートデスクトップサーバー上であなたの資格情報が利用可能になることはありません。

資格情報がRDPセッションに保存されないため、**ネットワークリソースにアクセスしようとすると**、資格情報は使用されません。**代わりにマシンのIDが使用されます**。

![](../../.gitbook/assets/ram.png)

[こちら](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/)から。

## キャッシュされた資格情報

**ドメイン資格情報**は、オペレーティングシステムのコンポーネントによって使用され、**Local** **Security Authority** (LSA)によって**認証**されます。通常、ドメイン資格情報は、ユーザーのログオンデータを認証する登録されたセキュリティパッケージによってユーザーに対して確立されます。この登録されたセキュリティパッケージは、**Kerberos**プロトコルまたは**NTLM**である可能性があります。

**Windowsは、ドメインコントローラがオフラインになった場合のために、最後の10回のドメインログイン資格情報を保存します**。ドメインコントローラがオフラインになった場合でも、ユーザーは**自分のコンピュータにログインすることができます**。この機能は主に、定期的に会社のドメインにログインしないノートパソコンユーザー向けです。コンピュータが保存する資格情報の数は、以下の**レジストリキー、またはグループポリシー経由で**制御できます：
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
認証情報は通常のユーザーから隠されており、管理者アカウントでさえもです。**SYSTEM** ユーザーのみがこれらの**認証情報**を**閲覧**する**権限**を持っています。管理者がレジストリ内のこれらの認証情報を閲覧するためには、SYSTEM ユーザーとしてレジストリにアクセスする必要があります。
キャッシュされた認証情報は、以下のレジストリの場所に保存されています：
```
HKEY_LOCAL_MACHINE\SECURITY\Cache
```
**Mimikatzからの抽出**: `lsadump::cache`\
[こちら](http://juggernaut.wikidot.com/cached-credentials)から。

## 保護されたユーザー

サインインしているユーザーが保護されたユーザーのグループのメンバーである場合、以下の保護が適用されます：

* 資格情報の委任（CredSSP）は、**Allow delegating default credentials** グループポリシー設定が有効になっていても、ユーザーの平文の資格情報をキャッシュしません。
* Windows 8.1およびWindows Server 2012 R2以降、Windows Digestは、Windows Digestが有効になっていても、ユーザーの平文の資格情報をキャッシュしません。
* **NTLM** は、ユーザーの **平文の資格情報** や NT **ワンウェイ関数**（NTOWF）を **キャッシュしません**。
* **Kerberos** は、**DES** や **RC4 キー** を作成 **しません**。また、初期のTGTが取得された後、ユーザーの平文の資格情報や長期キーをキャッシュしません。
* **サインインやアンロック時にキャッシュされた検証器は作成されません**ので、オフラインでのサインインはもはやサポートされません。

ユーザーアカウントが保護されたユーザーのグループに追加された後、ユーザーがデバイスにサインインすると保護が開始されます。**こちら** [**から**](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)**。**

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| アカウントオペレーター       | アカウントオペレーター        | アカウントオペレーター                                                             | アカウントオペレーター            |
| 管理者           | 管理者            | 管理者                                                                 | 管理者                |
| 管理者グループ          | 管理者グループ           | 管理者グループ                                                                | 管理者グループ               |
| バックアップオペレーター        | バックアップオペレーター         | バックアップオペレーター                                                              | バックアップオペレーター             |
| 証明書発行者         |                          |                                                                               |                              |
| ドメイン管理者           | ドメイン管理者            | ドメイン管理者                                                                 | ドメイン管理者                |
| ドメインコントローラー      | ドメインコントローラー       | ドメインコントローラー                                                            | ドメインコントローラー           |
| エンタープライズ管理者       | エンタープライズ管理者        | エンタープライズ管理者                                                             | エンタープライズ管理者            |
|                         |                          |                                                                               | エンタープライズキーアドミン        |
|                         |                          |                                                                               | キーアドミン                   |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| プリントオペレーター         | プリントオペレーター          | プリントオペレーター                                                               | プリントオペレーター              |
|                         |                          | 読み取り専用ドメインコントローラー                                                  | 読み取り専用ドメインコントローラー |
| レプリケーター              | レプリケーター               | レプリケーター                                                                    | レプリケーター                   |
| スキーマ管理者           | スキーマ管理者            | スキーマ管理者                                                                 | スキーマ管理者                |
| サーバーオペレーター        | サーバーオペレーター         | サーバーオペレーター                                                              | サーバーオペレーター             |

**こちら** [**からの表**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**。**

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でAWSハッキングをゼロからヒーローまで学ぶ</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksにあなたの会社を広告したい**、または **HackTricksをPDFでダウンロードしたい** 場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や [**テレグラムグループ**](https://t.me/peass)に**参加する**、または **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>
