# Windowsの資格情報保護

## 資格情報の保護

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## WDigest

[WDigest](https://technet.microsoft.com/pt-pt/library/cc778868\(v=ws.10\).aspx?f=255\&MSPPError=-2147217396)プロトコルは、Windows XPで導入され、認証にHTTPプロトコルを使用するために設計されました。マイクロソフトはこのプロトコルを**複数のWindowsのバージョンでデフォルトで有効にしています**（Windows XP〜Windows 8.0およびWindows Server 2003〜Windows Server 2012）。これは、**平文のパスワードがLSASS（Local Security Authority Subsystem Service）に保存**されていることを意味します。**Mimikatz**はLSASSとやり取りすることができ、以下のコマンドを使用して攻撃者はこれらの資格情報を**取得**することができます：
```
sekurlsa::wdigest
```
この動作は、_**HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ の _**UseLogonCredential**_ と _**Negotiate**_ の値を **1** に設定することで**無効化/有効化**できます。\
これらのレジストリキーが**存在しない**場合や値が**"0"**の場合、WDigestは**無効化**されます。
```
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA保護

マイクロソフトは**Windows 8.1以降**で、LSAの追加の保護を提供しています。これにより、信頼されていないプロセスがそのメモリを読み取ったり、コードを注入したりすることができなくなります。これにより、通常の`mimikatz.exe sekurlsa:logonpasswords`が正常に動作しなくなります。\
この保護を**有効にするには**、_**HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**_の値_**RunAsPPL**_を1に設定する必要があります。
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### バイパス

Mimikatzドライバーmimidrv.sysを使用して、この保護をバイパスすることが可能です：

![](../../.gitbook/assets/mimidrv.png)

## Credential Guard

**Credential Guard**は、Windows 10（EnterpriseおよびEducationエディション）の新機能であり、パス・ザ・ハッシュなどの脅威からマシン上の資格情報を保護する役割を果たします。これは、仮想化拡張機能を利用した仮想セキュアモード（VSM）という技術を通じて機能します（ただし、実際の仮想マシンではありません）。VSMは、通常のオペレーティングシステムプロセス、さらにはカーネルからも**分離された**キーの**プロセス**に対してメモリの**保護**を提供するためのものです。VSMでは、特定の信頼できるプロセス（**トラストレット**と呼ばれる）のみがVSM内のプロセスと通信できます。これにより、メインのOSのプロセスは、VSMのメモリを読み取ることができません。カーネルプロセスでさえもです。**ローカルセキュリティ機関（LSA）は、VSM内のトラストレットの1つ**であり、既存のプロセスとの互換性を確保するためにメインのOSで実行される**LSASS**プロセスに追加されていますが、実際にはプロキシまたはスタブとして機能し、VSM内のバージョンと通信することで実際の資格情報を実行し、攻撃から保護します。Windows 10では、Credential Guardはデフォルトで有効になっていないため、組織内で有効にする必要があります。
[https://www.itprotoday.com/windows-10/what-credential-guard](https://www.itprotoday.com/windows-10/what-credential-guard)から詳細情報とCredential Guardを有効にするためのPS1スクリプトを[ここで見つけることができます](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage)。ただし、Windows 11 Enterpriseのバージョン22H2およびWindows 11 Educationのバージョン22H2以降では、互換性のあるシステムではWindows Defender Credential Guardが[デフォルトで有効になっています](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage#Default%20Enablement)。

この場合、**Mimikatzでは**LSASSからハッシュを抽出するためにはあまり役に立ちません。ただし、常に**カスタムSSP**を追加して、ユーザーが**クリアテキスト**でログインしようとしたときに資格情報を**キャプチャ**することができます。
[**SSPとその方法に関する詳細情報はこちら**](../active-directory-methodology/custom-ssp.md)を参照してください。

Credentials Guardは、さまざまな方法で**有効にできます**。レジストリを使用して有効になっているかどうかを確認するには、キー_**LsaCfgFlags**_の値を確認します。キーの場所は _**HKLM\System\CurrentControlSet\Control\LSA**_です。値が**"1"**であれば、UEFIロック付きで有効です。**"2"**であればロックなしで有効です。**"0"**であれば無効です。これだけではCredentials Guardを有効にするには**十分ではありません**（ただし、強力な指標です）。
[こちらで詳細情報とCredential Guardを有効にするためのPS1スクリプトを見つけることができます](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage)。
```
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
## RDP RestrictedAdminモード

Windows 8.1およびWindows Server 2012 R2では、新しいセキュリティ機能が導入されました。そのセキュリティ機能の1つが、RDPのための「制限付き管理者モード」です。この新しいセキュリティ機能は、[パス・ザ・ハッシュ](https://blog.ahasayen.com/pass-the-hash/)攻撃のリスクを軽減するために導入されました。

RDPを使用してリモートコンピュータに接続すると、RDPで接続したリモートコンピュータには資格情報が保存されます。通常、リモートサーバに接続するために強力なアカウントを使用しており、これらのコンピュータに資格情報が保存されていることは確かにセキュリティ上の脅威です。

「制限付き管理者モード」を使用すると、コマンド**mstsc.exe /RestrictedAdmin**を使用してリモートコンピュータに接続すると、リモートコンピュータに認証されますが、過去に保存されていたように**資格情報はリモートコンピュータに保存されません**。つまり、マルウェアや悪意のあるユーザがそのリモートサーバ上で活動していても、資格情報はそのリモートデスクトップサーバ上でマルウェアに攻撃されることはありません。

資格情報がRDPセッションに保存されないため、**ネットワークリソースにアクセスしようとする場合、資格情報は使用されません**。代わりに、マシンの識別情報が使用されます。

![](../../.gitbook/assets/ram.png)

[ここから](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/)。

## キャッシュされた資格情報

**ドメインの資格情報**は、オペレーティングシステムのコンポーネントによって使用され、**ローカルセキュリティ機関**（LSA）によって**認証**されます。通常、ドメインの資格情報は、登録されたセキュリティパッケージがユーザのログオンデータを認証するときにユーザのために確立されます。この登録されたセキュリティパッケージは、**Kerberos**プロトコルまたは**NTLM**である場合があります。

**Windowsは、ドメインコントローラがオフラインになった場合に、最後の10個のドメインログイン資格情報を保存します**。ドメインコントローラがオフラインになっても、ユーザは**コンピュータにログインできます**。この機能は、定期的に会社のドメインにログインしないノートパソコンのユーザを主な対象としています。コンピュータが保存する資格情報の数は、次の**レジストリキーまたはグループポリシー**によって制御できます。
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
資格情報は通常のユーザーや管理者アカウントから隠されています。**SYSTEM**ユーザーだけがこれらの**資格情報**を**表示**する**権限**を持っています。管理者がレジストリ内のこれらの資格情報を表示するためには、SYSTEMユーザーとしてレジストリにアクセスする必要があります。\
キャッシュされた資格情報は、次のレジストリの場所に格納されています：
```
HKEY_LOCAL_MACHINE\SECURITY\Cache
```
**Mimikatzからの抽出**: `lsadump::cache`\
[ここ](http://juggernaut.wikidot.com/cached-credentials)から。

## Protected Users

サインインしているユーザーがProtected Usersグループのメンバーである場合、以下の保護が適用されます：

* **Allow delegating default credentials** グループポリシー設定が有効になっていても、Credential delegation (CredSSP) はユーザーの平文の資格情報をキャッシュしません。
* Windows 8.1およびWindows Server 2012 R2以降、Windows Digestはユーザーの平文の資格情報をキャッシュしません。
* **NTLM**はユーザーの平文の資格情報またはNTのワンウェイ関数（NTOWF）をキャッシュしません。
* **Kerberos**は**DESキー**または**RC4キー**を作成しません。また、初期のTGTを取得した後もユーザーの平文の資格情報や長期キーをキャッシュしません。
* サインインまたはロック時にキャッシュされた検証子は作成されないため、オフラインサインインはサポートされなくなりました。

ユーザーアカウントがProtected Usersグループに追加されると、保護がデバイスにサインインしたユーザーから開始されます。[ここ](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)から。

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

[ここ](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)からの表。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ HackTricksであなたの会社を宣伝したいですか？または、最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロードしたりしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[NFT](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>
