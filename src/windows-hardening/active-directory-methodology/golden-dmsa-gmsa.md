# Golden gMSA/dMSA Attack (Managed Service Account Passwords の Offline Derivation)

{{#include ../../banners/hacktricks-training.md}}

## 概要

Windows Managed Service Accounts は、管理者が長期間有効なパスワードを管理せずにサービスを実行するためのドメイン principal です。

1. **gMSA** (group Managed Service Account) は、`msDS-GroupMSAMembership` / `PrincipalsAllowedToRetrieveManagedPassword` によって認可されたコンピューターが使用できます。
2. **dMSA** (delegated Managed Service Account) は **Windows Server 2025** で導入されました。通常の認証を認可されたマシン identity にバインドし、migration workflow によってレガシー service account を置き換えられます。

**Golden dMSA** と **BadSuccessor** を混同しないでください。Golden dMSA には KDS root-key material の compromise と managed-account key の導出が必要です。一方、[BadSuccessor](badsuccessor-dmsa-migration-abuse.md) は dMSA object とその migration attributes の control を悪用します。

DC は、すべての gMSA について独立して生成された clear-text password を保存しているわけではありません。DC は、**KDS root key**、時刻によって index 付けされた Group Key Distribution Protocol (GKDI) key、および account SID から account password を導出します。root-key objects は `CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,...` 配下の `msKds-ProvRootKey` objects であり、sensitive value は `msKds-RootKeyData` です。`msDS-ManagedPasswordId` は **GUID ではありません**。これは、KDS root-key GUID、GKDI の `L0`/`L1`/`L2` indexes、および domain/forest metadata を含む binary key identifier です。DC は label `GMSA PASSWORD` と binary SID を context として KDF を適用し、その後、gMSA password の retrieve を認可された principals にのみ `MSDS-MANAGEDPASSWORD_BLOB` を公開します。<sup>[[2]](#references)</sup>

dMSA は通常、operational な点で異なります。その secret は DC 上に保持され、KDC は認可された machine に credentials を発行することが想定されています。しかし、dMSA は基盤となる KDS/GKDI password derivation を再利用します。Golden dMSA はこの secret を直接再構築するため、想定された machine-bound flow と service host 上の Credential Guard を bypass します。<sup>[[1]](#references)</sup>

## Golden gMSA / Golden dMSA Attack

KDS root key を抽出した後、attacker は `msDS-ManagedPassword` を読み取らずに、その key に紐付けられた accounts の passwords を導出できます。これにより、account ごとの password-retrieval ACL を bypass でき、compromised root key が使用され続ける限り、通常の managed-password rotation 後も access が維持されます。gMSA では、通常、読み取り可能な `msDS-ManagedPasswordId` が正確な key identifier を提供します。ACL によって制限された dMSA では、Golden dMSA により不足している identifier を **1,024 個の候補**にまで絞り込めます。<sup>[[1]](#references)[[2]](#references)</sup>

### Prerequisites

* 関連する KDS root-key object。通常は Enterprise Admin / forest-root Domain Admin rights、DC 上の `SYSTEM`、または公開された DC database や backup から取得します。<sup>[[1]](#references)[[2]](#references)</sup>
* target account の SID、DNS domain、forest name、および `sAMAccountName`。<sup>[[1]](#references)[[2]](#references)</sup>
* 直接 gMSA computation を行う場合は、base64-encoded `msDS-ManagedPasswordId`。Golden dMSA では、代わりにこれを推測できます。<sup>[[1]](#references)[[2]](#references)</sup>
* [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) 用の .NET Framework 4.7.2 を備えた x64 Windows host。<sup>[[3]](#references)</sup>

### Phase 1 - KDS root key の Extract

`GoldenDMSA` と [`GoldenGMSA`](https://github.com/Semperis/GoldenGMSA) は、root-key object fields を base64 blob として export します。domain argument を指定しない場合、tools は forest root に query を実行し、適切な privileged directory access を必要とします。domain/forest argument を指定すると、DC 上の `SYSTEM` は、その DC の local Configuration naming-context replica に query を実行できます。<sup>[[1]](#references)[[2]](#references)</sup>
```cmd
:: GoldenDMSA: Enterprise Admin, or SYSTEM on a DC with --domain
GoldendMSA.exe kds
GoldendMSA.exe kds -g KDS_ROOT_KEY_GUID
GoldendMSA.exe kds --domain child.example.local

:: GoldenGMSA equivalents
GoldenGMSA.exe kdsinfo
GoldenGMSA.exe kdsinfo --guid KDS_ROOT_KEY_GUID
```
root-key GUID と base64 root-key blob の両方を記録します。レジストリの `SECURITY`/`SYSTEM` hive のエクスポートだけでは KDS root key にはなりません。権威のある情報は AD Configuration パーティションにあります。<sup>[[1]](#references)[[2]](#references)</sup>

### フェーズ 2 - gMSA / dMSA オブジェクトの列挙

gMSA では、`sAMAccountName`、`objectSid`、およびバイナリの `msDS-ManagedPasswordId` を取得します。後者は、呼び出し元に `msDS-ManagedPassword` の取得が許可されていない場合でも、通常は読み取り可能です。<sup>[[2]](#references)</sup>
```powershell
Get-ADServiceAccount -Filter * -Properties objectSid,msDS-ManagedPasswordId |
Select-Object sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo --domain example.local
```
dMSA のデフォルト ACL により、低権限での LDAP enumeration が妨げられる場合があります。`GoldenDMSA info` は LDAP にクエリを実行するか、候補となる RID を列挙して `\PIPE\lsarpc` 経由で `LsaLookupSids` により SID を解決し、その後 dMSA、computer account、gMSA を区別できます。<sup>[[1]](#references)[[3]](#references)</sup>
```cmd
GoldendMSA.exe info -d example.local -m ldap
GoldendMSA.exe info -d example.local -m brute -u alice -p PASSWORD -o EXAMPLE -r 5000
```
### フェーズ 3 - `msDS-ManagedPasswordId` を再構築または推測する

このキー識別子には `L0Index`、`L1Index`、`L2Index` が含まれており、アカウント作成日時の後にランダムなビットが続くものではありません。Semperis は、password-generation path が候補となる `L0Index` を使用せず、`L1Index` と `L2Index` はそれぞれ `0..31` の値に制限されることを発見しました。その結果、root-key GUID、domain、forest、SID を知っている攻撃者は、`32 * 32 = 1,024` 個の候補識別子をすべて構築できます。<sup>[[1]](#references)</sup>
```cmd
:: Write 1,024 base64 ManagedPasswordId candidates to KDS_ROOT_KEY_GUID.txt
GoldendMSA.exe wordlist -s DMSA_SID -d example.local -f example.local -k KDS_ROOT_KEY_GUID

:: Derive and validate candidates; -t caches the successful TGT
GoldendMSA.exe bruteforce -s DMSA_SID -i KDS_ROOT_KEY_GUID -k KDS_ROOT_KEY_BASE64 -d example.local -u svc_dmsa$ -t
```
導出処理は offline で行われますが、現在有効な候補を特定するには通常、authentication attempts が必要です。そのため、有効な key が見つかるまで、Kerberos pre-authentication または NTLM validation の失敗が短時間に大量発生する可能性があります。AES Kerberos keys の場合、tool が使用する managed-account salt は、`UPPERCASE.DNS.DOMAIN` + `host` + 末尾の `$` を除いた lower-case account UPN です（例: `EXAMPLE.LOCALhostsvc_dmsa.example.local`）。<sup>[[1]](#references)</sup>

### Phase 4 - password の計算と使用

正確な identifier が既知の場合は、256-byte password buffer を計算し、NTLM/AES material に変換します。これらの tools が出力する base64 value は、encoded password buffer であり、LDAP の `MSDS-MANAGEDPASSWORD_BLOB` 自体ではありません。<sup>[[2]](#references)[[3]](#references)</sup>
```cmd
GoldendMSA.exe compute -s ACCOUNT_SID -k KDS_ROOT_KEY_BASE64 -d example.local -m MANAGED_PASSWORD_ID_BASE64
GoldendMSA.exe convert -d example.local -u svc_account$ -p BASE64_PASSWORD

GoldenGMSA.exe compute --sid ACCOUNT_SID --kdskey KDS_ROOT_KEY_BASE64 --pwdid MANAGED_PASSWORD_ID_BASE64
```
NTLM の結果は NTLM が受け入れられる場所で使用でき、AES key は、managed account が AES-only の場合に overpass-the-hash / TGT requests に使用できます。これにより、攻撃者のマシンを `PrincipalsAllowedToRetrieveManagedPassword` に追加することなく、侵害された managed service account の privileges、SPNs、delegation configuration、および resource access を利用できます。<sup>[[1]](#references)[[2]](#references)</sup>

### Cross-domain Configuration-partition の悪用

KDS root-key objects は forest Configuration naming context に存在し、child domains の DC にレプリケートされます。その結果、child-domain DC 上の `SYSTEM` は、child DC のローカルレプリカから forest-root KDS material を読み取れます。これは、child Domain Admins が forest-root DC から直接その object を読み取れない場合でも可能です。攻撃者が parent-domain gMSA の `msDS-ManagedPasswordId` も読み取れる場合、GoldenGMSA はその parent account の password を計算できます。SID filtering によって、この cryptographic attack を防ぐことはできません。<sup>[[5]](#references)</sup>
```cmd
:: Run as SYSTEM on a child.example.local DC
GoldenGMSA.exe kdsinfo --forest child.example.local

:: Query target metadata in the parent, then combine both inputs
GoldenGMSA.exe gmsainfo --domain example.local
GoldenGMSA.exe compute --sid PARENT_GMSA_SID --domain example.local --forest child.example.local
```
## 検知、封じ込め、復旧

* **Master Root Keys** コンテナーに SACL を構成し、`msKds-ProvRootKey` オブジェクトに継承させて、`msKds-RootKeyData` の成功した読み取りを監査します。Directory Service Access auditing を有効にすると、オンライン抽出によって Security event **4662** が生成されます。想定されていない DC または Tier-0 オペレーターによるアクセス元を調査してください。また、これらの SACL と root-key オブジェクト ACL の変更も監査します。<sup>[[1]](#references)[[2]](#references)[[4]](#references)</sup>
* child-to-parent attack では、侵害された child DC のローカルレプリカから KDS オブジェクトを読み取るため、forest-root domain ではその読み取りを検知できない場合があります。親ドメインでは、`msDS-GroupManagedServiceAccount` オブジェクト上の `msDS-ManagedPasswordId`（schema GUID `0e78295a-c6d3-0a40-b491-d62251ffa0a6`）の成功した読み取りを監査し、別のドメインの principal による読み取りを調査してください。<sup>[[5]](#references)</sup>
* KDS オブジェクトへのアクセスを、managed account による通常とは異なる logon や、`$` で終わる service account に対する Kerberos/NTLM failures の急増と相関分析します。以前に database または backup が盗まれた後のオフライン計算は、稼働中の DC からは検知できません。<sup>[[1]](#references)[[3]](#references)</sup>
* 通常の password rotation だけでは、root-key が漏洩した後の対策として不十分です。Microsoft の現在の復旧手順では、新しい KDS root key を作成し、関連するすべての DC で KDS を再起動し、影響を受けた account をその key に移行します。漏洩範囲または時期が不明で、安全な rolling を待つことが許容されない場合は、侵害された key を使用していたすべての gMSA を置き換えます。範囲が判明している場合、Microsoft は安全な rolling を強制する authoritative-restore workflow を文書化しています。古い key を削除する前に、`msDS-ManagedPasswordId` で新しい key GUID を検証してください。<sup>[[4]](#references)</sup>
* DC database と backup へのアクセス、Configuration-partition replication、KDS root-key administration は Tier-0 として扱います。`ManagedPasswordIntervalInDays` を短縮すると、一部の recovery window を制限できますが、すでに侵害された root key を revoke することはできません。<sup>[[4]](#references)</sup>

## Tooling

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) - dMSA/gMSA enumeration、identifier generation、1,024 候補の validation、password computation、NTLM/AES conversion。<sup>[[3]](#references)</sup>
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) - gMSA/KDS enumeration、および online、offline、cross-domain での password computation。<sup>[[2]](#references)</sup>
* [`Rubeus`](https://github.com/GhostPack/Rubeus) および [`Impacket`](https://github.com/fortra/impacket) - 認可された testing で、導出された NTLM/AES key を使用または検証します。



## References

- [1] [Golden dMSA - 委任された Managed Service Accounts に対する authentication bypass](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [2] [gMSA Active Directory Attacks](https://www.semperis.com/blog/golden-gmsa-attack/)
- [3] [Semperis/GoldenDMSA GitHub repository](https://github.com/Semperis/GoldenDMSA)
- [4] [Microsoft - Golden gMSA attack からの復旧方法](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/recover-from-golden-gmsa-attack)
- [5] [ドメイン間の security boundary としての SID filter？ Part 5 - Golden gMSA trust attack](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
{{#include ../../banners/hacktricks-training.md}}
