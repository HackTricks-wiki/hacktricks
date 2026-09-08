# Authorized Red-Team Infrastructure

耐久性が求められるオンサイトデバイスには、[Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) の設計と、発見が疑われる場合の runbook を使用してください。

professional red team の目的は、説明責任から逃れることではなく、**管理された帰属確認**です。対象にオペレーターの自宅 IP や個人アカウントを簡単に知られないようにする一方で、engagement の所有者は送信元を特定し、作戦を停止し、abuse report に対応し、証拠を保全し、許可を受けていることを証明できなければなりません。

このページは、合法的な engagement における deployment baseline です。侵害された ORB、residential relay、fronting、dead drop、近隣の wireless pivot など、これが模倣しようとする adversary tradecraft については、[Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md) と [Government and APT Case Studies](government-and-apt-case-studies.md) から始め、その後、必要な telemetry を [authorized labs](authorized-adversary-emulation-labs.md) で再現してください。

NIST は rules of engagement (ROE) を、定義された testing activity に対する権限を付与する、事前に定められた制約と定義しています。<sup>[[1]](#references)</sup> Privacy architecture によって、その権限を拡大することはできません。

## egress パターンを選択する

| パターン | 最適な用途 | Target から見えるもの | Provider/local observer から見えるもの | Accountability |
|---|---|---|---|---|
| Client-provided VPN/jump host | ほとんどの assessment | Client の address range | Client の identity と operator access | 最も強い |
| Red-team organization bastion | 再現性のある管理された egress | Organization の range | Hosting provider と organization | 強い |
| Engagement-specific VPS | Client/campaign の分離 | VPS の address | Host account、billing、control-plane、access log | 文書化されていれば強い |
| Approved commercial VPN | Provider と ROE で許可された research/scanning | 共有または専用の VPN egress | VPN account と source connection | 中程度 |
| Tor Browser | destination unlinkability が必要な Web research | Tor exit | Local network からは Tor/bridge、destination からは Tor | allowlisted source attribution には不向き |
| Client-approved on-site drop | Internal simulation | On-site device/address | Site network と remote tunnel provider | 資産管理されていれば強い |
| Lawful guest Wi-Fi | 低リスクの administrative/research use | Venue の public IP または tunnel egress | Venue、ISP、VPN/Tor | 弱く、物理的に観測可能 |

ほとんどの作業では、consumer anonymity service よりも、client が提供する、または organization が管理する固定 egress の方が安全で高速です。また、exercise の設計に従って、defender が既知の source range を allowlist に追加したり、監視したり、意図的に allowlist に追加しないようにしたりできます。

## ROE infrastructure annex

deployment 前に記録する項目:

- authorization を付与および受領する legal entity;
- 正確な target と明示的な除外対象;
- 開始時刻と終了時刻、time zone、許可される technique;
- source IP、autonomous-system/provider 名、domain、redirector、mail infrastructure、オンサイトデバイスの identifier;
- phishing、C2、credential capture、wireless testing、physical access、denial-of-service、persistence、third-party service のいずれが許可されるか;
- client と provider の承認（事前通知の reference を含む）;
- emergency stop phrase、24/7 の client および provider abuse contact、最大 response time;
- 収集可能な data class、encryption、access、retention、deletion;
- evidence と logging の要件（public infrastructure から operator への対応関係を誰が保持するかを含む）;
- teardown、domain expiration、certificate revocation、credential rotation、device recovery、最終 attestation。

public IP と domain が、実際に authorization を付与した party によって管理されているか、または明示的に scope に含まれているかを確認してください。NIST SP 800-115 は、testing 前に public target address が organization の管理下にあることを確認するよう推奨しています。<sup>[[2]](#references)</sup>

## Engagement-specific fast egress

### Build workflow

1. **engagement account/project を作成する:** 正確な billing と ownership details を使用し、red-team organization の管理下に作成します。他の client から role、API key、budget、audit log を分離します。
2. **すべての provider policy を確認する:** Cloud、VPS、CDN、domain、email、VPN provider には、それぞれ異なるルールがあります。たとえば AWS は、指定された assessment を許可していますが、hosted C2/covert simulation には事前承認が必要で、列挙された activity を禁止しています。<sup>[[3]](#references)</sup>
3. **固定 egress address を割り当てる:** それらを ROE annex に記載します。IP/resource の急速な cycling は避けてください。incident response を複雑にし、provider policy に違反する可能性があります。
4. **management を harden する:** key-only SSH または identity-aware management plane、phishing-resistant MFA、分離された admin network、least privilege、patch 適用済み image、public admin port の無効化、encrypted secret storage を使用します。
5. **full-tunnel path を作成する:** operator endpoint から bastion までの経路を構築します。DNS と IPv6 を意図的に route し、tunnel が停止した場合は firewall deny を適用します。
6. **outbound destination と port を制限する:** 可能な場合は、authorized scope に限定します。scanner を rate-limit し、不可逆または破壊的な technique には別途 approval gate を設けます。
7. **surveillance ではなく accountability のために log を取得する:** operator authentication、configuration change、start/stop、source address、scoped destination、tool/job identifier を記録します。exercise で必要とされ、data plan によって保護されている場合を除き、payload や credential の capture は避けます。
8. **organization が所有する controlled endpoint を通じて検証する:** 観測された IPv4/IPv6、DNS path、reverse DNS、clock、source-port behavior、failure/reconnect、provider abuse contact を確認します。
9. **attribution map を安全に共有する:** exercise controller または合意済みの escrow contact と共有します。blind detection が test の一部である場合は、target team に公開しないでください。

### Architecture
```text
dedicated operator context
|
fail-closed tunnel
|
engagement bastion / fixed egress ---- management + audit plane
|
scope allowlist / rate limits
|
authorized targets
```
VPSは宛先に対してのみ仮名性を持ちます。ホスト側には、連絡先、請求、身元、送信元IP、API、デバイス、位置情報、利用状況の記録が残る可能性があり、顧客が確認できるAWS CloudTrailの履歴だけでも管理操作が明らかになることがあります。<sup>[[4]](#references)</sup> 暗号通貨でホスティング料金を支払っても、これらの記録が消えるわけではありません。

## ドメインと証明書

- 組織が所有する、エンゲージメント専用のレジストラアカウントを使用する。
- レジストラロック、対応している場合はDNSSEC、MFA/security keysを有効にし、自動更新は承認期間に限って設定する。
- 登録者情報を偽るのではなく、公開情報を減らすために登録情報のプライバシー保護を使用する。ICANNポリシーでは、公開表示が削除または代理表示される場合でも、レジストラが登録データを収集することが義務付けられています。<sup>[[5]](#references)</sup>
- 無関係な第三者を違法に偽装する名前は避ける。Typosquatting/lookalike domainsには、クライアントとプロバイダー双方の明示的な承認が必要です。
- オペレーターやクライアントの情報をleakする可能性があるDNS、証明書、CDN/redirector設定、サードパーティ分析をインベントリ化する。
- teardown時には、レコードを削除し、証明書/tokenをrevokeし、合意済みの証拠を保全し、ドメインを防御目的で保持するか決定する。

## Authorized on-site drop nodes

Raspberry Piまたは同様のアプライアンスは、施設／ネットワーク所有者とクライアントが、正確な設置場所と動作内容を明示的に承認した場合に限り使用できます。安全な計画は次のとおりです。

1. デバイスのシリアル番号、MAC/private-MACポリシー、写真、所有者、承認済みの正確な設置場所、電源、回収期限、改ざん時の連絡先を記録する。
2. 最小構成の署名済みイメージ、暗号化されたsecret、read-onlyまたは復旧可能なストレージ、host firewall、可能な場合は自動security updatesを使用し、デフォルト認証情報は使用しない。
3. 指定したエンゲージメントendpointへのoutbound-only通信を設定する。認証されていないlistenerを公開しない。
4. 宛先と機能をallowlist化する。Packet capture、credential collection、wireless impersonation、lateral movementは、それぞれ明示的に承認されなければならない。
5. 相互認証、短期間のkey、remote kill、health reporting、帯域幅制限を使用する。
6. 紛失や盗難が発生しても、再利用可能なcredentialやクライアントデータが漏洩しないようにする。
7. 回収とsecure wipe/decommissionを予定表に登録し、署名済みの回収記録を取得する。

所有者／運営者の書面による許可なく、カフェ、ホテル、共有オフィス、近隣住民の敷地、または公共の場所にハードウェアを隠してはなりません。

## Guest networks and travel routers

承認済みのシナリオでguest accessが必要な場合：

- 会場／クライアントにSSIDとacceptable-use policyを確認する。
- 組織所有のtravel routerまたは低信頼のbridge deviceを使用して、privileged workstationを分離する。
- captive portalはprivileged workstationの外部で完了する。
- assessment trafficを開始する前に、承認済みのtunnelを開始する。
- tethered devicesが実際にそのtunnelを使用していることを確認する。
- 会場がradio association、portal、物理的な滞在、カメラ／決済記録を関連付けられると想定する。
- access controlを迂回したり、別のデバイスをcloneしたり、Wi-Fiを攻撃したり、機器を放置したりしない。

## Operational separation

- endpoint compartment、cloud project、secrets set、domain group、redirector set、evidence storeごとに、1クライアント／1エンゲージメントとする。
- 承認済みの組織システム外で、個人メール、browser sync、電話番号、cloud drive、SSH/GPG key、code-signing identity、支払いの立替精算を使用しない。
- 演習設計でfingerprintingを許容していない限り、特徴的なpayload configuration、callback paths、証明書、public repositoriesをクライアント間で再利用しない。
- インフラに停止日と予算アラートを設定する。放置されたシステムは、クライアントとInternetの双方にとってリスクになる。
- 事故を調査できるだけの内部 attributionを保持する。「ログなし」は通常、専門的な証拠保全および安全上の義務と両立しない。

## Blind to defenders, attributable to the controller

エンゲージメントの目的がallowlistをテストすることではなく検知能力を測定することである場合、運用のaccountabilityを失わずに、対象SOCから情報を隠すことができます。

1. エンゲージメントcontrollerは、すべての公開source、domain、certificate、on-site deviceを承認するが、その一覧をSOCには開示しない。
2. controllerは、source-to-engagement/operator mapを、2人承認による緊急アクセスを備えた別の暗号化vaultに保存する。
3. 各operator jobには、scope、time window、source compartment、不可逆なjob identifierを含む署名済みmanifestを割り当てる。通常の運用中、targetがmanifestを確認する必要はない。
4. Bastionのaudit eventsをchain化するか、controllerのストレージへappend-onlyで送信し、インシデント後にoperatorがattributionを密かに書き換えられないようにする。
5. 24/7のprovider-abuse contactが、クライアントを公に開示せずに承認を確認できるverification phrase/referenceを保持する。
6. すべてのpathに、assessment C2、target network、または1人のoperatorのアカウントに依存しないout-of-band stop channelを実装する。
7. live testingの前に、すべてのsourceからbenign canaryを送信する。controllerがROEのresponse time内にそれらを特定して停止できることを確認する。
8. 演習後、SOC telemetryとcontroller ledgerを比較し、source listを開示して、検知漏れや誤検知を説明する。

Anti-forensics、log destruction、compromised relays、false subscriber identitiesを追加してはなりません。これらはaccountable testingを改善するどころか、台無しにします。

## Teardown checklist

- [ ] エンゲージメントcontrollerが停止を確認する。
- [ ] C2、tunnel、redirector、mail、VPN、scheduled jobsを無効化する。
- [ ] On-site devicesを物理的に回収し、照合する。
- [ ] Token、API key、SSH key、certificate、captured credentialをrevoke/rotateする。
- [ ] DNSおよびcloud resourcesを削除するか、防御目的で保持できるよう移管する。
- [ ] クライアントデータを契約に従って返却、保持、または破棄する。
- [ ] 必要な財務、audit、authorization recordsを暗号化し、access-controlledな状態で保持する。
- [ ] Provider abuse caseを終了し、クライアントに最終的なsource indicatorsを提供する。
- [ ] 2人目のoperatorが、インフラが何も稼働していないことを確認する。

## References

- [1] [NIST CSRC — Rules of Engagement](https://csrc.nist.gov/glossary/term/Rules_of_Engagement)
- [2] [NIST SP 800-115 — 情報セキュリティテストおよび評価の技術ガイド](https://csrc.nist.gov/pubs/sp/800/115/final)
- [3] [AWS — ペネトレーションテストに関するカスタマーサポートポリシー](https://aws.amazon.com/security/penetration-testing/)
- [4] [AWS — プライバシー通知](https://aws.amazon.com/privacy/) and [CloudTrail Event History](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
- [5] [ICANN — 登録データポリシー](https://www.icann.org/en/contracted-parties/consensus-policies/registration-data-policy)
