# Authorized Red-Team Infrastructure

{{#include ../banners/hacktricks-training.md}}

耐久性が必要なオンサイトデバイスには、[Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) の設計と、発見が疑われる場合の runbook を使用します。

プロフェッショナルな red team の目標は、説明責任から逃れることではなく、**管理された attribution** です。ターゲットからオペレーターの自宅 IP や個人アカウントを簡単に確認できないようにする一方で、engagement の責任者は発信元を特定し、作戦を停止し、abuse report に対応し、証拠を保全し、承認を証明できなければなりません。

このページは、合法的な engagement のための deployment baseline です。侵害された ORB、住宅用 relay、fronting、dead drop、近隣の wireless pivot など、再現を目的とする adversary tradecraft については、[Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md) と [Government and APT Case Studies](government-and-apt-case-studies.md) から始め、[authorized labs](authorized-adversary-emulation-labs.md) で必要な telemetry を再現してください。

NIST は、rules of engagement (ROE) を、定義された testing activity に対する権限を与える、事前に定められた制約と定義しています。<sup>[[1]](#references)</sup> Privacy architecture によって、その権限を拡大することはできません。

## egress pattern を選択する

| Pattern | Best use | Target sees | Provider/local observer sees | Accountability |
|---|---|---|---|---|
| Client-provided VPN/jump host | Most assessments | Client address range | Client identity and operator access | Strongest |
| Red-team organization bastion | Repeatable controlled egress | Organization range | Hosting provider and organization | Strong |
| Engagement-specific VPS | Isolate clients/campaigns | VPS address | Host account, billing, control-plane and access logs | Strong if documented |
| Approved commercial VPN | Research/scanning permitted by provider and ROE | Shared/dedicated VPN egress | VPN account and source connection | Medium |
| Tor Browser | Web research needing destination unlinkability | Tor exit | Local network sees Tor/bridge; destination sees Tor | Poor fit for allowlisted source attribution |
| Client-approved on-site drop | Internal simulation | On-site device/address | Site network and remote tunnel provider | Strong if inventoried |
| Lawful guest Wi-Fi | Low-risk administrative/research use | Venue public IP or tunnel egress | Venue, ISP, VPN/Tor | Weak and physically observable |

ほとんどの作業では、consumer anonymity service よりも、client が提供する、または組織が管理する固定 egress のほうが安全で高速です。また、exercise の設計に従って、defender が既知の source range を allowlist に登録したり、監視したり、意図的に **allowlist に登録しない** ようにしたりできます。

## ROE infrastructure annex

deployment 前に記録します。

- authorization を付与および受領する legal entity；
- 正確な target と明示的な除外対象；
- 開始時刻と終了時刻、time zone、許可される technique；
- source IP、autonomous-system/provider 名、domain、redirector、mail infrastructure、オンサイトデバイス識別子；
- phishing、C2、credential capture、wireless testing、physical access、denial-of-service、persistence、third-party service の使用可否；
- client および provider の承認（事前通知の reference を含む）；
- 緊急停止用 phrase、client と provider の 24/7 abuse contact、最大 response time；
- 収集可能な data class、encryption、access、retention、deletion；
- 証拠と logging の要件（public infrastructure と operator の対応関係を誰が保持するかを含む）；
- teardown、domain expiration、certificate revocation、credential rotation、device recovery、最終 attestation。

public IP と domain が実際に authorization を付与した当事者によって管理されているか、または明示的に scope に含まれていることを確認します。NIST SP 800-115 は、testing 前に public target address が組織の管理下にあることを確認するよう推奨しています。<sup>[[2]](#references)</sup>

## Engagement-specific fast egress

### Build workflow

1. **engagement account/project を作成する:** 正確な billing 情報と ownership 情報を使用し、red team organization の配下に作成します。他の client から role、API key、budget、audit log を分離します。
2. **すべての provider policy を確認する:** Cloud、VPS、CDN、domain、email、VPN provider にはそれぞれ異なるルールがあります。たとえば AWS は、指定された assessment を許可していますが、hosted C2/covert simulation には事前承認を要求し、列挙された activity を禁止しています。<sup>[[3]](#references)</sup>
3. **固定 egress address を割り当てる:** ROE annex に記載します。IP/resource の急速な cycling は避けてください。incident response を複雑にし、provider policy に違反する可能性があります。
4. **management を harden する:** key-only SSH または identity-aware management plane、phishing-resistant MFA、分離された admin network、least privilege、patch 済み image、public admin port の無効化、暗号化された secret storage を使用します。
5. **full-tunnel path を作成する:** operator endpoint から bastion まで接続します。DNS と IPv6 を意図的に route し、tunnel が停止した場合は firewall deny を適用します。
6. **outbound destination と port を制限する:** 可能な場合は authorized scope に限定します。scanner には rate limit を設定し、不可逆または破壊的な technique は別の approval gate の配下に置きます。
7. **surveillance ではなく accountability のために log を取得する:** operator authentication、configuration change、start/stop、source address、scoped destination、tool/job identifier を記録します。exercise に必要で、data plan によって保護される場合を除き、payload や credential の capture は避けます。
8. **組織が所有する controlled endpoint を通じて検証する:** 観測された IPv4/IPv6、DNS path、reverse DNS、clock、source-port behavior、failure/reconnect、provider abuse contact を確認します。
9. **attribution map を安全に共有する:** exercise controller または合意済みの escrow contact と共有します。blind detection が test の一部である場合、target team には公開しません。

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
VPSは宛先に対してのみ仮名性を持ちます。ホスト側には、連絡先、請求、身元、送信元IP、API、デバイス、位置情報、利用状況の記録が存在する可能性があり、顧客から確認できるAWS CloudTrailの履歴だけでも管理活動が明らかになることがあります。<sup>[[4]](#references)</sup> ホスティング料金を暗号資産で支払っても、これらの記録が消えるわけではありません。

## Domains and certificates

- 組織が所有する、エンゲージメント専用のregistrarアカウントを使用する。
- registrar lock、対応している場合はDNSSEC、MFA/security keysを有効にし、auto-renewは承認された期間に限って有効にする。
- 公開される情報を減らすためにregistration privacyを使用する。ただし、登録者情報を偽ってはならない。ICANNのポリシーでは、公開表示が削除またはproxy経由の場合でも、registrarは登録データを収集する必要がある。<sup>[[5]](#references)</sup>
- 無関係な第三者を違法に偽装する名前は避ける。Typosquatting/lookalike domainsには、clientとproviderによる明示的な承認が必要である。
- DNS、certificates、CDN/redirector設定、operatorまたはclientの情報をleakする可能性があるthird-party analyticsを棚卸しする。
- teardown時には、レコードを削除し、certificates/tokensをrevokeし、合意した証拠を保全し、domainを防御目的で保持するか判断する。

## Authorized on-site drop nodes

Raspberry Piまたは同様のapplianceは、施設/network所有者とclientが、その正確な設置場所と動作を明示的に承認した場合に限り使用できる。安全な計画は次のとおりである。

1. デバイスのserial、MAC/private-MACポリシー、写真、所有者、正確な承認済み設置場所、電源、回収期限、tamper時の連絡先を記録する。
2. 最小構成のsigned image、暗号化されたsecrets、read-onlyまたは復旧可能なstorage、host firewall、実行可能な場合はautomatic security updatesを使用し、default credentialsを使用しない。
3. 指定されたengagement endpointへのoutbound-only通信を設定する。認証のないlistenerを公開してはならない。
4. 宛先とcapabilitiesをallowlist化する。Packet capture、credential collection、wireless impersonation、lateral movementは、それぞれ明示的に承認されなければならない。
5. Mutual authentication、短期間のkeys、remote kill、health reporting、bandwidth limitsを使用する。
6. 紛失または盗難が発生しても、再利用可能なcredentialsやclient dataが漏れないようにする。
7. 回収とsecure wipe/decommissionを予定表に入れ、署名済みの回収記録を取得する。

所有者またはoperatorの書面による許可なく、café、hotel、shared office、近隣住民の所有地、public venueにhardwareを隠してはならない。

## Guest networks and travel routers

承認されたシナリオでguest accessが必要な場合：

- 会場/clientにSSIDとacceptable-use policyを確認する。
- 組織所有のtravel routerまたはlow-trust bridge deviceを使用して、privileged workstationを分離する。
- captive portalsはprivileged workstationの外部で完了する。
- assessment trafficの前にapproved tunnelを開始する。
- tethered devicesが実際にそのtunnelを使用していることを確認する。
- 会場がradio association、portal、物理的な存在、camera/payment recordsを相関付けられると想定する。
- access controlを回避したり、別のdeviceをcloneしたり、Wi-Fiをattackしたり、equipmentを置き去りにしたりしてはならない。

## Operational separation

- endpoint compartment、cloud project、secrets set、domain group、redirector set、evidence storeごとに、1つのclient/engagementのみを割り当てる。
- 承認された組織のsystems外では、personal email、browser sync、phone number、cloud drive、SSH/GPG key、code-signing identity、payment reimbursementを使用しない。
- exercise designがfingerprintingを許容していない限り、client間で特徴的なpayload configuration、callback paths、certificates、public repositoriesを再利用しない。
- infrastructureにはkill dateとbudget alertを設定する。放置されたsystemsはclientとInternetの双方にとってriskになる。
- 事故を調査できるだけの内部attributionを保持する。「No logs」は通常、professionalな証拠保全および安全上の義務と両立しない。

## Blind to defenders, attributable to the controller

exerciseの目的がallowlistをテストすることではなくdetectionを測定することである場合、運用のaccountabilityを失わずに、対象SOCから情報を伏せることができる。

1. exercise controllerが、すべてのpublic source、domain、certificate、on-site deviceを承認する。ただし、その一覧はSOCには開示しない。
2. controllerは、source-to-engagement/operator mapを、2人による緊急accessが可能な別の暗号化vaultに保管する。
3. 各operator jobには、scope、time window、source compartment、変更不能なjob identifierを含むsigned manifestを付与する。通常の運用中、targetがmanifestを確認する必要はない。
4. bastion audit eventsをchain化するか、controller storageへappend-onlyで送信し、incident後にoperatorがattributionを密かに書き換えられないようにする。
5. 24/7のprovider-abuse contactが、clientを公に開示せずにauthorizationを確認できるverification phrase/referenceを保持する。
6. すべてのpathに、assessment C2、target network、または1人のoperatorのaccountに依存しないout-of-band stop channelを実装する。
7. live testingの前に、すべてのsourceからbenign canariesを送信する。controllerがROEのresponse time内にそれらを特定して停止できることを確認する。
8. exercise後、SOC telemetryとcontroller ledgerを比較し、source listを開示して、見逃しや誤検知について説明する。

Anti-forensics、log destruction、compromised relays、false subscriber identitiesを追加してはならない。これらはaccountableなtestingを改善するどころか、妨げるものである。

## Teardown checklist

- [ ] Exercise controllerがstopを確認する。
- [ ] C2、tunnels、redirectors、mail、VPN、scheduled jobsを無効化する。
- [ ] On-site devicesを物理的に回収し、照合する。
- [ ] Tokens、API keys、SSH keys、certificates、captured credentialsをrevoke/rotateする。
- [ ] DNSとcloud resourcesを削除するか、防御目的で保持するためにtransferする。
- [ ] Client dataをcontractに従って返却、保持、または破棄する。
- [ ] 必須のfinancial、audit、authorization recordsを暗号化し、access-controlledな状態で保持する。
- [ ] Provider abuse casesをクローズし、clientに最終的なsource indicatorsを提供する。
- [ ] 2人目のoperatorが、稼働中のinfrastructureが残っていないことを確認する。

## References

- [1] [NIST CSRC — Rules of Engagement](https://csrc.nist.gov/glossary/term/Rules_of_Engagement)
- [2] [NIST SP 800-115 — 情報セキュリティテストおよび評価のTechnical Guide](https://csrc.nist.gov/pubs/sp/800/115/final)
- [3] [AWS — Penetration Testingに関するCustomer Support Policy](https://aws.amazon.com/security/penetration-testing/)
- [4] [AWS — Privacy Notice](https://aws.amazon.com/privacy/) and [CloudTrail Event History](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
- [5] [ICANN — Registration Data Policy](https://www.icann.org/en/contracted-parties/consensus-policies/registration-data-policy)
{{#include ../banners/hacktricks-training.md}}
