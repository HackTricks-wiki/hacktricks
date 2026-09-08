# Capture-Resilient Authorized Field Nodes

{{#include ../banners/hacktricks-training.md}}

オンサイトの Raspberry Pi、mini-PC、travel router、または cellular appliance は、authorized red team に持続的な vantage point を提供できます。同時に、発見、窃盗、帰属特定の対象にもなり得ます。したがって、適切な設計目標は、追跡不能な implant ではなく、**field node の権限を低く抑えた、安定した管理下のアクセス**です。

このガイドは、サイト所有者の書面による許可を得て設置された機器にのみ適用されます。ネットワークに接続できるというだけで、coffee shop、近隣住民、ホテル、共有ビルがスコープに含まれるわけではありません。承諾のない場所に hardware を隠したり、captive portal を bypass したり、他人の credentials を使用したり、monitoring を妨害したり、発見後に証拠を消去しようとしたりしないでください。

{% hint style="warning" %}
信頼できる「痕跡を残さない」設定はありません。Radio association、DHCP/NAT、carrier、camera、購入記録、device、provider、controller、destination の記録は、device がなくなった後も残る可能性があります。説明責任のある red team は、代わりに **個人情報および無関係な secrets** を node から削除し、保護された controller 側の帰属情報を保持し、capture 時の封じ込めを容易にします。
{% endhint %}

## Pros and cons

**Pros:** 現実的な内部または target に近接した source；安定した高速 testing；NAC、egress、物理 inventory、SOC coverage の検証；operator の address 変更後も継続可能；限定された access を中央から revoke 可能。

**Cons:** 物理的な設置により強力な証拠が残る；紛失すると device credentials、network profiles、収集データが露出する可能性がある；繰り返される control traffic は検知可能；電源、portal、radio の変更により信頼性が低下する；広範な tunnel は管理不能な pivot になり得る。

## Threat model and design invariants

発見者が storage を取り外し、firmware を検査し、software が保持するすべての secrets をコピーし、その後の network behavior を監視し、device を client または law enforcement に提出できると仮定します。Full-disk encryption は、明示された threat model の範囲において、電源オフの device のみを保護します。実行中で unlock された node と、memory に展開された keys は別のケースです。

| Invariant | Practical consequence |
|---|---|
| No direct operator-to-node identity | Operator は organization gateway に sign in し、node には別の device identity を持たせる |
| No personal workstation material | 個人の SSH key、browser profile、email、password manager、phone pairing、cloud CLI cache を置かない |
| No controller master secret | 1 台の node から別の node を enroll したり、policy を変更したり、他の engagements を decrypt したりできない |
| Outbound-only and narrow | Field network は management listener を受け付けず、node は指定された rendezvous/update/time services にのみ接続する |
| Short-lived, scoped authority | 各 credential には、1 台の device、audience、service、expiry、即時 revoke path を 1 つずつ設定する |
| Minimal local data | Results は controller に stream し、cache は encrypted、size/TTL を bounded にし、authoritative なものにしない |
| Controller accountability survives capture | Asset-to-engagement mapping、approvals、operator access、commands を中央で保存し、access-controlled にする |
| Loss stops work | 発見または説明のつかない state change が発生した場合、remote destruction ではなく、stop、revoke、notify、evidence preservation を実行する |

NIST の IoT baseline は、device identification、configuration、data protection、logical access、secure software update、cybersecurity-state awareness を core capabilities として分類しています。特に、state awareness と off-device event records を、compromise investigation を支援するものとして扱っています。<sup>[[1]](#references)</sup>

## Reference architecture
```text
operator workstation
|  phishing-resistant MFA; named user; no field-device key
v
organization access gateway ----> immutable audit / alerting
|  per-engagement authorization          ^
v                                        |
rendezvous/broker <==== outbound mTLS or WireGuard ==== field node
|                                                     |-- approved site Wi-Fi/Ethernet
+---- allowlisted owned test services                 +-- organization cellular fallback
```
Gatewayは、どの名前付きoperatorがどの名前付きdeviceに到達したかを把握する必要がある。field nodeに必要なのは、rendezvous用のdevice credentialだけである。field nodeがoperatorの送信元アドレスやauthentication secretを知ることはなく、operatorがprivate management keyをfield nodeにコピーすることもない。これにより、exerciseのaccountabilityを損なうことなく、**field storageから**復元可能な個人との紐付きを減らせる。

より大規模なfleetでは、workload-identity systemによって短期間有効なX.509 identityを発行し、keyを自動的にrotateできる。SPIFFEは、可能な場合にはX.509 SVIDを推奨し、短い有効期間と頻繁なrotationがkey-compromise exposureを制限すると説明している。<sup>[[2]](#references)</sup> 小規模なteamでも、private CAとdeviceごとのcertificateを自動化することで同じ特性を適用できる。このpatternを満たすためだけにSPIREをinstallする必要はない。

## Step 1: authorize and register the placement

1. owner、site、正確な許可配置zone、許可されたnetwork、assessment window、許可されたdestination/action、緊急連絡先を記録する。
2. model、serial、storage serial、有線/無線MAC、modem IMEI/eSIMまたはSIM ICCID、power supply、現在の写真を記録する。
3. deviceには、例えば`E2026-014-DROP03`のようなpersonと紐付かないengagement identifierを付与する。broadcast hostnameやSSIDにclient nameを含めない。
4. このtestにおける「lost」「moved」「discovered」の意味をexercise controllerと、必要最小限のphysical-security/SOC deconfliction groupに伝える。
5. 誰がretrieveできるか、finderがどのように報告できるかを事前に合意する。safety labelでは、sensitiveなclient detailを省略しつつ、controlled callbackを提供できる。
6. 自動的なauthorization expiryを設定する。scope終了後もconnectivityが継続していては、permissionが延長されてはならない。

## Step 2: build a minimal recoverable image

supported OS imageを使用し、vendorが文書化したchannelを通じてsignature/checksumを検証し、security updateをinstallして、reproducible build manifestを保持する。softwareが許可する場合は、small writable data partitionを備えたread-onlyまたはimmutable baseを優先する。

1. default account、demo service、compiler、authorized workloadに不要なpackageを削除する。
2. exerciseで明示的に必要とされない限り、local GUI、Bluetooth、discovery protocol、file sharing、Wi-Fi P2P、inbound administrationをdisableする。
3. hardwareが実際にサポートしている場合は、secure bootとmeasured boot/TPM-backed key releaseをenableする。正確なmodelを検証せずに、Raspberry PiのconfigurationがPC-class measured bootを備えると主張してはならない。
4. local writable stateをencryptし、strictなmaximum sizeとretention timeを設定する。Encryptionはdelay/containment controlであり、running nodeが何も明らかにしないことの証明ではない。
5. 重要なlogをdevice外へ送信する。storage exhaustionを防ぐためlocal journalに上限を設けるが、log wipingやanti-forensic deletionをconfigureしてはならない。
6. image manifest、package version、configuration hash、recovery instructionをcontrollerに保存する。
7. manifestからspareをreimageし、同じhealth testを実行する。builderだけがrecoverできるdesignはfield-readyではない。

## Step 3: issue identities with one-way trust

3種類の異なるidentityを作成する。

- **device identity**：このdevice用のrendezvousだけが受け入れるidentity。
- **operator identity**：organization gatewayが受け入れ、phishing-resistant MFAで保護するidentity。
- **controller/deployment identity**：approved jobまたはconfigurationへの署名に使用し、operatorとfield nodeの双方の外部で保持するidentity。

nodeにはsigned jobをverifyするために必要なpublic keyを持たせるが、signing keyは決して持たせない。captureされたdevice credentialでcloud console、source repository、payment account、他のnode、client productionにauthenticateできてはならない。

自動renewalを確実に行える場合は、短いcertificate lifetimeを使用する。長期間有効なWireGuard keyが運用上必要な場合は、そのpublic keyをrevocation handleとして扱い、peer固有のtunnel address、firewall policy、broker authorizationで制約する。そのpeerを即座にremoveする、test済みのcontroller actionを用意しておく。

## Step 4: stable outbound rendezvous

以下のowned-lab patternは、inbound serviceを公開せずにNAT越しのstable managementを提供する。これは通常のWireGuard networkingであり、covert reverse shellではない。documentation addressを使用し、組織が所有するendpointに置き換える。

organization rendezvousでは`10.77.0.1/32`を割り当て、field nodeには`10.77.0.20/32`を割り当てる。gateway peer entryでは、nodeの単一addressのみを受け入れるべきである。
```ini
# rendezvous: /etc/wireguard/wg-field.conf (relevant peer only)
[Peer]
PublicKey = <DROP03_PUBLIC_KEY>
AllowedIPs = 10.77.0.20/32
```
ノードは rendezvous への outbound 接続を開始し、必要な場合にのみ NAT mapping を維持します。
```ini
# field node: /etc/wireguard/wg-field.conf
[Interface]
Address = 10.77.0.20/32
PrivateKey = <DROP03_PRIVATE_KEY>

[Peer]
PublicKey = <RENDEZVOUS_PUBLIC_KEY>
Endpoint = vpn.redteam.example:51820
AllowedIPs = 10.77.0.1/32
PersistentKeepalive = 25
```
WireGuardは、永続性が必要な場合、多くのNAT/firewall実装で25秒を妥当なkeepalive間隔として文書化しています。必要ない場合は無効のままにする方が望ましいです。<sup>[[3]](#references)</sup> `AllowedIPs = 10.77.0.1/32` により、これは意図的に管理用パスとなっており、default-route pivotではありません。

次に、WireGuardの外側でcontrolsを適用します。

1. 承認済みのbootstrap DNS pathを通じて`vpn.redteam.example`を解決し、想定するorganization endpointをdeployment recordsに固定します。
2. node上では、outbound DHCP/RA、必要なDNS/NTP、rendezvous endpointおよび最小限の承認済みupdate pathを許可します。すべてのuplinkで、未承諾のinbound trafficを拒否します。
3. rendezvousでは、`10.77.0.20`がexerciseに必要なbroker/health serviceにのみ到達できるようにします。client networkへ一般的にforwardしてはなりません。
4. interactive operator accessはorganization gatewayの背後に置きます。signed pull-job interfaceでassessmentを満たせる場合は、tunnel経由でnodeからSSHを公開しないでください。
5. service managerがnetworking後にtunnelを起動し、障害後は上限付きbackoffでrestartし、繰り返し失敗した場合にalertするよう設定します。restart loopによってvenueを圧迫したり、根本原因を隠したりしてはなりません。
6. peerのlatest handshakeを確認しますが、「handshakeが存在する」ことをdeviceがcompromisedでない証拠として使用してはなりません。

TURNは、専用のWebRTC control planeにrelay-only reachabilityを提供でき、message queueは断続的なserviceに耐えられます。TURNはNATの背後にいるclientにpublic relay addressを明示的に提供しますが、そのserverはobserverのままです。<sup>[[4]](#references)</sup> observerまたはreliability benefitを明示しないままtunnelを積み重ねるのではなく、1つのcontrol architectureを選択してください。

## Step 5: personal linksを使わないuplink stability

承認済みのvenue nodeでは、次の順序を優先します。

1. client提供の有線接続または専用test VLAN；
2. owner承認済みのenterprise/guest Wi-Fi profile；
3. organizationが契約したcellular/private APN fallback。

personal phone hotspot、home SSID、personal eSIM、personal Apple/Google account、または日常用laptopからexportしたWi-Fi profileを決して登録しないでください。これらはcaptureが接続する対象となるartifactそのものです。

承認済みの各uplinkについて、次を実施します。

- SSID/BSSIDまたはswitch/VLAN、および想定されるcaptive-portal behaviorを記録する；
- deterministic priorityと、所有するendpointへのhealth checkを設定する；
- failoverではunderlayのみを変更し、deviceおよびoperator identityはbrokerに残す；
- transition中にDNS、IPv6およびapplication trafficがrendezvousを迂回しないようにする；
- unknown SSID/BSSID、SIM変更、新しいdefault gateway、public-IP/ASN変更、または同時uplinkをalertする；
- deployment前に、power loss、DHCP renewal、AP restart、public-IP変更、24時間idle、tunnel loss、primary-to-secondary-to-primary recoveryをテストする。

Private MAC addressingは、ネットワーク間のcasual trackingを減らせますが、承認済みNACにはnetworkごとにstableなMACが必要になることがあります。選択したOSが実際に行うことを記録し、ownerのaccess controlを回避するためにrotateしないでください。

## Step 6: workとdataを制限する

safeなfield nodeは、mailboxから任意のshell textを受け付けるべきではありません。`health`、`fetch-owned-url`、`capture-approved-interface-for-60s`など、rules of engagementで明示的に指定されたactionに対応するsigned job typeを定義します。destination、duration、rate、output size、scopeをnode上でも再度validateします。

1. すべてのjobに、unique ID、device audience、issue time、expiry、scope reference、maximum outputを付与する。
2. controller/deployment identityでsignする。
3. unknown field、expired/replayed job、および別device向けのjobをrejectする。
4. resultをowned collectorへstreamし、避けられないlocal spoolはencryptしてTTLを設定する。
5. accepted/rejected job IDとresult hashをcontrollerに記録する。sensitive command parameterをpublic monitoring channelに置かない。
6. authorizationのexpiry、identity rotationの失敗、またはcontrollerによるdevice quarantine時にはprocessingを停止する。

## discovery、lossまたはcompromiseのMonitoring

Monitoringは、observed stateが変化したことをcontrollerに伝えられます。しかし、「investigatorがdeviceを発見した」ことを確実に証明するものではなく、respondersをsurveilしたり、そのsystemをprobeしたりすることはauthorized assessmentの範囲を超えます。

### device外でstateを収集する

randomizedだがboundedなoperational intervalで、signedかつlow-volumeのhealth recordをcontrollerへ送信します。controllerが必要とするものだけを含めます。

- device ID、boot ID/counter、monotonic uptime；
- configuration/image hash、software version；
- device-certificate serial、renewal state；
- uplink class、interface、authorizedな場合のBSSIDまたはswitch context、default-gateway hash、owned serviceが観測したpublic IP/ASN；
- tunnel handshake age、packet counters、queue depth；
- ownerがsensorを承認している場合のenclosure switchまたはhardware-tamper state；
- disk pressure、temperature、clock-offset estimate、last successful job ID；
- replayまたはgapを明らかにするsequence numberとsignature。

gateway authentication、policy decision、operator access、job submission、result hash、provider audit event、alertをcentralに保存します。CISAは、logのcentralization、削除からの保護、通常activityのbaseline化、incident-response contactの指定を推奨しています。<sup>[[5]](#references)</sup>

### Discovery/compromise indicators

| Signal | Possible explanations | Controller action |
|---|---|---|
| Heartbeat absent | power/network failure、portal change、damage、deliberate blockingまたはremoval | provider/site stateとcorroborateする；unapproved pathからreconnectしない |
| Boot counter changed unexpectedly | power cut、crash、removalまたはmaintenance | jobをquarantineする；timeとsite eventを比較する |
| Config/image hash changed | update error、storage faultまたはtampering | workを停止する；controller-approved releaseでなければrevokeする |
| New uplink/BSSID/gateway/ASN | AP replacement、roaming、deviceの移動またはinterception | approved inventoryと比較する；説明できないtransitionをquarantineする |
| Repeated rejected job/signature | corruption、replayまたはunauthorized controller | processingを停止し、gateway/controller logを調査する |
| Device credential used twice or from incompatible paths | cloned key、snapshot reuseまたはnetwork transition | 即時revokeする；両方のsession recordを保持する |
| Unexpected local login、interface、processまたはprivilege event | maintenanceまたはcompromise | broker policyを通じてisolateする；evidenceを保全する |
| Enclosure switch/state transition | service、movementまたはdiscovery | 指定されたsite contactに通知する；destructive actionをtriggerしない |
| Provider abuse notice/account queryまたはSOC alert | detection、misconfigurationまたはout-of-scope traffic | activityを停止し、deconfliction/incident processを開始する |
| Sentinel credential touched | このnode専用のno-privilege decoy secretを誰かが読み取った | real device identityをrevokeし、alert trailを保全する |

sentinel credentialは**accessを一切付与せず**、organization-owned alert serviceだけを呼び出し、rules of engagementに開示しなければなりません。これはunauthorized readingに対するtripwireであり、equipmentを発見した者をtrackingするbeaconではありません。

### Alert thresholds

劇的な「caught」alarmを1つだけ使うのではなく、stateful ruleを使用します。

- **warning:** 1回のinterval miss、通常のaddress change、またはqueue growth；
- **degraded:** 3回連続のmiss、renewal delay、primary-uplink loss、またはrepeated restart；
- **quarantine:** unapproved hash/boot/uplink change、duplicate credential、sentinel use、またはunexpected privileged event；
- **confirmed discovery/loss:** site/controller report、physical inventory mismatch、unplanned partyによるdevice recovery、またはvalidated provider/SOC escalation。

field nodeから独立したchannelを通じてalert deliveryをテストします。sensitiveなclient/device detailをpersonal messagingやconsumer push accountへ送信しないでください。

## Discoveryまたはcaptureが疑われる場合のrunbook

1. **Stop:** 新しいjobとoperator sessionをsuspendします。「監視されているか確認する」probeを送信してはなりません。
2. **Quarantine:** brokerでdevice identityとそのrouteをdenyし、既存のlogは保持します。
3. **Revoke:** device certificate/key、queue token、update credential、single-purpose service tokenをrevokeします。physical lossが考えられる場合はorganization SIMをsuspendします。
4. **Preserve:** controller、gateway、provider、alert recordをsnapshotし、trusted time、実施者、last known configurationを記録します。nodeをclearまたはremote wipeしてはなりません。
5. **Notify:** authorizationで定義されたexercise controller、client incident contact、legal/privacy contactに連絡します。third partyが発見した場合は、事前合意済みのrecovery processを使用します。
6. **Assess:** node上のすべてのsecretとcached resultがexposeされたと仮定します。各secretがaccessできた対象と、suspicious event後に使用されたかを正確に列挙します。
7. **Contain downstream:** 影響を受けたservice credentialをrotateし、pending jobをinvalidateし、owned target/provider logでunexpected behaviorを調査します。
8. **Recover safely:** authorized personを通じてのみretrieveし、撮影・梱包し、custodyを記録し、clientの指示に従ってforensic evidenceを取得します。
9. **Resume with a new identity:** captured credentialを黙って再有効化してはなりません。known manifestからrebuildし、control failureを修正し、明示的な承認を取得します。

NISTの現行incident-response guidanceは、preparation、detection、response、recoveryをorganization-wide cybersecurity risk managementに統合しています。clientが何が起きたかを判断し、適切なresponseを選択できるよう、まずpreserveしてください。<sup>[[6]](#references)</sup>

## deployment前のCapture drill

unlockされたtest unitまたはそのstorageのcopyを別のreviewerに渡し、次を列挙してもらいます。

1. device/site/engagement identifier；
2. operator name、personal account、home/workstation network、recovery contact；
3. controller/broker destination、credential；
4. client network profile、cached result；
5. 各secretで到達可能な他のdevice/project；
6. valueまたはpayment credential；
7. controllerがrevokeできるものと、その所要時間；
8. central logからattributableなまま残るactivity。

Pass criteria：personal account/workstation keyがゼロ；cross-engagementまたはenrollment authorityがゼロ；payment credentialなし；bounded encrypted cache；documented device-revocation actionが1つ；controller-side accountabilityが完全であること。予期しないpersonal linkまたはlateral capabilityはrelease blockerとして扱います。

## Closeout

1. jobを停止し、scope終了時にbroker routeをdisableします。
2. 正確なinventoryをretrieveしてreconcileし、missingなものがあれば報告します。
3. engagement retention planに従い、log/resultおよび必要な場合はforensic imageを保全します。
4. hardwareがrecoveredされた場合でも、device、SIM、queue、update、service identityをrevokeします。
5. preservation/acceptance後にのみ、owner承認済みのdata-disposal processでmediaをsanitizeまたはdestroyし、完了を記録します。これはlifecycle managementであり、concealmentではありません。
6. venue NAC/DHCP reservation、broker route、DNS、cloud role、alert rule、temporary contactを削除します。
7. observed detection、missed telemetry、quarantineまでの時間、captureによって露出したすべてのartifactを記録します。

## References

- [1] [NIST — IoT Device Cybersecurity Capability Catalog](https://pages.nist.gov/IoT-Device-Cybersecurity-Requirement-Catalogs/) and [NIST — Cybersecurity Event Awareness](https://pages.nist.gov/FederalProfile-8259A/technical/event/)
- [2] [SPIFFE — Concepts and short-lived workload identities](https://spiffe.io/docs/latest/spiffe/concepts/)
- [3] [WireGuard — Quick Start: Persistent Keepalive](https://www.wireguard.com/quickstart/)
- [4] [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [5] [CISA — Business SystemsでLoggingを使用する](https://www.cisa.gov/audiences/small-and-medium-businesses/secure-your-business/use-logging-on-business-systems)
- [6] [NIST SP 800-61 Rev. 3 — Incident Response Recommendations and Considerations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
{{#include ../banners/hacktricks-training.md}}
