# Capture-Resilient Authorized Field Nodes

オンサイトの Raspberry Pi、mini-PC、travel router、または cellular appliance は、authorized red team に永続的な vantage point を提供できます。同時に、発見、盗難、帰属特定の対象になりやすい存在でもあります。したがって適切な設計目標は、追跡不能な implant ではなく、**field node 上の権限を小さくした、安定した制御可能なアクセス**です。

このガイドは、site owner の書面による authorization を得て設置する機器にのみ適用されます。coffee shop、近隣住民、hotel、または共有 building は、ネットワークに接続可能というだけでは対象範囲に含まれません。同意のない場所に hardware を隠したり、captive portal を bypass したり、他人の credentials を使用したり、monitoring を妨害したり、発見後に証拠を消去しようとしたりしないでください。

{% hint style="warning" %}
信頼できる「痕跡を残さない」設定は存在しません。Radio association、DHCP/NAT、carrier、camera、購入、device、provider、controller、destination の records は、device の後にも残る可能性があります。accountable な red team は、代わりに node から **個人的な秘密情報および無関係な秘密情報**を削除し、保護された controller 側の attribution を保持し、capture 時の封じ込めを容易にします。
{% endhint %}

## Pros and cons

**Pros:** 現実的な内部または target に近い source、安定した高速 testing、NAC、egress、物理 inventory、SOC coverage の検証、operator の address 変更後も継続可能、bounded access を中央から revoke 可能。

**Cons:** 物理的な設置により強力な証拠が生じる。紛失すると device credentials、network profiles、収集データが露出する可能性がある。control traffic の反復は検知可能である。電源、portal、radio の変更により reliability が低下する。広範な tunnel は uncontrolled pivot になり得る。

## Threat model and design invariants

発見者が storage を取り外し、firmware を検査し、software が保持するすべての secret をコピーし、その後の network behavior を観察し、device を client または law enforcement に引き渡せるものとします。Full-disk encryption は、定義された threat model の下で電源オフの device のみを保護します。実行中で unlock された node と、memory に解放された keys は別のケースです。

| Invariant | Practical consequence |
|---|---|
| Operator と node の identity を直接結び付けない | Operator は organization gateway に sign in し、node には別の device identity を持たせる |
| Personal workstation の情報を持ち込まない | Personal SSH key、browser profile、email、password manager、phone pairing、cloud CLI cache を置かない |
| Controller の master secret を持たせない | 1 台の node から別の node の enroll、policy の変更、他の engagement の decrypt をできないようにする |
| Outbound-only かつ narrow | Field network は management listener を受け付けず、node は指定した rendezvous/update/time services にのみ接続する |
| 短期間かつ scope を限定した authority | 各 credential に 1 台の device、audience、service、expiry、即時 revocation path を設定する |
| Local data を最小化する | Results は controller に stream し、caches は暗号化し、size/TTL を制限して authoritative ではないものにする |
| Controller の accountability は capture 後も維持する | Asset と engagement の mapping、approvals、operator access、commands を中央に保存し、access-control を適用する |
| Loss が work を停止させる | Discovery または説明のつかない state change が発生したら、remote destruction ではなく stop、revoke、notify、evidence preservation を実行する |

NIST の IoT baseline は、device identification、configuration、data protection、logical access、secure software update、cybersecurity-state awareness を core capabilities として分類しています。特に state awareness と off-device event records は、compromise investigation を支援するものとして扱われています。<sup>[[1]](#references)</sup>

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
ゲートウェイは、どの名前付き operator がどの名前付き device に到達したかを把握する必要があります。field node に必要なのは、rendezvous 用の device credential だけです。field node が operator の送信元アドレスや authentication secret を知ることはなく、operator が private management key を field node にコピーすることもありません。これにより、exercise の説明責任を損なうことなく、**field storage から**復元可能な個人との関連付けを減らせます。

より大規模な fleet では、workload-identity system によって短期間有効な X.509 identity を発行し、key を自動的に rotate できます。SPIFFE は可能な場合に X.509 SVID を推奨しており、短い有効期間と頻繁な rotation によって key-compromise exposure を制限できると説明しています。<sup>[[2]](#references)</sup> 小規模な team でも、private CA と device ごとの certificate を自動化することで同じ特性を適用できます。この pattern を満たすためだけに SPIRE を install する必要はありません。

## Step 1: authorize and register the placement

1. owner、site、正確な許可 placement zone、許可された network、assessment window、許可された destination/action、emergency contact を記録します。
2. model、serial、storage serial、有線/無線 MAC、modem IMEI/eSIM または SIM ICCID、power supply、現在の photograph を記録します。
3. device に個人と結び付かない engagement identifier（例: `E2026-014-DROP03`）を付与します。broadcast hostname や SSID に client name を埋め込まないでください。
4. この test における「lost」「moved」「discovered」の意味を exercise controller と、必要最小限の physical-security/SOC deconfliction group に伝えます。
5. 誰が retrieve してよいか、finder がどのように報告できるかを事前に合意します。safety label には、controlled callback を提供しつつ、sensitive な client detail を省略できます。
6. 自動的な authorization expiry を設定します。scope 終了後も connectivity が継続していることによって、permission が延長されてはなりません。

## Step 2: build a minimal recoverable image

supported OS image を使用し、vendor が文書化した channel を通じてその signature/checksum を検証し、security update を install して、再現可能な build manifest を保持します。software が許可する場合は、小さな writable data partition を備えた read-only または immutable base を優先します。

1. default account、demo service、compiler、および authorized workload に不要な package を削除します。
2. exercise が明示的に必要としない限り、local GUI、Bluetooth、discovery protocol、file sharing、Wi-Fi P2P、inbound administration を無効にします。
3. hardware が実際に対応している場合は secure boot と measured boot/TPM-backed key release を有効にします。正確な model を検証せずに、Raspberry Pi の configuration が PC-class measured boot を備えていると主張してはなりません。
4. local writable state を encrypt し、厳格な maximum size と retention time を設定します。Encryption は delay/containment control であり、running node が何も漏らさないことの証明ではありません。
5. 重要な log を off-device に送信します。storage exhaustion を防ぐため local journal に上限を設けますが、log wiping や anti-forensic deletion を設定してはなりません。
6. image manifest、package version、configuration hash、recovery instruction を controller に保存します。
7. manifest から spare を reimage し、同じ health test を実行します。builder だけが recovery できる design は field-ready ではありません。

## Step 3: issue identities with one-way trust

3 種類の異なる identity を作成します。

- **device identity**: この device の rendezvous のみが受け入れるもの。
- **operator identity**: organization gateway が受け入れ、phishing-resistant MFA で保護するもの。
- **controller/deployment identity**: approved job または configuration の sign に使用し、operator と field node の両方の外部で保持するもの。

node には signed job を verify するために必要な public key を持たせるべきであり、signing key を持たせてはいけません。capture された device credential によって、cloud console、source repository、payment account、他の node、client production に authenticate できてはなりません。

automatic renewal が確実に機能する場合は、短い certificate lifetime を使用します。長期間有効な WireGuard key が operational に必要な場合は、その public key を revocation handle として扱い、peer-specific tunnel address、firewall policy、broker authorization によって制約します。その peer を直ちに削除する、テスト済みの controller action を保持します。

## Step 4: stable outbound rendezvous

次の owned-lab pattern は、inbound service を公開せずに NAT 経由で stable management を提供します。これは通常の WireGuard networking であり、covert reverse shell ではありません。documentation address を使用し、organization が所有する endpoint に置き換えてください。

organization rendezvous では `10.77.0.1/32` を割り当て、field node には `10.77.0.20/32` を割り当てます。gateway peer entry は、node の単一の address のみを受け入れるようにします。
```ini
# rendezvous: /etc/wireguard/wg-field.conf (relevant peer only)
[Peer]
PublicKey = <DROP03_PUBLIC_KEY>
AllowedIPs = 10.77.0.20/32
```
ノードはランデブーに向けて外向きに接続し、必要な場合にのみNATマッピングを維持します。
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
WireGuard は、永続性が必要な場合、多くの NAT/firewall 実装で 25 秒を妥当な keepalive 間隔として文書化している。必要でない場合は、無効のままにする方が望ましい。<sup>[[3]](#references)</sup> `AllowedIPs = 10.77.0.1/32` により、これは意図的に管理用パスとなり、default-route pivot にはならない。

次に、WireGuard の外側で controls を適用する:

1. 承認済みの bootstrap DNS path を通じて `vpn.redteam.example` を解決し、期待される organization endpoint を deployment records に固定する。
2. node 上では、送信 DHCP/RA、必要な DNS/NTP、rendezvous endpoint、および最小限の承認済み update path のみを許可する。すべての uplink で、要求されていない inbound traffic を拒否する。
3. rendezvous では、`10.77.0.20` が exercise に必要な broker/health service にのみ到達できるようにする。client network 内へ一般的に forward してはならない。
4. 対話的な operator access は organization gateway の背後に置く。signed pull-job interface で assessment の要件を満たせる場合は、tunnel 経由で node から SSH を公開しない。
5. service manager を設定し、networking 後に tunnel を起動し、障害後は上限付き backoff で restart し、連続した障害後に alert を発生させる。restart loop によって venue を圧迫したり、根本的な fault を隠したりしてはならない。
6. peer の latest handshake を確認する。ただし、「handshake が存在する」ことを device が侵害されていない証拠として使用してはならない。

TURN は、専用の WebRTC control plane に relay-only reachability を提供でき、message queue は断続的な service に耐えられる。TURN は NAT の背後にある client に public relay address を明示的に与えるが、その server は observer のままである。<sup>[[4]](#references)</sup> observer または reliability benefit を明示しないまま tunnel を積み重ねるのではなく、1 つの control architecture を選択する。

## Step 5: 個人の link を使わない uplink の安定性

承認済みの venue node では、次の順序を優先する:

1. client が提供する有線接続または専用 test VLAN;
2. owner が承認した enterprise/guest Wi-Fi profile;
3. organization が契約した cellular/private APN fallback。

personal phone hotspot、home SSID、personal eSIM、personal Apple/Google account、または日常的に使用する laptop から export した Wi-Fi profile を、決して登録してはならない。これらはまさに capture が接続する artifact である。

承認済みの各 uplink について:

- SSID/BSSID または switch/VLAN と、想定される captive-portal の挙動を記録する;
- deterministic priority と、所有する endpoint への health check を設定する;
- failover で変更するのは underlay のみとし、device と operator の identities は broker に残す;
- transition 中に DNS、IPv6、application traffic が rendezvous を bypass しないようにする;
- unknown SSID/BSSID、SIM change、新しい default gateway、public-IP/ASN change、または同時 uplink を alert する;
- deployment 前に、power loss、DHCP renewal、AP restart、public-IP change、24 時間の idle、tunnel loss、primary-to-secondary-to-primary recovery をテストする。

Private MAC addressing は、ネットワークをまたいだ casual な tracking を減らせるが、承認済み NAC には network ごとに安定した MAC が必要になることが多い。選択した OS が実際に行う動作を記録し、owner の access control を回避するために rotate してはならない。

## Step 6: 作業と data を制限する

安全な field node は、mailbox から任意の shell text を受け付けるべきではない。`health`、`fetch-owned-url`、`capture-approved-interface-for-60s`、または rules of engagement に明示的に記載された別の action など、signed job types を定義する。destination、duration、rate、output size、scope を node 上でも再度検証する。

1. すべての job に、unique ID、device audience、issue time、expiry、scope reference、maximum output を付与する。
2. controller/deployment identity で署名する。
3. unknown fields、expired/replayed jobs、別の device 向けの jobs を拒否する。
4. results を所有する collector に stream し、避けられない local spool は encrypt して TTL を設定する。
5. accepted/rejected job ID と result hash を controller で log する。sensitive command parameters を public monitoring channel に配置してはならない。
6. authorization の期限が切れた場合、identity rotation に失敗した場合、または controller が device を quarantined とした場合は、処理を停止する。

## discovery、loss、または compromise の monitoring

Monitoring は、観測された state が変化したことを controller に伝えられる。しかし、「investigators が device を発見した」ことを確実に証明することはできない。また responders を surveil したり、その systems を probe したりすることは、authorized assessment の範囲を超える。

### off-device state を収集する

randomized だが運用上の上限がある interval で、signed low-volume health record を controller に送信する。controller が必要とするものだけを含める:

- device ID、boot ID/counter、monotonic uptime;
- configuration/image hash、software version;
- device-certificate serial、renewal state;
- uplink class、interface、承認済みの場合は BSSID または switch context、default-gateway hash、owned service が観測した public IP/ASN;
- tunnel handshake age、packet counters、queue depth;
- owner が sensor を承認した場合は enclosure switch または hardware-tamper state;
- disk pressure、temperature、clock-offset estimate、last successful job ID;
- replay または gaps を明らかにする sequence number と signature。

gateway authentication、policy decisions、operator access、job submission、result hashes、provider audit events、alerts を中央で保存する。CISA は、logs の centralizing、削除からの保護、通常の activity の baselining、incident-response contacts の指定を推奨している。<sup>[[5]](#references)</sup>

### Discovery/compromise indicators

| Signal | Possible explanations | Controller action |
|---|---|---|
| Heartbeat absent | power/network failure、portal change、damage、意図的な blocking、または removal | provider/site state と照合する; 承認されていない path から reconnect しない |
| Boot counter changed unexpectedly | power cut、crash、removal、または maintenance | jobs を quarantine する; time と site events を比較する |
| Config/image hash changed | update error、storage fault、または tampering | work を停止する; controller-approved release でなければ revoke する |
| New uplink/BSSID/gateway/ASN | AP replacement、roaming、device の移動、または interception | approved inventory と比較する; 説明できない transition は quarantine する |
| Repeated rejected job/signature | corruption、replay、または unauthorized controller | processing を停止し、gateway/controller logs を調査する |
| Device credential used twice or from incompatible paths | cloned key、snapshot reuse、または network transition | 直ちに revoke する; 両方の session records を保持する |
| Unexpected local login, interface, process or privilege event | maintenance または compromise | broker policy を通じて isolate する; evidence を保持する |
| Enclosure switch/state transition | service、movement、または discovery | 指定された site contact に通知する; destructive action は発動しない |
| Provider abuse notice/account query or SOC alert | detection、misconfiguration、または out-of-scope traffic | activity を停止し、deconfliction/incident process を開始する |
| Sentinel credential touched | この node 固有の、privilege を持たない decoy secret を誰かが読んだ | 実際の device identity を revoke し、alert trail を保持する |

sentinel credential は **access を一切付与せず**、organization が所有する alert service のみを呼び出し、rules of engagement に開示しなければならない。これは unauthorized reading に対する tripwire であり、equipment を発見した者を tracking する beacon ではない。

### Alert thresholds

1 つの劇的な「caught」alarm ではなく、stateful rules を使用する:

- **warning:** 1 回の interval missed、通常の address change、または queue growth;
- **degraded:** 3 回連続の misses、renewal delay、primary-uplink loss、または repeated restart;
- **quarantine:** unapproved hash/boot/uplink change、duplicate credential、sentinel use、または unexpected privileged event;
- **confirmed discovery/loss:** site/controller report、physical inventory mismatch、planned でない party による device recovery、または validated provider/SOC escalation。

field node から独立した channel を通じて alert delivery をテストする。sensitive な client/device detail を personal messaging または consumer push accounts に送信しない。

## Suspected discovery or capture runbook

1. **Stop:** 新しい jobs と operator sessions を suspend する。「監視されているか」を確認する probe を送信してはならない。
2. **Quarantine:** broker に device identity とその routes を deny させ、既存の logs は保持する。
3. **Revoke:** device certificate/key、queue token、update credential、single-purpose service token を revoke する。physical loss が疑われる場合は organization SIM を suspend する。
4. **Preserve:** controller、gateway、provider、alert records の snapshot を取得し、trusted time、実行者、last known configuration を記録する。node を clear または remotely wipe してはならない。
5. **Notify:** exercise controller、client incident contact、authorization で定義された legal/privacy contacts に連絡する。第三者が発見した場合は、事前合意済みの recovery process を使用する。
6. **Assess:** node 上のすべての secret と cached result が exposed になったと想定する。各 secret が access できた対象と、suspicious event 後に使用されたかを正確に列挙する。
7. **Contain downstream:** 影響を受けた service credentials を rotate し、pending jobs を invalidate し、owned target/provider logs を調査して unexpected behavior がないか確認する。
8. **Recover safely:** authorized person を通じてのみ回収する; 写真撮影と梱包を行い、custody を記録し、client の指示に従って forensic evidence を取得する。
9. **Resume with a new identity:** captured credential を黙って再有効化してはならない。known manifest から rebuild し、control failure を修正して、明示的な承認を得る。

NIST の current incident-response guidance は、preparation、detection、response、recovery を organization-wide cybersecurity risk management に統合している。client が何が起きたかを判断し、適切な response を選択できるよう、最初に preserve する。<sup>[[6]](#references)</sup>

## Capture drill before deployment

unlocked test unit またはその storage の copy を別の reviewer に渡し、次の項目を列挙するよう依頼する:

1. device/site/engagement identifiers;
2. operator names、personal accounts、home/workstation networks、recovery contacts;
3. controller/broker destinations と credentials;
4. client network profiles と cached results;
5. 各 secret で到達可能な other devices/projects;
6. value または payment credentials;
7. controller が何を revoke でき、どれほど迅速に実行できるか;
8. central logs から、どの activity が attribution 可能なまま残るか。

Pass criteria: personal accounts/workstation keys がゼロ; cross-engagement または enrollment authority がゼロ; payment credential がない; bounded encrypted cache; document 化された device-revocation action が 1 つ; controller-side accountability が完全であること。予期しない personal link または lateral capability は、release blocker として扱う。

## Closeout

1. scope の終了時に jobs を停止し、broker route を disable する。
2. 正確な inventory を回収・照合し、missing なものがあれば報告する。
3. engagement retention plan に従い、logs/results と、必要な場合は forensic image を保持する。
4. hardware が回収された場合でも、device、SIM、queue、update、service identities を revoke する。
5. preservation/acceptance の後にのみ、owner が承認した data-disposal process で media を sanitize または destroy し、完了を記録する。これは lifecycle management であり、concealment ではない。
6. venue NAC/DHCP reservations、broker routes、DNS、cloud roles、alert rules、temporary contacts を削除する。
7. observed detection、missed telemetry、quarantine までの時間、capture が exposed にしたすべての artifact を記録する。

## References

- [1] [NIST — IoT Device Cybersecurity Capability Catalog](https://pages.nist.gov/IoT-Device-Cybersecurity-Requirement-Catalogs/) and [NIST — Cybersecurity Event Awareness](https://pages.nist.gov/FederalProfile-8259A/technical/event/)
- [2] [SPIFFE — Concepts and short-lived workload identities](https://spiffe.io/docs/latest/spiffe/concepts/)
- [3] [WireGuard — Quick Start: Persistent Keepalive](https://www.wireguard.com/quickstart/)
- [4] [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [5] [CISA — Use Logging on Business Systems](https://www.cisa.gov/audiences/small-and-medium-businesses/secure-your-business/use-logging-on-business-systems)
- [6] [NIST SP 800-61 Rev. 3 — Incident Response Recommendations and Considerations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
