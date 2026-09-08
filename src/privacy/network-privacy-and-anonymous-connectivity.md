# Network Privacy & Anonymous Connectivity

{{#include ../banners/hacktricks-training.md}}

Network privacy は routing の選択であり、完全な identity ではありません。経路を選ぶ際は、**source**、**destination**、**content**、**timing** のうち、誰がどれを結び付けられないようにする必要があるかを考えてください。

標準化された inventory（すべての access-path family に対する `Pros`、`Cons`、step-by-step の `Procedure`、`Detection`）については、まず [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) を参照してください。このページでは、一般的に deploy 可能な選択肢を詳しく説明します。

## 各 observer が通常確認できる情報

| Path | Local network / ISP | Intermediary | Destination | Main limitation | Relative speed |
|---|---|---|---|---|---|
| Direct HTTPS | Source、destination の metadata、timing/volume | Hosting/CDN は connection を確認 | Source IP、browser/app data | source-IP privacy がない | 最速 |
| Commercial VPN | VPN に接続した source、通常の destination metadata は見えない | VPN は source と destination の metadata を確認 | VPN egress IP | 1 つの provider が correlation point になる | 通常は高速 |
| Self-hosted VPN/VPS | VPS に接続した source | Host/account/payment/control-plane logs | VPS egress IP | rented server/account に容易に attribution できる | 通常は高速 |
| Tor Browser | Tor/bridge に接続した source、timing/volume | 各 relay は限定された一部のみ確認 | Tor exit、browser data | 遅い、account/endpoint/correlation risks | 中速/低速 |
| Tails/Whonix | より強い routing boundaries を持つ同様の Tor path | 同じ Tor limitations | Tor exit/application data | Operational mistakes と host/hardware は残る | 中速/低速 |
| Public guest Wi-Fi + HTTPS | Venue は local device/timing と destination を確認 | Venue の ISP は metadata を確認 | Guest public IP | 物理的な captive-portal/device correlation | 高速/変動 |
| Cellular hotspot | Carrier は subscriber/device/location と destination を確認 | 使用時は VPN/Tor | Carrier、VPN、または Tor egress IP | Mobile subscription と location は永続的な identifier | 高速/変動 |
| Mixnet | Access は mixnet の利用、timing/volume を確認 | 複数の mixing node | Gateway/egress | 発展途上の ecosystem、latency と bandwidth cost | 最低速 |

HTTPS は transit 中の content を保護しますが、すべての metadata を保護するわけではありません。EFF によると、page path、credentials、messages が暗号化されていても、domain、time、traffic size は intermediary から見える場合があります。<sup>[[1]](#references)</sup>

## VPN: 高速な privacy と集中した trust

VPN は、access ISP から destination metadata を隠したり、untrusted network 上の first hop を保護したり、安定した engagement egress address を提示したり、private network に到達したりする用途に有用です。ただし、VPN によって user が anonymous になるわけではありません。VPN は source connection を確認でき、destination metadata を観測できます。また、accounts、cookies、GPS、fingerprints、payment information は残ります。<sup>[[1]](#references)</sup>

### Provider evaluation checklist

1. **Ownership and jurisdiction:** legal entity、parent company、operating countries、infrastructure subcontractors、適用される legal process を特定します。
2. **Collected data:** account/billing、source IP、connection timestamps、bandwidth、crash telemetry、DNS queries、destination logs を区別します。“No browsing logs” は “no data” を意味しません。
3. **Retention and deletion:** 正確な保存期間と、backups、fraud systems、processors が同じ schedule に従うかを確認します。
4. **Evidence:** scope、date、findings、remediation が公開された audits、reproducible/open clients、transparency reports、documented incidents を優先します。
5. **Protocol and client:** 維持管理された WireGuard、OpenVPN、またはレビュー済みの別の protocol、automatic updates、DNS と IPv6 handling、kill switch、platform ごとの leak tests を確認します。
6. **Business model:** 無料または補助金で運営される service の資金源を理解します。App-store への掲載だけでは、trustworthy な operation の証拠になりません。
7. **Payment fit:** alternative payment により VPN への billing disclosure は減らせますが、すべての connection で観測される source IP が消えるわけではありません。

### VPN の configure と verify

1. Provider/organization の signed client を公式 source から install します。
2. documented route を bypass する必要がない限り、**full tunnel** を選択します。Split tunneling は correlation と leak paths を作ります。
3. fail-closed/always-on behavior を有効にし、reconnect 中の traffic を block します。
4. DNS を tunnel 経由にし、IPv4 と IPv6 の両方を test します。安全に tunnel できない場合に限り protocol を disable し、その functionality loss を受け入れます。
5. sleep/wake、network switching、captive-portal login、tunnel crash、hotspot tethering を test します。NCSC は、一部の platform では tethered clients が phone の VPN を bypass する可能性があると警告しています。<sup>[[2]](#references)</sup>
6. organization-controlled test endpoint を使用して、観測された IPv4、IPv6、DNS resolver、connection timing を記録します。sensitive engagement を無作為な “leak test” sites に公開しないでください。
7. client、OS、network、または policy を変更した後に再度 test します。

## Tor Browser: より強い web unlinkability

Tor は複数の relay を通る circuit を構築するため、通常、単一の relay が source と destination の両方を知ることはありません。Destination には user の IP ではなく Tor exit が見え、local network には通常 Tor connection が見えます。<sup>[[3]](#references)</sup> Tor は low-latency TCP applications 向けに設計されているため、速度が遅く、両端を correlation できる adversary に対する protection を保証できません。<sup>[[4]](#references)</sup>

### Safe Tor Browser workflow

1. Tor Browser は Tor Project または公式 mirror からのみ download し、可能な場合は signature を verify します。
2. Tor SOCKS port を指定した通常の browser ではなく、**Tor Browser** を使用します。通常の browser は DNS/WebRTC や identifying state を leak する可能性があります。<sup>[[5]](#references)</sup>
3. default の size、fonts、extensions、privacy settings を維持します。Additional add-ons により browser がより unique になる可能性があります。<sup>[[6]](#references)</sup>
4. breakage の増加を許容できる場合は、**Safer** または **Safest** security level を選択します。
5. direct Tor が block されている場合、または通常の relay IP が許容できない local visibility を生む場合は bridge を使用します。Bridge は容易な recognition を減らしますが、traffic analysis を排除するものではありません。<sup>[[7]](#references)</sup>
6. identifying account に login したり、identifying information を提供したり、download した active documents を外部の networked application で開いたりしないでください。
7. 各 identity に別々の session/context を使用します。“New circuit” は browser/application identity の消去と同じではありません。必要に応じて **New Identity** を使用するか、isolated environment を restart します。
8. authenticated HTTPS または authenticated onion service を優先します。Tor exit は暗号化されていない HTTP traffic を観測できます。

### Tor plus VPN

これらを組み合わせても、自動的に安全性が高まるわけではありません。Tor の前に VPN を置くと、ISP から direct Tor relay connections を隠せますが、VPN には source が見えます。Tor の前に VPN を置く場合、VPN には Tor 後の activity が安定して見え、anonymity set が小さくなる可能性があります。Misconfiguration は leaks を生むことがあります。Tor Project は、このような組み合わせを advanced で明確な threat model がある場合にのみ推奨しています。<sup>[[8]](#references)</sup>

## Public and guest Wi-Fi

Modern HTTPS により、passive neighbors は適切に暗号化された web content を通常読めませんが、guest Wi-Fi は anonymity ではありません。Venue は association times、device identifiers、captive-portal data、destinations、DHCP details を記録できます。また、cameras、purchases、transport、physical observation により user を特定できます。偽の、似た名前の hotspot によって portal credentials を取得されたり、暗号化されていない traffic を操作されたりする可能性もあります。<sup>[[9]](#references)</sup>

### Lawful guest-network workflow

1. Guests 向けに提供された network、または owner が明示的に permission を付与した network のみを使用します。スタッフに正確な SSID と portal procedure を確認します。
2. 到着前に endpoint と travel router を update します。file/printer sharing、inbound discovery、auto-join、remembered-network probing を disable します。
3. OS の private/randomized Wi-Fi address を有効にします。現在の Apple systems は open/weak networks で rotating addresses を使用でき、modern Android randomization は通常 SSID ごとに persistent です。これは 1 つの local identifier のみを減らします。<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. privileged workstation と guest network の間に、organization-controlled travel router または low-trust bridge device を置くことを優先します。これにより firewall/VPN policy を集中管理できますが、venue から router が見えなくなるわけではありません。<sup>[[12]](#references)</sup>
5. captive portal は designated low-trust device/browser からのみ完了します。supposedly anonymous context で personal または reused credentials を入力しないでください。connectivity 確立後は portal browser を閉じます。
6. sensitive activity の前に full-tunnel VPN または Tor を開始し、fail-closed behavior を確認します。
7. 使用後は network を forget し、portal account/data-retention policy を確認します。

{% hint style="danger" %}
Neighbor の Wi-Fi を Cracking すること、portal を bypass すること、leaked guest credentials を使用すること、別の guest の access を clone すること、または café に Raspberry Pi を隠すことは unauthorized activity であり、privacy technique ではありません。安全な代替手段は、lawful guest network、client-approved site、または property owner's written consent を得て設置・回収する documented drop node です。
{% endhint %}

## Travel routers

Travel router は workstation を hostile local broadcasts から isolate し、firewall を enforce し、一貫した internal SSID を提供し、VPN に自動 reconnect できます。ただし、anonymous ではありません。Upstream からは radio identity と traffic timing が見え、VPN provider からは tunnel source が見えます。

- Supported OpenWrt/vendor firmware を使用し、unused services を削除します。
- Ethernet または unique password を設定した dedicated management SSID 経由で administer します。
- WAN-side administration、UPnP、WPS、file sharing、unsolicited inbound traffic を disable します。
- Supported and permitted な場合のみ、randomized/private WAN MAC を使用します。
- DNS と IPv6 を含む VPN policy を router 上で enforce し、tunnel failure 時には egress を block します。
- Phone hotspot が tethered devices を phone の VPN 経由にするとは限りません。必ず test してください。

## Cellular、SIM、eSIM

Cellular は便利ですが anonymous ではありません。Operators は subscriber/device identifiers と、network attachment から導出される location を保持します。eSIM も mobile subscription です。Prepaid だからといって reliably unregistered になるわけではありません。要件は country により異なり、変更されます。<sup>[[13]](#references)</sup>

Operationally:

- personal data の exposure を減らすために、separate で supported な device を使用します。fictional subscriber を作成するためではありません。
- threat model に co-location が含まれる場合、personal phone と “separate” device を常に一緒に持ち歩かないでください。
- unused cellular、Wi-Fi、Bluetooth、location access を disable します。power off は UI toggle より強い radio boundary です。
- sensitive traffic を approved VPN/Tor path 内に置きます。ただし、carrier は subscription/device location と tunnel endpoint を引き続き把握できます。
- national regulator または local counsel に current registration and retention rules を確認します。“anonymous SIM countries” の online lists に依存しないでください。

## DNS と TLS metadata

- **DoH/DoT/DoQ** は client と resolver の間の DNS を暗号化し、単純な local reading または modification を防ぎますが、resolver には queries と transport identifiers が見えます。Trust を移動するだけで、anonymity を提供するものではありません。<sup>[[14]](#references)</sup>
- **ODoH** は proxy を追加し、proxy と target が collude しない限り resolver が client IP を知る必要をなくします。Traffic analysis は明示的に out of scope です。<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)** は、client、DNS、server が対応している場合、TLS handshake 内の inner server name を保護できます。Destination IP、timing、volume、endpoint は引き続き見えます。<sup>[[16]](#references)</sup>
- 正しく configured された VPN または Tor environment では、DNS はその environment が support する route に従うべきです。別の resolver を追加すると、新しい observer または fingerprint が生じる可能性があります。

### Encrypted-DNS/ECH verification workflow

1. DNS を VPN/Tor environment、OS、application のどれが control するか決定します。無関係な resolver を stacking せず、意図した **1 つ**の layer で configure します。
2. 公開された privacy/retention policy に基づいて resolver を選択し、platform が対応している場合は strict encrypted mode を有効にします。Opportunistic fallback により、気付かないうちに plaintext に戻る可能性があります。
3. 自分が control する authoritative test zone の unique subdomain を query し、authoritative log が意図した recursive resolver を確認していることを確認します。
4. Authorization を得た上で、test device の traffic のみを capture します。Access network が plaintext DNS を読めないことを確認しつつ、encrypted resolver/tunnel endpoint は見えることを認識します。
5. Blocked/unreachable な encrypted resolver を test します。Pass condition は、選択した fail-closed または documented fallback behavior であり、偶発的な clear query ではありません。
6. ECH については、controlled ECH-enabled host を使用し、client/server diagnostics を inspect して **inner** ClientHello が accepted されたことを確認します。HTTPS record が提供されているだけでは ECH succeeded の証明になりません。
7. Network changes、captive portals、browser updates、VPN reconnects の後に repeat します。どの component が DNS/ECH を所有するかを記録し、後続の administrators が bypass を作らないようにします。

## Mixnets

Nym や Katzenpost などの Mixnets は、fixed-size packets、delay、reordering、cover traffic を追加し、timing correlation に resist します。これらの properties には latency と bandwidth が必要であり、independent deployment-scale evidence は限定的です。現在の consumer mixnets は、Tor/VPN より高速または guaranteed な replacement ではなく、**emerging/high-latency options** として扱ってください。<sup>[[17]](#references)</sup>

### Evaluation workflow

1. Maintained client と、正確に supported された application を特定します。Undocumented proxy 経由で arbitrary browser/system traffic を無理に送らないでください。
2. Entry、mix nodes、gateway、destination、collusion assumptions に関する current threat model を読みます。
3. Official signed source から separate test compartment に install し、benign な自分の endpoint のみを使用します。
4. Delivery latency、message-size limits、reliability、retransmission、gateway unavailable 時の behavior を測定します。
5. Local traffic と自分の endpoint を inspect し、意図した path と source を確認します。Replies が同じ privacy design を使用するか確認します。
6. Shutdown/failure を test します。Application が direct Internet access に silently fallback してはいけません。
7. 速度だけを理由に cover traffic を disable したり、delays を減らしたり、unusual fixed routes を選択したりしないでください。これらの変更により、記載された anonymity model が無効になる可能性があります。
8. Specific deployment、independent analysis、operational reliability が consequence level を満たすまで experimental として扱います。

## Network preflight checklist

- [ ] Authorization が access network、target、dates、source infrastructure を対象としている。
- [ ] Endpoint に unrelated identities や active sync sessions が存在しない。
- [ ] IPv4、IPv6、DNS、reconnect behavior が plan と一致している。
- [ ] Destination からは expected egress のみが見えている。
- [ ] Captive portal と hotspot behavior を sensitive traffic なしで test 済みである。
- [ ] Local sharing/discovery と automatic network joining が disable されている。
- [ ] Observer table と residual traffic-correlation risk を受け入れている。
- [ ] Provider policy、retention、emergency contact が最新である。

Split-knowledge relays、route-enforced workloads、pluggable transports、onion services、I2P、disposable remote browsers については、[Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md) を参照してください。

## References

- [1] [EFF — VPN の選び方](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Device security guidance: Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Tor が提供する privacy と anonymity の保護](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — Tor の短い introduction](https://spec.torproject.org/intro/)
- [5] [Tor Project — 他の browser で Tor を使用する](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Tor Browser の plugins と add-ons](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Tor の unblocking](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — VPN と Tor Browser の併用](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — Public Wi-Fi Networks は安全か？](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Apple devices における Wi-Fi privacy](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — MAC randomization の実装](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Secure Privileged Access Workstations の principles](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Mandatory SIM registration: policy and regulatory perspectives](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — DNS Privacy Service Operators への recommendations](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Threat Model](https://katzenpost.network/docs/threat_model/)
{{#include ../banners/hacktricks-training.md}}
