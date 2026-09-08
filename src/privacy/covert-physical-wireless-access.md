# Covert Physical and Wireless Access

{{#include ../banners/hacktricks-training.md}}

アウトバウンド rendezvous、電源/uplink の復旧、device-held secrets の最小化、capture testing、および発見の可能性に対する monitoring を含む、所有者の承認を受けた詳細な実装については、[Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) を参照してください。

ネットワーク経路を変更すると、見かけ上の物理的な発信元も変わる可能性があります。高度な攻撃者は、近隣の侵害済みシステム、隠しデバイス、public access、cellular backhaul、または satellite receiver を使用し、target のログが operator とは異なる場所を指すようにする場合があります。これらはいずれも物理的証拠、radio の証拠、または provider の証拠を消去するものではなく、attribution を別のデータセットへ移すだけです。

## Technique matrix

| Technique | 見かけ上の発信元 | 必要な条件 | 価値の高い証拠 |
|---|---|---|---|
| Nearby wireless pivot | target の隣の business/home | 侵害済みの dual-homed host と target の Wi-Fi access | neighbor-host の endpoint logs、RF association、target の RADIUS/DHCP |
| Public/guest network | venue の NAT または tunnel exit | 合法的な access または access-control bypass | captive portal、DHCP、AP association、CCTV、payment/location records |
| Covert drop device | target/近隣の wired、Wi-Fi、または cellular address | 物理的な設置または配送 | switchport/USB、RF、inventory、power、outbound tunnel telemetry |
| Cellular router/eSIM | carrier NAT または dedicated APN | modem/SIM/subscription | IMEI/IMSI/eSIM、cell-sector、carrier account、traffic timing |
| Satellite-link abuse | beam footprint 内の subscriber address | protocol および service 固有の weakness | RF location、uplink flow、impossible RTT/routing、provider records |

## Nearest-neighbor attack

Volexity は、攻撃者が最終的な target から離れた場所にいた、2022 年の APT28/GRU の operation を記録しています。攻撃者は target の public service に password-spraying を行って有効な credentials を取得しましたが、MFA によって Internet からの直接 login は阻止されました。target の enterprise Wi-Fi は、それらの credentials を MFA なしで受け入れました。攻撃者は target の物理的に近くにある organizations を侵害し、wireless reach を持つ dual-homed system を発見して、その system を使用して target の Wi-Fi に authenticate しました。Volexity はこれを **Nearest Neighbor Attack** と名付けました。<sup>[[1]](#references)</sup>
```text
remote operator
|
compromised organization C
|
compromised organization B -- Wi-Fi radio --> target organization A
|
internal service
```
新規性は、その組み合わせにあります。オペレーターは標的の場所へ移動せず、Internet-facing service の MFA は引き続き機能します。侵害された近隣システムが物理的な近接性を提供し、盗まれた標的の credential が論理アクセスを提供し、標的の Wi-Fi が境界を越える経路になります。

### 前提条件と可視性

- 近隣のシステムがリモート制御可能であり、互換性のある radio、または別の近隣 pivot へのアクセスを備えている必要があります。
- 標的の SSID がそのシステムまで到達し、Wi-Fi admission が再利用可能な credential、certificate、または device state を受け入れる必要があります。
- pivot には多くの場合、オペレーターへ戻る経路と標的 WLAN 内へ入る経路という、2つの同時接続が必要です。
- 標的側には新しい station MAC と正規の username が見える一方で、対応する managed-device certificate、posture、履歴、または想定された建物への入場記録が見えない可能性があります。
- Neighbor endpoint のログには、wireless scan、新しい profile、interface の変更、tunneling、remote-control activity が記録される可能性があります。

### 検知と防止

1. Enterprise Wi-Fi には certificate-backed EAP-TLS と managed-device posture を必須にします。Internet 上で MFA に失敗した password が、radio 経由で届いたというだけで十分な認証になるようにしてはいけません。
2. RADIUS authentication を、MDM/NAC identity、過去の station/device binding、AP location、physical-access event、同時進行中の session と相関させます。
3. Account が初めて associate した場合、通常とは異なる AP edge から接続した場合、managed certificate がない場合、または同じ identity が別の場所でも active な場合に alert を出します。
4. Interface の bridging が可能な endpoint を監視します。Windows、Linux、network appliance では、想定外の WLAN profile、forwarding/NAT configuration、virtual adapter、persistent tunnel を調査します。
5. 適切な AP placement と power planning により、不要な signal spill を減らします。これは補助的な control であり、authentication ではありません。
6. 近隣 tenant と incident response を調整します。最終的な radio source 自体が victim である可能性があります。

[2組織による所有済み lab](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot)では、近隣への攻撃を行わずに、これらの観測可能な事象を再現します。

## 公共施設と third-party Wi-Fi

Café、hotel、airport、または municipal Wi-Fi を使用すると、destination に表示される IP が変わります。匿名性が生まれるわけではありません。施設またはその provider は、AP association、device MAC、DHCP lease、captive-portal account、SMS/email validation、flow log を保持している可能性があります。物理的な入場、CCTV、購入記録、mobile-location、travel record によって、デジタル上の event と個人を結び付けられる可能性があります。

Actor は、randomized MAC address、別の device、cash、または tunnel を使用して、手掛かりの1つを減らそうとする可能性があります。それでも、到着時刻、繰り返される venue pattern、radio fingerprint、portal behavior、traffic timing、camera footage、tunnel provider を通じた cross-layer correlation は可能です。VPN を使用しても、destination が venue log から VPN log に移るだけであり、その device が施設内に存在したという venue 側の認識がなくなるわけではありません。

Public access の防御側は、client を分離し、lateral traffic を block し、可能な場合は WPA2/3-Enterprise または per-device key を使用し、適切な範囲の DHCP/RADIUS/security log を保持し、captive portal を保護し、abuse process を公開すべきです。Red team は、venue の規約と engagement が許可する場合にのみ、そのような施設を使用すべきです。Portal の bypass、access の窃取、他の guest を標的にすることは、authorized testing の近道ではありません。

## Covert drop device と warshipping

Drop は、site 内に設置または搬入された後、outbound Ethernet、Wi-Fi、または cellular を通じて制御される小型システムです。Warshipping では、通常の配送によって device が radio perimeter の内側へ運ばれるように、その device を梱包します。使用される hardware は、single-board computer、modified charger、USB peripheral、network appliance、battery-powered modem など多岐にわたります。

Operational architecture:
```text
operator -> controlled rendezvous <- outbound encrypted tunnel <- drop
|
scoped local interface
```
このデバイスは、リモート foothold の確保、wireless measurements の実行、authorized exercise peripheral のエミュレート、または traffic の relay を行う可能性があります。外見上の発信元はローカルですが、serial numbers、packaging、fingerprints、cameras、access logs、power draw、USB descriptors、switchport negotiation、DHCP fingerprints、MAC OUI/randomization behavior、RF emissions、繰り返し発生する rendezvous connections などの物理的な痕跡を残します。

### Defensive controls

- receiving-room と asset-inventory の手順を維持し、予期しない電子機器や、存在しない従業員宛ての package を検査します。
- 有線および wireless access に 802.1X/NAC を使用し、未使用の port を無効化して、不明なデバイスを制限された remediation VLAN に配置します。
- 新しい DHCP fingerprints、継続して使用される locally administered MAC、新しい USB network/HID devices、unauthorized Wi-Fi Direct/Bluetooth、長時間継続する outbound tunnels を alert の対象にします。
- switchport、power-over-Ethernet、DNS、TLS の behavior を baseline 化します。inventory record がない小型 host が定期的に encrypted connections を行っている場合、単に「Raspberry Pi OUI」であることよりも強い signal になります。
- exercise 中は、inventory、label、scope、encrypt、remote kill の提供、retrieval deadline の設定を行い、紛失しても再利用可能な credentials が露出しないようにします。

## Cellular and eSIM backhaul

cellular modem は target の Internet gateway を回避し、outbound rendezvous を通じて carrier NAT の背後にある drop への到達性を維持できます。Mobile address は rotate したり共有されたりする可能性がありますが、cellular operator は依然として強力な subscriber および network evidence を保有しています。これには SIM/eSIM identity、IMSI、assigned addresses/ports、cell/sector timing、account/payment、roaming records が含まれます。

enterprise の観点では、wireless/RF surveys、endpoint USB/PCI inventory、MDM restrictions、rogue-SSID monitoring、physical inspection によって、予期しない modem や personal hotspot を検出します。control に cellular を使用する drop であっても、local Ethernet/Wi-Fi behavior と radio emissions によって発見できる可能性があります。

authorized exercises では、組織が subscription と modem を所有し、識別子を controller とともに記録し、carrier/provider の terms がその traffic を許可していることを確認すべきです。prepaid label や cryptocurrency による購入であっても、tower、device、retail records が消えるわけではありません。

## MAC randomization and device fingerprinting

Modern systems は、network ごとに locally administered random MAC を使用できます。これにより、安定した factory MAC による受動的な長期 tracking は軽減されますが、以下を隠すことはできません。

- probe/association timing と、要求された network capabilities の集合
- 802.11 information elements、supported rates、vendor-specific behavior
- DHCP options/hostname、IPv6 identifiers、captive-portal/browser fingerprint
- authenticated 802.1X identity または certificate
- higher-layer account、tunnel、traffic pattern、または
- physical observation

Defenders は MAC allowlists を authentication として使用すべきではありません。radio identity を certificate/device posture に紐付け、他の context が anomalous でない限り、変化する MAC を通常のものとして扱います。

## Satellite-link hijacking

Kaspersky は、Turla が古い one-way DVB-S satellite Internet の weaknesses を利用していたことを documentation しました。報告された model では、legitimate remote subscriber が terrestrial link 経由で outbound requests を送信する一方、downstream data は unencrypted wide-area satellite broadcast 経由で受信していました。satellite footprint 内の actor は downlink を監視し、active subscriber IP を選択して、C2 replies がその IP 宛てになるように手配できました。legitimate subscriber と actor はどちらも broadcast を受信し、actor は選択した port の traffic を抽出する一方、legitimate subscriber は unsolicited packets を破棄しました。その後、C2 operator は別の geography にある satellite-provider address を使用しているように見えました。<sup>[[2]](#references)</sup>
```text
actor uplink request -> C2 server -> Internet -> satellite gateway
satellite broadcast
+--------------+-------------+
|                            |
legitimate subscriber          actor receiver
```
これはプロトコル／service 固有で、帯域幅の制約があり、現代の双方向暗号化衛星ターミナルを侵害することと同等ではありませんでした。また、十分な能力を持つ観測者から、攻撃者の outbound request path を隠すこともできませんでした。検知の機会には、非対称または不可能な routing、flow を開始していない subscriber への traffic、通常とは異なる destination port、provider telemetry、receiver location／RF investigation、malware configuration などがあります。この事例は、C2 IP の geolocate によって controller の場所も特定できるという前提を検証するために使用してください。build recipe として使用するものではありません。

## Physical-to-digital correlation worksheet

一見すると local source に見えるものが疑わしい場合は、1つの timeline を作成します。

1. AP、RADIUS、DHCP、DNS、proxy、VPN、EDR、switch、physical-access の各 clock を normalize する。
2. 最初の alert だけでなく、最初の radio association または link-up を特定する。
3. station を certificate、device posture、DHCP fingerprint、switch／AP location にマッピングする。
4. 近隣の systems 上で、同時刻に remote-control／tunnel activity が発生していないか確認する。
5. applicable policy／law の下で、deliveries、visitors、inventory exceptions、cameras、RF findings を確認する。
6. suspected device と volatile network state を保全する。無闇に power-cycle してはいけない。
7. 見かけ上の source が actor-controlled infrastructure なのか、それとも別の victim なのかを判断する。

## References

- [1] [Volexity — The Nearest Neighbor Attack: ロシアの APT が近隣の Wi-Fi networks を weaponize した方法](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [Kaspersky Securelist — Satellite Turla: 空中における APT の command and control](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [3] [MITRE ATT&CK — Hardware Additions (T1200)](https://attack.mitre.org/techniques/T1200/)
- [4] [NIST SP 800-153 — Wireless Local Area Networks の security guidelines](https://csrc.nist.gov/pubs/sp/800/153/final)
{{#include ../banners/hacktricks-training.md}}
