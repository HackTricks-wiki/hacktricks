# Covert Physical and Wireless Access

アウトバウンド rendezvous、電源/uplink の復旧、device-held secrets の最小化、capture testing、発見の可能性に対する monitoring を含む、所有者の承認を得た詳細な実装については、[Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) を参照してください。

ネットワーク経路を変更すると、見かけ上の物理的な発信元も変わる可能性があります。高度な攻撃者は、近隣の侵害済みシステム、隠しデバイス、public access、cellular backhaul、または satellite receiver を使用し、target のログが operator から離れた場所を指すようにすることがあります。これらはいずれも、物理、radio、または provider の証拠を消すものではありません。attribution を別のデータセットへ移すだけです。

## Technique matrix

| Technique | 見かけ上の発信元 | 必要な条件 | 価値の高い証拠 |
|---|---|---|---|
| Nearby wireless pivot | target の隣にある business/home | 侵害済みの dual-homed host と target Wi-Fi への access | neighbor-host の endpoint logs、RF association、target の RADIUS/DHCP |
| Public/guest network | venue の NAT または tunnel exit | lawful access または access-control bypass | captive portal、DHCP、AP association、CCTV、payment/location records |
| Covert drop device | target/近隣の wired、Wi-Fi、または cellular address | 物理的な設置または delivery | switchport/USB、RF、inventory、power、outbound tunnel telemetry |
| Cellular router/eSIM | carrier NAT または dedicated APN | modem/SIM/subscription | IMEI/IMSI/eSIM、cell-sector、carrier account、traffic timing |
| Satellite-link abuse | beam footprint 内の subscriber address | protocol および service 固有の weakness | RF location、uplink flow、impossible RTT/routing、provider records |

## Nearest-neighbor attack

Volexity は、actor が最終的な target から離れた場所にいた、2022 年の APT28/GRU operation を記録しています。actor は target の public service に password spraying を行って valid credentials を取得しましたが、MFA により Internet からの直接 login は阻止されました。target の enterprise Wi-Fi は、MFA なしでこれらの credentials を受け入れていました。actor は target の物理的に近くにある organizations を侵害し、wireless reach を持つ dual-homed system を見つけ、その system を使って target Wi-Fi に authenticate しました。Volexity はこれを **Nearest Neighbor Attack** と名付けました。<sup>[[1]](#references)</sup>
```text
remote operator
|
compromised organization C
|
compromised organization B -- Wi-Fi radio --> target organization A
|
internal service
```
新規性は、その構成にあります。オペレーターは標的の場所へ移動せず、Internet-facing service の MFA も引き続き機能します。侵害された近隣システムが物理的な近接性を提供し、盗まれた標的の credential が論理アクセスを提供し、標的の Wi-Fi が境界を越える経路になります。

### 前提条件と可視性

- 近隣のシステムをリモート制御でき、互換性のある radio、または別の近隣 pivot へのアクセスが必要です。
- 標的 SSID がそのシステムまで到達し、Wi-Fi admission が再利用可能な credential、certificate、または device state を受け入れる必要があります。
- pivot には、オペレーターへ戻る経路と標的 WLAN へ入る経路という、2つの同時接続が必要になることがよくあります。
- 標的側には、新しい station MAC や正規の username は見えても、それに対応する managed-device certificate、posture、履歴、または想定される建物への入館記録が見えない可能性があります。
- Neighbor endpoint のログには、wireless scans、新しい profiles、interface changes、tunneling、remote-control activity が記録される可能性があります。

### 検知と防止

1. Enterprise Wi-Fi では、certificate-backed EAP-TLS と managed-device posture を必須にします。Internet 上で MFA に失敗した password が radio 経由で届いたというだけで、十分な認証とみなさないでください。
2. RADIUS authentication を、MDM/NAC identity、過去の station/device binding、AP location、physical-access events、同時進行中の sessions と相関分析します。
3. Account が初めて associate した場合、通常とは異なる AP edge から接続した場合、managed certificate がない場合、または同じ identity が別の場所で active になっている場合に alert を発生させます。
4. Interface bridging が可能な endpoints を監視します。Windows、Linux、network appliances では、予期しない WLAN profiles、forwarding/NAT configuration、virtual adapters、persistent tunnels を調査します。
5. 適切な AP placement と power planning により、不要な signal spill を減らします。これは補助的な control であり、authentication ではありません。
6. 近隣 tenant と incident response を調整します。最終的な radio source 自体が被害者である可能性があります。

[owned two-organization lab](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) では、近隣を攻撃せずに、これらの observables を再現します。

## Public venues と third-party Wi-Fi

Café、hotel、airport、municipal Wi-Fi を使用すると、destination に表示される IP が変わります。匿名性が生まれるわけではありません。venue またはその provider は、AP association、device MAC、DHCP lease、captive-portal account、SMS/email validation、flow logs を保持している可能性があります。物理的な入場記録、CCTV、購入記録、mobile-location、travel records により、digital event と個人を結び付けられる可能性があります。

Actor は、randomized MAC addresses、別の device、cash、または tunnel を使用して、1つの手掛かりを減らそうとする場合があります。それでも、到着時刻、venue の利用パターン、radio fingerprints、portal behavior、traffic timing、camera footage、tunnel provider を通じた cross-layer correlation は可能です。VPN を使用しても、destination が venue logs から VPN logs に移るだけです。device がその場所に存在していたことを venue が把握できなくなるわけではありません。

Public access の defender は、clients を分離し、lateral traffic を block し、可能な場合は WPA2/3-Enterprise または per-device keys を使用し、適切な範囲の DHCP/RADIUS/security logs を保持し、captive portals を保護し、abuse process を公開する必要があります。Red team は、venue の terms と engagement が許可している場合に限り、そのような venue を使用すべきです。portal の bypass、access の窃取、他の guest の targeting は、authorized testing の近道ではありません。

## Covert drop devices と warshipping

Drop とは、site 内に設置または搬入し、その後 outbound Ethernet、Wi-Fi、cellular 経由で制御する小型システムです。「Warshipping」では、通常の配送によって device が radio perimeter 内へ運ばれるように device を梱包します。使用可能な hardware は、single-board computer、modified charger、USB peripheral、network appliance、battery-powered modem など多岐にわたります。

Operational architecture:
```text
operator -> controlled rendezvous <- outbound encrypted tunnel <- drop
|
scoped local interface
```
このデバイスは、remote footholdの確立、wireless measurementsの実施、認証済みの演習用 peripheral のエミュレート、または traffic の relay を可能にします。見かけ上の発信元はローカルですが、serial numbers、packaging、fingerprints、cameras、access logs、power draw、USB descriptors、switchport negotiation、DHCP fingerprints、MAC OUI/randomization behavior、RF emissions、定期的な rendezvous connections などの物理的な痕跡を残します。

### 防御 controls

- receiving-room と asset-inventory の手順を維持し、想定外の電子機器や、存在しない従業員宛ての荷物を検査する。
- 有線および wireless access に 802.1X/NAC を使用し、未使用のポートを無効化して、未知のデバイスを制限付きの remediation VLAN に配置する。
- 新しい DHCP fingerprints、長期間継続する locally administered MACs、新しい USB network/HID devices、認証されていない Wi-Fi Direct/Bluetooth、長時間存続する outbound tunnels を alert の対象にする。
- switchport、power-over-Ethernet、DNS、TLS の behavior を baseline 化する。inventory record がなく、定期的に encrypted connections を行う小型 host は、「Raspberry Pi OUI」だけの場合よりも高い signal である。
- 演習中は、inventory、label、scope、encrypt、remote kill の提供、retrieval deadline の設定を行い、紛失しても再利用可能な credentials が露出しないようにする。

## Cellular と eSIM backhaul

Cellular modem は target の Internet gateway を回避し、outbound rendezvous を通じて carrier NAT の背後でも drop への到達性を維持できます。Mobile addresses はローテーションまたは共有される可能性がありますが、cellular operator には依然として強力な subscriber および network の証拠があります。これには SIM/eSIM identity、IMSI、assigned addresses/ports、cell/sector timing、account/payment および roaming records が含まれます。

enterprise の視点では、wireless/RF surveys、endpoint USB/PCI inventory、MDM restrictions、rogue-SSID monitoring、physical inspection により、想定外の modems や personal hotspots を検出します。control に cellular を使用する drop も、ローカルの Ethernet/Wi-Fi behavior と radio emissions によって発見できる可能性があります。

認証済みの演習では、組織が subscription と modem を所有し、identifier を controller とともに記録し、carrier/provider の規約が traffic を許可していることを確認すべきです。prepaid label や cryptocurrency による購入でも、tower、device、retail の records が消えるわけではありません。

## MAC randomization と device fingerprinting

Modern systems は、network ごとに locally administered random MAC を使用できます。これにより、安定した factory MAC による受動的な長期 tracking は低減されますが、次の情報が隠れるわけではありません。

- probe/association timing と、要求された network capabilities の集合
- 802.11 information elements、supported rates、vendor-specific behavior
- DHCP options/hostname、IPv6 identifiers、captive-portal/browser fingerprint
- authenticated 802.1X identity または certificate
- higher-layer account、tunnel、traffic pattern
- physical observation

Defenders は MAC allowlists を authentication として使用すべきではありません。radio identity を certificate/device posture に関連付け、他の context に異常がない限り、MAC の変化を正常なものとして扱います。

## Satellite-link hijacking

Kaspersky は、Turla が旧式の一方向 DVB-S satellite Internet の weaknesses を利用していたことを documented しました。報告された model では、正規の remote subscriber が terrestrial link 経由で outbound requests を送信し、downstream data は unencrypted wide-area satellite broadcast 経由で受信していました。satellite footprint 内の actor は downlink を観測し、active subscriber の IP を選択して、C2 replies がその IP 宛てになるように手配できました。正規の subscriber と actor はどちらも broadcast を受信し、actor は選択した port の traffic を抽出する一方、正規の subscriber は unsolicited packets を破棄しました。その後、C2 operator は別の geography にある satellite-provider address を使用しているように見えました。<sup>[[2]](#references)</sup>
```text
actor uplink request -> C2 server -> Internet -> satellite gateway
satellite broadcast
+--------------+-------------+
|                            |
legitimate subscriber          actor receiver
```
これは protocol/service 固有で、帯域幅に制約があり、modern bidirectional encrypted satellite terminal の compromise と同等ではありませんでした。また、十分な能力を持つ observer から actor の outbound request path を隠すこともできませんでした。Detection opportunities には、非対称または不可能な routing、flow を開始していない subscriber への traffic、通常とは異なる destination port、provider telemetry、receiver location/RF investigation、malware configuration などがあります。この事例は、C2 IP の geolocation によって controller の geolocation も判明するという前提を問い直すために使用してください。build recipe として使用するものではありません。

## Physical-to-digital correlation worksheet

一見すると local source に見えるものが suspicious な場合は、1本の timeline を作成します。

1. AP、RADIUS、DHCP、DNS、proxy、VPN、EDR、switch、physical-access の clock を normalize する；
2. 最初の alert だけでなく、最初の radio association または link-up を特定する；
3. station を certificate、device posture、DHCP fingerprint、switch/AP location に関連付ける；
4. 近隣の system 上で、同時に remote-control/tunnel activity が発生していないか確認する；
5. 適用される policy/law に従い、deliveries、visitors、inventory exceptions、cameras、RF findings を確認する；
6. suspected device と volatile network state を preserve する。むやみに power-cycle してはならない；
7. apparent source が actor-controlled infrastructure なのか、別の victim なのかを判断する。

## References

- [1] [Volexity — The Nearest Neighbor Attack: How a Russian APT weaponized nearby Wi-Fi networks](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [Kaspersky Securelist — Satellite Turla: APT command and control in the sky](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [3] [MITRE ATT&CK — Hardware Additions (T1200)](https://attack.mitre.org/techniques/T1200/)
- [4] [NIST SP 800-153 — Guidelines for Securing Wireless Local Area Networks](https://csrc.nist.gov/pubs/sp/800/153/final)
