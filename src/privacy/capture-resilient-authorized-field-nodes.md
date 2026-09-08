# 抗捕获的授权现场节点

{{#include ../banners/hacktricks-training.md}}

现场部署的 Raspberry Pi、mini-PC、travel router 或 cellular appliance 可以为授权 red team 提供持久的观察点。同时，它也很可能成为被发现、盗窃和归因的目标。因此，正确的设计目标是：**让现场节点拥有较少权限，同时保持稳定、受控的访问**，而不是构建无法追踪的 implant。

本指南仅适用于根据场所有者书面授权部署的设备。仅仅因为某个网络可访问，并不意味着咖啡店、邻居、酒店或共享建筑属于测试范围。不要在未经同意的场所隐藏硬件，不要绕过 captive portal，不要使用他人的凭据，不要干扰监控，也不要在设备被发现后尝试擦除证据。

{% hint style="warning" %}
不存在可靠的“leave no traces”设置。Radio association、DHCP/NAT、carrier、camera、purchase、device、provider、controller 和 destination records 都可能在设备上保留。负责任的 red team 应从节点中移除**个人及无关的 secrets**，在 controller 端保留受保护的归因信息，并使设备被捕获后能够低成本地进行隔离。
{% endhint %}

## 优点和缺点

**优点：** 提供真实的内部或目标邻近 source；支持稳定的高速测试；可以验证 NAC、egress、physical inventory 和 SOC coverage；即使 operator address 发生变化也能继续运行；可以在中央撤销受限访问。

**缺点：** 物理部署会产生强烈证据；设备丢失可能暴露 device credentials、network profiles 和 collected data；重复的 control traffic 容易被检测；电源、portals 和 radio 变化会降低可靠性；宽泛的 tunnel 可能演变为不受控的 pivot。

## Threat model 和设计不变量

假设发现设备的人可以移除存储介质、检查 firmware、复制软件持有的所有 secrets、观察设备之后的 network behavior，并将设备交给客户或执法机构。Full-disk encryption 只能在其声明的 threat model 下保护已关机的设备；正在运行且已解锁的节点，与已释放到内存中的 keys 属于不同情况。

| 不变量 | 实际影响 |
|---|---|
| 不存在 operator-to-node 的直接身份关联 | Operator 登录 organization gateway；节点使用不同的 device identity |
| 不包含个人 workstation 材料 | 不得包含 personal SSH key、browser profile、email、password manager、phone pairing 或 cloud CLI cache |
| 不包含 controller master secret | 单个节点无法 enroll 其他节点、修改 policy 或 decrypt 其他 engagements |
| 仅出站且范围狭窄 | 现场网络不接受 management listener；节点只能连接指定的 rendezvous/update/time services |
| 短期且受限的权限 | 每个 credential 仅对应一个 device、audience、service 和 expiry，并具备立即 revocation path |
| 本地数据最少化 | Results 流向 controller；caches 经过加密，且具有大小和 TTL 限制，不具备权威性 |
| 捕获后 controller accountability 仍然有效 | Asset-to-engagement mapping、approvals、operator access 和 commands 均集中存储并进行 access control |
| 丢失后停止工作 | 发现设备或出现无法解释的 state change 时，应执行 stop、revoke、notify 和 evidence preservation，而不是 remote destruction |

NIST 的 IoT baseline 将 device identification、configuration、data protection、logical access、secure software update 和 cybersecurity-state awareness 归类为核心能力。它特别将 state awareness 和 off-device event records 视为支持 compromise investigation 的机制。<sup>[[1]](#references)</sup>

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
网关必须知道哪个具名 operator 连接到了哪个具名 device。field node 只需要一个 device credential 用于 rendezvous。它永远不会获知 operator 的源地址或 authentication secret，而 operator 也不会将 private management key 复制到其中。这会减少可从 **field storage** 中恢复的个人关联信息，同时不会破坏 exercise accountability。

对于规模更大的 fleet，workload-identity system 可以签发短期 X.509 identities 并自动轮换 keys。SPIFFE 在可能的情况下推荐使用 X.509 SVIDs，并说明较短的生命周期和频繁轮换有助于限制 key-compromise exposure。<sup>[[2]](#references)</sup> 小型团队可以通过 private CA 和自动化的 per-device certificates 应用相同属性；仅为满足这一模式，并不要求安装 SPIRE。

## Step 1: 授权并登记部署位置

1. 记录 owner、site、确切的允许部署区域、允许的 networks、assessment window、允许的 destinations/actions 以及 emergency contacts。
2. 记录 model、serial、storage serial、有线/无线 MACs、modem IMEI/eSIM 或 SIM ICCID、power supply 以及当前照片。
3. 为 device 提供一个非个人化的 engagement identifier，例如 `E2026-014-DROP03`。不要在 broadcast hostnames 或 SSIDs 中编码 client name。
4. 告知 exercise controller 以及最小必要范围内的 physical-security/SOC deconfliction group，在本次 test 中“lost”“moved”和“discovered”分别意味着什么。
5. 预先约定谁可以 retrieve 它，以及 finder 如何报告。safety label 可以省略敏感的 client detail，同时提供受控的 callback。
6. 设置 automatic authorization expiry。scope 结束后仍持续的 connectivity 不得延长 permission。

## Step 2: 构建最小可恢复 image

使用受支持的 OS image，通过 vendor 的 documented channel 验证其 signature/checksum，安装 security updates，并保留可复现的 build manifest。在软件允许的情况下，优先使用 read-only 或 immutable base，并配置一个小型 writable data partition。

1. 移除 default accounts、demo services、compilers 以及 authorized workload 不需要的 packages。
2. 禁用 local GUI、Bluetooth、discovery protocols、file sharing、Wi-Fi P2P 和 inbound administration，除非 exercise 明确要求其中某项。
3. 如果 hardware 确实支持，启用 secure boot 和 measured boot/TPM-backed key release；在验证确切 model 之前，不要声称 Raspberry Pi configuration 具备 PC-class measured boot。
4. 加密 local writable state，并配置严格的 maximum size 和 retention time。Encryption 是 delay/containment control，而不是证明运行中的 node 不会泄露任何信息。
5. 将重要 logs 发送到 off-device。限制 local journals 以防止 storage exhaustion，但不要配置 log wiping 或 anti-forensic deletion。
6. 在 controller 处保存 image manifest、package versions、configuration hash 和 recovery instructions。
7. 根据 manifest 为 spare 重新制作 image，并运行相同的 health test。只有构建者能够恢复的 design 尚未达到 field-ready 状态。

## Step 3: 使用单向 trust 签发 identities

创建三种不同的 identities：

- **device identity**，仅由该 device 的 rendezvous 接受；
- **operator identity**，由 organization gateway 接受，并通过 phishing-resistant MFA 保护；以及
- **controller/deployment identity**，用于签署已批准的 jobs 或 configuration，并保存在 operator 和 field node 之外。

node 应持有用于验证 signed jobs 的 public key，而绝不能持有 signing key。被捕获的 device credential 不得用于向 cloud consoles、source repositories、payment accounts、other nodes 或 client production 进行 authentication。

在 automatic renewal 可靠的情况下，使用较短的 certificate lifetimes。当 operationally necessary 而必须使用 long-lived WireGuard key 时，将其 public key 作为 revocation handle，并通过 peer-specific tunnel address、firewall policy 和 broker authorization 对其进行约束。保留一个经过测试的 controller action，以便立即移除该 peer。

## Step 4: 稳定的 outbound rendezvous

以下 owned-lab pattern 可在不暴露 inbound service 的情况下，通过 NAT 提供稳定的 management。这是普通的 WireGuard networking，而不是 covert reverse shell。使用 documentation addresses，并仅将其替换为 organization-owned endpoints。

在 organization rendezvous 处分配 `10.77.0.1/32`；为 field node 分配 `10.77.0.20/32`。gateway peer entry 应仅接受该 node 的单个 address：
```ini
# rendezvous: /etc/wireguard/wg-field.conf (relevant peer only)
[Peer]
PublicKey = <DROP03_PUBLIC_KEY>
AllowedIPs = 10.77.0.20/32
```
该节点向外连接 rendezvous，并仅在需要时保持 NAT 映射：
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
在许多 NAT/firewall 实现中，WireGuard 将 25 秒记录为需要持久连接时合理的 keepalive 间隔；不需要时，最好保持禁用。<sup>[[3]](#references)</sup> `AllowedIPs = 10.77.0.1/32` 有意将其设为管理路径，而不是 default-route pivot。

然后在 WireGuard 之外应用控制措施：

1. 通过批准的 bootstrap DNS 路径解析 `vpn.redteam.example`，并在 deployment records 中固定预期的组织 endpoint。
2. 在节点上，允许出站 DHCP/RA、所需的 DNS/NTP、rendezvous endpoint 以及最低限度的批准更新路径。在每个 uplink 上拒绝未经请求的入站流量。
3. 在 rendezvous 上，仅允许 `10.77.0.20` 访问演练所需的 broker/health service。不要将其一般性地转发到 client network。
4. 将交互式 operator 访问置于组织 gateway 之后。如果 signed pull-job interface 能满足 assessment，避免通过 tunnel 暴露来自节点的 SSH。
5. 配置 service manager 在 networking 之后启动 tunnel，失败后以有界 backoff 重启，并在反复失败后发出 alert。restart loop 不得压垮场地网络或掩盖底层故障。
6. 验证 peer 的 latest handshake，但不要将“存在 handshake”作为设备未被 compromise 的证明。

TURN 可以为专用的 WebRTC control plane 提供仅 relay 的可达性，而 message queue 可以容忍间歇性服务。TURN 会明确向 NAT 后的 client 提供 public relay address；其 server 仍然只是 observer。<sup>[[4]](#references)</sup> 应选择一种 control architecture，而不是在没有说明 observer 或 reliability benefit 的情况下堆叠 tunnels。

## Step 5: 不使用个人 links 的 uplink 稳定性

对于经过授权的 venue node，优先顺序如下：

1. client 提供的有线网络或专用 test VLAN；
2. owner 批准的 enterprise/guest Wi-Fi profile；
3. organization 签约的 cellular/private APN fallback。

绝不要使用个人 phone hotspot、家庭 SSID、个人 eSIM、个人 Apple/Google account，或从日常使用的 laptop 导出的 Wi-Fi profile 对其进行预置。这些正是 capture 会加入的 artifacts。

对于每个批准的 uplink：

- 记录 SSID/BSSID 或 switch/VLAN，以及预期的 captive-portal 行为；
- 设置确定性的 priority，并对一个自有 endpoint 进行 health check；
- 确保 failover 只改变 underlay；device 和 operator identities 保留在 broker；
- 确保 DNS、IPv6 和 application traffic 在转换期间不会绕过 rendezvous；
- 对未知 SSID/BSSID、SIM 变更、新 default gateway、public-IP/ASN 变更或 simultaneous uplinks 发出 alert；
- 在 deployment 前测试断电、DHCP renewal、AP restart、public-IP 变更、24 小时 idle、tunnel loss，以及 primary-to-secondary-to-primary recovery。

Private MAC addressing 可以减少普通的跨网络 tracking，但对于经过授权的 NAC，通常需要每个 network 使用稳定的 MAC。记录所选 OS 的实际行为，不要围绕 owner 的 access control 进行轮换。

## Step 6: 限制工作与数据

安全的 field node 不应接受来自 mailbox 的任意 shell 文本。定义 signed job types，例如 `health`、`fetch-owned-url`、`capture-approved-interface-for-60s`，或 rules of engagement 中明确列出的其他 action。在 node 上再次验证 destination、duration、rate、output size 和 scope。

1. 为每个 job 提供唯一 ID、device audience、issue time、expiry、scope reference 和 maximum output。
2. 使用 controller/deployment identity 对其签名。
3. 拒绝未知字段、已过期/重放的 jobs，以及面向其他 device 的 jobs。
4. 将结果 stream 到自有 collector；对任何无法避免的 local spool 进行 encryption 并设置 TTL。
5. 在 controller 记录已接受/拒绝的 job ID 和 result hash。不要将敏感的 command parameters 放入 public monitoring channel。
6. 当 authorization 过期、identity rotation 失败或 controller 将 device 标记为 quarantined 时，停止处理。

## 用于发现、丢失或 compromise 的 Monitoring

Monitoring 可以告知 controller 所观察到的状态发生了变化。它不能可靠地证明“investigators 找到了 device”，而试图监视 responders 或 probe 其 systems 会超出 authorized assessment 的范围。

### 收集 off-device state

以随机但有界的 operational interval 向 controller 发送 signed、低流量的 health record。只包含 controller 所需的信息：

- device ID、boot ID/counter 和 monotonic uptime；
- configuration/image hash 和 software version；
- device-certificate serial 和 renewal state；
- uplink class、interface、经授权的 BSSID 或 switch context、default-gateway hash，以及 owned service 观察到的 public IP/ASN；
- tunnel handshake age、packet counters 和 queue depth；
- 如果 owner 批准了 sensor，则包括 enclosure switch 或 hardware-tamper state；
- disk pressure、temperature、clock-offset estimate 和 last successful job ID；
- sequence number 和 signature，用于暴露 replay 或 gaps。

集中存储 gateway authentication、policy decisions、operator access、job submission、result hashes、provider audit events 和 alerts。CISA 建议集中化 logs、保护 logs 免遭删除、建立正常 activity 的 baseline，并指定 incident-response contacts。<sup>[[5]](#references)</sup>

### Discovery/compromise indicators

| Signal | Possible explanations | Controller action |
|---|---|---|
| Heartbeat absent | power/network failure、portal 变更、damage、deliberate blocking 或 removal | corroborate provider/site state；不要从未批准的 path 重新连接 |
| Boot counter changed unexpectedly | power cut、crash、removal 或 maintenance | quarantine jobs；对比 time 和 site events |
| Config/image hash changed | update error、storage fault 或 tampering | stop work；如果不是 controller-approved release，则 revoke |
| New uplink/BSSID/gateway/ASN | AP replacement、roaming、device 被移动或 interception | 对比 approved inventory；quarantine 无法解释的 transition |
| Repeated rejected job/signature | corruption、replay 或 unauthorized controller | stop processing，并调查 gateway/controller logs |
| Device credential used twice or from incompatible paths | cloned key、snapshot reuse 或 network transition | 立即 revoke；保留两条 session records |
| Unexpected local login, interface, process or privilege event | maintenance 或 compromise | 通过 broker policy isolate；保留 evidence |
| Enclosure switch/state transition | service、movement 或 discovery | 通知指定的 site contact；不要触发 destructive action |
| Provider abuse notice/account query or SOC alert | detection、misconfiguration 或 out-of-scope traffic | 停止 activity，并启动 deconfliction/incident process |
| Sentinel credential touched | 某人读取了仅对该 node 唯一且无 privilege 的 decoy secret | revoke real device identity，并保留 alert trail |

Sentinel credential 必须**不授予任何 access**，只能调用 organization-owned alert service，并且必须在 rules of engagement 中披露。它是用于检测 unauthorized reading 的 tripwire，而不是用于 tracking 找到设备的人。

### Alert thresholds

使用有状态的 rules，而不是一个戏剧性的“caught” alarm：

- **warning:** 一次 missed interval、正常的 address change 或 queue growth；
- **degraded:** 连续三次 misses、renewal delay、primary-uplink loss 或 repeated restart；
- **quarantine:** 未批准的 hash/boot/uplink change、duplicate credential、sentinel use 或 unexpected privileged event；
- **confirmed discovery/loss:** site/controller report、physical inventory mismatch、设备被未计划的第三方找回，或经过验证的 provider/SOC escalation。

通过独立于 field node 的 channel 测试 alert delivery。避免将敏感的 client/device detail 发送到个人 messaging 或 consumer push accounts。

## Suspected discovery or capture runbook

1. **Stop:** suspend new jobs 和 operator sessions。不要发送“检查是否被监视”的 probe。
2. **Quarantine:** 让 broker 拒绝 device identity 及其 routes，同时保留现有 logs。
3. **Revoke:** revoke device certificate/key、queue token、update credential 和任何 single-purpose service token。如果 physical loss 可能发生，则 suspend organization SIM。
4. **Preserve:** snapshot controller、gateway、provider 和 alert records；记录 trusted time、执行人员以及 last known configuration。不要 clear 或 remotely wipe node。
5. **Notify:** 联系 exercise controller、client incident contact，以及 authorization 中定义的 legal/privacy contacts。如果是 third party 找到它，则使用预先约定的 recovery process。
6. **Assess:** 假设 node 上的每个 secret 和 cached result 都已暴露。准确列出每个 secret 可访问的内容，以及 suspicious event 之后是否被使用。
7. **Contain downstream:** rotate 受影响的 service credentials，invalidate pending jobs，并检查 owned target/provider logs 是否存在 unexpected behavior。
8. **Recover safely:** 仅通过 authorized person retrieve；对其拍照/包装，记录 custody，并按照 client 指示获取 forensic evidence。
9. **Resume with a new identity:** 绝不静默地重新启用 captured credential。根据 known manifest 重建，修复 control failure，并取得明确批准。

NIST 当前的 incident-response guidance 将 preparation、detection、response 和 recovery 整合到组织范围的 cybersecurity risk management 中；应先 preserve，以便 client 确定发生了什么并选择适当的 response。<sup>[[6]](#references)</sup>

## Capture drill before deployment

将一台已解锁的 test unit 或其 storage 的副本交给独立 reviewer，并要求其列举：

1. device/site/engagement identifiers；
2. operator names、personal accounts、home/workstation networks 和 recovery contacts；
3. controller/broker destinations 和 credentials；
4. client network profiles 和 cached results；
5. 使用每个 secret 可 reach 的其他 devices/projects；
6. value 或 payment credentials；
7. controller 可以 revoke 什么，以及速度如何；
8. 哪些 activity 仍可从 central logs 中归因。

通过标准：零 personal accounts/workstation keys；零 cross-engagement 或 enrollment authority；无 payment credential；有界的 encrypted cache；一个有文档记录的 device-revocation action；完整的 controller-side accountability。将任何意外的 personal link 或 lateral capability 视为 release blocker。

## Closeout

1. 在 scope 结束时停止 jobs，并 disable broker route。
2. Retrieve 并核对 exact inventory；报告任何缺失项。
3. 根据 engagement retention plan 保留 logs/results，并在需要时保留 forensic image。
4. 即使 hardware 已 recovery，也 revoke device、SIM、queue、update 和 service identities。
5. 仅在 preservation/acceptance 完成后，使用 owner 批准的 data-disposal process 对 media 进行 sanitize 或 destroy，并记录完成情况。这是 lifecycle management，而非 concealment。
6. 移除 venue NAC/DHCP reservations、broker routes、DNS、cloud roles、alert rules 和临时 contacts。
7. 记录已观察到的 detection、遗漏的 telemetry、quarantine 所需时间，以及 capture 暴露的每个 artifact。

## References

- [1] [NIST — IoT 设备 Cybersecurity Capability Catalog](https://pages.nist.gov/IoT-Device-Cybersecurity-Requirement-Catalogs/) and [NIST — Cybersecurity Event Awareness](https://pages.nist.gov/FederalProfile-8259A/technical/event/)
- [2] [SPIFFE — Concepts 和短期 workload identities](https://spiffe.io/docs/latest/spiffe/concepts/)
- [3] [WireGuard — Quick Start：Persistent Keepalive](https://www.wireguard.com/quickstart/)
- [4] [RFC 8656 — 使用 Relays 绕过 NAT（TURN）](https://www.rfc-editor.org/rfc/rfc8656.html)
- [5] [CISA — 在 Business Systems 上使用 Logging](https://www.cisa.gov/audiences/small-and-medium-businesses/secure-your-business/use-logging-on-business-systems)
- [6] [NIST SP 800-61 Rev. 3 — Incident Response Recommendations and Considerations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
{{#include ../banners/hacktricks-training.md}}
