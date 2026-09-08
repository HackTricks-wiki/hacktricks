# 抗捕获的授权现场节点

现场部署的 Raspberry Pi、mini-PC、travel router 或 cellular appliance 可以为授权的 red team 提供持久的观察点。但它也很可能成为被发现、被盗和被溯源的目标。因此，正确的设计目标是**稳定、受控的访问，同时让现场节点拥有尽可能少的权限**，而不是打造无法追踪的 implant。

本指南仅适用于根据站点所有者书面授权部署的设备。仅仅因为某个网络可访问，并不意味着 coffee shop、邻居、hotel 或共享建筑属于范围。不要在未同意的场所隐藏硬件、绕过 captive portal、使用他人的凭据、干扰监控，或在设备被发现后试图擦除证据。

{% hint style="warning" %}
不存在可靠的“leave no traces”设置。Radio association、DHCP/NAT、carrier、camera、purchase、device、provider、controller 和 destination 记录都可能在设备上被发现后继续保留。负责任的 red team 应从节点中移除**个人和无关的 secrets**，在 controller 端保留受保护的归因信息，并让设备被捕获后的处置成本尽可能低。
{% endhint %}

## 优点和缺点

**优点：** 提供真实的内部或目标邻近来源；支持稳定的高速测试；可验证 NAC、egress、物理资产清单和 SOC 覆盖情况；可以在 operator 地址发生变化时继续运行；可在中央位置撤销受限访问权限。

**缺点：** 物理部署会产生强烈的证据；设备丢失可能暴露设备凭据、网络配置文件和收集的数据；反复的控制流量容易被检测；电源、portal 和 radio 变化会影响可靠性；宽泛的 tunnel 可能演变为不受控制的 pivot。

## 威胁模型和设计不变量

假设发现者可以移除存储介质、检查 firmware、复制软件持有的每个 secret、观察设备之后的网络行为，并将设备交给客户或执法机构。全盘加密仅在其声明的威胁模型下保护已关机的设备；正在运行且已解锁的节点，以及已释放到内存中的 keys，是不同的情况。

| 不变量 | 实际影响 |
|---|---|
| 不存在 operator 到节点的直接身份关联 | Operator 登录 organization gateway；节点使用不同的 device identity |
| 不包含个人工作站材料 | 不得包含个人 SSH key、browser profile、email、password manager、phone pairing 或 cloud CLI cache |
| 不包含 controller master secret | 单个节点不能注册另一个节点、修改 policy 或解密其他 engagement |
| 仅出站且范围狭窄 | 现场网络不接受 management listener；节点只能访问明确指定的 rendezvous/update/time services |
| 权限短时有效且范围受限 | 每个 credential 仅对应一个 device、audience、service、expiry，并具有立即撤销路径 |
| 本地数据最少化 | Results 流式传输到 controller；cache 必须加密，并限制大小和 TTL，且不具有权威性 |
| Controller 的 accountability 在设备被捕获后仍然保留 | Asset 与 engagement 的映射、审批、operator 访问和 commands 都集中存储并实施 access control |
| 设备丢失会停止工作 | 发现设备或状态发生无法解释的变化时，应停止、撤销、通知并保存证据，而不是远程销毁 |

NIST 的 IoT baseline 将 device identification、configuration、data protection、logical access、secure software update 和 cybersecurity-state awareness 归为核心能力。它特别将状态感知和设备外 event records 视为支持 compromise investigation 的机制。<sup>[[1]](#references)</sup>

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
网关必须知道哪个具名 operator 连接到了哪个具名 device。field node 只需要一个 device credential 来完成 rendezvous。它永远不会获知 operator 的源地址或 authentication secret，而 operator 也不会将 private management key 复制到该节点。这会减少**从 field storage 中**可恢复的个人关联信息，同时不会破坏 exercise accountability。

对于更大的 fleet，workload-identity 系统可以签发短期 X.509 identities 并自动轮换 keys。SPIFFE 在可能的情况下推荐使用 X.509 SVIDs，并说明较短的生命周期和频繁轮换可以限制 key-compromise exposure。<sup>[[2]](#references)</sup>小型团队可以通过 private CA 和自动化的 per-device certificates 实现相同属性；仅为满足这一模式，并不要求安装 SPIRE。

## Step 1: 授权并登记部署位置

1. 记录 owner、site、精确的允许放置区域、允许使用的 networks、assessment window、允许的 destinations/actions 以及 emergency contacts。
2. 记录 model、serial、storage serial、有线/无线 MACs、modem IMEI/eSIM 或 SIM ICCID、电源以及当前照片。
3. 为 device 分配一个非个人化的 engagement identifier，例如 `E2026-014-DROP03`。不要在广播 hostnames 或 SSIDs 中编码 client name。
4. 告知 exercise controller 以及最小必要范围的 physical-security/SOC deconfliction group，在本次 test 中“lost”“moved”和“discovered”分别意味着什么。
5. 预先约定谁可以取回 device，以及 finder 如何报告。safety label 可以省略敏感的 client detail，同时提供受控 callback。
6. 设置 automatic authorization expiry。scope 结束后仍在继续的 connectivity 不得延长 permission。

## Step 2: 构建最小化的可恢复 image

使用受支持的 OS image，通过 vendor 记录的 channel 验证其 signature/checksum，安装 security updates，并保留可复现的 build manifest。在 software 允许的情况下，优先使用 read-only 或 immutable base，并配备一个小型 writable data partition。

1. 移除 default accounts、demo services、compilers 以及 authorized workload 不需要的 packages。
2. 禁用 local GUI、Bluetooth、discovery protocols、file sharing、Wi-Fi P2P 和 inbound administration，除非 exercise 明确要求其中某项。
3. 如果 hardware 确实支持，则启用 secure boot 和 measured boot/TPM-backed key release；未经验证 exact model，不要声称 Raspberry Pi configuration 具有 PC-class measured boot。
4. 加密 local writable state，并配置严格的 maximum size 和 retention time。Encryption 是 delay/containment control，而不是 running node 不会泄露任何信息的证明。
5. 将重要 logs 发送到 device 外部。限制 local journals 以防止 storage exhaustion，但不要配置 log wiping 或 anti-forensic deletion。
6. 在 controller 处保存 image manifest、package versions、configuration hash 和 recovery instructions。
7. 根据 manifest 对 spare 重新执行 reimage，并运行相同的 health test。只有构建者本人能够恢复的 design 不适合部署到 field。

## Step 3: 使用单向 trust 签发 identities

创建三种不同的 identities：

- **device identity**，仅由此 device 的 rendezvous 接受；
- **operator identity**，由 organization gateway 接受，并使用 phishing-resistant MFA 保护；以及
- **controller/deployment identity**，用于签署已批准的 jobs 或 configuration，并保存在 operator 和 field node 之外。

node 应持有用于验证 signed jobs 的 public key，而绝不能持有 signing key。被捕获的 device credential 不得用于向 cloud consoles、source repositories、payment accounts、其他 nodes 或 client production 进行 authentication。

在 automatic renewal 可靠的情况下，使用较短的 certificate lifetimes。当 operationally necessary 而必须使用 long-lived WireGuard key 时，将其 public key 视为 revocation handle，并通过 peer-specific tunnel address、firewall policy 和 broker authorization 对其进行约束。保留一个经过测试的 controller action，以便立即移除该 peer。

## Step 4: 稳定的 outbound rendezvous

以下 owned-lab pattern 可以在不暴露 inbound service 的情况下，通过 NAT 提供稳定的 management。这是普通的 WireGuard networking，而不是 covert reverse shell。使用 documentation addresses，并且仅将其替换为 organization-owned endpoints。

在 organization rendezvous 处分配 `10.77.0.1/32`；为 field node 分配 `10.77.0.20/32`。gateway peer entry 应仅接受 node 的单个 address：
```ini
# rendezvous: /etc/wireguard/wg-field.conf (relevant peer only)
[Peer]
PublicKey = <DROP03_PUBLIC_KEY>
AllowedIPs = 10.77.0.20/32
```
节点向 rendezvous 发起出站连接，并仅在需要时保持 NAT 映射：
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
WireGuard 在许多 NAT/firewall 实现中将 25 秒记录为需要持久连接时合理的 keepalive 间隔；不需要时，最好将其禁用。<sup>[[3]](#references)</sup> `AllowedIPs = 10.77.0.1/32` 有意将其限定为管理路径，而不是 default-route pivot。

然后在 WireGuard 之外应用控制措施：

1. 通过批准的 bootstrap DNS 路径解析 `vpn.redteam.example`，并在 deployment records 中固定预期的组织 endpoint。
2. 在节点上，允许出站 DHCP/RA、所需的 DNS/NTP、rendezvous endpoint 以及最低限度的批准更新路径。在每个 uplink 上拒绝未经请求的入站流量。
3. 在 rendezvous 上，仅允许 `10.77.0.20` 访问 exercise 所需的 broker/health service。不要将其一般性地转发到 client network。
4. 将 interactive operator access 置于组织 gateway 之后。如果 signed pull-job interface 能满足 assessment，避免通过 tunnel 从节点暴露 SSH。
5. 配置 service manager，使 tunnel 在 networking 之后启动；发生故障时以有界 backoff 重启，并在连续失败后发出 alert。重启循环不得压垮场地网络或掩盖底层故障。
6. 验证 peer 的 latest handshake，但不要将“存在 handshake”作为设备未被 compromise 的证明。

TURN 可以为专用 WebRTC control plane 提供仅 relay 的可达性，message queue 则可以容忍间歇性 service。TURN 会明确向 NAT 后的 client 提供 public relay address；其 server 仍然是 observer。<sup>[[4]](#references)</sup> 选择一种 control architecture，不要在没有明确 observer 或 reliability benefit 的情况下叠加 tunnels。

## Step 5: 不使用个人 links 的 uplink 稳定性

对于 authorized venue node，优先采用以下顺序：

1. client 提供的有线网络或专用 test VLAN；
2. owner-approved enterprise/guest Wi-Fi profile；
3. organization-contracted cellular/private APN fallback。

绝不要使用个人手机 hotspot、家庭 SSID、个人 eSIM、个人 Apple/Google account，或从日常使用的 laptop 导出的 Wi-Fi profile 为其预置。这些正是 capture 会加入的 artifacts。

对于每个批准的 uplink：

- 记录 SSID/BSSID 或 switch/VLAN，以及预期的 captive-portal 行为；
- 设置确定性的 priority，并对自有 endpoint 执行 health check；
- 确保 failover 只改变 underlay；设备和 operator identities 保留在 broker；
- 确保 DNS、IPv6 和 application traffic 在切换期间不会绕过 rendezvous；
- 对未知 SSID/BSSID、SIM 变更、新 default gateway、public-IP/ASN 变更或 simultaneous uplinks 发出 alert；
- 在 deployment 前测试断电、DHCP renewal、AP restart、public-IP 变更、24 小时 idle、tunnel loss，以及 primary-to-secondary-to-primary recovery。

Private MAC addressing 可以减少随意的跨网络 tracking，但 authorized NAC 往往需要每个 network 使用稳定的 MAC。记录所选 OS 的实际行为，不要围绕 owner 的 access control 进行轮换。

## Step 6: 限制工作和数据

安全的 field node 不应接受来自 mailbox 的任意 shell text。定义 signed job types，例如 `health`、`fetch-owned-url`、`capture-approved-interface-for-60s`，或 rules of engagement 中明确列出的其他 action。在 node 上再次验证 destination、duration、rate、output size 和 scope。

1. 为每个 job 分配唯一 ID、device audience、issue time、expiry、scope reference 和 maximum output。
2. 使用 controller/deployment identity 对其进行 sign。
3. Reject unknown fields、expired/replayed jobs 以及面向其他 device 的 jobs。
4. 将 results stream 到自有 collector；对不可避免的 local spool 进行加密并设置 TTL。
5. 在 controller 记录 accepted/rejected job ID 和 result hash。不要将敏感的 command parameters 放入 public monitoring channel。
6. 当 authorization 过期、identity rotation 失败或 controller 将设备标记为 quarantined 时，停止处理。

## 用于发现、丢失或 compromise 的 monitoring

Monitoring 可以告知 controller 观察到的 state 发生了变化。但它无法可靠证明“investigators 找到了设备”；试图 surveil responders 或 probe 其 systems 将超出 authorized assessment 的范围。

### Collect off-device state

以随机但有界的 operational interval，向 controller 发送 signed、低流量的 health record。仅包含 controller 所需的信息：

- device ID、boot ID/counter 和 monotonic uptime；
- configuration/image hash 和 software version；
- device-certificate serial 和 renewal state；
- uplink class、interface、经授权的 BSSID 或 switch context、default-gateway hash，以及由自有 service 观察到的 public IP/ASN；
- tunnel handshake age、packet counters 和 queue depth；
- 如果 owner 批准该 sensor，则包含 enclosure switch 或 hardware-tamper state；
- disk pressure、temperature、clock-offset estimate 和 last successful job ID；
- sequence number 和 signature，用于暴露 replay 或 gaps。

集中存储 gateway authentication、policy decisions、operator access、job submission、result hashes、provider audit events 和 alerts。CISA 建议集中化 logs，保护其免遭删除，为正常 activity 建立 baseline，并指定 incident-response contacts。<sup>[[5]](#references)</sup>

### Discovery/compromise indicators

| Signal | Possible explanations | Controller action |
|---|---|---|
| Heartbeat absent | power/network failure、portal change、damage、deliberate blocking 或 removal | corroborate provider/site state；不要从未经批准的 path 重新连接 |
| Boot counter changed unexpectedly | power cut、crash、removal 或 maintenance | quarantine jobs；对比 time 和 site events |
| Config/image hash changed | update error、storage fault 或 tampering | stop work；如果不是 controller-approved release，则 revoke |
| New uplink/BSSID/gateway/ASN | AP replacement、roaming、moved device 或 interception | 对比 approved inventory；quarantine 无法解释的 transition |
| Repeated rejected job/signature | corruption、replay 或 unauthorized controller | stop processing，并调查 gateway/controller logs |
| Device credential used twice or from incompatible paths | cloned key、snapshot reuse 或 network transition | 立即 revoke；保留两条 session records |
| Unexpected local login, interface, process or privilege event | maintenance 或 compromise | 通过 broker policy isolate；preserve evidence |
| Enclosure switch/state transition | service、movement 或 discovery | 通知指定的 site contact；不要触发 destructive action |
| Provider abuse notice/account query or SOC alert | detection、misconfiguration 或 out-of-scope traffic | stop activity，并启动 deconfliction/incident process |
| Sentinel credential touched | 某人读取了一个仅属于此 node、无 privilege 的 decoy secret | revoke real device identity，并保留 alert trail |

Sentinel credential 必须授予 **no access**，只能调用组织自有的 alert service，并且必须在 rules of engagement 中披露。它是用于检测 unauthorized reading 的 tripwire，而不是用于 tracking 发现设备的人。

### Alert thresholds

使用 stateful rules，而不是一个戏剧性的“caught” alarm：

- **warning:** 一次 missed interval、正常的 address change 或 queue growth；
- **degraded:** 三次连续 misses、renewal delay、primary-uplink loss 或 repeated restart；
- **quarantine:** 未批准的 hash/boot/uplink change、duplicate credential、sentinel use 或 unexpected privileged event；
- **confirmed discovery/loss:** site/controller report、physical inventory mismatch、设备被未计划的人员 recovery，或经过验证的 provider/SOC escalation。

通过独立于 field node 的 channel 测试 alert delivery。避免将敏感的 client/device detail 发送到个人 messaging 或 consumer push accounts。

## Suspected discovery or capture runbook

1. **Stop:** suspend new jobs 和 operator sessions。不要发送“检查是否被监视”的 probe。
2. **Quarantine:** 让 broker deny 该 device identity 及其 routes，同时保留现有 logs。
3. **Revoke:** revoke device certificate/key、queue token、update credential 和所有 single-purpose service token。如果存在 physical loss 的可能性，则 suspend organization SIM。
4. **Preserve:** snapshot controller、gateway、provider 和 alert records；记录 trusted time、执行者和 last known configuration。不要 clear 或 remotely wipe node。
5. **Notify:** 联系 exercise controller、client incident contact 以及 authorization 中定义的 legal/privacy contacts。如果是 third party 找到设备，则使用预先约定的 recovery process。
6. **Assess:** 假设 node 上的每个 secret 和 cached result 都已暴露。准确列出每个 secret 可访问的内容，以及其是否在可疑 event 之后被使用。
7. **Contain downstream:** rotate 受影响的 service credentials，invalidate pending jobs，并检查自有 target/provider logs 中是否存在 unexpected behavior。
8. **Recover safely:** 仅通过 authorized person 取回；拍照并妥善包装，记录 custody，并按 client 指示获取 forensic evidence。
9. **Resume with a new identity:** 绝不要静默重新启用 captured credential。根据 known manifest 重建，修复 control failure，并取得明确批准。

NIST 当前的 incident-response guidance 将 preparation、detection、response 和 recovery 整合进组织范围的 cybersecurity risk management；应先 preserve，以便 client 确定发生了什么并选择适当的 response。<sup>[[6]](#references)</sup>

## Capture drill before deployment

将一台 unlocked test unit 或其 storage 的副本交给独立 reviewer，并要求其列举：

1. device/site/engagement identifiers；
2. operator names、personal accounts、home/workstation networks 和 recovery contacts；
3. controller/broker destinations 和 credentials；
4. client network profiles 和 cached results；
5. 使用每个 secret 可到达的其他 devices/projects；
6. value 或 payment credentials；
7. controller 可以 revoke 的内容以及所需时间；
8. 哪些 activity 仍可从 central logs 中归因。

通过标准：零 personal accounts/workstation keys；零 cross-engagement 或 enrollment authority；无 payment credential；有界的 encrypted cache；一个有文档记录的 device-revocation action；完整的 controller-side accountability。将任何意外的 personal link 或 lateral capability 视为 release blocker。

## Closeout

1. 在 scope 结束时停止 jobs，并 disable broker route。
2. 取回并核对 exact inventory；报告任何缺失项。
3. 根据 engagement retention plan 保留 logs/results，并在需要时保留 forensic image。
4. 即使 hardware 已取回，也要 revoke device、SIM、queue、update 和 service identities。
5. 只有在 preservation/acceptance 完成后，才使用 owner 批准的 data-disposal process 对 media 进行 sanitization 或 destruction，并记录完成情况。这是 lifecycle management，而不是 concealment。
6. 移除 venue NAC/DHCP reservations、broker routes、DNS、cloud roles、alert rules 和临时 contacts。
7. 记录已观察到的 detection、遗漏的 telemetry、quarantine 所需时间，以及 capture 暴露的每一项 artifact。

## References

- [1] [NIST — IoT Device Cybersecurity Capability Catalog](https://pages.nist.gov/IoT-Device-Cybersecurity-Requirement-Catalogs/) and [NIST — Cybersecurity Event Awareness](https://pages.nist.gov/FederalProfile-8259A/technical/event/)
- [2] [SPIFFE — Concepts and short-lived workload identities](https://spiffe.io/docs/latest/spiffe/concepts/)
- [3] [WireGuard — Quick Start: Persistent Keepalive](https://www.wireguard.com/quickstart/)
- [4] [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [5] [CISA — Use Logging on Business Systems](https://www.cisa.gov/audiences/small-and-medium-businesses/secure-your-business/use-logging-on-business-systems)
- [6] [NIST SP 800-61 Rev. 3 — Incident Response Recommendations and Considerations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
