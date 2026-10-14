# Offensive Infrastructure and Attribution Evasion

{{#include ../banners/hacktricks-training.md}}

操作人员很少能仅凭单个代理获得有意义的匿名性。真正的行动会构建一张**隔离图**：操作人员连接到接入节点，转发节点将该节点与出口隔开，redirector 保护真正的 C2，而一次性域名则指向公共边缘。

使用[Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md)，查看每种路径经过标准化整理的优缺点、部署和检测信息。本页将深入探讨对抗性基础设施的组合方式。

```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
                |                 |                |
          account/provider   relay operator   target telemetry
```

因此，目标最后看到的地址是路径的证据，而不是谁在操作键盘的证明。MITRE 将主要组成部分映射到 Acquire Infrastructure (T1583)、Compromise Infrastructure (T1584)、Proxy (T1090)、Dynamic Resolution (T1568) 和 Web Service (T1102)。<sup>[[1]](#references)</sup>

## 基础设施类别

| 类别 | 行为者使用它的原因 | 持久暴露面 | 防御者最佳关联切入点 |
|---|---|---|---|
| 租用的 VPS/cloud | 部署快速、可预测、可路由，且易于重建 | 租户、账单、控制台、源登录和镜像历史 | 账户/控制平面事件及重复出现的服务器指纹 |
| 商业 VPN/Tor | 大型共享出口集；无需管理服务器 | 服务商/观察方可见性及端到端时序 | 目标行为、端点证据和流量关联 |
| 住宅/移动 proxy | 消费者 ASN 和地理位置看似合理 | 经纪商/客户记录；proxyware 或受感染主机行为 | 不可能的旅行轨迹、proxy 协议及按会话发生的地址轮换 |
| 受控服务器/路由器/IoT | 借用受害者的信誉和管辖区 | implant、管理流量和重复出现的上游控制器 | 设备遥测和 ORB 拓扑，而非单个出口 IP |
| CDN/redirector | 将公开边缘节点与后端 C2 分离 | TLS/HTTP 语法、证书、路由和云账户痕迹 | 边缘到源站的关联及请求形态聚类 |
| 合法 Web 服务 | 混入获准的 GitHub/cloud/社交流量 | API token、租户/对象标识符及异常进程沿袭 | 端点进程以及服务/API 语义 |
| 物理/蜂窝/卫星路径 | 改变表面上的物理来源 | RF、运营商、订户、设备和位置记录 | 结合无线电/物理证据与网络证据 |

## 运维中继盒网络

**ORB network** 是作为中间服务使用的托管 proxy 机群。Mandiant 将其分为租用服务器组成的预置网络、由受控路由器/IoT 组成的非预置网络，以及混合网络。成熟的拓扑包含四种逻辑角色：<sup>[[2]](#references)</sup>

1. **管理服务器（ACOS）：** 维护资产清单、凭据、运行状况和路由策略。
2. **接入/中继节点：** 对客户或操作人员进行身份验证；它是通往不断变化的 mesh 的稳定入口。
3. **Traversal 节点：** 一个或多个租用或受控系统中继不透明连接。
4. **出口/暂存节点：** 向侦察、利用或 C2 目标呈现最终源地址。

该 mesh 可以按国家/地区、ASN、延迟或可用性选择出口，并轮换不健康的节点。多个威胁组织可能租用同一网络。Mandiant 观察到，某些 ORB 关联的 IPv4 地址存续时间短至 31 天；因此，它建议将**网络视为一个不断演变、类似行为者的实体**，而不是封锁一份过时的 IP 列表。<sup>[[2]](#references)</sup>

### 这能带来什么——又会泄露什么

- 目标看到的出口可能地理位置相近，而且看起来像住宅网络。
- 出口能看到目标和前一跳，但不一定能看到操作人员。
- 接入服务能看到客户和路由请求。独立管理的 mesh 可以将客户与出口隔离，但这会留下强有力的第三方记录。
- 即使 IP 不断轮换，重复出现的端口、握手顺序、服务器标语、证书、运行时间窗口和控制器关系仍可能暴露整个机群。
- 受控路由器通常缺少端点遥测，但其 ISP 仍持有订户和流量数据；设备被扣押后会暴露 implant/配置痕迹。

{% hint style="info" %}
在授权演练中，使用组织自有的 VM 或路由器复现该拓扑，并保留控制器的归属映射。不要招募开放 proxy 或第三方设备。[lab guide](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) 会创建相同的防御者可见跳转结构，而不会伤害中间方。
{% endhint %}

## 住宅和移动 proxy 网络

住宅 proxy 服务会将会话分配到消费者宽带地址；移动 proxy 则通过运营商 NAT 地址池出口。供应来源可能包括明确注册的设备、捆绑在消费者应用中的 SDK/proxyware、转售商或 malware。这些来源并不等同：缺乏知情同意会使隐私服务沦为受控基础设施。

轮换模式会影响检测：

- **按请求轮换**会造成 IP 和 ASN/地理位置快速变化，而更高层的身份特征保持稳定；
- **粘性会话**会让一个出口保持几分钟或几小时，表现得像普通订户；
- **backconnect gateway**会向客户暴露一个 broker 端点，并在内部选择出口；
- **移动池**会让许多真实订户共享少量运营商 NAT 地址，因此封锁 IP 的代价很高。

防御者应将 IP 与经过身份验证的会话、TLS/客户端指纹、HTTP 顺序、设备 cookie 和行为关联起来。如果某个据称来自本地住宅网络的登录，随后出现于另一个国家，而所有更高层特征都完全相同，那么这比单靠信誉判断更有力。反过来，地址共享和移动网络切换也会造成合法的变化，因此绝不要仅凭住宅/proxy 分类就下定论。

### Proxyware 控制平面与转售商重叠

不要将住宅地址池建模为一份扁平的出口列表。对 IPIDEA 生态系统的分析揭示了一种可复用的**双层控制平面**：嵌入式 SDK 首先向 Tier One 域名报告设备/注册元数据，并接收调度信息以及 Tier Two 的 `connect`/`proxy` IP:port 对。节点会定期轮询 Tier Two connect 端口以获取编码任务，向配对的 proxy 端口发起第二个连接，再将提供的字节中继到请求的目标。名义上不同的 SDK 和 proxy 品牌虽有各自独立的发现域名，但由于共同所有权和转售关系，最终汇聚到共享的 Tier Two 基础设施和重叠的出口池。<sup>[[13]](#references)</sup>

```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```

这会产生比 residential IP block 更持久的狩猎线索：<sup>[[13]](#references)</sup>

- 一个意料之外的 utility、VPN、游戏或嵌入式设备进程发送稳定的设备 ID/客户密钥，并接收不断变化的服务器列表；
- 终端先轮询一个使用异常端口的直接 IP，然后在打开指向新目标的 socket 之前，立即连接同一地址上的另一个端口；
- 多个表面上不同的品牌共用 Tier Two 地址、协议语法、SDK 代码或出口节点；
- 联系不同 Tier One 域名的不同应用，收到来自同一 Tier Two 池的地址。

这种重叠也限制了 attribution：在某个供应商公布的池中看到一个 IP，并不能证明相关时间内是哪个 reseller、客户或 threat actor 使用了它。保留流量时间戳、进程来源链、Tier One 响应正文和 Tier Two 任务标识符。<sup>[[13]](#references)</sup> 在授权演练中，只能使用组织自有的终端模拟此层级；绝不要注册消费者设备或第三方 proxyware。

## Multi-hop proxy chains

MITRE 区分了外部代理与 **multi-hop proxies (T1090.003)**。关键属性不在于跳数，而在于知识和管理权的分离。<sup>[[3]](#references)</sup>

```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
              sees source                         sees destination
```

如果同一方运营 A 和 B，共享日志或流量时序就可能还原出这条链路。通过同一端点/账户串联多个商业 VPN，可能增加延迟，却仍会留下共同的身份、付款和时序证据。Tor 通过独立选择中继并采用共享客户端设计来降低这一问题，但低延迟交互式网络无法保证抵御同时监测两端的观察者。

常见故障包括 DNS 或 IPv6 绕过、应用自行打开套接字、管理流量直接到达中继、活动时间同步、重复使用 SSH 密钥，以及登录可识别身份的账户。正确的验证方式是进行故障测试：依次停止每个中继，并证明工作负载无法回退到明文路径。

### 隧道坍塌与上游泄漏

中继架构在发生故障时往往最容易被归因。Unit 42 记录了一条多层间谍路径，其中使用了面向受害者的 VPS、中继 VPS、住宅代理、Tor 和其他代理服务；当某个隧道被遗漏或坍塌时，隐藏的上游基础设施会直接连接到中继和面向受害者的系统。调查还利用一张曾短暂暴露在上游基础设施上的 X.509 证书，作为跨层关联线索。<sup>[[14]](#references)</sup>

将**数据平面**（`victim <-> exit`）与**控制平面**（`operator/upstream -> relay administration`）分开。在每个自有层保留入口和身份验证日志、证书历史记录以及短暂的失败连接记录，而不只是成功的 C2 会话。在中继中断期间才出现，或直接管理多个面向受害者节点的来源，比普通出口更可能是上游节点；但其 ASN/地理位置仍只是推测，不能证明操作者的身份。

经授权的实验环境应确保工作负载故障时默认拒绝通信。对于隔离在 Linux 网络命名空间中的工作负载，首选路由必须使用隧道；移除隧道后，请求和路由查询都必须失败，而不能改用物理上行链路：

```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
  --resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```

对 DNS 和 IPv6 重复测试，并在每个中继边界处进行测试。如果任何探测成功，在修复策略路由或防火墙之前，记录实际的接口/源地址；这就是调查人员会看到的 attribution leak。

## Redirector tiers and traffic shaping

公共 **redirector** 接受符合特定行动语法的流量，并将其转发到受保护的团队服务器。其他所有流量都可以拒绝，或返回无害内容。

```text
implant/browser -> CDN or redirector -> relay -> team server
                       |
                 request policy
           host + path + method + header + time
```

多层架构可以限制暴露范围：烧掉一个公开域名，不一定会暴露团队服务器。CDN 提供 anycast 容量和信誉良好的外层域名，但 CDN 账户和边缘日志会成为归因线索。TLS 指纹、证书历史、独特路径/标头顺序、响应大小、重定向行为和源站 allowlist，都可能将看似无关的前端关联起来。

为了检测，应在规范化之前记录反向代理字段，比较 SNI/Host/authority，检查罕见的标头组合，对响应正文和 TLS 指纹进行聚类，并在云/CDN 审计日志中查找配置重叠。对于经授权的红队演练，避免仿冒真实品牌，也不要把凭据收集放在无关的第三方服务后面。

## Domain fronting 和无域名 fronting

在经典的 **domain fronting (T1090.004)** 中，TLS 连接在 SNI 中声明一个获准的前端域名，而加密的 HTTP `Host` 或 HTTP/2 `:authority` 则请求另一个后端域名。配合使用的 CDN 会根据内层值进行路由。无法解密 TLS 的网络观察者只能看到前端；CDN 则能看到这两个值和源站。在无域名变体中，SNI 可能为空，而另一个路由字段会选择目的地。<sup>[[4]](#references)</sup>

这不是神奇的伪装：只有在中间方有意或无意地允许这种不匹配，并且知道如何根据内层名称路由时，它才会生效。主要服务商已限制跨账户 fronting。Encrypted ClientHello (ECH) 会改变链路上的观察者能看到的内容，但不会抹去 CDN、端点或应用程序记录。

检测点包括：

- 端点进程的祖先链，以及应用程序不应访问的目的地；
- 在 TLS 检查合法且可用的情况下，检查 SNI 与 HTTP authority 是否不匹配；
- CDN 日志显示一个租户/前端路由到另一个 authority/源站；
- 通常用于交互的服务出现异常的长连接或周期性会话；
- 尽管前端域名不断变化，加密流量的大小和节奏却保持稳定。

安全的实验室环境会在自有反向代理上模拟路由不匹配；不会滥用公共 CDN。

## 动态解析：DDNS、DGA 和 fast flux

动态解析将逻辑服务与固定基础设施解耦：

- **DDNS：**经过身份验证的客户端会在地址变化后更新一个稳定名称。
- **DGA：**端点和控制器都根据时间/密钥种子生成候选域名；操作者只注册其中少量域名。
- **Fast flux：**一个名称返回一组快速变化的受控/代理地址，通常使用较低的 TTL。
- **Double flux：**服务地址和权威名称服务器地址都会轮换，从而也隐藏控制层。

Fast flux 是一种被攻击者利用的负载分配模式，不只是“DNS 返回了许多答案”。更有力的证据需要结合较低 TTL、较多的唯一地址、广泛分散的 ASN/地理位置、较短的节点存活时间、重复的应用行为以及可疑的注册历史。CDN 也会合法地具备其中多种特征。MITRE 建议将 DNS 行为与进程及后续连接关联起来。<sup>[[5]](#references)</sup>

可以通过词法熵、辅音/数字模式、NXDOMAIN 激增、首次发现域名的同步性和进程上下文来检测 DGA。基于词表的 DGA 和生成式模型会绕过简单的熵规则，因此全机群范围内的时间聚类和端点溯源关系更为重要。

## 被攻陷的域名和域名影子化

攻击者可能劫持注册商/DNS 账户、接管遗留子域名，或在其他方面信誉良好的域名下添加记录。**域名影子化**会保留合法的顶级域名，同时让大量攻击者控制的子域名指向不断变化的投递或 C2 主机。它借用域名的历史和信誉，并可能绕过针对整个域名的封锁。<sup>[[6]](#references)</sup>

防御者需要注册商和权威 DNS 审计日志、MFA、注册局/注册商锁定措施、针对新委派/API token/名称服务器的告警、证书透明度监控，以及 DNS 所引用云资源的资产清单。应独立调查子域名的解析和证书历史，不要仅凭顶级域名的信誉作判断。

## Web 服务和 dead-drop resolver

**dead-drop resolver (T1102.001)** 会将指向当前 C2 的编码指针存放在合法帖子、个人资料、文档、代码仓库、云对象或区块链字段中。恶意软件会获取该公开对象，解码出域名/IP，然后连接下一阶段。双向变体会通过服务 API 交换命令或文件。<sup>[[7]](#references)</sup>

一种针对 GitHub 的 resolver 变体，仅在经过身份验证的代码仓库通道失败时才使用 Issues Search API。客户端会搜索与当前日期、代码仓库和 issue 类型匹配的 issue，访问每个 issue 的评论 URL，并提取 `<!--` 和 `-->` 标记之间的密文。按主机和日期派生的解密操作完成后，`Owner`、`LicRepo` 和 `LicToken` 等字段会替换主要代码仓库的所有者、路径和 token。这样，操作者无需替换客户端即可轮换凭据和端点；issue 评论充当 resolver，而代码仓库文件仍是任务下发通道。<sup>[[15]](#references)</sup>

这提高了韧性，也让静态二进制分析难以发现后端 C2。但它也会产生稳定的对象、租户、代码仓库、API 和访问模式标识符。防御者应关联：

1. 联系该服务的进程；
2. 确切的 API 路径/对象及响应哈希；
3. 解码或字符串处理活动；
4. 不久之后出现的新出站连接；以及
5. 机群中其他位置的相同行为。

封锁所有 GitHub、云存储或社交媒体通常不可行。具备服务感知能力的出站策略和进程级关联，优于仅按域名封锁。

## Persona、账户和采购隔离区

如果 persona、恢复邮箱、电话、付款方式、浏览器或管理员 IP 连通不同隔离区，基础设施匿名性就会失效。与国家有关联的行动往往会在使用前长期培养社交资料、电子邮件身份和云账户；ATT&CK 将此记录为 Establish Accounts (T1585)，包括社交、电子邮件和云相关子技术。<sup>[[8]](#references)</sup>

防御者或调查人员会根据以下信息构建关联图：

- 创建和首次登录时间、地区设置、时区及工作时间安排；
- 恢复信息、MFA 设备、身份证明文件和支付工具；
- 浏览器/TLS 指纹及源网络历史；
- 头像复用、图像来源、写作风格和社交关系增长；
- 共用的域名注册人、名称服务器、证书、分析 ID 或代码仓库提交；
- 绕过公共中继架构的管理平面操作。

对于经授权的红队演练，合成 persona 应向演练负责人备案，使用组织拥有的恢复/支付渠道，避免冒充无关的真实人员，并制定退役计划。SOC 可以继续不知情，但行动必须可问责。

## 威胁建模中值得关注的新兴复合模式

以下是**由防御者驱动的组合方案**，并非声称某个具名攻击者已部署了每一种具体设计。它们结合了已有观察到的原语，可作为紫队演练假设。

### 非对称单向任务下发

命令通过公开、广播或只追加的数据源传入，结果则在延迟后通过无关通道发出。这类原语包括 Web 服务单向通信和 dead drop。通道分离可避免单条流量呈现双向特征，也会妨碍简单的请求/响应关联。<sup>[[9]](#references)</sup>

**检测：**保留对象级读取记录，然后在更长的时间窗口内关联进程状态变化和后续出站传输。即使没有立即回复，也要搜寻读取同一公开对象的罕见进程。

### 多阶段通道升级

低调的第一阶段执行资产盘点，并仅将选定系统升级到无关的第二阶段通道。第二阶段的端点、协议和进程可能与第一阶段没有任何基础设施关联。这样可以减少高能力基础设施的暴露；ATT&CK 将其明确建模为 T1104。<sup>[[10]](#references)</sup>

**检测：**关联 `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`；封锁第一个域名后不要就此结束事件调查。

### 跨协议中继转换

不同跳点会转换 HTTPS、QUIC、WebSocket、DNS、SSH 或消息队列 API，而不是透明转发数据包。转换会抹去单一端到端协议指纹，但也会形成具有独特时序、缓冲和语义转换特征的网关。协议隧道 (T1572) 可与代理和服务伪装结合使用。<sup>[[11]](#references)</sup>

**检测：**查找接收一种协议、再以紧密关联的字节数/时间行为发起另一种协议的网关主机；将端点意图与实际承载的协议进行比较。

### 边缘设备上的被动激活

植入物不会发送 beacon，而是监控已到达路由器/VPN 的流量，仅在遇到魔术值、源端口模式或经过身份验证的 token 时激活。正常流量会继续流向真实服务。ATT&CK 将此称为 Traffic Signaling (T1205)，并记录了网络设备和 APT 案例。<sup>[[12]](#references)</sup>

**检测：**检查固件/文件完整性，在经授权的搜寻期间进行原始数据包捕获，查找异常的套接字过滤器和服务行为差异。没有周期性 beacon 并不能证明边缘设备干净。

### Serverless 和短暂源站轮换

前端保持稳定的逻辑身份，而短生命周期的函数/容器则在多个区域/账户中处理单独阶段。这会缩短磁盘数据的存留时间，并减少固定源站 IP，但控制平面的创建记录、镜像/层、角色、密钥、请求 ID 和计费遥测会形成持久关联图。

**检测：**将云审计和调用日志保存在工作负载之外；对部署模板、角色、环境密钥以及前端与源站之间的关系进行聚类。

### 隐私层多样化

行动可能会刻意避免使用单一同质链路：例如，一个通道使用租用的中继，任务下发使用公开对象，出口来自自有实验室蜂窝链路，管理则使用独立的组织网络。这样可降低攻陷单一服务商的价值，但会增加跨层时序关联和操作失误的风险。

**检测：**跨身份、DNS、SaaS、网络和云传感器构建行动时间线。搜寻同步的状态转换，而不只是相同的指标。

### 去中心化或透明度日志中的 dead drop

攻击者可以在任何持久的公开只追加系统、内容寻址存储或类似透明度日志的数据流中放置小型加密指针。公开对象具有韧性，但其确切索引/内容哈希和客户端轮询行为会成为稳定标识符。

**检测：**记录完整的 API/对象标识符和响应哈希；对轮询不可变对象、随后执行解码或建立新连接的非标准进程发出告警。

### 延迟式存储转发行动

交互式 C2 会产生明显的时序关联。存储转发设计会批量处理加密任务，并在数分钟或数小时后通过另一个队列或物理转移返回结果。它牺牲响应速度，以削弱端到端时序关联。

**检测：**延长关联窗口，对周期性队列访问进行建模，并检查端点暂存行为。批处理会将信号从数据包时序转移到定时的进程/文件行为；它不会将信号抹去。

## 设计审查：从观察者视角思考

对于每条路径，在部署前和收集后都填写此表：

| 层 | 能看到源？ | 能看到目的地？ | 能看到内容？ | 稳定标识符 | 保留期限/法律责任方 |
|---|---:|---:|---:|---|---|
| 本地网络/运营商 | | | | | |
| 接入/入口服务 | | | | | |
| 中转运营方 | | | | | |
| 出口/redirector/CDN | | | | | |
| 权威 DNS/注册商 | | | | | |
| 目标 | | | | | |
| 账户/支付服务商 | | | | | |

如果一个普通服务商就能填满所有列，那么该架构只能对目标实现隐蔽，无法实现可靠隔离。如果没有任何内部负责人能够将活动映射回某项演练，那么它就不适合专业红队演练。

## References

- [1] [MITRE ATT&CK — 获取基础设施 (T1583)、攻陷基础设施 (T1584) 和代理 (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — 中国关联的间谍活动组织使用 ORB 网络](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — 多跳代理 (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — 攻陷基础设施：域名 (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web 服务：Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — 建立账户 (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web 服务：单向通信 (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — 多阶段通道 (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — 协议隧道 (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — 流量信令 (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — 瓦解全球最大的住宅代理网络](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — Shadow Campaigns：揭露全球间谍活动](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
- [15] [Unit 42 - Blinder Tunnel Campaign Targets Iraqi Infrastructure](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
{{#include ../banners/hacktricks-training.md}}
