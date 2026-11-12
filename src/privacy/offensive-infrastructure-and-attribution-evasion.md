# Offensive Infrastructure and Attribution Evasion

{{#include ../banners/hacktricks-training.md}}

操作者很少能仅凭单个 proxy 获得有意义的匿名性。真正的行动会构建一张**隔离图**：操作者连接到一个接入节点，遍历节点将该节点与出口隔离，redirector 保护真正的 C2，而一次性域名则指向公网边缘。

使用 [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md)，查看每条路径经标准化整理的优缺点、部署和检测信息。本页将深入探讨对抗性基础设施的组合方式。

```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
                |                 |                |
          account/provider   relay operator   target telemetry
```

目标最后看到的地址因此只是路径的证据，而不能证明是谁在操作键盘。MITRE 将主要组成部分映射为 Acquire Infrastructure (T1583)、Compromise Infrastructure (T1584)、Proxy (T1090)、Dynamic Resolution (T1568) 和 Web Service (T1102)。<sup>[[1]](#references)</sup>

## 基础设施类别

| 类别 | 行为者使用它的原因 | 持久性暴露 | 防御者最佳关联线索 |
|---|---|---|---|
| 租用的 VPS/cloud | 部署快速、行为可预测、可路由，且容易重建 | 租户、账单、控制台、源登录和镜像历史 | 账户/控制平面事件和重复出现的服务器指纹 |
| 商业 VPN/Tor | 大型共享出口池；无需管理服务器 | 服务提供商/监控方可见性及端到端时序 | 目标行为、端点证据和流量关联 |
| Residential/mobile proxy | 消费者 ASN 和地理位置更可信 | 经纪商/客户记录；proxyware 或受感染主机行为 | 不可能的旅行、代理协议和按会话变化的地址 |
| 受感染的服务器/路由器/IoT | 借用受害者的信誉和司法管辖区 | 植入程序、管理流量和重复出现的上游控制器 | 设备遥测和 ORB 拓扑，而非单个出口 IP |
| CDN/redirector | 将公共边缘与后端 C2 分离 | TLS/HTTP 语法、证书、路由和 cloud 账户痕迹 | 边缘到源站的关联及请求形态聚类 |
| 合法 Web 服务 | 混入获准的 GitHub/cloud/social 流量 | API token、租户/对象标识符和异常进程谱系 | 端点进程及服务/API 语义 |
| 物理/蜂窝/卫星路径 | 改变表面上的物理来源 | RF、运营商、订户、设备和位置记录 | 结合无线电/物理证据与网络证据 |

## 运营型中继箱网络

**ORB network** 是一种作为中间服务使用的托管代理集群。Mandiant 将其分为租用服务器组成的预置网络、由受感染路由器/IoT 组成的非预置网络，以及混合网络。成熟的拓扑包含四种逻辑角色：<sup>[[2]](#references)</sup>

1. **管理服务器 (ACOS)：** 维护资产清单、凭据、运行状况和路由策略。
2. **接入/中继节点：** 对客户或操作人员进行身份验证；它是进入不断变化的网状网络的稳定入口。
3. **遍历节点：** 一个或多个租用或受感染系统中继不透明连接。
4. **出口/暂存节点：** 向侦察、利用或 C2 目标呈现最终源地址。

网状网络可以根据国家/地区、ASN、延迟或可用性选择出口，并轮换状态不佳的节点。多个威胁组织可能租用同一网络。Mandiant 观察到，一些 ORB 的 IPv4 地址与网络关联的时间短至 31 天；因此，它建议将**网络视为不断演变、类似行为者的实体**，而不是封禁一份过时的 IP 清单。<sup>[[2]](#references)</sup>

### 这能带来什么——以及它会泄露什么

- 目标看到的出口可能在地理位置上很近，而且看起来像住宅网络。
- 出口能看到目标和前一跳，但未必能看到操作人员。
- 接入服务能看到客户和路由请求。独立管理的网状网络可以将客户与出口隔离，但也会留下重要的对手方记录。
- 即使 IP 不断轮换，重复出现的端口、握手顺序、服务器标识、证书、运行时间窗口和控制器关系仍可能暴露整个集群。
- 受感染的路由器通常缺乏端点遥测，但其 ISP 仍掌握订户和流量数据；设备被扣押后会暴露植入程序/配置痕迹。

{% hint style="info" %}
对于经授权的演练，可使用组织自有的 VM 或路由器复现此拓扑，并保留控制器的归因映射。不要招募开放代理或第三方设备。[lab guide](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) 会创建相同的、对防御者可见的跳点结构，且不会伤害中间方。
{% endhint %}

## Residential 和 mobile proxy 网络

Residential proxy 服务会为会话分配消费者宽带地址；mobile proxy 则通过运营商 NAT 地址池出口。代理资源可能来自明确注册的设备、捆绑在消费者应用中的 SDK/proxyware、转售商或恶意软件。这些来源并不等同：缺乏知情同意会让隐私服务沦为受感染基础设施。

轮换模式会影响检测：

- **按请求轮换**会导致 IP 及 ASN/地理位置快速变化，而高层身份保持稳定；
- **粘性会话**会让出口保持数分钟或数小时，看起来像普通订户；
- **回连网关**会向客户暴露一个经纪商端点，并在内部选择出口；
- **mobile 池**会让许多真实订户共享少量运营商 NAT 地址，因此封禁 IP 的代价很高。

防御者应将 IP 与经过身份验证的会话、TLS/客户端指纹、HTTP 顺序、设备 cookie 和行为进行关联。一个看似本地的 residential 登录，随后在高层特征完全相同的情况下出现在另一个国家，这比单凭信誉判断更有力。反过来，地址共享和 mobile 切换也会造成正常的地址变化，因此绝不能将 residential/proxy 分类本身视为定论。

### Proxyware 控制平面与转售商重叠

不要将 residential 池建模为一份扁平的出口清单。对 IPIDEA 生态系统的分析揭示了一种可复用的**双层控制平面**：嵌入式 SDK 首先向 Tier One 域报告设备/注册元数据，并接收调度信息以及 Tier Two `connect`/`proxy` IP:port 对。节点会定期轮询 Tier Two connect 端口以获取编码任务，随后与配对的 proxy 端口建立第二个连接，并将提供的字节中继到请求的目标。名义上不同的 SDK 和 proxy 品牌拥有各自独立的发现域，但通过共同所有权和转售关系汇聚到共享的 Tier Two 基础设施和重叠的出口池。<sup>[[13]](#references)</sup>

```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```

这比住宅 IP 地址段能产生更持久的狩猎线索：<sup>[[13]](#references)</sup>

- 意料之外的实用程序、VPN、游戏或嵌入式设备进程发送稳定的设备 ID/客户密钥，并接收不断变化的服务器列表；
- 端点先轮询非常规端口上的直接 IP，然后在打开新的目标套接字前，立即连接同一地址上的另一个端口；
- 多个表面上不同的品牌共享 Tier Two 地址、协议语法、SDK 代码或出口节点重叠；
- 联系不同 Tier One 域名的不同应用，从同一个 Tier Two 地址池接收地址。

这种重叠也限制了归因：在某个供应商公布的地址池中看到一个 IP，并不能证明相关时段内是哪个转售商、客户或威胁行为者使用了它。保留流量时间戳、进程沿袭、Tier One 响应正文和 Tier Two 任务标识符。<sup>[[13]](#references)</sup> 在获得授权的演练中，只能使用组织自有端点模拟这种层级结构；切勿注册消费者设备或第三方代理软件。

## Multi-hop proxy chains

MITRE 区分了外部代理和 **multi-hop proxies (T1090.003)**。关键属性不在于跳数，而在于知识与管理权限的分离。<sup>[[3]](#references)</sup>

```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
              sees source                         sees destination
```

如果同一方同时运营 A 和 B，共享日志或流量时序就可能还原出这条链路。使用同一端点/账户依次连接多个商业 VPN，可能会增加延迟，却仍留下共同的身份、付款和时序证据。Tor 通过独立选择中继和共享客户端设计来降低这个问题，但低延迟交互式网络无法保证抵御同时监测两端的观察者。

常见故障包括 DNS 或 IPv6 绕过、应用自行打开套接字、管理流量直接到达中继、活动同步、重复使用 SSH 密钥，以及登录可识别身份的账户。正确的验证方式是进行故障测试：依次停止每个中继，并证明工作负载无法回退到明文路径。

### 隧道坍塌与上游泄露

中继架构往往在故障时最容易被追踪。Unit 42 记录了一条多层间谍活动路径，使用面向受害者的 VPS、中继 VPS、住宅代理、Tor 和其他代理服务；当某个隧道被省略或坍塌时，隐藏的上游基础设施会直接连接中继系统和面向受害者的系统。该调查还利用上游基础设施上短暂暴露的 X.509 证书，跨层追踪线索。<sup>[[14]](#references)</sup>

将**数据平面**（`victim <-> exit`）与**控制平面**（`operator/upstream -> relay administration`）分开。在每个自有层级保留入口日志和身份验证日志、证书历史记录，以及短暂失败的连接记录，而不仅仅是成功的 C2 会话。如果某个来源只在中继故障期间出现，或直接管理多个面向受害者的节点，那么它比普通出口更可能是上游节点；但其 ASN/地理位置仍只是推测，不能证明运营者身份。

经授权的实验室应确保工作负载发生故障时默认拒绝连接。对于隔离在 Linux 网络命名空间中的工作负载，第一条路由必须使用隧道；移除隧道后，请求和路由查询都必须失败，而不能改用物理上行链路：

```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
  --resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```

对 DNS 和 IPv6 重复测试，并在每个中继边界进行测试。如果任何探测成功，在修复策略路由或防火墙之前，记录实际的接口/源地址；这是调查人员会看到的 attribution leak。

## Redirector tiers and traffic shaping

公共 **redirector** 接受符合特定操作语法的流量，并将其转发到受保护的团队服务器。其他所有流量都可以被拒绝，或返回无害内容。

```text
implant/browser -> CDN or redirector -> relay -> team server
                       |
                 request policy
           host + path + method + header + time
```

多层基础设施可以限制暴露范围：弃用一个公开域名，不一定会暴露 team server。CDN 提供 anycast 容量和信誉良好的外层域名，但 CDN 账户和边缘日志会成为归因线索。TLS 指纹、证书历史、独特的路径/标头顺序、响应大小、重定向行为和源站允许列表，都可能将看似无关的前端归为一组。

为了检测，应在规范化之前记录反向代理字段，比较 SNI/Host/authority，检查罕见的标头组合，对响应正文和 TLS 指纹进行聚类，并搜索 cloud/CDN 审计日志中的配置重叠。对于获得授权的 red team，不要仿冒真实品牌，也不要把凭据收集放在无关的第三方服务后面。

## Domain fronting 和 domainless fronting

使用经典的 **domain fronting (T1090.004)** 时，TLS 连接会在 SNI 中声明一个获准的前端域名，而加密的 HTTP `Host` 或 HTTP/2 `:authority` 请求另一个后端域名。配合使用的 CDN 会根据内部值进行路由。无法解密 TLS 的网络观察者只能看到前端；CDN 则能看到这两个值和源站。在 domainless 变体中，SNI 可能为空，而另一个路由字段会选择目标。<sup>[[4]](#references)</sup>

这不是神奇的伪装：只有在中间层有意或无意地允许这种不匹配，并且知道如何根据内部名称路由时，它才会奏效。主要服务提供商已限制跨账户 fronting。Encrypted ClientHello (ECH) 会改变链路观察者能看到的内容，但不会抹去 CDN、端点或应用程序记录。

检测点包括：

- 端点进程的祖先链，以及该应用程序不应访问的目标；
- 在合法且可用 TLS 检查的情况下，检查 SNI 与 HTTP authority 是否不匹配；
- CDN 日志显示某个租户/前端将流量路由到另一个 authority/源站；
- 与通常以交互方式使用的服务建立异常的长连接或周期性会话；
- 在前端域名变化时，流量大小和时间间隔仍保持稳定的加密流。

安全的实验室环境可在自有反向代理上模拟路由不匹配；不要滥用公共 CDN。

## 动态解析：DDNS、DGA 和 fast flux

动态解析使逻辑服务不再依赖固定基础设施：

- **DDNS：**经过身份验证的客户端会在地址变化后更新一个稳定名称。
- **DGA：**端点根据种子派生域名，种子通常是时间或密钥，有时也会是可变的公开内容；操作者会为当前有效名称配置 DNS。<sup>[[17]](#references)</sup>
- **Fast flux：**一个名称会返回一组快速变化的受感染/代理地址，TTL 通常较低。
- **Double flux：**服务地址和权威名称服务器地址都会轮换，从而也隐藏控制层。

Fast flux 是一种被用于对抗活动的负载分配模式，而不只是“有很多 DNS 答案”。更有力的证据包括低 TTL、较高的唯一地址数量、广泛的 ASN/地理位置分布、节点存活时间短、重复的应用程序行为以及可疑的注册历史。CDN 也会合法地具备其中一些特征。MITRE 建议将 DNS 行为与进程及后续连接关联分析。<sup>[[5]](#references)</sup>

可通过词汇熵、辅音/数字模式、NXDOMAIN 突发、首次出现域名的同步性以及进程上下文来检测 DGA。基于词表的 DGA 和生成模型会绕过简单的熵规则，因此，全机群的时间聚类和端点溯源关系更为重要。

### 用可变图像作为基于词表的 DGA 种子

DGA 不一定依赖时间。一个加载器会获取公开的 Telegram 频道页面，读取其 `tgme_page_photo_image` 元素的 `src`，下载该头像图片，并对其**文件末尾的 50 个字节**进行哈希，而不是对解码后的像素进行哈希。四个哈希种子会分别选择一个形容词、名词、动词和数字。更换图像就会改变派生出的 DNS 名称，无需发布新客户端。两端必须使用完全相同的已下载图像字节和词表顺序；重新编码图像或调整词表顺序都会生成不同的名称。<sup>[[17]](#references)</sup>

有了从客户端恢复的词表后，就可以复现名称选择步骤。源代码中的逐字节哈希使用一个 64 位累加器、乘数 `0x1000193`，并为每个组成部分使用单独的种子：<sup>[[17]](#references)</sup>

<details>
<summary>复现基于图像种子的词表名称选择</summary>

```python
def wordlist_domain(image: bytes, adjectives: list[str], nouns: list[str], verbs: list[str], suffix: str) -> str:
    if len(image) < 50:
        raise ValueError("Image must contain at least 50 bytes")
    tail = image[-50:]
    def hashed(seed: int) -> int:
        value = seed
        for byte in tail:
            value = ((value ^ byte) * 0x1000193) & 0xFFFFFFFFFFFFFFFF
        return value
    a = adjectives[hashed(0x811C9DC5) % len(adjectives)]
    n = nouns[hashed(0xAF0154A5) % len(nouns)]
    v = verbs[hashed(0xFE5439E4) % len(verbs)]
    digit = hashed(0xFFA7471A) % 1000
    return f"{a}-{n}-{v}-{digit}.{suffix}"
```

</details>

与会发布端点本身的 [dead-drop resolver](#web-services-and-dead-drop-resolvers) 不同，这里的公共对象只提供一个可变种子；客户端在本地派生端点。

随后，客户端通过 `https://dns.google/resolve?name=<domain>&type=TXT` 查询生成的名称对应的 DNS TXT 记录。客户端对 JSON 响应的 `data` 字段进行 Base64 解码，使用内嵌的公钥验证 Ed25519 签名，之后才会使用 AES-ECB 解密命令。观察到的明文以方法选择器和加密载荷的 URL 开头。签名检查意味着，仅有可解析的 TXT 记录并不足以提供可接受的任务指令。<sup>[[17]](#references)</sup>

## 被攻陷的域名与 domain shadowing

攻击者可能劫持注册商/DNS 帐户、接管失效的子域名，或在其他方面信誉良好的域名下添加记录。**Domain shadowing** 会保留合法的顶级域名，同时创建大量由攻击者控制、指向不断变化的投递或 C2 主机的子域名。它借助域名的年限和信誉，可能躲过针对整个域名的封锁。<sup>[[6]](#references)</sup>

防御方需要注册商和权威 DNS 审计日志、MFA、注册局/注册商锁定、针对新增委派/API token/名称服务器的告警、证书透明度监控，以及 DNS 所引用的云资源清单。应独立调查子域名的解析与证书历史，不要依赖顶级域名的信誉。

## Web 服务与 dead-drop resolvers

**Dead-drop resolver (T1102.001)** 会在合法的帖子、个人资料、文档、代码库、云对象或区块链字段中存储指向当前 C2 的编码指针。恶意软件获取公共对象、解码出域名/IP，再连接下一阶段。双向变体会通过服务 API 交换命令或文件。<sup>[[7]](#references)</sup>

一种特定于 GitHub 的 resolver 变体仅在经过身份验证的代码库通道失效时才使用 Issues Search API。客户端搜索符合当前日期、代码库和议题类型的议题，跟随每个议题的评论 URL，并提取 `<!--` 与 `-->` 标记之间的密文。按主机和日期派生的方式解密后，`Owner`、`LicRepo` 和 `LicToken` 等字段会替换主要代码库所有者、路径和 token。这样，操作者无需替换客户端即可轮换凭据和端点；议题评论充当 resolver，而代码库文件仍是任务指令通道。<sup>[[15]](#references)</sup>

一种 Android 变体会在启动时从两个公共 Telegram 页面中选择一个，并提取 APK 内嵌标记两次出现之间的密文。它会对该值进行 Base64URL 解码，再使用 AES-128-CBC 解密：`SHA-256(marker)` 的前 16 个字节是密钥，剩余 16 个字节是 IV。明文是真正的 C2 基础 URL，而不是 Telegram 页面 URL。复现解析过程时，应保留页面内容和精确的标记；更改公共页面即可轮换端点，无需重新构建 APK。<sup>[[16]](#references)</sup>

这种方式可提高韧性，并隐藏静态二进制分析中的后端 C2。但它也会留下稳定的对象、租户、代码库、API 和访问模式标识符。防御方应关联以下信息：

1. 联系该服务的进程；
2. 精确的 API 路径/对象及响应哈希；
3. 解码或字符串处理活动；
4. 随后不久建立的新出站连接；以及
5. 机群中其他位置的相同行为。

全面封锁 GitHub、云存储或社交媒体通常不可行。了解服务特性的出口策略和进程级关联，比仅按域名封锁更有效。

## 身份角色、帐户与采购隔离区

当身份角色、恢复邮箱、电话、付款方式、浏览器或管理员 IP 关联起不同隔离区时，基础设施匿名性就会失效。与国家有关联的行动会在使用之前很久就开始培育社交资料、电子邮件身份和云帐户；ATT&CK 将其记录为 Establish Accounts (T1585)，并包含社交、电子邮件和云相关子技术。<sup>[[8]](#references)</sup>

防御人员或调查人员可基于以下信息构建关系图：

- 创建和首次登录时间、区域设置、时区及工作时间；
- 恢复信息、MFA 设备、身份证件和付款工具；
- 浏览器/TLS 指纹及源网络历史；
- 头像复用、图像来源、写作风格和社交关系增长；
- 共享的域名注册人、名称服务器、证书、分析 ID 或代码库提交；
- 绕过公共中继架构的管理平面操作。

对于经授权的 red team，合成身份应记录在演练控制方的文档中，使用组织拥有的恢复/付款渠道，避免冒充无关的真实人员，并制定退役计划。SOC 可以继续不知情，但行动必须可追责。

## 建模分析的新兴复合模式

以下内容是**由防御方提出的组合设计**，并非声称某个具名攻击者已经部署了每种精确设计。它们组合了已观察到的基本技术，可作为 purple-team 假设。

### 非对称单向任务指令

命令通过公共、广播或仅追加数据源传入，而结果则在延迟后通过无关通道发出。这些基本技术包括 Web 服务单向通信和 dead drop。将两者分离，可避免单个流量看起来具有双向性，并增加简单请求/响应关联的难度。<sup>[[9]](#references)</sup>

**检测：** 保留对象级读取记录，然后在更长的时间窗口内关联进程状态变化和后续出站传输。即使没有紧随其后的回复，也要搜寻读取同一公共对象的罕见进程。

### 多阶段通道升级

第一阶段保持低调，执行清点，仅将选定系统升级到无关的第二阶段通道。第二个端点、协议和进程可能与第一阶段没有任何基础设施关联。这样可以减少高能力基础设施暴露的机会；ATT&CK 将其明确建模为 T1104。<sup>[[10]](#references)</sup>

**检测：** 关联 `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`；封锁第一个域名后，不要就此结案。

### 跨协议中继转换

不同跳点会转换 HTTPS、QUIC、WebSocket、DNS、SSH 或消息队列 API，而不是透明地转发数据包。转换消除了单一的端到端协议指纹，但会产生具有独特时序、缓冲和语义转换特征的网关。Protocol tunneling (T1572) 可与代理和服务伪装结合使用。<sup>[[11]](#references)</sup>

**检测：** 查找接收一种协议后又发起另一种协议、且字节数/时间紧密相关的网关主机；对比端点意图与实际承载的协议。

### 边缘设备上的被动激活

植入程序不发送 beacon，而是监控已到达路由器/VPN 的流量，仅在遇到特定 magic value、源端口模式或经过身份验证的 token 时激活。正常流量仍会送达真实服务。ATT&CK 将其称为 Traffic Signaling (T1205)，并记录了网络设备和 APT 案例。<sup>[[12]](#references)</sup>

**检测：** 检查固件/文件完整性，在经授权的调查期间捕获原始数据包，查找异常 socket filter 和服务行为差异。没有周期性 beacon 并不能证明边缘设备是干净的。

### Serverless 与短生命周期源站轮换

前端保持稳定的逻辑身份，而短生命周期函数/容器则在多个区域/帐户中处理各个阶段。这样可以缩短磁盘数据的留存时间，并避免固定源站 IP，但控制平面创建记录、镜像/层、角色、密钥、请求 ID 和账单遥测会成为持久的关系图。

**检测：** 将云审计日志和调用日志保留在工作负载之外；根据部署模板、角色、环境密钥以及前端到源站的关系进行聚类。

### 隐私层多样化

行动可能会有意避免使用单一同质链路：例如，一个通道使用租用的中继，任务指令使用公共对象，出口来自自有实验室的蜂窝链路，管理则使用独立的组织网络。这样可降低攻陷单一服务提供商带来的影响，但会增加跨层时序关联和操作失误的风险。

**检测：** 基于身份、DNS、SaaS、网络和云传感器构建行动时间线。搜索同步的状态转换，而非相同的指标。

### 去中心化或透明度日志 dead drop

攻击者可以在任何持久的公共仅追加系统、内容寻址存储或类似透明度日志的 feed 中放置小型加密指针。公共对象具有韧性，但其精确索引/内容哈希和客户端轮询行为会成为稳定标识符。

**检测：** 记录完整的 API/对象标识符及响应哈希；针对轮询不可变对象、随后执行解码或建立新连接的非标准进程发出告警。

### 延迟式存储转发行动

交互式 C2 会产生明显的时序关联。存储转发设计会将加密任务打包，并在几分钟或几小时后通过另一个队列或物理转移返回结果。它牺牲响应速度，以降低端到端时序关联性。

**检测：** 延长关联窗口，对队列访问进行周期性建模，并检查端点暂存行为。打包会将信号从数据包时序转移到计划性进程/文件行为，但不会让信号消失。

## 设计审查：从观察者角度思考

对于每条路径，在部署前和收集后填写此表：

| 层 | 能看到源端吗？ | 能看到目标端吗？ | 能看到内容吗？ | 稳定标识符 | 保留期限/法律责任方 |
|---|---:|---:|---:|---|---|
| 本地网络/运营商 | | | | | |
| 入口/接入服务 | | | | | |
| 中间转发方 | | | | | |
| 出口/重定向器/CDN | | | | | |
| 权威 DNS/注册商 | | | | | |
| 目标 | | | | | |
| 帐户/付款服务提供商 | | | | | |

如果一个普通服务提供商就能填满每一列，那么该架构只能向目标隐藏信息，却无法实现稳健的隔离。如果没有内部控制方能够将活动对应回某次演练，则不适用于专业 red team。

## References

- [1] [MITRE ATT&CK — Acquire Infrastructure (T1583)、Compromise Infrastructure (T1584) 和 Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — 与中国有关联的间谍活动组织使用 ORB 网络](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Compromise Infrastructure: Domains (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Establish Accounts (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: One-Way Communication (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Multi-Stage Channels (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — 瓦解全球最大的住宅代理网络](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — Shadow Campaigns：揭露全球间谍活动](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
- [15] [Unit 42 - Blinder Tunnel Campaign 针对伊拉克基础设施发起攻击](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [16] [RemControl：AI 构建了覆盖层，受害者丢失 PIN](https://www.group-ib.com/blog/remcontrol-android-banking-trojan/)
- [17] [Check Point Research — 通过经签名的 ChatGPT 和 Claude 二进制文件部署旧有伎俩](https://research.checkpoint.com/2026/tricks-from-the-past-deployed-via-signed-chatgpt-and-claude-binaries/)
{{#include ../banners/hacktricks-training.md}}
