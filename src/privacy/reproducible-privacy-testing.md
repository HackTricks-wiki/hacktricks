# 可复现的 Privacy Testing

{{#include ../banners/hacktricks-training.md}}

Privacy 配置并不是在成功连接时就完成了。只有当其声明的边界在正常使用、故障、恢复和拆除过程中都经过测试后，才算完成。请针对你拥有或获授权检查的基础设施进行测试；公共“leak test”网站会成为另一个观察者。

## 构建小型授权测试环境

使用三个角色，最好分别位于不同的 provider/network：
```text
operator endpoint ---- privacy path ---- owned web/DNS endpoint
|                                      |
local packet/route view                 server-side logs
|
controller/provider dashboards and payment/account records
```
在每次测试前记录：

- 测试 ID、UTC 开始/结束时间、操作员和授权信息；
- endpoint/OS/client 版本及配置哈希；
- 预期的 IPv4、IPv6、DNS、TLS、账户、支付和物理观察结果；
- 将检查哪些日志，以及这些日志使用的时钟/时区；
- 通过/失败规则和 teardown 时间。

切勿先测试敏感身份。使用 synthetic account，以及由 tester 所有的、无害且唯一的 canary 值。

## Network-path test

### 1. Capture the baseline

启用隐私路径前，记录本地路由和解析器：
```bash
ip route
ip -6 route
resolvectl status
```
在 macOS 上使用 `route -n get default`、`netstat -rn -f inet6` 和 `scutil --dns`。仅将输出保存到受控证据存储中；其中可能包含本地标识符。

### 2. 连接并检查 routing

启用 VPN/Tor/工作负载 namespace，然后检查为受控公共地址选择的 route：
```bash
ip route get 192.0.2.10
ip -6 route get 2001:db8::10
```
将文档地址替换为测试服务器地址。确认所选接口/表与设计一致。

### 3. 从两端观察

设置自有 endpoint 的 URL，然后请求一个唯一且无害的路径：
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl --fail --show-error --silent \
"${PRIVACY_TEST_URL}/privacy-check/run-20260907-001"
```
使用由 tester 控制的真实 domain、经过身份验证的 TLS，以及不包含敏感信息的 path token。检查 server log：

- source address/ASN 和预期的 egress；
- IPv4 与 IPv6；
- endpoint 可见的 Host/SNI 行为；
- user agent 和 application headers；
- exact time 以及 request reuse。

不要向一个据称已隔离的 request 添加 `X-Forwarded-For`、唯一的 debug headers 或包含身份信息的 cookies。

### 4. 使用自有的 canary 测试 DNS

配置一个由你控制 query logs 的 authoritative test zone。通过该 compartment 查询一个唯一的随机 label：
```bash
dig run-20260907-001.privacy-test.example A
dig run-20260907-001.privacy-test.example AAAA
```
检查权威日志。它通常看到的是 recursive resolver，不一定是客户端。将该 resolver 与预期的 VPN/Tor/application DNS 设计进行比较。不需要使用随机的公共 DNS leak 网站。

### 5. 测试 fail-closed 行为

保持一个针对自有 endpoint 的无害 request loop 运行，然后停止 privacy path。工作负载必须失败，而不能切换到物理接口。检查两个地址族和 DNS：
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl -4 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v4"
curl -6 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v6"
dig privacy-test.example
```
在以下情况下重复测试：

- tunnel 进程崩溃；
- Wi-Fi 切换到 Ethernet 或 hotspot；
- 睡眠/唤醒；
- DHCP renewal；
- captive-portal 状态变化；
- provider reconnect/key expiry。

对于 Linux namespace/container，停止其 tunnel，并验证它没有其他默认路由或 resolver：
```bash
ip netns exec privacy-workload ip route
ip netns exec privacy-workload ip -6 route
ip netns exec privacy-workload resolvectl status
```
名称和命令会因部署而异。不要在没有 console 恢复能力的情况下，将它们粘贴到远程 production host 中。

### 6. 检查本地 sockets 和数据包

在获得授权后，检查实际进行通信的进程/接口：
```bash
ss -tpn
ss -upn
sudo tcpdump -ni any 'host TEST_SERVER_IP'
```
将 `TEST_SERVER_IP` 替换为明确的自有地址；避免广泛捕获无关用户的流量。物理接口应看到 tunnel/bridge peer，而明文目标流量只能存在于预期的层。

## Tor 和 onion-service 测试

1. 在 Tor Browser 中访问 Tor Project 的连接检查页面，并确认正在使用 Tor。不要将其视为身份凭证。<sup>[[1]](#references)</sup>
2. 使用唯一的 canary 访问自有 HTTPS endpoint，并确认它看到的是 Tor exit、没有识别性 cookies，且处于标准浏览器环境。
3. 选择 **New Identity**，使用不同的 canary 再次访问，并验证本地状态已按预期清除。Exit IP 发生变化并非必然，也不是 New Identity 的目的。
4. 对于 onion service，只能通过 Tor Browser 访问。通过经授权的外部扫描确认 service host 没有 public listener，并确认应用响应不包含 public hostname/IP。
5. 检查 origin 的 outbound DNS/HTTP、templates、error pages、email/webhooks 和 third-party assets。任何直接 fetch 都可能泄露 origin 或 operator account。
6. 如果启用了 client authorization，请确认未提供凭据的干净 Tor Browser 无法连接，而提供凭据的浏览器可以连接。
7. 轮换测试 authorization key，并确认被撤销的 client 无法继续访问，同时 onion identity 不发生变化。

## Browser-compartment 测试

创建一个受控页面，仅记录测试所需的字段，并设置较短的保留期限。比较个人 compartment 和 privacy compartment 中的：

- cookies/local storage/service workers 和 cache；
- browser sync/login state；
- language、time zone、screen/window dimensions 和 fonts；
- WebRTC/network candidates；
- permissions 和 extension-visible modifications；
- server 端的 TLS/HTTP user-agent data。

不要尝试让 Tor Browser 变得“更加随机”。通过条件是：它与标准 anonymity set 相似，并且不存在个人状态，而不是与个人浏览器产生最大差异。

测试 copy/paste、drag/drop、downloaded-file opening、password-manager suggestions 和 identity-provider buttons。这些是 compartment 之间常见的桥梁。

## Operating-system isolation 测试

### Tails

1. 在没有 Persistent Storage 的 session 中，以一个无害文件/canary 开始。
2. 完全关机、重新启动，并确认该文件已消失。
3. 仅启用一个必需的 persistence category，重复测试，并确认无关的 browser/application state 未被保留。
4. 验证在 portal login 后不能使用 Unsafe Browser 进行敏感活动，并确认 Tor applications 能正常重新连接。

### Whonix/Qubes

1. 停止 Gateway/net qube，并证明 Workstation/app qube 无法访问 IPv4、IPv6 或 DNS。
2. 仅尝试明确配置的 inter-qube clipboard/file path，并确认其他 shared-folder/device paths 不存在。
3. 在 disposable qube 中打开一个无害的测试文档，关闭它，并确认其状态已消失。
4. 检查 vault qube 没有 NetVM，并确认无法通过 template/default change 获取 NetVM。
5. 对测试 VM 执行 snapshot/restore，并检查是否意外恢复了包含身份信息的状态。

## Communications metadata 测试

针对每个选定的 messenger：

1. 在受控设备上创建仅用于测试的参与者。
2. 记录注册所需的信息：phone、app-store account、IP、push service、username 或 invitation。
3. 发送一条无害消息，同时检查 notification previews、linked desktops、wearables 和 backups。
4. 通过独立路径验证 safety/security codes。
5. 一次仅禁用 receipts/push，或启用 Tor/local transports，并观察 reliability/metadata 的变化。
6. 导出或恢复测试 backup，并准确记录其中包含的 profile、contacts 和 history。
7. 使测试设备丢失/撤销，并确认其余参与者看到预期的 key/device change。

不要通过联系无关人员或生成滥用流量来进行测试。

## File-sanitization 测试

1. 在加密的 evidence storage 中对原始文件进行 hash 并保留：
```bash
sha256sum ./original/file > ./original/file.sha256
```
2. 使用 [隐私保护通信与共享](privacy-preserving-communications-and-sharing.md) 中针对特定格式的流程创建清理后的副本。
3. 比较元数据清单：
```bash
exiftool -a -u -g1 ./original/file
exiftool -a -u -g1 ./clean/file
```
4. 在一次性上下文中渲染/打开副本。检查隐藏内容、附件、链接、表单、图层、缩略图和视觉标识符。
5. 仅在暂存副本中搜索已知的 canary 作者/电子邮件/路径字符串。
6. 对最终输出进行哈希处理，并由第二人验证实际发布的确切文件。

ExifTool 输出中不存在相关信息，并不能证明匿名性；格式内部结构、像素、文本内容和分发记录仍然存在。

## Payment privacy test

使用允许的最小金额，或使用官方测试网络/sandbox：

1. 为付款方、收款方/商户、发行方/交易所、网络/节点、公开账本以及会计人员/控制者写出预期视图。
2. 创建唯一的测试发票/商户上下文，不得伪造身份。
3. 支付一次，然后收集**你自己的**收据、账单、商户 dashboard、钱包/节点日志，以及适用时的公开链视图。
4. 检查金额、时间戳、地址/token、账户、IP/设备、交付和退款路径是否与观察者表匹配。
5. 对于 Bitcoin，在钱包的 coin-control 视图中检查地址重用、选定的 inputs、找零以及之后的合并。
6. 对于 shielded protocols，验证实际的 pool/path 以及 viewing key 能揭示什么；不要根据钱包 branding 推断隐私性。
7. 对于 e-cash/Taler，使用小额测试备份/恢复、退款和兑换；记录 mint/exchange/federation 边界记录。
8. 撤销虚拟卡/测试凭证，并确认之后的授权失败，同时确保合法退款处理仍然清晰可理解。
9. 对账并加密保存所需的税务/授权证据。

绝不要创建循环转账、拆分金额以规避阈值、虚假购买或可疑退款作为“隐私测试”。

## Authorized red-team accountability drill

在演练前，执行 tabletop 和技术演练：

1. 操作员从每条获批准的源路径启动一个无害的 canary。
2. 目标 SOC 记录其检测到的内容；如果计划进行盲测，则不得接收操作员身份。
3. 演练控制者根据托管的映射表和已签名的 job record，将源 → engagement → 操作员对应起来。
4. 控制者发送 emergency stop；操作员和基础设施所有者在 ROE 规定的时间内演示关闭操作。
5. Provider abuse 团队收到正确的 24/7 联系方式和授权引用。
6. 证据能够显示目标、时间、工具/job 和操作员，但不保留不必要的 payload 内容。
7. 第二名操作员验证凭证撤销和资源拆除。

如果 SOC 能轻易看到个人/家庭基础设施，**或**控制者无法快速归因并停止该源，则应判定准备情况审查失败。

## Test record template
```text
Test ID / date (UTC):
Authorization / owner:
Claim under test:
Expected observers:
Endpoint + versions:
Configuration hash:
Normal result:
Failure/reconnect result:
Server/provider/account evidence:
Unexpected linkage:
Pass/fail:
Remediation + retest ID:
Evidence retention/deletion date:
```
## References

- [1] [Tor Project — Connection check](https://check.torproject.org/)
- [2] [WireGuard — 路由与 Network Namespaces](https://www.wireguard.com/netns/)
- [3] [ExifTool — FAQ 与 metadata 指南](https://exiftool.org/faq.html)
- [4] [NIST SP 800-115 — 信息安全测试与评估技术指南](https://csrc.nist.gov/pubs/sp/800/115/final)
{{#include ../banners/hacktricks-training.md}}
