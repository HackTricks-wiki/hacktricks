# 可复现的隐私测试

隐私配置并不是在成功连接时就完成了。只有当其声明的边界经过正常使用、故障、恢复和拆除流程的测试后，才算完成。请针对你拥有或获授权检查的基础设施进行测试；公共的“leak test”网站会成为另一个观察者。

## 构建一个小型的授权测试环境

使用三个角色，最好位于不同的 provider/network 上：
```text
operator endpoint ---- privacy path ---- owned web/DNS endpoint
|                                      |
local packet/route view                 server-side logs
|
controller/provider dashboards and payment/account records
```
在每次测试前记录：

- test ID、UTC 开始/结束时间、operator 和授权信息；
- endpoint/OS/client 版本及 configuration hash；
- 预期的 IPv4、IPv6、DNS、TLS、account、payment 和 physical observations；
- 将检查哪些 logs，以及它们的 clocks/time zones；
- pass/fail rule 和 teardown time。

切勿首先测试敏感身份。使用 synthetic account，以及由 tester 所拥有的无害且唯一的 canary values。

## Network-path 测试

### 1. Capture baseline

在启用 privacy path 之前，记录本地 routes 和 resolvers：
```bash
ip route
ip -6 route
resolvectl status
```
在 macOS 上使用 `route -n get default`、`netstat -rn -f inet6` 和 `scutil --dns`。仅将输出保存到受控证据存储中；其中可能包含本地标识符。

### 2. 连接并检查路由

启用 VPN/Tor/工作负载 namespace，然后检查为受控公共地址选择的路由：
```bash
ip route get 192.0.2.10
ip -6 route get 2001:db8::10
```
将文档中的地址替换为测试服务器地址。确认所选接口/表与设计相匹配。

### 3. 从两端观察

设置自有 endpoint 的 URL，然后请求一个唯一且无害的路径：
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl --fail --show-error --silent \
"${PRIVACY_TEST_URL}/privacy-check/run-20260907-001"
```
使用由测试人员控制的真实 domain、经过身份验证的 TLS 以及非敏感的路径 token。检查 server log，确认：

- 源地址/ASN 以及预期的 egress；
- IPv4 与 IPv6；
- endpoint 可见的 Host/SNI 行为；
- user agent 和 application headers；
- 精确时间以及 request reuse。

不要向声称已隔离的 request 添加 `X-Forwarded-For`、唯一的 debug headers 或包含身份信息的 cookies。

### 4. 使用自有 canary 测试 DNS

配置一个由你控制 query logs 的 authoritative test zone。通过该 compartment 查询一个唯一的随机 label：
```bash
dig run-20260907-001.privacy-test.example A
dig run-20260907-001.privacy-test.example AAAA
```
检查权威日志。它通常看到的是 recursive resolver，不一定是客户端。将该 resolver 与预期的 VPN/Tor/application DNS design 进行比较。不需要使用随机的公共 DNS leak 检测站点。

### 5. 测试 fail-closed 行为

保持一个针对自有 endpoint 的无害请求循环运行，然后停止 privacy path。工作负载必须失败，而不是切换到物理接口。检查两个地址族和 DNS：
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
- DHCP 续租；
- captive-portal 状态变化；
- provider 重新连接或 key 过期。

对于 Linux namespace/container，停止其 tunnel，并验证它没有其他默认路由或 resolver：
```bash
ip netns exec privacy-workload ip route
ip netns exec privacy-workload ip -6 route
ip netns exec privacy-workload resolvectl status
```
名称和命令会因部署而异。不要在没有控制台恢复能力的情况下，将它们粘贴到远程生产主机中。

### 6. 检查本地套接字和数据包

在获得授权后，检查实际进行通信的进程/接口：
```bash
ss -tpn
ss -upn
sudo tcpdump -ni any 'host TEST_SERVER_IP'
```
将 `TEST_SERVER_IP` 替换为明确的自有地址；避免大范围捕获无关用户的数据。物理接口应能看到 tunnel/bridge peer，而明文 destination traffic 只能存在于预期的 layer。

## Tor 和 onion-service 测试

1. 在 Tor Browser 中访问 Tor Project 的连接检查页面，并确认正在使用 Tor。不要将此视为身份证明。<sup>[[1]](#references)</sup>
2. 使用唯一的 canary 访问自有的 HTTPS endpoint，并确认它看到的是 Tor exit、没有识别性 cookies，且处于标准浏览器上下文中。
3. 选择 **New Identity**，使用不同的 canary 再次访问，并验证本地状态已按预期清除。Exit IP 变化并不保证，也不是 New Identity 的目的。
4. 对于 onion service，只能通过 Tor Browser 访问。使用已授权的外部扫描确认 service host 没有 public listener，并确认 application 响应中不包含 public hostname/IP。
5. 检查 origin 的 outbound DNS/HTTP、templates、error pages、email/webhooks 和 third-party assets。任何 direct fetch 都可能暴露 origin 或 operator account。
6. 如果启用了 client authorization，确认未提供凭据的干净 Tor Browser 无法连接，而提供凭据的浏览器可以连接。
7. 轮换测试 authorization key，并确认被撤销的 client 失去访问权限，同时 onion identity 不发生变化。

## 浏览器隔离测试

创建一个受控页面，只记录测试所需的字段，并设置较短的 retention period。比较个人 compartment 和隐私 compartment 中的：

- cookies/local storage/service workers 和 cache；
- browser sync/login state；
- language、time zone、screen/window dimensions 和 fonts；
- WebRTC/network candidates；
- permissions 以及 extension-visible modifications；
- server 端的 TLS/HTTP user-agent data。

不要试图让 Tor Browser 变得“更加随机”。通过条件是与其标准 anonymity set 相似，并且不存在个人 state，而不是与个人浏览器产生最大差异。

测试 copy/paste、drag/drop、下载文件的打开、password-manager suggestions 和 identity-provider buttons。这些经常是 compartment 之间的桥梁。

## 操作系统隔离测试

### Tails

1. 在没有 Persistent Storage 的 session 中，以一个无害文件/canary 开始。
2. 完全关机、重新启动，并确认该文件已消失。
3. 仅启用一个必需的 persistence category，重复测试，并确认无关的 browser/application state 没有被保留。
4. 验证 portal login 后无法使用 Unsafe Browser 进行敏感活动，并确认 Tor applications 能正常重新连接。

### Whonix/Qubes

1. 停止 Gateway/net qube，并证明 Workstation/app qube 无法访问 IPv4、IPv6 或 DNS。
2. 仅尝试明确配置的 inter-qube clipboard/file path，并确认其他 shared-folder/device paths 不存在。
3. 在 disposable qube 中打开一个无害的测试文档，关闭该 qube，并确认其 state 已消失。
4. 检查 vault qube 没有 NetVM，并且无法通过 template/default change 获取 NetVM。
5. 对测试 VM 执行 snapshot/restore，并检查 identity-bearing state 是否意外恢复。

## 通信 metadata 测试

针对每个选定的 messenger：

1. 在受控设备上创建仅用于测试的 participants。
2. 记录注册所需的信息：phone、app-store account、IP、push service、username 或 invitation。
3. 发送一条无害消息，同时检查 notification previews、linked desktops、wearables 和 backups。
4. 通过独立路径验证 safety/security codes。
5. 一次只禁用 receipts/push，或启用 Tor/local transports，并观察 reliability/metadata 的变化。
6. 导出或恢复测试 backup，并准确记录其中包含哪些 profile、contacts 和 history。
7. 丢失/撤销一台测试设备，并确认其余 participants 看到预期的 key/device change。

不要通过联系无关人员或生成 abusive traffic 来进行测试。

## 文件清理测试

1. 在加密的 evidence storage 中对原始文件进行 hash 并保留：
```bash
sha256sum ./original/file > ./original/file.sha256
```
2. 使用 [Privacy-Preserving Communications and Sharing](privacy-preserving-communications-and-sharing.md) 中针对格式的流程创建清理后的副本。  
3. 比较元数据清单：
```bash
exiftool -a -u -g1 ./original/file
exiftool -a -u -g1 ./clean/file
```
4. 在 disposable context 中渲染/打开副本。检查隐藏内容、附件、链接、表单、图层、缩略图和视觉标识符。
5. 仅在 staged copy 中搜索已知的 canary 作者/邮箱/路径字符串。
6. 对最终输出进行 hash，并由第二人验证实际发布的确切文件。

ExifTool 输出中不存在相关信息，并不能证明匿名性；格式内部信息、像素、文字内容和分发记录仍然存在。

## Payment privacy test

使用获准的最小金额，或官方 test network/sandbox：

1. 写明 payer、payee/merchant、issuer/exchange、network/node、public ledger 和 accountant/controller 各自预期能够看到的内容。
2. 创建唯一的测试 invoice/merchant context，不使用虚假身份。
3. 支付一次，然后收集**你自己的**收据、账单、merchant dashboard、wallet/node log，以及适用时的 public-chain view。
4. 检查金额、时间戳、地址/token、账户、IP/设备、交付和退款路径是否与 observer table 相符。
5. 对于 Bitcoin，在 wallet 的 coin-control view 中检查地址复用、所选 inputs、找零以及后续 consolidation。
6. 对于 shielded protocols，验证实际的 pool/path 以及 viewing key 能够揭示的内容；不要从 wallet branding 推断隐私性。
7. 对于 e-cash/Taler，使用小额测试 backup/recovery、退款和 redemption；记录 mint/exchange/federation 边界记录。
8. 撤销 virtual card/test credential，并确认后续授权失败，同时确保合法退款处理仍然清晰。
9. 对账并加密保存所需的税务/授权证据。

绝不要将循环转账、拆分阈值、虚假购买或可疑退款作为“隐私测试”。

## Authorized red-team accountability drill

在演练前，执行 tabletop 和 technical drill：

1. Operator 从每条获准的 source path 启动一个 benign canary。
2. 如果 intended blind testing，目标 SOC 记录其检测到的内容，但不接收 operator 身份。
3. Exercise controller 根据 escrowed map 和 signed job record，将 source → engagement → operator 进行对应。
4. Controller 发送 emergency stop；operator 和 infrastructure owner 在 ROE 规定的时间内演示关闭操作。
5. Provider abuse 获得正确的 24/7 联系方式和授权引用。
6. 证据能够显示 target、时间、tool/job 和 operator，同时不保留不必要的 payload 内容。
7. 第二名 operator 验证 credential revocation 和 resource teardown。

如果 SOC 能够轻易看到个人/家庭 infrastructure，**或** controller 无法快速确定并停止 source，则 readiness review 不通过。

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

- [1] [Tor Project — 连接检查](https://check.torproject.org/)
- [2] [WireGuard — 路由和网络命名空间](https://www.wireguard.com/netns/)
- [3] [ExifTool — FAQ 和 metadata 指南](https://exiftool.org/faq.html)
- [4] [NIST SP 800-115 — 信息安全测试与评估技术指南](https://csrc.nist.gov/pubs/sp/800/115/final)
