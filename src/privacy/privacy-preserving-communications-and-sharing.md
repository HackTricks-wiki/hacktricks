# 隐私保护通信与共享

{{#include ../banners/hacktricks-training.md}}

端到端加密可以保护内容，但不会自动隐藏账户、电话号码、联系人图谱、IP 地址、push token、通知预览、时间信息、文件 metadata 或收件人行为。应根据工具能够移除的 metadata 以及它引入的观察者来选择工具。

## 比较通信模型

| 工具/模型 | 有用特性 | 仍存在的观察者与限制 |
|---|---|---|
| Signal | 成熟的 E2EE；usernames 可以在不共享电话号码的情况下发起联系；sealed sender 可减少服务 metadata | 注册需要电话号码；服务、push provider、联系人和 endpoints 仍会保留部分观察信息 |
| SimpleX | 没有全局用户标识符；每个联系人的队列；可选 Tor transport | Relay timing/transport、push service、invitations 和 endpoints；生态系统较新且规模较小 |
| Briar | 直接同步；在线时使用 Tor；离线时使用 Bluetooth/Wi-Fi；没有 central message store | 联系人和 endpoints；本地 radio observers；主要面向 Android；双方必须同时可用，或使用 Mailbox |
| OnionShare | 通过临时 onion service 直接传输文件/接收文件/聊天/网站；没有 storage provider | 发送方 computer 就是 service；持有 link 的人可以访问；timing 和 endpoints 仍会保留 |
| `age` encrypted file | 独立于 transport 的简单 recipient-key encryption | Transport 可看到 sender/recipient/timing/size；filenames/archive metadata 和 endpoints 仍会保留 |
| 普通 email + TLS | server-to-server channel encryption | 两个 mail providers 通常都可以读取内容，并保留 routing/account metadata |

## Signal：不披露号码的私密联系

Signal usernames 可以在不向新联系人披露用户电话号码的情况下开始聊天，但注册仍需要电话号码。<sup>[[1]](#references)</sup> Sealed sender 是渐进式 metadata 保护，并不能抵御所有 IP/timing correlation。<sup>[[2]](#references)</sup>

### 工作流程

1. 从官方 app store/project 安装 Signal，并先更新 OS。
2. 使用你依法有权使用的号码进行注册。不要使用租用的 SMS activations、他人的号码，或使用虚假身份获取的 provider account。
3. 在 **Settings → Privacy → Phone Number** 中，根据 threat model 设置谁可以查看号码，以及谁可以通过号码找到该账户。
4. 创建 username 以便新联系人发现账户。通过已经 authenticated 的 channel 分享其准确 link/QR；usernames 可以更改，并且不是 profile name。
5. 如果便利性不值得承担关联风险，请禁用 contact upload/permissions；在平台支持的情况下手动添加联系人。
6. 打开联系人详情，在发送敏感内容前，通过第二个 channel 或当面比较 safety number/QR。
7. 检查 linked devices、registration lock/PIN、notification previews、screen security、call relaying、disappearing-message defaults 和 backup behavior。
8. 发送一条非敏感测试消息并进行通话。检查双方 lock-screen、desktop、wearable 和 cloud-notification traces。
9. 将 safety number 发生变化或出现意外 linked device 视为需要调查的事件，而不是自动忽略的提醒。

不要将 pseudonymous profile photo、bio、group membership 或 schedule 与可识别身份的 Signal context 混用。

## SimpleX：不使用全局标识符的逐联系人连接

SimpleX 通过单向 queues 路由消息，不分配 network-wide user identifier。其自身 policy 仍记录了 transport sessions、temporary server data、push-notification tradeoffs 和 endpoint responsibility。<sup>[[3]](#references)</sup>

### 工作流程

1. 从官方 project/store 下载受维护的 client，并验证 publisher。当不同身份不得混用时，使用专用 OS/app profile。
2. 创建一个 **local** profile，使用与特定 context 对应的 display name 和 image。未进行 backup 就删除 app，可能会丢失 profile 和 connections。
3. 首次启动时，有意识地选择 notification mode。即时 mobile push 可能会向 Apple/Google infrastructure 暴露额外 metadata。
4. 为一个联系人创建一次性 invitation link。通过 authenticated channel 传输；任何获得有效 invitation 的人都可能尝试使用它。
5. 连接后，打开联系人详情，当面或通过独立的 verified channel 比较 security code。<sup>[[4]](#references)</sup>
6. 在支持的情况下，为每个 group 使用 incognito profile，而不是在不相关的 groups 之间重复使用同一个 profile。
7. 如果 local network/server 不应看到 direct IP，请配置 client 支持的 Tor transport。更改后确认连接；不要强制使用不受支持的 system proxy。
8. 检查 delivery receipts、link previews、calls、automatic downloads 和 database export/backup。每项设置都会改变 metadata 或 endpoint exposure。
9. 在备用的隔离设备上测试 recovery，但不要运行重复的 live profile state；该 project 警告称，并发副本可能干扰 conversations。

没有全局标识符，并不能阻止联系人通过内容、profile reuse、invitation delivery、timing 或 social graph 识别用户。

## Briar：直接且抗干扰的消息传递

Briar 在设备之间直接同步：在线时通过 Tor，发生本地中断时通过 Bluetooth/Wi-Fi。官方 threat model 假设对短距离 radio 只有有限的 adversarial monitoring，因此 local wireless 并非不可见。<sup>[[5]](#references)</sup>

### 工作流程

1. 从官方 Briar distribution 安装并验证 package source。使用具有最新 security updates 的受支持 Android 设备。
2. 使用独特的 context nickname 和强密码创建 local account。没有 password-reset path；测试 unlock secret 是否可以恢复。
3. 尽可能通过扫描彼此的 QR codes 当面添加联系人。这可以 authenticate 联系人，并避免通过可被关联的 channel 发送 link。
4. 在 connectivity settings 中仅启用所需的 transports：Tor/Internet、Wi-Fi 和/或 Bluetooth。不需要时禁用 local radios。
5. 对于 asynchronous delivery，评估在专用且持续供电的设备上运行 Briar Mailbox；应像 message server 一样对其进行 inventory 和物理保护。
6. 在 Internet 可用时发送一条无害测试消息，然后在经过所有者授权的地点禁用 Internet，测试计划中的 outage path。
7. 检查 Android backups、notification previews、screenshots 和 exported content。endpoint 解锁或遭到 compromise 时，本地 encrypted storage 会暴露。
8. 移除丢失的 contacts/devices；如果 physical custody 或 account password 遭到 compromise，则停用整个 context。

## OnionShare：直接临时传输

OnionShare 在发送方/接收方的 computer 上运行 onion service；文件不会上传到 storage provider，且 traffic 在 Tor 内部进行端到端加密。<sup>[[6]](#references)</sup> 完整 onion URL 是 bearer capability，必须受到保护。

### GUI 文件共享工作流程

1. 从官方签名 distribution 安装 OnionShare，并在接收方安装 Tor Browser。
2. 将文件的 **sanitized copies** 放入专用 staging directory。不要将 OnionShare 指向个人 home directory。
3. 打开 **Share Files**，仅添加 staged files，保持 private key/access protection 启用；对于单个接收者，保持 **Stop sharing after files have been sent** 启用。
4. 开始共享，并通过已经 authenticated 的 E2EE channel 发送完整 onion URL。不要将其粘贴到 email、issue trackers 或 public chats 中。
5. 接收方在 Tor Browser 中打开 URL，与发送方核对预期的 filenames/size，然后下载。
6. 当文件本身是 security boundary 时，双方比较预先约定或通过独立方式传送的 SHA-256 digest，以验证完整性。
7. 确认 OnionShare 在下载后已停止；否则手动停止并关闭 application。
8. 根据 retention policy 删除 staged copy，并检查 OnionShare history/log settings，防止意外披露 filename。

### CLI 工作流程

官方 CLI 接受作为 positional arguments 提供的文件，并在默认的单次 completed share 后停止。在安装了官方 CLI/Tor 的 host 上：
```bash
# Inspect the installed version and options first
onionshare-cli --help

# Share one sanitized file; stop after one hour even if unused
onionshare-cli --auto-stop-timer 3600 ./staging/report-clean.pdf
```
安全地传递最终的完整 URL。除非威胁模型明确要求暴露结果，否则不要添加 `--public`、`--no-autostop-sharing`、详细的文件名日志记录或持久化。<sup>[[7]](#references)</sup>

将接收到的文档视为恶意内容。应在一次性 VM/Dangerzone 风格的渲染器中打开它们，而不是在带有身份信息的主机上打开。

## 使用 `age` 独立加密文件

与传输方式无关的加密在存储/电子邮件提供商可能看到对象时非常有用。除非另行处理，否则它不会隐藏发送者、接收者、大小、时间信息或文件名。

### 接收者设置
```bash
# Creates a secret identity file; protect its permissions and backup
age-keygen -o recipient-identity.txt

# Derive a public recipient file safe to share
age-keygen -y recipient-identity.txt > recipient-public.txt
```
通过第二个渠道验证公开的接收方字符串。然后发送方运行：
```bash
age -R recipient-public.txt -o package.tar.age package.tar
```
接收方将其解密到一个新路径：
```bash
age --decrypt -i recipient-identity.txt -o package-restored.tar package.tar.age
```
官方 CLI 警告称，`-o` 会覆盖现有输出，因此请使用新目录，并在移动前验证摘要/内容。<sup>[[8]](#references)</sup> 切勿将身份文件与 ciphertext 一起发送。

## 可复现的文件清理流程

元数据清除取决于具体格式。当真实性、取证或证据保管链很重要时，请保留加密的原始文件；在副本上进行操作。

### JPEG 示例
```bash
mkdir -p ./clean

# Inventory embedded metadata
exiftool -a -u -g1 ./original/photo.jpg

# Write a new JPEG while retaining color-profile/color-space information
exiftool -all= --icc_profile:all -tagsfromfile @ -colorspacetags \
-o ./clean/photo.jpg ./original/photo.jpg

# Re-inspect the output
exiftool -a -u -g1 ./clean/photo.jpg
```
这遵循 ExifTool 更安全的 JPEG 指导：盲目移除每个标签也可能删除色彩信息。<sup>[[9]](#references)</sup> 然后目视检查像素中是否存在人脸、反射、屏幕、地标以及独特的损坏/噪声模式。

### Office/PDF 工作流

1. 将可编辑原件加密保存，并与发布环境隔离。
2. 在创作应用中移除评论、修订痕迹、隐藏的幻灯片/工作表、嵌入文件、个人模板和文档属性。
3. 使用专用的干净配置文件导出新的 PDF；不要“打印”到 cloud printer。
4. 同时使用格式感知工具和一次性视觉渲染器进行检查：
```bash
exiftool -a -u -g1 ./clean/report.pdf
pdfinfo ./clean/report.pdf
```
5. 在渲染后的输出中搜索名称、路径、电子邮件地址和修订文本。栅格化可以移除活动结构，但会损害可访问性和搜索功能，并不会移除可见内容或写作风格。
6. 对最终制品进行哈希处理，并且仅通过 publication compartment 传输该副本。

## Privacy Pass：面向服务设计者的匿名授权

Privacy Pass 将 token 的**签发**与**兑换**分离。origin 可以获知客户端持有 issuer 批准的 token，而无需获知客户端具体的签发交互。重复使用 token、唯一元数据、时间信息或串通可能重新引入可关联性。<sup>[[10]](#references)</sup>

安全部署模式：

1. 定义 token 所证明的声明（例如速率限制资格），而不是隐藏的全局身份。
2. 使用标准化架构和签发协议；不要从头实现盲签名密码学。
3. 在所需属性要求时，分离 issuer/attester 与 origin 的管理。
4. 最小化 public/private token 元数据，并确保匿名集合足够大。
5. 在支持的情况下于使用前签发批次 token，使签发时间不会与兑换时间轻易匹配。
6. 每个 token 仅兑换一次，验证 origin 绑定的 challenge，并删除过期的 token 状态。
7. 防止 cookies、IP logging 和应用程序账户悄然破坏 token 的隐私属性。
8. 测试 issuer 和 origin 的日志是否可以通过时间、元数据或唯一错误信息，将一次受控的签发事件与兑换事件关联起来。

Privacy Pass 是应用程序功能，不是用户可以附加到任意账户上的功能。

## 通信验证清单

- [ ] 联系人/邀请/密钥已独立完成身份验证。
- [ ] 已了解电话号码、用户名、个人资料、群组和联系人上传所造成的暴露。
- [ ] 已列出直接 IP、relay、Tor、push-provider 和 local-radio 观察者。
- [ ] 已测试通知预览、可穿戴设备、已关联的桌面设备和备份。
- [ ] 文件已完成清理，需要时已加密，并在 disposable context 中打开。
- [ ] 恢复流程可以在不连接无关身份的情况下运行。
- [ ] 日志、历史记录和临时共享服务都有关闭/保留规则。

## References

- [1] [Signal — 电话号码隐私和用户名](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [2] [Signal — Sealed Sender](https://signal.org/blog/sealed-sender/)
- [3] [SimpleX — 隐私政策和使用条件](https://simplex.chat/privacy/) and [Protocol design](https://simplex.chat/docs/simplex.html)
- [4] [SimpleX — 隐私和安全指南](https://simplex.chat/docs/guide/privacy-security.html)
- [5] [Briar — 工作原理](https://briarproject.org/how-it-works/) and [Quick Start](https://briarproject.org/quick-start/)
- [6] [OnionShare — 安全设计](https://docs.onionshare.org/2.6/en/security.html)
- [7] [OnionShare 2.6.3 — 高级用法和 CLI](https://docs.onionshare.org/2.6.3/en/advanced.html)
- [8] [`age` — 官方 CLI 和用法](https://github.com/FiloSottile/age)
- [9] [ExifTool FAQ — 安全移除元数据](https://exiftool.org/faq.html#Q32)
- [10] [RFC 9576 — Privacy Pass 架构](https://www.rfc-editor.org/rfc/rfc9576.html), [RFC 9577 — HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html), and [RFC 9578 — Issuance Protocols](https://www.rfc-editor.org/rfc/rfc9578.html)
{{#include ../banners/hacktricks-training.md}}
