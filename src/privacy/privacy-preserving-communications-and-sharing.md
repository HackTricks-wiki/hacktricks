# 隐私保护通信与共享

端到端加密可以保护内容，但不会自动隐藏账户、电话号码、联系人图谱、IP 地址、push token、通知预览、时间信息、文件元数据或接收方行为。应根据工具移除的元数据以及它引入的观察者来选择工具。

## 比较通信模型

| 工具/模型 | 有用特性 | 仍存在的观察者和限制 |
|---|---|---|
| Signal | 成熟的 E2EE；可通过用户名发起联系而无需共享号码；sealed sender 可减少服务元数据 | 注册需要电话号码；服务、push provider、联系人和端点仍会保留部分信息 |
| SimpleX | 没有全局用户标识符；每个联系人的队列；可选 Tor transport | relay 的时间信息/transport、push service、邀请和端点；生态系统较新且规模较小 |
| Briar | 直接同步；在线时使用 Tor；离线时使用 Bluetooth/Wi-Fi；没有中央消息存储 | 联系人和端点；本地无线电观察者；以 Android 为主；双方必须同时可用，或使用 Mailbox |
| OnionShare | 通过临时 onion service 直接传输文件/接收文件/聊天/建站；没有 storage provider | 发送方计算机就是该 service；获得链接的人可以尝试访问；时间信息和端点仍然存在 |
| `age` encrypted file | 独立于 transport 的简单接收方密钥加密 | transport 可看到发送方/接收方/时间/大小；文件名、archive 元数据和端点仍然存在 |
| 普通 email + TLS | 服务器之间的 channel encryption | 两个 mail provider 通常都能读取内容，并保留路由/账户元数据 |

## Signal：无需披露号码的私密联系

Signal usernames 可以在不向新联系人透露用户电话号码的情况下发起聊天，但注册仍然需要电话号码。<sup>[[1]](#references)</sup> Sealed sender 是渐进式的元数据保护，并不能抵抗所有 IP/时间关联分析。<sup>[[2]](#references)</sup>

### 工作流程

1. 从官方 app store/project 安装 Signal，并先更新 OS。
2. 使用你依法有权使用的号码进行注册。不要使用租用的 SMS activations、他人的号码，或使用虚假身份获取的 provider account。
3. 在 **Settings → Privacy → Phone Number** 中，根据 threat model 设置谁可以看到号码，以及谁可以通过号码找到该账户。
4. 创建 username 以便新联系人发现账户。通过已经认证的 channel 分享其完整 link/QR；username 可以更改，且不是 profile name。
5. 如果便利性不值得承担关联风险，请禁用 contact upload/permissions；在平台支持时手动添加联系人。
6. 打开联系人详情，在发送敏感内容前，通过第二 channel 或当面比较 safety number/QR。
7. 检查 linked devices、registration lock/PIN、notification previews、screen security、call relaying、disappearing-message defaults 和 backup 行为。
8. 发送一条非敏感测试消息并进行通话。检查双方的锁屏、桌面端、穿戴设备和 cloud-notification 痕迹。
9. 将 safety number 变化或意外的 linked device 视为需要调查的事件，而不是自动忽略的提醒。

不要将假名 profile photo、bio、group membership 或日程安排，与可识别身份的 Signal context 混用。

## SimpleX：没有全局标识符的每联系人连接

SimpleX 通过单向队列路由消息，不分配网络范围内的用户标识符。其自身 policy 仍记录了 transport sessions、临时 server data、push-notification 权衡以及端点责任。<sup>[[3]](#references)</sup>

### 工作流程

1. 从官方 project/store 下载受维护的 client，并验证 publisher。当身份不能混用时，使用专用 OS/app profile。
2. 创建一个**本地** profile，并使用特定于该 context 的 display name 和 image。没有 backup 就删除 app，可能会丢失 profile 和 connections。
3. 首次启动时，谨慎选择 notification mode。即时 mobile push 可能向 Apple/Google infrastructure 暴露额外元数据。
4. 为一个联系人创建一次性 invitation link。通过 authenticated channel 传输；任何获得有效 invitation 的人都可能尝试使用它。
5. 连接后，打开联系人详情，在当面或通过独立的已验证 channel 比较 security code。<sup>[[4]](#references)</sup>
6. 在支持时，为每个 group 使用 incognito per-group profile，而不是在无关群组之间重复使用同一个 profile。
7. 配置 client 支持的 Tor transport，使本地网络/server 无法看到 direct IP。更改后确认连接；不要强制使用不受支持的 system proxy。
8. 检查 delivery receipts、link previews、calls、automatic downloads 以及 database export/backup。每一项都会改变元数据或端点暴露情况。
9. 在不运行重复的 live profile state 的情况下，于备用隔离设备上测试恢复；该 project 警告并发副本可能破坏对话。

没有全局标识符，并不能阻止联系人通过内容、profile 重用、邀请传递、时间信息或社交图谱识别用户。

## Briar：直接且抗中断的消息传递

Briar 在设备之间直接同步：在线时通过 Tor，发生本地中断时通过 Bluetooth/Wi-Fi。官方 threat model 假设对短距离无线电只有有限的对抗性监控，因此本地无线并非不可见。<sup>[[5]](#references)</sup>

### 工作流程

1. 从官方 Briar distribution 安装并验证 package source。使用具有最新 security updates 的受支持 Android 设备。
2. 使用独特的 context nickname 和强密码创建本地账户。不存在 password-reset 路径；应测试 unlock secret 是否可以恢复。
3. 尽可能通过扫描彼此的 QR codes 当面添加联系人。这可以认证联系人，并避免通过可关联 channel 发送 link。
4. 在 connectivity settings 中只启用所需的 transport：Tor/Internet、Wi-Fi 和/或 Bluetooth。不需要时禁用本地无线电。
5. 对于异步传递，评估在专用且持续供电的设备上运行 Briar Mailbox；应像 message server 一样对其进行清点并实施物理保护。
6. 在 Internet 可用时发送一条无害测试消息，然后在得到设备所有者授权的位置禁用 Internet，测试计划中的中断路径。
7. 检查 Android backups、notification previews、screenshots 和 exported content。端点解锁或被 compromise 时，本地加密存储会暴露。
8. 移除丢失的联系人/设备；如果 physical custody 或 account password 被 compromise，则废弃整个 context。

## OnionShare：直接的临时传输

OnionShare 在发送方/接收方的计算机上运行 onion service；文件不会上传到 storage provider，且流量在 Tor 内部进行端到端加密。<sup>[[6]](#references)</sup> 完整的 onion URL 是一种 bearer capability，必须受到保护。

### GUI 文件共享工作流程

1. 从官方签名 distribution 安装 OnionShare，并在接收方安装 Tor Browser。
2. 将文件的**已清理副本**放入专用 staging directory。不要将 OnionShare 指向个人 home directory。
3. 打开 **Share Files**，只添加 staging 文件，保持 private key/access protection 启用；对于单个接收方，保持 **Stop sharing after files have been sent** 启用。
4. 开始共享，并通过已经认证的 E2EE channel 发送完整的 onion URL。不要将其粘贴到 email、issue trackers 或 public chats 中。
5. 接收方在 Tor Browser 中打开 URL，与发送方核对预期的 filenames/size，然后下载。
6. 当文件本身是 security boundary 时，双方比较预先约定或通过独立渠道发送的 SHA-256 digest，以验证完整性。
7. 确认 OnionShare 在下载后已停止；否则手动停止并关闭 application。
8. 根据 retention policy 删除 staging 副本，并检查 OnionShare history/log settings，确认没有意外泄露 filename。

### CLI 工作流程

官方 CLI 接受作为 positional arguments 提供的文件，并在默认的单次 share 完成后停止。在已安装官方 CLI/Tor 的主机上：
```bash
# Inspect the installed version and options first
onionshare-cli --help

# Share one sanitized file; stop after one hour even if unused
onionshare-cli --auto-stop-timer 3600 ./staging/report-clean.pdf
```
安全地传递最终的完整 URL。除非威胁模型明确要求暴露结果，否则不要添加 `--public`、`--no-autostop-sharing`、详细的文件名日志记录或持久化功能。<sup>[[7]](#references)</sup>

将收到的文档视为恶意内容。应在一次性 VM 或 Dangerzone-style 渲染器中打开，而不要在承载身份信息的主机上打开。

## 使用 `age` 独立加密文件

当存储/邮件提供商可能看到对象时，与传输方式无关的加密很有用。除非另行处理，否则它不会隐藏发送者、接收者、大小、时间信息或文件名。

### 接收者设置
```bash
# Creates a secret identity file; protect its permissions and backup
age-keygen -o recipient-identity.txt

# Derive a public recipient file safe to share
age-keygen -y recipient-identity.txt > recipient-public.txt
```
通过第二个渠道验证公开接收者字符串。然后发送者运行：
```bash
age -R recipient-public.txt -o package.tar.age package.tar
```
接收方解密到一个新路径：
```bash
age --decrypt -i recipient-identity.txt -o package-restored.tar package.tar.age
```
官方 CLI 警告称，`-o` 会覆盖现有输出，因此应使用新目录，并在移动文件前验证摘要/内容。<sup>[[8]](#references)</sup> 切勿将身份文件与密文一同发送。

## 可复现的文件清理流程

元数据清除取决于文件格式。当真实性、取证或保管链很重要时，请保留加密原件；在副本上进行操作。

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
这遵循 ExifTool 更安全的 JPEG 指导：盲目移除每个 tag 也可能会删除颜色信息。<sup>[[9]](#references)</sup> 然后目视检查像素，关注面部、反射、屏幕、地标以及独特的损坏/噪声模式。

### Office/PDF 工作流

1. 将可编辑的原始文件加密保存，并使其与发布环境隔离。
2. 在创作应用程序中移除评论、修订、更改记录、隐藏的幻灯片/工作表、嵌入文件、个人模板和文档属性。
3. 使用专用的干净配置导出新的 PDF；不要“打印”到 cloud printer。
4. 同时使用格式感知工具和一次性视觉渲染器进行检查：
```bash
exiftool -a -u -g1 ./clean/report.pdf
pdfinfo ./clean/report.pdf
```
5. 在渲染后的输出中搜索名称、路径、电子邮件地址和修订文本。Rasterization 可以移除 active structures，但会损害可访问性和搜索功能，并不会移除可见内容或写作风格。
6. 对最终 artifact 进行 Hash，并且仅通过 publication compartment 传输该副本。

## Privacy Pass：面向服务设计者的匿名授权

Privacy Pass 将 token 的 **issuance** 与 **redemption** 分离。origin 可以得知客户端持有由 issuer 批准的 token，而无需得知客户端具体的 issuance 交互。重复使用 token、唯一 metadata、时序或共谋都可能重新引入 linkability。<sup>[[10]](#references)</sup>

安全部署模式：

1. 定义 token 所证明的声明（例如 rate-limit eligibility），而不是隐藏的全局身份。
2. 使用标准化架构和 issuance protocols；不要从头实现 blind-signature cryptography。
3. 在所需属性要求的情况下，将 issuer/attester 与 origin 的管理分离。
4. 最小化 public/private token metadata，并确保 anonymity sets 足够大。
5. 在支持的情况下，在使用前 issue batches，使 issuance time 不会与 redemption time 轻易匹配。
6. 每个 token 仅 redeem 一次，验证 origin-bound challenge，并删除过期的 token state。
7. 防止 cookies、IP logging 和 application accounts 在不知不觉中破坏 token 的隐私属性。
8. 测试 issuer 和 origin 的 logs 是否能够通过 timing、metadata 或 unique errors 关联一次受控的 issuance 和 redemption event。

Privacy Pass 是一项 application feature，并不是用户可以附加到任意 account 上的功能。

## Communications verification checklist

- [ ] Contact/invitation/key 已经过独立 authentication。
- [ ] Phone number、username、profile、group 和 contact-upload exposure 已被了解。
- [ ] 已列出 direct IP、relay、Tor、push-provider 和 local-radio observers。
- [ ] 已测试 notification previews、wearables、linked desktops 和 backups。
- [ ] Files 已完成 sanitization，必要时已 encryption，并在 disposable context 中打开。
- [ ] Recovery 可以在不桥接无关 identities 的情况下运行。
- [ ] Logs、history 和 temporary share services 具有 shutdown/retention 规则。

## References

- [1] [Signal — 电话号码隐私和 Usernames](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [2] [Signal — Sealed Sender](https://signal.org/blog/sealed-sender/)
- [3] [SimpleX — Privacy Policy and Conditions of Use](https://simplex.chat/privacy/) and [Protocol design](https://simplex.chat/docs/simplex.html)
- [4] [SimpleX — Privacy and security guide](https://simplex.chat/docs/guide/privacy-security.html)
- [5] [Briar — 工作原理](https://briarproject.org/how-it-works/) and [Quick Start](https://briarproject.org/quick-start/)
- [6] [OnionShare — Security Design](https://docs.onionshare.org/2.6/en/security.html)
- [7] [OnionShare 2.6.3 — Advanced Usage and CLI](https://docs.onionshare.org/2.6.3/en/advanced.html)
- [8] [`age` — 官方 CLI 和 usage](https://github.com/FiloSottile/age)
- [9] [ExifTool FAQ — 安全移除 metadata](https://exiftool.org/faq.html#Q32)
- [10] [RFC 9576 — Privacy Pass Architecture](https://www.rfc-editor.org/rfc/rfc9576.html), [RFC 9577 — HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html), and [RFC 9578 — Issuance Protocols](https://www.rfc-editor.org/rfc/rfc9578.html)
