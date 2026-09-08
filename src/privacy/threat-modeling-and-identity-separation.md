# 威胁建模与身份隔离

最常见的匿名失败原因不是密码学被破解，而是**关联**：某个标识符、时间模式、设备、账户、付款方式、文件或人的习惯，将两个原本应当保持分离的场景连接起来。

## 构建隐私威胁模型

EFF 的六问安全计划是一个很好的基础：必须保护什么、需要防范谁、失败的影响和可能性、可投入的精力，以及能够提供帮助的盟友。<sup>[[1]](#references)</sup> 使用一个小表格使其变得可执行：

| 资产/操作 | 观察者 | 可观测数据 | 关联路径 | 控制措施 | 残余风险 |
|---|---|---|---|---|---|
| 研究客户资料 | ISP | 目标地址/时间元数据 | 家庭订户记录 | Tor Browser | Tor 使用可见；端到端关联 |
| 假名账户 | 平台 | IP、浏览器、恢复数据 | 重复使用的手机/邮箱/照片 | 专用场景和别名 | 写作/社交图谱关联 |
| 在线购买 | 商户 | 账户、配送信息、tokenized card | 地址和账户历史 | Guest checkout、最少字段、virtual card | 发卡机构和承运商保留记录 |
| Red-team 流量 | 目标/客户 | 源 IP 和行为 | Provider/engagement 记录 | 专用的授权出口 | 在升级处理时有意保持可归因 |

每当位置、provider、设备、交互方或后果发生变化时，都应重新检查该表。

## 绘制可关联图

将每个身份视为一个独立节点。每个共享属性都添加一条边：

- email 或恢复地址；
- 手机号码或通讯录上传；
- 用户名、头像、照片、个人简介，或写作/代码风格；
- 密码、passkey-sync 账户或恢复问题；
- 设备、advertising ID、浏览器配置文件、cookies、字体或扩展；
- IP 地址、时区、语言、日程或同时在线状态；
- 银行卡、exchange 账户、钱包集群、配送地址或 loyalty program；
- 文档作者字段、EXIF 位置、打印机标记或 cloud-share 所有者；
- 同事、群组成员关系和社交图谱。

一条边并不一定会造成致命后果，但它会告诉你哪些观察者能够建立这种关联。EFF 特别警告，电话号码、电子邮件地址和重复使用的照片都可能将不同 profile 关联起来。<sup>[[2]](#references)</sup>

## 逐步创建隔离区

1. **命名场景并规定禁止建立的关联。** 示例：`client-red-2026`，禁止与个人邮箱、家庭浏览器配置文件、个人支付方式和无关客户产生关联。
2. **选择隔离边界。** 按强度递增依次为：独立浏览器配置文件 → 独立 OS 账户 → 独立 VM/qube → 专用设备。单独的标签页或 private window 不是安全边界。
3. **在该边界内创建全新的标识符。** 使用特定于该场景的 email/alias、用户名、password-manager vault 或 collection，以及 authentication keys。如果与 provider 的不可关联性很重要，不要添加个人恢复渠道。
4. **选择一种网络策略。** 决定该场景是否始终使用 client VPN、engagement VPS、trusted VPN 或 Tor。尽可能强制执行 fail-closed 路由。
5. **选择支付策略。** 支付方式必须符合观察者模型；virtual card 可能会对商户隐藏 PAN，但仍会向发卡机构表明客户身份。
6. **制定数据传输规则。** 优先采用范围狭窄且经过明确规划的传输。将剪贴板、共享文件夹、USB 设备、cloud sync、打印机和屏幕截图视为潜在桥梁。
7. **记录创建和拆除日期。** 明确哪些证据必须因合同/税务/合规要求而保留，以及哪些临时数据应当过期。
8. **使用前测试关联。** 检查账户设置、恢复字段、公开 profile、IP/DNS、浏览器状态、文件元数据和 provider dashboards。

{% hint style="warning" %}
如果某项服务或法律要求提供准确信息，不要编造身份信息。隐私隔离区的目标是数据最小化和分离，而不是身份欺诈或绕过客户尽职调查。
{% endhint %}

## 端点和账户基线

- 使用受支持的硬件，并及时安装 OS、浏览器、钱包和 firmware 更新。
- 启用设备加密并使用强设备密码。静态加密有助于保护丢失或被扣押的关机设备，但无法防止 malware 或已解锁的会话读取数据。<sup>[[3]](#references)</sup>
- 在 password manager 中使用唯一且随机生成的密码。
- 在威胁模型允许其恢复/同步模型的情况下，优先使用抗 phishing 的 authentication，例如 WebAuthn/passkeys 或硬件安全密钥。NIST 指出，手动输入的 OTP 不具备抗 phishing 能力，因为冒充者可以转发这些 OTP。<sup>[[4]](#references)</sup>
- 将恢复代码离线保存，并与端点分开。检查已同步的 passkey 账户是否会将本应保持分离的身份连接起来。
- 禁用不必要的位置、联系人、麦克风、摄像头、Bluetooth、advertising-ID 和后台权限。
- 不要将个人 cloud sync、浏览器同步、password-manager 账户或 app stores 混入高隔离场景。

## 浏览器隐私

Browser fingerprinting 使用可观测的配置、设备、环境和行为来识别或关联用户。清除 cookies 或更改 IP 地址并不能可靠地绕过它，而 W3C 认为通过广泛部署的方式在技术上完全消除它并不现实。<sup>[[5]](#references)</sup>

对于日常隐私：

1. 使用维护中的浏览器，并启用 HTTPS-only 模式和强 tracking protection。
2. 在支持的情况下阻止第三方 tracking 并 partition state。
3. 为真正独立的场景使用不同的浏览器配置文件。
4. 禁用不需要的权限，并按规定的时间表清除站点数据。
5. 在进行无关的敏感研究时，避免登录包含大量身份信息的账户。

对于 Web anonymity，请使用**标准配置的 Tor Browser**。不要让普通浏览器通过 Tor 进行 proxy：Tor Project 警告，普通浏览器可能通过 DNS/WebRTC、持久化状态、字体、插件和 fingerprint 差异发生 leak。<sup>[[6]](#references)</sup> 避免使用额外扩展、不常见的窗口大小、自定义字体，以及会使浏览器显得与众不同的偏好设置。<sup>[[7]](#references)</sup>

## 通信和元数据

元数据包括发送者、接收者、时间、位置和其他上下文，即使消息内容经过加密，这些信息仍可能存在。<sup>[[8]](#references)</sup>

- 在实际可行的情况下，优先使用服务器端元数据最少且采用开放协议/客户端的端到端加密工具。
- 使用独立渠道或当面方式验证敏感联系人。Signal safety numbers 就是为此验证而设计的。<sup>[[9]](#references)</sup>
- Signal usernames 可以在不共享电话号码的情况下发起联系，但注册时仍需要电话号码；应有意配置电话号码的可见性/可发现性。<sup>[[9]](#references)</sup>
- Disappearing messages 可以减少保留的副本，但接收者仍然可以拍照、复制、转发或归档内容。
- Email 通常会暴露路由元数据。即使是注重隐私的 provider，也无法在对方使用普通 email 的情况下让消息实现端到端加密，除非双方都使用兼容的 E2EE 方法。例如，Proton 的文档说明，向其他 provider 发送普通邮件时使用 TLS，且邮件内容仍可被接收方 provider 读取。<sup>[[10]](#references)</sup>
- 分开使用地址簿，不要将个人联系人上传到假名账户。

## 文件、照片和作者信息

Tails 警告称，照片可能包含相机和位置数据，办公文档可能包含作者和创建时间字段。<sup>[[11]](#references)</sup>

分享前：
```bash
# Inspect recursively; do not assume the extension tells the whole story
exiftool -a -u -g1 path/to/file

# Create a cleaned copy. Verify the copy before publishing.
exiftool -all= -o cleaned-file path/to/file
```
然后在隔离的查看器中重新打开清理后的副本，并检查：

- 文档属性、评论、修订记录、隐藏的工作表/幻灯片、缩略图和附件；
- EXIF/XMP/IPTC、GPS、时间戳、设备/软件名称和唯一 ID；
- 可见的反射、地标、屏幕内容、人声、面部和背景声音；
- 文件名、归档路径、cloud-share 所有者、签名证书和修订历史。

清理可能会损害证据或真实性。当保管链或后续验证很重要时，应保留加密的原件。Stylometry 和 coding style 也可能将内容与作者关联起来；移除 metadata 不会改变人的写作风格。

## 常见失败模式

- 通过“匿名”连接登录个人账户。
- 重复使用恢复电话号码、头像、用户名、公钥、wallet 或捐款地址。
- 在存在关联性的环境中同时操作两个身份。
- 通过个人 cloud clipboard 或共享文件夹复制文本/文件。
- 安装具有独特特征的 Tor Browser extensions，或更改大量默认设置。
- 在不了解记录了哪些数据、保存多长时间以及由哪些 subcontractors 记录的情况下，轻信“无日志”声明。
- 认为备用手机是匿名的，却让它与个人手机一起移动。EFF 指出，蜂窝网络位置和共同移动可能会关联这些设备。<sup>[[3]](#references)</sup>
- 将加密视为删除；endpoints 和接收方可能保留明文。

## 验证清单

- [ ] 该环境没有个人恢复地址、电话号码、sync 账户或重复使用的媒体，除非已明确接受相关风险。
- [ ] 预期的网络路径处于活动状态，并且会 fail closed。
- [ ] 浏览器/设备时区、locale、extensions 和权限与计划一致。
- [ ] compartment 中没有打开个人账户。
- [ ] 文件已检查并完成 sanitization；原件单独处理。
- [ ] 通过第二渠道对联系人进行身份验证。
- [ ] 已了解 provider 可见的 metadata 和保留期限。
- [ ] 已记录 teardown、证据保留和账户恢复流程。

## References

- [1] [EFF Surveillance Self-Defense — 你的安全计划](https://ssd.eff.org/module/your-security-plan)
- [2] [EFF Surveillance Self-Defense — 在社交网络上保护自己](https://ssd.eff.org/module/protecting-yourself-social-networks)
- [3] [EFF Surveillance Self-Defense — 参加抗议活动](https://ssd.eff.org/module/attending-protest)
- [4] [NIST SP 800-63B-4 — 身份验证和验证器管理](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [5] [W3C — 在 Web 规范中缓解浏览器指纹识别](https://www.w3.org/TR/fingerprinting-guidance/)
- [6] [Tor Project — 将 Tor 与其他浏览器结合使用](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [7] [Tor Project — Tor Browser 中的 Plugins 和 add-ons](https://support.torproject.org/tor-browser/features/plugins/)
- [8] [EFF Surveillance Self-Defense — 通信 Metadata 为什么重要](https://ssd.eff.org/module/why-metadata-matters)
- [9] [Signal — 电话号码隐私和用户名：深入探讨](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [10] [Proton — Proton Mail 中哪些内容经过加密？](https://proton.me/support/what-is-encrypted-within-protonmail)
- [11] [Tails — 警告：Tails 很安全，但不是魔法](https://tails.net/doc/about/warnings/index.en.html)
