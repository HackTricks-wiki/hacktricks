# 威胁建模与身份隔离

{{#include ../banners/hacktricks-training.md}}

最常见的匿名失败原因不是密码学遭到破坏，而是**关联**：某个标识符、时间模式、设备、账户、支付方式、文件或人的习惯，将原本应该保持分离的两个上下文连接起来。

## 构建隐私威胁模型

EFF 的六问安全计划是一个很好的基础：必须保护什么、要防范谁、失败的影响和可能性、可投入的精力，以及可以提供帮助的盟友。<sup>[[1]](#references)</sup> 通过一个小表格将其落实为可执行方案：

| 资产/操作 | 观察者 | 可观察数据 | 关联路径 | 控制措施 | 残余风险 |
|---|---|---|---|---|---|
| 研究客户信息 | ISP | 目标地址/时间元数据 | 家庭订户记录 | Tor Browser | Tor 使用可见；端到端关联 |
| 假名账户 | 平台 | IP、浏览器、恢复数据 | 重复使用的手机/邮箱/照片 | 专用上下文和别名 | 写作/社交图谱关联 |
| 在线购买 | 商家 | 账户、配送、tokenized card | 地址和账户历史 | Guest checkout、最少字段、virtual card | Issuer 和 carrier 保留记录 |
| Red-team 流量 | 目标/客户 | 源 IP 和行为 | Provider/engagement 记录 | 专用授权出口 | 在升级处理时有意保持可归因 |

每当位置、provider、设备、对方或后果发生变化时，都应重新审查该表格。

## 绘制可关联性图

将每个身份视为一个独立节点。为每个共享属性添加一条边：

- 电子邮箱或恢复地址；
- 电话号码或通讯录上传；
- 用户名、头像、照片、个人简介，或写作/代码风格；
- 密码、passkey-sync 账户，或恢复问题；
- 设备、广告 ID、浏览器配置文件、cookies、字体或扩展；
- IP 地址、时区、语言、日程或同时在线状态；
- 银行卡、exchange 账户、wallet cluster、配送地址或 loyalty program；
- 文档作者字段、EXIF 位置、打印机标记或 cloud-share 所有者；
- 同事、群组成员身份和社交图谱。

一条边并不一定会造成致命后果，但它会告诉你哪些观察者能够建立这种关联。EFF 特别警告，电话号码、电子邮件地址和重复使用的照片可能会将多个资料关联起来。<sup>[[2]](#references)</sup>

## 逐步创建隔离区

1. **命名上下文并规定禁止的关联。** 示例：`client-red-2026`，禁止与个人邮箱、家庭浏览器配置文件、个人支付方式及无关客户关联。
2. **选择隔离边界。** 按强度递增依次为：独立浏览器配置文件 → 独立 OS 账户 → 独立 VM/qube → 专用设备。单独的标签页或隐私窗口不是安全边界。
3. **在该边界内创建全新的标识符。** 使用上下文专用的电子邮箱/别名、用户名、密码管理器 vault 或 collection，以及 authentication keys。如果与 provider 的不可关联性很重要，不要添加个人恢复渠道。
4. **选择一项网络策略。** 决定该上下文是否始终使用 client VPN、engagement VPS、trusted VPN 或 Tor。尽可能执行 fail-closed routing。
5. **选择支付策略。** 支付方式必须符合观察者模型；virtual card 可能会向商家隐藏 PAN，但仍会向 issuer 识别客户身份。
6. **制定数据传输规则。** 优先进行范围狭窄且有意为之的传输。将剪贴板、共享文件夹、USB 设备、cloud sync、打印机和截图视为可能的桥梁。
7. **记录创建和拆除日期。** 明确哪些证据必须因合同/税务/合规要求而保留，以及哪些临时数据应当过期。
8. **使用前测试关联。** 检查账户设置、恢复字段、公开资料、IP/DNS、浏览器状态、文件元数据和 provider 控制面板。

{% hint style="warning" %}
如果某项服务或法律要求准确身份识别，不要编造身份信息。隐私隔离区的目的在于数据最小化和分离，而不是身份欺诈或绕过客户尽职调查。
{% endhint %}

## Endpoint 和账户基线

- 使用受支持的硬件，并及时安装 OS、浏览器、wallet 和 firmware 更新。
- 启用设备加密，并使用强设备密码。静态加密有助于保护丢失或被扣押的关机设备，但当 malware 或已解锁的会话可以读取数据时则无能为力。<sup>[[3]](#references)</sup>
- 在密码管理器中使用唯一且随机生成的密码。
- 在威胁模型允许其恢复/同步模式的情况下，优先使用 WebAuthn/passkeys 或硬件安全密钥等抗 phishing authentication。NIST 指出，手动输入的 OTP 不具备抗 phishing 能力，因为冒充者可以转发这些 OTP。<sup>[[4]](#references)</sup>
- 将恢复代码离线保存，并与 endpoint 分离。检查已同步的 passkey 账户是否会将本应保持分离的身份关联起来。
- 禁用不必要的位置、联系人、麦克风、摄像头、Bluetooth、广告 ID 和后台权限。
- 不要将个人 cloud sync、浏览器同步、密码管理器账户或 app store 混入高隔离上下文。

## 浏览器隐私

浏览器 fingerprinting 利用可观察的配置、设备、环境和行为来识别用户或建立用户关联。清除 cookies 或更改 IP 地址并不能可靠地抵御这种技术，而 W3C 认为，通过广泛部署的手段在技术上完全消除它并不现实。<sup>[[5]](#references)</sup>

对于普通隐私：

1. 使用受维护的浏览器，并启用 HTTPS-only 模式和强 tracking protection。
2. 阻止第三方跟踪，并在支持的情况下 partition state。
3. 为真正独立的上下文使用不同的浏览器配置文件。
4. 禁用不需要的权限，并按既定计划清除站点数据。
5. 进行无关的敏感研究时，避免登录身份信息丰富的账户。

对于 Web 匿名，使用**标准配置的 Tor Browser**。不要将普通浏览器通过 Tor 代理：Tor Project 警告，普通浏览器可能通过 DNS/WebRTC、持久化状态、字体、插件和 fingerprint 差异发生 leak。<sup>[[6]](#references)</sup> 避免使用额外扩展、异常窗口大小、自定义字体，以及会使浏览器显得与众不同的偏好设置。<sup>[[7]](#references)</sup>

## 通信和元数据

元数据包括发送者、接收者、时间、位置及其他上下文，即使消息内容已加密也仍然存在。<sup>[[8]](#references)</sup>

- 在实际可行的情况下，优先使用服务器端元数据最少且采用开放协议/客户端的端到端加密工具。
- 使用独立渠道或当面方式验证敏感联系人。Signal safety numbers 就是为此类检查而设计的。<sup>[[9]](#references)</sup>
- Signal usernames 可以在不共享电话号码的情况下发起联系，但注册时仍然需要电话号码；应有意配置电话号码的可见性/可发现性。<sup>[[9]](#references)</sup>
- Disappearing messages 可以减少保留的副本；但接收者仍然可以拍照、复制、转发或归档内容。
- 电子邮件通常会暴露路由元数据。即使是注重隐私的 provider，在对方使用普通电子邮件时，也无法让消息实现端到端加密，除非双方使用兼容的 E2EE 方法。例如，Proton 说明，向其他 provider 发送的普通邮件使用 TLS，并且对接收 provider 仍然可读。<sup>[[10]](#references)</sup>
- 分离地址簿，不要将个人联系人上传到假名账户。

## 文件、照片和作者身份

Tails 警告，照片可能包含相机和位置数据，办公文档可能包含作者和创建时间字段。<sup>[[11]](#references)</sup>

分享前：
```bash
# Inspect recursively; do not assume the extension tells the whole story
exiftool -a -u -g1 path/to/file

# Create a cleaned copy. Verify the copy before publishing.
exiftool -all= -o cleaned-file path/to/file
```
然后在隔离的 viewer 中重新打开已清理的副本，并检查：

- document properties、comments、tracked changes、hidden sheets/slides、thumbnails 和 attachments；
- EXIF/XMP/IPTC、GPS、timestamps、device/software names 和 unique IDs；
- 可见的 reflections、landmarks、screen contents、voices、faces 和 background sounds；
- filename、archive paths、cloud-share owner、signing certificate 和 revision history。

Sanitization 可能损害证据或真实性。当 chain of custody 或后续 verification 很重要时，请保留加密的原件。Stylometry 和 coding style 也可能将内容与作者关联起来；metadata removal 不会改变 human style。

## 常见失败模式

- 通过“anonymous”连接登录 personal account。
- 重复使用 recovery phone、avatar、username、public key、wallet 或 donation address。
- 在存在相关性的 contexts 中同时操作两个 identities。
- 通过 personal cloud clipboard 或 shared folder 复制文本/文件。
- 安装具有明显特征的 Tor Browser extensions 或更改许多默认设置。
- 在不了解记录了什么、保存多久以及由哪些 subcontractors 记录的情况下，盲目信任“no logs”声明。
- 认为 secondary phone 是 anonymous，却让它与 personal phone 一同移动。EFF 指出，cellular location 和 co-travel 可能使这些 devices 产生关联。<sup>[[3]](#references)</sup>
- 将 encryption 视为 deletion；endpoints 和 recipients 可能保留 plaintext。

## Verification checklist

- [ ] 该 context 没有 personal recovery address、phone、sync account 或 reused media，除非已明确接受这些关联。
- [ ] 预期的 network path 处于 active 状态，并且能够 fail closed。
- [ ] Browser/device time zone、locale、extensions 和 permissions 与计划一致。
- [ ] Compartment 中没有打开 personal accounts。
- [ ] Files 已检查并完成 sanitization；originals 单独处理。
- [ ] Contacts 已通过第二 channel 进行 authentication。
- [ ] 已了解 provider-visible metadata 和 retention period。
- [ ] Teardown、evidence retention 和 account-recovery procedures 已记录。

## References

- [1] [EFF Surveillance Self-Defense — 你的安全计划](https://ssd.eff.org/module/your-security-plan)
- [2] [EFF Surveillance Self-Defense — 保护你在社交网络上的安全](https://ssd.eff.org/module/protecting-yourself-social-networks)
- [3] [EFF Surveillance Self-Defense — 参加抗议活动](https://ssd.eff.org/module/attending-protest)
- [4] [NIST SP 800-63B-4 — Authentication 和 Authenticator Management](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [5] [W3C — 在 Web Specifications 中 Mitigating Browser Fingerprinting](https://www.w3.org/TR/fingerprinting-guidance/)
- [6] [Tor Project — 将 Tor 与其他 browsers 配合使用](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [7] [Tor Project — Tor Browser 中的 Plugins 和 add-ons](https://support.torproject.org/tor-browser/features/plugins/)
- [8] [EFF Surveillance Self-Defense — 为什么 Communication Metadata 很重要](https://ssd.eff.org/module/why-metadata-matters)
- [9] [Signal — Phone Number Privacy 和 Usernames：深入探讨](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [10] [Proton — Proton Mail 中哪些内容经过 encrypted？](https://proton.me/support/what-is-encrypted-within-protonmail)
- [11] [Tails — Warnings：Tails 安全，但并非 magic](https://tails.net/doc/about/warnings/index.en.html)
{{#include ../banners/hacktricks-training.md}}
