# Electron 自动更新信任边界

{{#include ../../banners/hacktricks-training.md}}

## Electron 自动更新攻击面

将更新器视为远程代码执行边界：它会获取可执行内容、判断该内容是否更新且可信、将其暂存到本地，并交给安装程序。审查完整的信任图——发布索引、各版本元数据、制品、分离签名、内嵌验证密钥、缓存、临时路径和安装程序，而不只是最终的 `.app` 是否已签名。<sup>[[1]](#references)[[2]](#references)</sup>

### 高价值测试

- **回滚/重放：**重放以前有效的清单及其仍然带有有效签名的制品。签名可以验证其输入，但不能保证新鲜度；除非经过身份验证的恢复策略明确授权回滚，否则客户端必须拒绝低于持久化单调下限的版本。<sup>[[2]](#references)</sup>
- **元数据/制品替换：**分别篡改版本、URL、预期哈希、制品和分离签名。还要尝试将某个发布版本的有效制品/签名组合与另一个版本的元数据混用。如果发布元数据未签名，TLS 或已签名的最终可执行文件无法阻止遭到入侵的源站/CDN 更改选择逻辑。<sup>[[1]](#references)[[2]](#references)</sup>
- **签名渠道混淆：**通过生产 feed 提供合法签名的 alpha、beta、开发版或调试版。跨环境复用同一密钥和策略，会使制品通过仅检查签名者的验证；生产环境身份/渠道必须纳入经过身份验证的策略，或使用单独的信任根。<sup>[[2]](#references)</sup>
- **临时文件 TOCTOU：**确定验证操作是否通过路径名打开文件，而安装操作之后是否会重新打开该路径名。如果本地攻击者能在这两个操作之间重命名、替换或重定向暂存对象，安装程序可能会使用从未经过验证的字节。权限为 `0700` 的暂存目录可以限制访问，但无法让这两个操作成为原子操作。<sup>[[2]](#references)</sup>

静态分析和运行时排查可以快速定位这些边界。<sup>[[1]](#references)[[2]](#references)</sup>

```bash
npx asar extract /path/to/app.asar /tmp/app-src
rg -n 'autoUpdater|electron-updater|setFeedURL|latest\.yml|allowInsecureTLS|downgrade' /tmp/app-src
rg -n 'sha(256|512)|ed25519|verify|signature|version|mkdtemp|chmod|rename' /tmp/app-src
sudo fs_usage -w -f filesystem "$PID" | rg -i 'update|latest|\.ya?ml|\.zip|\.dmg|tmp'
```

在授权测试期间，拦截更新检查，归档每个响应，并每次只修改一个字段。然后检查暂存目录的所有权/权限模式，并跟踪从下载到安装期间的文件打开操作。在 macOS 上，如果流程涉及特权 helper，请继续进行[安装程序信任边界测试](../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/macos-installers-abuse.md)，并审查[代码签名弱点](../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing-weaknesses-and-sandbox-escapes.md)，而不要将“已签名”视为完整的身份检查。<sup>[[2]](#references)</sup>

### 预期的绑定与策略

可靠的设计会同时验证选择元数据和制品字节。SafeUpdater 参考设计展示了嵌入式 Ed25519 公钥、已签名的清单和制品、由 `SHA-256(file)` 与版本派生的签名消息，以及存储在已签名元数据中的 SHA-512 制品摘要；它明确是研究参考，而非可用于生产的现成软件包。<sup>[[1]](#references)[[2]](#references)</sup>

验证目标是否还具备以下特性。<sup>[[1]](#references)[[2]](#references)</sup>

- 使用明确无歧义的签名表示，将制品摘要与其规范版本和发布环境绑定；
- 默认禁用降级，并对授权回滚强制执行最低可接受版本；
- 通过不同的密钥/渠道或经过身份验证的发布策略数据，将生产环境与非生产环境隔离；以及
- 安装已经验证过的打开文件（或等效的不可变句柄/对象），而不是再次解析同一路径。

## References

- [1] [Doyensec ElectronSafeUpdater 参考实现](https://github.com/doyensec/ElectronSafeUpdater)
- [2] [Electron SafeUpdater：设计安全的 Electron 自动更新机制](https://blog.doyensec.com/2026/02/16/electron-safe-updater.html)
{{#include ../../banners/hacktricks-training.md}}
