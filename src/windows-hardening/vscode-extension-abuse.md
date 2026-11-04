# VS Code Extension Drop-Share Execution

{{#include ../banners/hacktricks-training.md}}

VS Code extensions and Visual Studio VSSDK extensions both use `.vsix` packaging, but they have different manifests and runtimes. A writable SMB drop share becomes an execution path **only if** another user or deployment job installs its packages into VS Code. The extension's `activate()` function then runs in the extension host with that user's privileges. Merely writing a `.vsix` to a share does not execute it.<sup>[[1]](#references)[[2]](#references)</sup>

## Package and activation workflow

First confirm the consuming VS Code version and that the share is actually synchronized or installed. Generate a TypeScript extension and put the intended Node.js action in `activate()`. Use an activation event that runs without a user-selected command, such as `onStartupFinished`, then compile and package the extension. `engines.vscode` is the **runtime compatibility gate**; matching `@types/vscode` to the target API version is a build-time compatibility measure, not an install-time requirement.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

```bash
npx --package yo --package generator-code -- yo code
npm install --save-dev @types/vscode@^1.118.0
npm install -g @vscode/vsce
vsce package
code --install-extension ./example-0.0.1.vsix   # Test locally before delivery
```

For an editor running VS Code 1.118, the relevant `package.json` fields are:<sup>[[1]](#references)[[2]](#references)</sup>

```json
{
  "activationEvents": ["onStartupFinished"],
  "engines": { "vscode": "^1.118.0" },
  "devDependencies": { "@types/vscode": "^1.118.0" }
}
```

A minimal `activate()` check can execute a command and log its output from the extension host. Replace the test action only after verifying the package is activated in the expected account/session. The `onStartupFinished` event runs after startup, so it is not evidence of execution until the editor actually starts and the extension is installed and enabled.<sup>[[1]](#references)[[2]](#references)</sup>

```typescript
import { execFile } from 'node:child_process';
export function activate() {
  execFile('cmd.exe', ['/c', 'whoami'], (_err, stdout) => {
    console.log(stdout);
  });
}
export function deactivate() {}
```

An attacker with write access to the drop share can upload the tested package and wait for the consuming job. In the Checkpoint example, the restored account's share access supplied that write; the low-privileged starting account could only read the share. Keep those two prerequisites distinct. For **Visual Studio** extensions, use the separate [Visual Studio VSIX extension abuse](visual-studio-vsix-extension-abuse.md) chapter rather than this VS Code workflow.<sup>[[1]](#references)</sup>

## References

- [1] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
- [2] [VS Code - Activation Events](https://code.visualstudio.com/api/references/activation-events)
- [3] [VS Code - Publishing Extensions](https://code.visualstudio.com/api/working-with-extensions/publishing-extension)
