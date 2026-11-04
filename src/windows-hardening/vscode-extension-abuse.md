# VS Code Extension Drop-Share Üzerinden Çalıştırma

{{#include ../banners/hacktricks-training.md}}

VS Code extensions ve Visual Studio VSSDK extensions, `.vsix` paketlemesini kullanır ancak manifestleri ve çalışma ortamları farklıdır. Yazılabilir bir SMB drop share, **yalnızca** başka bir kullanıcı veya deployment işi paketlerini VS Code'a yüklerse bir çalıştırma yoluna dönüşür. Ardından extension'ın `activate()` fonksiyonu, o kullanıcının ayrıcalıklarıyla extension host'ta çalışır. Bir `.vsix` dosyasını yalnızca bir share'e yazmak, dosyayı çalıştırmaz.<sup>[[1]](#references)[[2]](#references)</sup>

## Paketleme ve etkinleştirme iş akışı

Öncelikle paketi kullanacak VS Code sürümünü ve share'in gerçekten senkronize edildiğini veya yüklendiğini doğrulayın. Bir TypeScript extension oluşturun ve amaçlanan Node.js eylemini `activate()` içine yerleştirin. Kullanıcının bir komut seçmesini gerektirmeden çalışan `onStartupFinished` gibi bir activation event kullanın, ardından extension'ı derleyip paketleyin. `engines.vscode`, **çalışma zamanı uyumluluğu eşiğidir**; `@types/vscode` sürümünü hedef API sürümüyle eşleştirmek ise yükleme zamanı gereksinimi değil, derleme zamanı uyumluluk önlemidir.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

```bash
npx --package yo --package generator-code -- yo code
npm install --save-dev @types/vscode@^1.118.0
npm install -g @vscode/vsce
vsce package
code --install-extension ./example-0.0.1.vsix   # Test locally before delivery
```

VS Code 1.118 çalıştıran bir editör için ilgili `package.json` alanları şunlardır:<sup>[[1]](#references)[[2]](#references)</sup>

```json
{
  "activationEvents": ["onStartupFinished"],
  "engines": { "vscode": "^1.118.0" },
  "devDependencies": { "@types/vscode": "^1.118.0" }
}
```

Minimal bir `activate()` kontrolü, extension host üzerinden bir komut çalıştırıp çıktısını kaydedebilir. Test eylemini yalnızca paketin beklenen hesapta/oturumda etkinleştirildiğini doğruladıktan sonra değiştirin. `onStartupFinished` olayı başlangıçtan sonra çalışır; bu nedenle düzenleyici gerçekten açılana ve extension yüklenip etkinleştirilene kadar çalıştırıldığının kanıtı değildir.<sup>[[1]](#references)[[2]](#references)</sup>

```typescript
import { execFile } from 'node:child_process';
export function activate() {
  execFile('cmd.exe', ['/c', 'whoami'], (_err, stdout) => {
    console.log(stdout);
  });
}
export function deactivate() {}
```

Drop share üzerinde yazma erişimi olan bir saldırgan, test edilen paketi yükleyip paketi kullanan işin çalışmasını bekleyebilir. Checkpoint örneğinde bu yazma erişimini, hesabı geri yüklenen hesabın share erişimi sağlıyordu; düşük ayrıcalıklı başlangıç hesabı ise share'i yalnızca okuyabiliyordu. Bu iki ön koşulu birbirinden ayrı tutun. **Visual Studio** extensions için bu VS Code iş akışı yerine ayrı [Visual Studio VSIX extension abuse](visual-studio-vsix-extension-abuse.md) bölümünü kullanın.<sup>[[1]](#references)</sup>

## References

- [1] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
- [2] [VS Code - Etkinleştirme Olayları](https://code.visualstudio.com/api/references/activation-events)
- [3] [VS Code - Eklentileri Yayımlama](https://code.visualstudio.com/api/working-with-extensions/publishing-extension)
