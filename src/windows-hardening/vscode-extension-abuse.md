# Execução por meio de compartilhamento drop de extensão do VS Code

{{#include ../banners/hacktricks-training.md}}

As extensões do VS Code e as extensões do Visual Studio VSSDK usam o empacotamento `.vsix`, mas têm manifests e runtimes diferentes. Um compartilhamento SMB com permissão de gravação torna-se um caminho de execução **somente se** outro usuário ou job de implantação instalar seus pacotes no VS Code. A função `activate()` da extensão é então executada no host da extensão com os privilégios desse usuário. Apenas gravar um `.vsix` em um compartilhamento não o executa.<sup>[[1]](#references)[[2]](#references)</sup>

## Fluxo de empacotamento e ativação

Primeiro, confirme a versão do VS Code usada pelo consumidor e se o compartilhamento é realmente sincronizado ou instalado. Gere uma extensão TypeScript e coloque a ação Node.js desejada em `activate()`. Use um evento de ativação que seja executado sem um comando selecionado pelo usuário, como `onStartupFinished`, e então compile e empacote a extensão. `engines.vscode` é o **limite de compatibilidade do runtime**; compatibilizar `@types/vscode` com a versão da API de destino é uma medida de compatibilidade em tempo de build, não um requisito de instalação.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

```bash
npx --package yo --package generator-code -- yo code
npm install --save-dev @types/vscode@^1.118.0
npm install -g @vscode/vsce
vsce package
code --install-extension ./example-0.0.1.vsix   # Test locally before delivery
```

Para um editor que executa o VS Code 1.118, os campos relevantes de `package.json` são:<sup>[[1]](#references)[[2]](#references)</sup>

```json
{
  "activationEvents": ["onStartupFinished"],
  "engines": { "vscode": "^1.118.0" },
  "devDependencies": { "@types/vscode": "^1.118.0" }
}
```

Uma verificação mínima de `activate()` pode executar um comando e registrar sua saída no host da extensão. Substitua a ação de teste somente depois de verificar se o pacote foi ativado na conta/sessão esperada. O evento `onStartupFinished` é executado após a inicialização, portanto, não comprova a execução até que o editor seja realmente iniciado e a extensão esteja instalada e habilitada.<sup>[[1]](#references)[[2]](#references)</sup>

```typescript
import { execFile } from 'node:child_process';
export function activate() {
  execFile('cmd.exe', ['/c', 'whoami'], (_err, stdout) => {
    console.log(stdout);
  });
}
export function deactivate() {}
```

Um atacante com acesso de escrita ao compartilhamento de entrega pode carregar o pacote testado e aguardar o job que o consome. No exemplo do Checkpoint, o acesso ao compartilhamento da conta restaurada forneceu essa permissão de escrita; a conta inicial com poucos privilégios só podia ler o compartilhamento. Mantenha esses dois pré-requisitos distintos. Para extensões do **Visual Studio**, use o capítulo separado [Abuso de extensões VSIX do Visual Studio](visual-studio-vsix-extension-abuse.md), em vez deste fluxo de trabalho do VS Code.<sup>[[1]](#references)</sup>

## References

- [1] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
- [2] [VS Code - Eventos de ativação](https://code.visualstudio.com/api/references/activation-events)
- [3] [VS Code - Publicação de extensões](https://code.visualstudio.com/api/working-with-extensions/publishing-extension)
