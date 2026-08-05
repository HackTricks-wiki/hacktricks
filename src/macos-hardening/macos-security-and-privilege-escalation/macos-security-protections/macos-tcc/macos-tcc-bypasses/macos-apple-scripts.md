# Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

É uma linguagem de script usada para automatizar tarefas **interagindo com processos remotos**. Ela torna bastante fácil **solicitar que outros processos executem algumas ações**. **Malware** pode abusar desses recursos para explorar funções exportadas por outros processos.\
Por exemplo, um malware poderia **injetar código JS arbitrário em páginas abertas no navegador**. Ou **clicar automaticamente** em algumas permissões de autorização solicitadas ao usuário;<sup>[[3]](#references)</sup>.
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Aqui estão alguns exemplos: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Encontre mais informações sobre malware usando AppleScripts [**aqui**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

### Particularidades de Automation / TCC

As aprovações de Apple Events são **direcionais**: o prompt é para um par **processo de origem -> processo de destino**. Depois que o usuário clica em **Allow**, solicitações futuras da mesma origem para o mesmo destino são permitidas até que a entrada seja redefinida. Durante os testes, conceder `Terminal -> Finder` ou `Terminal -> System Events` uma vez é suficiente para reutilizar a permissão posteriormente sem outro popup.<sup>[[1]](#references)</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Isso é especialmente relevante quando o **alvo** é o **Finder**, porque o Finder sempre tem **Full Disk Access**, mesmo que não apareça na UI do FDA. Portanto, qualquer host que já tenha Automation sobre o Finder pode ser usado como um proxy AppleScript/JXA para acessar arquivos protegidos pelo TCC.<sup>[[1]](#references)</sup> Os payloads genéricos do Finder e do System Events já estão documentados [na página principal do TCC](../README.md) e [na página do Apple Events](../macos-apple-events.md).

### Tradecraft ofensivo moderno

`/usr/bin/osascript` é apenas o ponto de entrada mais visível. AppleScript e JXA também podem ser executados a partir de **binários Mach-O** por meio de **`NSAppleScript`** / **`OSAScript`**, o que é útil tanto para evasão quanto para operar dentro de um host que já tenha grants de TCC interessantes.<sup>[[2]](#references)</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Se você criar um helper personalizado que envie Apple Events diretamente, fornecer a ele uma **identidade real de app** torna os testes e as operações muito mais confiáveis. Na prática, isso significa incorporar um `Info.plist` com `CFBundleIdentifier` e `NSAppleEventsUsageDescription`, assinar o binário e conceder o entitlement `com.apple.security.automation.apple-events`. Caso contrário, o prompt do Apple Events frequentemente é atribuído ao **host pai** (por exemplo, `Terminal`) ou a execução do `NSAppleScript` simplesmente falha com erros confusos `-1750` / `errOSASystemError`.<sup>[[2]](#references)</sup>

Os Apple scripts podem ser facilmente "**compilados**". Essas versões podem ser facilmente "**descompiladas**" com `osadecompile`

No entanto, esses scripts também podem ser **exportados como "Somente leitura"** (por meio da opção "Exportar..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
e, neste caso, o conteúdo não pode ser decompilado nem mesmo com `osadecompile`

No entanto, ainda existem algumas ferramentas que podem ser usadas para entender esse tipo de executável; [**leia esta pesquisa para obter mais informações**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)).<sup>[[4]](#references)</sup> A ferramenta [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler), juntamente com [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile), será muito útil para entender como o script funciona.

## Referências

- [1] [Contornando as proteções de privacidade do usuário do macOS TCC por acidente e por design](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [Fazendo o AppleScript funcionar em ferramentas CLI do macOS: as partes não documentadas](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [Como agentes ofensivos usam AppleScript para atacar o macOS](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Aventuras na engenharia reversa de AppleScripts maliciosos Run-Only](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)

{{#include ../../../../../banners/hacktricks-training.md}}
