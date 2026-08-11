# Apple Scripts do macOS

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

AppleScript é uma linguagem de automação que pode enviar Apple Events para aplicativos compatíveis com scripts. Com as permissões relevantes, um malware pode injetar JavaScript em uma aba de navegador compatível com scripts ou usar System Events/Accessibility para clicar em uma caixa de diálogo de permissão. Apple Events e Accessibility são serviços TCC distintos e geralmente exigem as respectivas aprovações do usuário.<sup>[[3]](#references)</sup>
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
O repositório `abbeycode/AppleScripts` contém exemplos de automação.<sup>[[7]](#references)</sup>\
Encontre mais informações sobre malware usando applescripts [**aqui**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).<sup>[[3]](#references)</sup>

### Automação / peculiaridades do TCC

As aprovações do Apple Events são **direcionais**: o aviso é para um par **processo de origem -> processo de destino**. Depois que o usuário clica em **Permitir**, solicitações futuras da mesma origem para o mesmo destino são permitidas até que a entrada seja redefinida. Durante os testes, conceder `Terminal -> Finder` ou `Terminal -> System Events` uma vez é suficiente para reutilizar a permissão posteriormente sem outro aviso.<sup>[[1]](#references)</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Isso é especialmente relevante quando o **alvo** é o **Finder**, porque o Finder sempre tem **Full Disk Access**, mesmo que não apareça na UI do FDA. Portanto, qualquer host que já tenha Automation sobre o Finder pode ser usado como um proxy AppleScript/JXA para acessar arquivos protegidos pelo TCC.<sup>[[1]](#references)</sup> Os payloads genéricos do Finder e do System Events já estão documentados [na página principal do TCC](../README.md) e [na página do Apple Events](../macos-apple-events.md).

### Práticas ofensivas modernas

`/usr/bin/osascript` é apenas o entry point mais visível. AppleScript e JXA também podem ser executados a partir de **binários Mach-O** via **`NSAppleScript`** / **`OSAScript`**, o que é útil tanto para evasão quanto para operar dentro de um host que já tenha grants interessantes do TCC.<sup>[[2]](#references)</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Se você criar um helper personalizado que envia Apple Events diretamente, fornecer a ele uma **identidade real de app** torna os testes e as operações muito mais confiáveis. Na prática, isso significa incluir um `Info.plist` com `CFBundleIdentifier` e `NSAppleEventsUsageDescription`, assinar o binário e conceder o entitlement `com.apple.security.automation.apple-events`. Caso contrário, o prompt do Apple Events frequentemente é atribuído ao **parent host** (por exemplo, `Terminal`) ou a execução de `NSAppleScript` simplesmente falha com erros confusos `-1750` / `errOSASystemError`.<sup>[[2]](#references)</sup>

AppleScripts podem ser salvos em formato compilado e normalmente descompilados com `osadecompile`.

No entanto, esses scripts também podem ser **exportados como "Somente leitura"** (por meio da opção "Exportar..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
Nesse caso, o `osadecompile` se recusa a recuperar o código-fonte normal, mas o bytecode e a terminologia de Apple Event ainda podem ser analisados.

A pesquisa da SentinelOne sobre run-only descreve como recuperar a estrutura apesar dessa restrição. `applescript-disassembler` e `aevt_decompile` ajudam a inspecionar o script compilado e os dados de Apple Event.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Contornando as Proteções de Privacidade do Usuário do macOS TCC por Acidente e por Design](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [Fazendo o AppleScript Funcionar em Ferramentas CLI do macOS: As Partes Não Documentadas](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [Como Atores Ofensivos Usam AppleScript para Atacar o macOS](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Aventuras na Engenharia Reversa de AppleScripts Maliciosos Run-Only](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)
- [5] [Jinmo/applescript-disassembler](https://github.com/Jinmo/applescript-disassembler)
- [6] [SentineLabs/aevt_decompile](https://github.com/SentineLabs/aevt_decompile)
- [7] [Exemplos de AppleScripts de abbeycode](https://github.com/abbeycode/AppleScripts)
{{#include ../../../../../banners/hacktricks-training.md}}
