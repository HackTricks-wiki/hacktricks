# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

É uma linguagem de scripting usada para automação de tarefas **interagindo com processos remotos**. Ela torna bem fácil **pedir a outros processos que executem algumas ações**. **Malware** pode abusar desses recursos para abusar de funções exportadas por outros processos.\
Por exemplo, um malware poderia **injetar código JS arbitrário em páginas abertas no navegador**. Ou **clicar automaticamente** em alguns pedidos de permissões allow apresentados ao usuário;
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Aqui você tem alguns exemplos: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Encontre mais informações sobre malware usando applescripts [**aqui**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

### Automation / TCC quirks

As aprovações de Apple Events são **directional**: o prompt é para um par **source process -> target process**. Uma vez que o usuário clica em **Allow**, futuras requests do mesmo source para o mesmo target são permitidas até que a entry seja reset. Durante o testing, conceder `Terminal -> Finder` ou `Terminal -> System Events` uma vez é suficiente para reutilizar a permission depois sem outro popup.
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Isso é especialmente relevante quando o **target** é o **Finder**, porque o Finder sempre tem **Full Disk Access** mesmo que não apareça na interface de usuário da FDA. Portanto, qualquer host que já tenha Automation sobre o Finder pode ser usado como um proxy AppleScript/JXA para acessar arquivos protegidos pelo TCC. Os payloads genéricos do Finder e do System Events já estão documentados em [the main TCC page](../README.md) e em [the Apple Events page](../macos-apple-events.md).

### Modern offensive tradecraft

`/usr/bin/osascript` é apenas o ponto de entrada mais visível. AppleScript e JXA também podem ser executados a partir de **binários Mach-O** via **`NSAppleScript`** / **`OSAScript`**, o que é útil tanto para evasão quanto para permanecer dentro de um host que já tenha concessões TCC interessantes.
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Se você criar um helper personalizado que envia Apple Events diretamente, dar a ele uma **identidade real de app** torna os testes e as operações muito mais confiáveis. Na prática, isso significa incorporar um `Info.plist` com `CFBundleIdentifier` e `NSAppleEventsUsageDescription`, assinar o binário e conceder a entitlement `com.apple.security.automation.apple-events`. Caso contrário, o prompt de Apple Events frequentemente é atribuído ao **parent host** (por exemplo `Terminal`) ou a execução de `NSAppleScript` simplesmente falha com erros confusos `-1750` / `errOSASystemError`.

Apple scripts podem ser facilmente "**compiled**". Essas versões podem ser facilmente "**decompiled**" com `osadecompile`

No entanto, esses scripts também podem ser **exported as "Read only"** (via a opção "Export..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
e neste caso o conteúdo não pode ser decompilado mesmo com `osadecompile`

No entanto, ainda há algumas ferramentas que podem ser usadas para entender esse tipo de executáveis, [**leia esta pesquisa para mais info**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)). A ferramenta [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) com [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) será muito útil para entender como o script funciona.

## References

- [Bypassing macOS TCC User Privacy Protections by Accident and Design](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [Making AppleScript Work in macOS CLI Tools: The Undocumented Parts](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)

{{#include ../../../../../banners/hacktricks-training.md}}
