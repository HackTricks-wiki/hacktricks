# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

É uma linguagem de script usada para automação de tarefas **interagindo com processos remotos**. Facilita bastante **pedir a outros processos que realizem algumas ações**. **Malware** pode abusar dessas funcionalidades para explorar funções exportadas por outros processos.\
Por exemplo, um malware poderia **injetar código JS arbitrário em páginas abertas no navegador**. Ou **clicar automaticamente** em algumas permissões solicitadas ao usuário;
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Aqui estão alguns exemplos: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Encontre mais informações sobre malware usando applescripts [**aqui**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

Os scripts Apple podem ser facilmente "**compilados**". Essas versões podem ser facilmente "**decompiladas**" com `osadecompile`

No entanto, esses scripts também podem ser **exportados como "Somente leitura"** (via a opção "Exportar..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
e, neste caso, o conteúdo não pode ser decompilado mesmo com `osadecompile`

No entanto, ainda existem algumas ferramentas que podem ser usadas para entender esse tipo de executáveis, [**leia esta pesquisa para mais informações**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)). A ferramenta [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) com [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) será muito útil para entender como o script funciona.

{{#include ../../../../../banners/hacktricks-training.md}}
