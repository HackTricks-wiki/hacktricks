# Bypasses da Admin Protection via UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Overview
- Windows AppInfo expõe `RAiLaunchAdminProcess` para spawnar processos UIAccess (destinado à acessibilidade). UIAccess contorna a maioria dos filtros de User Interface Privilege Isolation (UIPI) para que software de acessibilidade possa controlar UI de IL mais alto.
- Habilitar UIAccess diretamente requer `NtSetInformationToken(TokenUIAccess)` com **SeTcbPrivilege**, então chamadores com poucos privilégios dependem do serviço. O serviço realiza três verificações no binário alvo antes de setar UIAccess:
- Embedded manifest contém `uiAccess="true"`.
- Assinado por qualquer certificado confiável pelo Local Machine root store (sem requisito de EKU/Microsoft).
- Localizado em um caminho somente para administradores no system drive (por exemplo, `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, excluindo subpaths específicos graváveis).
- `RAiLaunchAdminProcess` não apresenta prompt de consentimento para launches UIAccess (caso contrário as ferramentas de acessibilidade não poderiam controlar o prompt).

## Token shaping and integrity levels
- Se as verificações tiverem sucesso, AppInfo **copia o token do chamador**, habilita UIAccess, e aumenta o Integrity Level (IL):
- Limited admin user (user is in Administrators but running filtered) ➜ **High IL**.
- Non-admin user ➜ IL aumentado em **+16 levels** até um limite **High** (System IL nunca é atribuído).
- Se o token do chamador já tem UIAccess, o IL permanece inalterado.
- Truque “Ratchet”: um processo UIAccess pode desabilitar UIAccess em si mesmo, relançar via `RAiLaunchAdminProcess`, e ganhar outro incremento de +16 IL. Medium➜High leva 255 relaunches (barulhento, mas funciona).

## Why UIAccess enables an Admin Protection escape
- UIAccess permite que um processo de IL inferior envie mensagens de janela para janelas de IL superior (contornando filtros UIPI). Em **IL igual**, primitivos clássicos de UI como `SetWindowsHookEx` **permitem injeção de código/carregamento de DLL** em qualquer processo que possua uma janela (incluindo **message-only windows** usados por COM).
- Admin Protection lança o processo UIAccess sob a **identidade do usuário limitado** mas em **High IL**, silenciosamente. Uma vez que código arbitrário rode dentro desse processo UIAccess de High IL, o atacante pode injetar em outros processos High IL na área de trabalho (mesmo pertencentes a usuários diferentes), quebrando a separação pretendida.

## HWND-to-process handle primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- On Windows 10 1803+ a API foi movida para Win32k (`NtUserGetWindowProcessHandle`) e pode abrir um handle de processo usando um `DesiredAccess` fornecido pelo chamador. O caminho do kernel usa `ObOpenObjectByPointer(..., KernelMode, ...)`, que contorna checagens normais de acesso em user-mode.
- Pré-condições na prática: a janela alvo deve estar na mesma desktop, e as checagens UIPI devem passar. Historicamente, um chamador com UIAccess podia contornar a falha UIPI e ainda obter um handle em kernel-mode (corrigido como CVE-2023-41772).
- Impacto: um handle de janela torna-se uma **capability** para obter um handle de processo poderoso (comumente `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`) que o chamador normalmente não poderia abrir. Isso possibilita acesso cross-sandbox e pode quebrar limites de Protected Process / PPL se o alvo expuser qualquer janela (incluindo message-only windows).
- Fluxo prático de abuso: enumerar ou localizar HWNDs (ex.: `EnumWindows`/`FindWindowEx`), resolver o PID proprietário (`GetWindowThreadProcessId`), chamar `GetProcessHandleFromHwnd`, então usar o handle retornado para operações de leitura/gravação de memória ou primitivos de hijack de código.
- Com o patch: UIAccess não concede mais opens em kernel-mode quando UIPI falha e os direitos de acesso permitidos foram restringidos ao conjunto legado de hooks; Windows 11 24H2 adiciona checagens de proteção de processo e caminhos mais seguros ativados por feature flags. Desabilitar UIPI system-wide (`EnforceUIPI=0`) enfraquece essas proteções.

## Secure-directory validation weaknesses (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo resolve o caminho fornecido via `GetFinalPathNameByHandle` e então aplica **checagens de string allow/deny** contra roots/exclusões hardcoded. Múltiplas classes de bypass surgem dessa validação simplista:
- **Directory named streams**: Diretórios excluídos graváveis (ex.: `C:\Windows\tracing`) podem ser contornados com um named stream no próprio diretório, ex.: `C:\Windows\tracing:file.exe`. As checagens de string veem `C:\Windows\` e não detectam o subpath excluído.
- **Writable file/directory inside an allowed root**: `CreateProcessAsUser` não requer extensão `.exe`. Sobrescrever qualquer arquivo gravável sob um allowed root com um payload executável funciona, ou copiar um EXE assinado com `uiAccess="true"` em qualquer subdiretório gravável (ex.: leftovers de update tais como `Tasks_Migrated` quando presente) permite que passe a checagem de secure-path.
- **MSIX into `C:\Program Files\WindowsApps` (fixed)**: Non-admins podiam instalar pacotes MSIX assinados que acabavam em `WindowsApps`, que não estava excluído. Empacotar um binário UIAccess dentro do MSIX e então lançá-lo via `RAiLaunchAdminProcess` resultava em um processo UIAccess High-IL **sem prompt**. A Microsoft mitigou excluindo esse path; a capability MSIX restrita `uiAccess` já requer instalação admin.

## Attack workflow (High IL without a prompt)
1. Obtain/build a **signed UIAccess binary** (manifest `uiAccess="true"`).
2. Place it where AppInfo’s allowlist accepts it (or abuse a path-validation edge case/writable artifact as above).
3. Call `RAiLaunchAdminProcess` to spawn it **silently** with UIAccess + elevated IL.
4. From that High-IL foothold, target another High-IL process on the desktop using **window hooks/DLL injection** or other same-IL primitives to fully compromise the admin context.

## Enumerating candidate writable paths
Run the PowerShell helper to discover writable/overwritable objects inside nominally secure roots from the perspective of a chosen token:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Execute como Administrator para maior visibilidade; defina `-ProcessId` para um processo low-priv para espelhar o acesso desse token.
- Filtre manualmente para excluir subdiretórios conhecidos como proibidos antes de usar candidatos com `RAiLaunchAdminProcess`.

## Referências
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
