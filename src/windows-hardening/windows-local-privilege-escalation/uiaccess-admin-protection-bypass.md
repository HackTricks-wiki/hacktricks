# Bypasses de Proteção de Administrador via UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Visão geral
- Windows AppInfo expõe `RAiLaunchAdminProcess` para spawnar processos UIAccess (destinado a accessibility). UIAccess contorna a maioria dos filtros do User Interface Privilege Isolation (UIPI) de mensagens de interface para que software de accessibility possa controlar UI de IL superior.
- Habilitar UIAccess diretamente requer `NtSetInformationToken(TokenUIAccess)` com **SeTcbPrivilege**, então chamadores de baixo privilégio dependem do service. O service realiza três checagens no binário alvo antes de setar UIAccess:
- Embedded manifest contém `uiAccess="true"`.
- Assinado por qualquer certificado confiado pelo Local Machine root store (sem requisito de EKU/Microsoft).
- Localizado em um caminho somente para administradores no disco do sistema (por exemplo, `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, excluindo subpaths específicos graváveis).
- `RAiLaunchAdminProcess` não exibe prompt de consentimento para launches UIAccess (caso contrário tooling de accessibility não poderia controlar o prompt).

## Token shaping and integrity levels
- Se as checagens passam, AppInfo **copia o caller token**, habilita UIAccess, e aumenta o Integrity Level (IL):
- Limited admin user (user is in Administrators but running filtered) ➜ **High IL**.
- Non-admin user ➜ IL aumentado em **+16 levels** até um teto **High** (System IL nunca é atribuído).
- Se o caller token já tem UIAccess, o IL permanece inalterado.
- “Ratchet” trick: um processo UIAccess pode desabilitar UIAccess nele mesmo, relançar via `RAiLaunchAdminProcess`, e ganhar outro incremento de +16 IL. Medium➜High leva 255 relançamentos (barulhento, mas funciona).

## Por que UIAccess permite um escape do Admin Protection
- UIAccess permite que um processo de IL inferior envie mensagens de janela para janelas de IL superior (contornando filtros UIPI). Em **IL igual**, primitivas clássicas de UI como `SetWindowsHookEx` **permitem injeção de código/carregamento de DLL** em qualquer processo que possua uma janela (incluindo **message-only windows** usados pelo COM).
- Admin Protection lança o processo UIAccess sob a **identidade do usuário limitado** mas em **High IL**, silenciosamente. Uma vez que código arbitrário execute dentro desse processo UIAccess de High IL, o atacante pode injetar em outros processos de High IL no desktop (mesmo pertencentes a outros usuários), quebrando a separação pretendida.

## HWND-to-process handle primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- On Windows 10 1803+ the API moved into Win32k (`NtUserGetWindowProcessHandle`) and can open a process handle using a caller-supplied `DesiredAccess`. The kernel path uses `ObOpenObjectByPointer(..., KernelMode, ...)`, which bypasses normal user-mode access checks.
- Pré-condições na prática: a janela alvo deve estar no mesmo desktop, e checagens UIPI devem passar. Historicamente, um chamador com UIAccess podia contornar falha UIPI e ainda obter um handle em kernel-mode (corrigido como CVE-2023-41772).
- Impacto: um handle de janela torna-se uma **capability** para obter um handle de processo poderoso (comumente `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`) que o chamador normalmente não poderia abrir. Isso permite acesso cross-sandbox e pode quebrar fronteiras de Protected Process / PPL se o alvo expuser qualquer janela (incluindo message-only windows).
- Fluxo prático de abuso: enumerar ou localizar HWNDs (por exemplo, `EnumWindows`/`FindWindowEx`), resolver o PID dono (`GetWindowThreadProcessId`), chamar `GetProcessHandleFromHwnd`, então usar o handle retornado para leitura/escrita de memória ou primitivas de code-hijack.
- Com o fix: UIAccess não concede mais opens em kernel-mode quando há falha UIPI e os direitos de acesso permitidos são restritos ao conjunto legado de hooks; Windows 11 24H2 adiciona checagens de proteção de processo e caminhos mais seguros sob feature flags. Desabilitar UIPI no sistema inteiro (`EnforceUIPI=0`) enfraquece essas proteções.

## Fraquezas na validação de diretório seguro (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo resolve o path fornecido via `GetFinalPathNameByHandle` e então aplica **checagens de string allow/deny** contra roots/exclusões hardcoded. Múltiplas classes de bypass originam-se dessa validação simplista:
- **Directory named streams**: Diretórios excluídos graváveis (por exemplo, `C:\Windows\tracing`) podem ser contornados com um named stream no próprio diretório, ex. `C:\Windows\tracing:file.exe`. As checagens de string veem `C:\Windows\` e perdem a subpasta excluída.
- **Writable file/directory inside an allowed root**: `CreateProcessAsUser` não requer **extensão `.exe`**. Sobrescrever qualquer arquivo gravável sob uma raiz permitida com um payload executável funciona, ou copiar um EXE assinado com `uiAccess="true"` para qualquer subdiretório gravável (por exemplo, restos de atualização como `Tasks_Migrated` quando presente) permite que passe a checagem de secure-path.
- **MSIX into `C:\Program Files\WindowsApps` (fixed)**: Non-admins could install signed MSIX packages that landed in `WindowsApps`, which was not excluded. Packaging a UIAccess binary inside the MSIX then launching it via `RAiLaunchAdminProcess` yielded a **promptless High-IL UIAccess process**. Microsoft mitigated by excluding this path; the `uiAccess` restricted MSIX capability itself already requires admin install.

## Fluxo de ataque (High IL sem prompt)
1. Obter/construir um **signed UIAccess binary** (manifest `uiAccess="true"`).
2. Colocá-lo onde a allowlist do AppInfo o aceite (ou abusar de um edge case de validação de path/artifato gravável como acima).
3. Chamar `RAiLaunchAdminProcess` para spawná-lo **silenciosamente** com UIAccess + IL elevado.
4. A partir desse foothold de High IL, mirar outro processo High IL no desktop usando **window hooks/DLL injection** ou outras primitivas same-IL para comprometer completamente o contexto de admin.

## Enumerando caminhos candidatos graváveis
Execute o helper em PowerShell para descobrir objetos graváveis/sobrescrítiveis dentro de raízes nominalmente seguras do ponto de vista de um token escolhido:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Execute como Administrator para maior visibilidade; defina `-ProcessId` para um processo com privilégios baixos para espelhar o acesso desse token.
- Filtre manualmente para excluir subdiretórios conhecidos como não permitidos antes de usar candidatos com `RAiLaunchAdminProcess`.

## Referências
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
