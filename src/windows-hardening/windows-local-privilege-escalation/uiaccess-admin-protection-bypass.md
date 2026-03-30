# Bypasses de Proteção de Administrador via UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Visão geral
- Windows AppInfo expõe `RAiLaunchAdminProcess` para spawn de processos UIAccess (destinados à acessibilidade). UIAccess contorna a maior parte do User Interface Privilege Isolation (UIPI) message filtering para que software de acessibilidade possa controlar UI de IL mais alto.
- Habilitar UIAccess diretamente requer `NtSetInformationToken(TokenUIAccess)` com **SeTcbPrivilege**, então chamadores com poucos privilégios dependem do serviço. O serviço realiza três verificações no binário alvo antes de setar UIAccess:
- O manifest embutido contém `uiAccess="true"`.
- Assinado por qualquer certificado confiável pela raiz Local Machine (sem requisito de EKU/Microsoft).
- Localizado em um caminho exclusivo de administrador no system drive (por exemplo, `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, excluindo subpaths específicos graváveis).
- `RAiLaunchAdminProcess` não apresenta nenhum prompt de consentimento para lançamentos UIAccess (caso contrário ferramentas de acessibilidade não poderiam controlar o prompt).

## Modelagem de token e níveis de integridade
- Se as checagens tiverem sucesso, AppInfo **copia o token do chamador**, habilita UIAccess e aumenta o Integrity Level (IL):
- Limited admin user (usuário está em Administrators mas executando filtrado) ➜ **High IL**.
- Non-admin user ➜ IL aumentado em **+16 levels** até um limite **High** (System IL nunca é atribuído).
- Se o token do chamador já possui UIAccess, o IL permanece inalterado.
- Truque “Ratchet”: um processo UIAccess pode desabilitar UIAccess em si mesmo, relançar via `RAiLaunchAdminProcess`, e ganhar outro incremento de +16 IL. Medium➜High leva 255 relançamentos (ruidoso, mas funciona).

## Por que UIAccess permite escapar da Proteção de Administrador
- UIAccess permite que um processo de IL inferior envie mensagens de janela para janelas de IL superior (contornando os filtros UIPI). Em **IL igual**, primitivas clássicas de UI como `SetWindowsHookEx` **permitem injeção de código/carregamento de DLL** em qualquer processo que possua uma janela (incluindo **message-only windows** usados pelo COM).
- A Proteção de Administrador lança o processo UIAccess sob a identidade do **usuário limitado** mas em **High IL**, silenciosamente. Uma vez que código arbitrário rode dentro desse processo UIAccess de High IL, o atacante pode injetar em outros processos de High IL no desktop (mesmo pertencentes a usuários diferentes), quebrando a separação pretendida.

## Primitiva HWND-para-handle de processo (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- No Windows 10 1803+ a API foi movida para Win32k (`NtUserGetWindowProcessHandle`) e pode abrir um handle de processo usando um `DesiredAccess` fornecido pelo chamador. O caminho no kernel usa `ObOpenObjectByPointer(..., KernelMode, ...)`, que contorna checagens normais de acesso em user-mode.
- Pré-condições na prática: a janela alvo deve estar no mesmo desktop, e checagens UIPI devem passar. Historicamente, um chamador com UIAccess podia contornar a falha UIPI e ainda obter um handle em kernel-mode (corrigido como CVE-2023-41772).
- Impacto: um handle de janela torna-se uma **capability** para obter um handle de processo poderoso (comummente `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`) que o chamador normalmente não poderia abrir. Isso habilita acesso cross-sandbox e pode quebrar limites de Protected Process / PPL se o alvo expuser qualquer janela (incluindo message-only windows).
- Fluxo prático de abuso: enumerar ou localizar HWNDs (por exemplo, `EnumWindows`/`FindWindowEx`), resolver o PID dono (`GetWindowThreadProcessId`), chamar `GetProcessHandleFromHwnd`, e então usar o handle retornado para primitivos de leitura/escrita de memória ou hijack de código.
- Com a correção: UIAccess não mais garante aberturas em kernel-mode quando há falha UIPI e direitos de acesso permitidos são restritos ao conjunto legado de hooks; Windows 11 24H2 adiciona checagens de proteção de processo e caminhos mais seguros com feature flags. Desabilitar UIPI system-wide (`EnforceUIPI=0`) enfraquece essas proteções.

## Fraquezas na validação de diretório seguro (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo resolve o path fornecido via `GetFinalPathNameByHandle` e então aplica **checagens de string allow/deny** contra raízes/exclusões hardcoded. Múltiplas classes de bypass derivam dessa validação simplista:
- **Directory named streams**: Diretórios excluídos graváveis (ex., `C:\Windows\tracing`) podem ser contornados com um named stream no próprio diretório, ex. `C:\Windows\tracing:file.exe`. As checagens de string veem `C:\Windows\` e não detectam o subpath excluído.
- **Arquivo/diretório gravável dentro de uma raiz permitida**: `CreateProcessAsUser` **não requer extensão `.exe`**. Sobregravar qualquer arquivo gravável sob uma raiz permitida com um payload executável funciona, ou copiar um EXE assinado com `uiAccess="true"` em qualquer subdiretório gravável (ex., restos de atualização como `Tasks_Migrated` quando presente) permite que ele passe na checagem de caminho seguro.
- **MSIX em `C:\Program Files\WindowsApps` (corrigido)**: Non-admins podiam instalar pacotes MSIX assinados que eram colocados em `WindowsApps`, que não estava excluído. Empacotar um binário UIAccess dentro do MSIX e então lançá-lo via `RAiLaunchAdminProcess` resultava em um processo UIAccess High-IL **sem prompt**. A Microsoft mitigou excluindo esse path; a capability `uiAccess` restrita do MSIX já requer instalação por admin.

## Fluxo de ataque (High IL sem prompt)
1. Obter/compilar um **signed UIAccess binary** (manifest `uiAccess="true"`).
2. Colocá-lo onde a allowlist do AppInfo o aceita (ou abusar de uma edge case de validação de path/artifato gravável conforme acima).
3. Chamar `RAiLaunchAdminProcess` para spawná-lo **silenciosamente** com UIAccess + IL elevado.
4. A partir desse foothold de High IL, direcionar outro processo de High IL no desktop usando **window hooks/DLL injection** ou outras primitivas same-IL para comprometer totalmente o contexto de admin.

## Enumerando caminhos candidatos graváveis
Execute o helper PowerShell para descobrir objetos graváveis/sobresgraváveis dentro de raízes nominalmente seguras do ponto de vista de um token escolhido:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Executar como Administrador para maior visibilidade; defina `-ProcessId` para um processo de baixo privilégio para espelhar o acesso desse token.
- Filtre manualmente para excluir subdiretórios conhecidos como não permitidos antes de usar candidatos com `RAiLaunchAdminProcess`.

## Relacionado

Propagação do registro de acessibilidade do Secure Desktop LPE (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## Referências
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
