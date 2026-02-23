# Evasões da Admin Protection via UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Visão geral
- Windows AppInfo expõe `RAiLaunchAdminProcess` para iniciar processos UIAccess (destinados à acessibilidade). UIAccess contorna a maior parte da filtragem de mensagens do User Interface Privilege Isolation (UIPI) para que softwares de acessibilidade possam controlar UI de IL superior.
- Habilitar UIAccess diretamente requer `NtSetInformationToken(TokenUIAccess)` com **SeTcbPrivilege**, então chamadores de baixo privilégio dependem do serviço. O serviço executa três verificações no binário alvo antes de definir UIAccess:
  - Embedded manifest contém `uiAccess="true"`.
  - Assinado por qualquer certificado confiável pelo Local Machine root store (sem requisito de EKU/Microsoft).
  - Localizado em um caminho apenas para administradores no disco do sistema (por exemplo, `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, excluindo subcaminhos específicos graváveis).
- `RAiLaunchAdminProcess` não exibe prompt de consentimento para lançamentos com UIAccess (caso contrário ferramentas de acessibilidade não poderiam interagir com o prompt).

## Modelagem de token e níveis de integridade
- Se as verificações tiverem sucesso, AppInfo **copia o token do chamador**, habilita UIAccess e aumenta o Integrity Level (IL):
  - Limited admin user (user is in Administrators but running filtered) ➜ **High IL**.
  - Non-admin user ➜ IL aumenta em **+16 níveis** até um limite **High** (System IL nunca é atribuído).
- Se o token do chamador já tiver UIAccess, o IL permanece inalterado.
- Truque “Ratchet”: um processo UIAccess pode desabilitar UIAccess em si mesmo, relançar via `RAiLaunchAdminProcess` e obter outro incremento de +16 IL. Medium➜High exige 255 relançamentos (barulhento, mas funciona).

## Por que UIAccess permite escapar da Admin Protection
- UIAccess permite que um processo de IL mais baixo envie mensagens de janela para janelas de IL mais alto (contornando os filtros UIPI). Em **IL igual**, primitivas clássicas de UI como `SetWindowsHookEx` **permitem injeção de código/carregamento de DLL** em qualquer processo que possua uma janela (incluindo **message-only windows** usadas pelo COM).
- Admin Protection lança o processo UIAccess sob a **identidade do usuário limitado** mas em **High IL**, silenciosamente. Uma vez que código arbitrário execute dentro desse processo UIAccess de High-IL, o atacante pode injetar em outros processos de High-IL na área de trabalho (até mesmo pertencentes a usuários diferentes), quebrando a separação pretendida.

## Fraquezas na validação de diretório seguro (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo resolve o caminho fornecido via `GetFinalPathNameByHandle` e então aplica **checagens de string allow/deny** contra raízes/exclusões hardcoded. Múltiplas classes de bypass surgem dessa validação simplista:
- **Directory named streams**: Diretórios excluídos e graváveis (ex.: `C:\Windows\tracing`) podem ser contornados com um named stream no próprio diretório, ex.: `C:\Windows\tracing:file.exe`. As checagens de string veem `C:\Windows\` e não reconhecem o subcaminho excluído.
- **Arquivo/diretório gravável dentro de uma raiz permitida**: `CreateProcessAsUser` **não requer extensão `.exe`**. Sobrescrever qualquer arquivo gravável sob uma raiz permitida com um payload executável funciona, ou copiar um EXE assinado com `uiAccess="true"` em qualquer subdiretório gravável (ex.: restos de atualização como `Tasks_Migrated`, quando presentes) permite passar a checagem de caminho seguro.
- **MSIX em `C:\Program Files\WindowsApps` (corrigido)**: Não-admins podiam instalar pacotes MSIX assinados que iam para `WindowsApps`, que não estava excluído. Embalar um binário UIAccess dentro do MSIX e então lançá-lo via `RAiLaunchAdminProcess` gerava um processo UIAccess de High-IL sem prompt. A Microsoft mitigou excluindo esse caminho; a capability MSIX restrita `uiAccess` já exige instalação por admin.

## Fluxo de ataque (High IL sem prompt)
1. Obter/construir um **binário UIAccess assinado** (manifest `uiAccess="true"`).
2. Colocá-lo onde a allowlist do AppInfo o aceita (ou abusar de uma condição de validação de caminho/artifact gravável conforme acima).
3. Chamar `RAiLaunchAdminProcess` para spawn silencioso com UIAccess + IL elevado.
4. Dessa posição de High-IL, mirar outro processo de High-IL na área de trabalho usando **window hooks/DLL injection** ou outras primitivas de mesmo IL para comprometer completamente o contexto admin.

## Enumerando caminhos graváveis candidatos
Execute o helper em PowerShell para descobrir objetos graváveis/sobrescrevíveis dentro de raízes nominalmente seguras do ponto de vista de um token escolhido:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Execute como Administrador para maior visibilidade; defina `-ProcessId` para um processo low-priv para espelhar o acesso desse token.
- Filtre manualmente para excluir subdiretórios conhecidos como não permitidos antes de usar os candidatos com `RAiLaunchAdminProcess`.

## Referências
- [Contornando a Proteção do Administrador ao Abusar do UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
