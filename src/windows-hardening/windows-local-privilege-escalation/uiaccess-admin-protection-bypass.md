# Bypasses da Admin Protection via UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Visão geral
- O Windows AppInfo expõe `RAiLaunchAdminProcess` para iniciar processos UIAccess (destinados à acessibilidade). O UIAccess ignora a maior parte da filtragem de mensagens do User Interface Privilege Isolation (UIPI), permitindo que softwares de acessibilidade controlem interfaces com IL mais alto.
- Habilitar o UIAccess diretamente requer `NtSetInformationToken(TokenUIAccess)` com **SeTcbPrivilege**; por isso, callers com poucos privilégios dependem do serviço. O serviço executa três verificações no binário-alvo antes de definir o UIAccess:
- O manifest incorporado contém `uiAccess="true"`.
- Assinado por qualquer certificado confiável pelo repositório de raízes da Local Machine (sem requisito de EKU/Microsoft).
- Localizado em um path exclusivo para administradores na unidade do sistema (por exemplo, `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`), excluindo subpaths específicos graváveis.
- `RAiLaunchAdminProcess` não exibe prompt de consentimento para launches de UIAccess (caso contrário, as ferramentas de acessibilidade não poderiam controlar o prompt).<sup>[[1]](#references)</sup>

## Modelagem de tokens e níveis de integridade
- Se as verificações forem bem-sucedidas, o AppInfo **copia o token do caller**, habilita o UIAccess e aumenta o Integrity Level (IL):
- Usuário administrador limitado (o usuário está no grupo Administrators, mas executa com filtragem) ➜ **High IL**.
- Usuário não administrador ➜ IL aumentado em **+16 níveis**, até o limite **High** (System IL nunca é atribuído).
- Se o token do caller já tiver UIAccess, o IL permanece inalterado.
- Truque do “ratchet”: um processo UIAccess pode desabilitar o UIAccess em si mesmo, relançar via `RAiLaunchAdminProcess` e obter outro incremento de +16 IL. Medium➜High requer 255 relaunches (ruidoso, mas funciona).<sup>[[1]](#references)</sup>

## Por que o UIAccess permite escapar da Admin Protection
- O UIAccess permite que um processo com IL inferior envie mensagens de janela para janelas com IL superior (ignorando os filtros do UIPI). Com **IL igual**, primitivas clássicas de UI, como `SetWindowsHookEx`, **permitem injeção de código/carregamento de DLL** em qualquer processo que possua uma janela (incluindo **message-only windows** usadas pelo COM).
- A Admin Protection inicia o processo UIAccess com a identidade do usuário limitado, mas com **High IL**, silenciosamente. Depois que um código arbitrário é executado dentro desse processo UIAccess com High IL, o atacante pode injetar em outros processos com High IL na área de trabalho (mesmo pertencentes a usuários diferentes), quebrando a separação pretendida.<sup>[[1]](#references)</sup>

## Primitiva de handle de HWND para processo (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- No Windows 10 1803+, a API foi movida para o Win32k (`NtUserGetWindowProcessHandle`) e pode abrir um handle de processo usando um `DesiredAccess` fornecido pelo caller. O caminho do kernel usa `ObOpenObjectByPointer(..., KernelMode, ...)`, ignorando as verificações normais de acesso no user-mode.<sup>[[2]](#references)</sup>
- Pré-condições na prática: a janela-alvo deve estar na mesma área de trabalho, e as verificações do UIPI devem ser aprovadas. Historicamente, um caller com UIAccess podia ignorar a falha do UIPI e ainda obter um handle em kernel-mode (corrigido como CVE-2023-41772).
- Impacto: um handle de janela se torna uma **capability** para obter um handle de processo poderoso (comumente `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`) que o caller normalmente não conseguiria abrir. Isso permite acesso cross-sandbox e pode quebrar os limites de Protected Process / PPL se o alvo expuser qualquer janela (incluindo message-only windows).
- Fluxo prático de abuse: enumerar ou localizar HWNDs (por exemplo, `EnumWindows`/`FindWindowEx`), resolver o PID proprietário (`GetWindowThreadProcessId`), chamar `GetProcessHandleFromHwnd` e usar o handle retornado para primitivas de leitura/escrita de memória ou hijack de código.
- Comportamento após a correção: o UIAccess não concede mais aberturas em kernel-mode quando há falha do UIPI, e os direitos de acesso permitidos são restritos ao conjunto de hooks legado; o Windows 11 24H2 adiciona verificações de proteção de processos e paths mais seguros controlados por feature flags. Desabilitar o UIPI em todo o sistema (`EnforceUIPI=0`) enfraquece essas proteções.<sup>[[2]](#references)</sup>

## Fraquezas na validação de secure-directory (AppInfo `AiCheckSecureApplicationDirectory`)
O AppInfo resolve o path fornecido por meio de `GetFinalPathNameByHandle` e depois aplica **verificações de allow/deny baseadas em strings** contra roots/exclusions hardcoded. Várias classes de bypass resultam dessa validação simplista:
- **Named streams de diretórios**: diretórios graváveis excluídos (por exemplo, `C:\Windows\tracing`) podem ser contornados com um named stream no próprio diretório, como `C:\Windows\tracing:file.exe`. As verificações de string identificam `C:\Windows\` e não detectam o subpath excluído.
- **Arquivo/diretório gravável dentro de um root permitido**: `CreateProcessAsUser` **não exige uma extensão `.exe`**. Sobrescrever qualquer arquivo gravável dentro de um root permitido com um payload executável funciona; alternativamente, copiar um EXE assinado com `uiAccess="true"` para qualquer subdiretório gravável (por exemplo, sobras de updates como `Tasks_Migrated`, quando presentes) permite que ele passe pela verificação de secure-path.
- **MSIX em `C:\Program Files\WindowsApps` (corrigido)**: usuários não administradores podiam instalar pacotes MSIX assinados que eram colocados em `WindowsApps`, que não era excluído. Empacotar um binário UIAccess dentro do MSIX e então iniciá-lo via `RAiLaunchAdminProcess` produzia um **processo UIAccess com High-IL, sem prompt**. A Microsoft mitigou isso excluindo esse path; a própria capability restrita `uiAccess` do MSIX já exige instalação por um administrador.<sup>[[1]](#references)</sup>

## Workflow do ataque (High IL sem prompt)
1. Obter/construir um **binário UIAccess assinado** (manifest `uiAccess="true"`).
2. Colocá-lo onde a allowlist do AppInfo o aceite (ou abusar de um edge case de validação de path/artefato gravável, conforme descrito acima).
3. Chamar `RAiLaunchAdminProcess` para iniciá-lo **silenciosamente** com UIAccess + IL elevado.
4. A partir desse foothold com High-IL, atingir outro processo com High-IL na área de trabalho usando **hooks de janela/injeção de DLL** ou outras primitivas com o mesmo IL, comprometendo completamente o contexto do administrador.<sup>[[1]](#references)</sup>

## Enumerando paths graváveis candidatos
Execute o helper do PowerShell para descobrir objetos graváveis/sobrescrevíveis dentro de roots nominalmente seguros, a partir da perspectiva de um token escolhido:<sup>[[1]](#references)</sup>
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Execute como Administrador para obter maior visibilidade; defina `-ProcessId` como um processo com poucos privilégios para espelhar o acesso desse token.
- Faça a filtragem manualmente para excluir subdiretórios conhecidos como não permitidos antes de usar os candidatos com `RAiLaunchAdminProcess`.

## Relacionado

Secure Desktop accessibility registry propagation LPE (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## Referências

- [1] [Ignorando a Administrator Protection abusando de UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [Análise aprofundada de GetProcessHandleFromHwnd (GPHFH)](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
