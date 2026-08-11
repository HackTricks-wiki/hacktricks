# Bypasses da proteção de administradores via UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Visão geral
- O Windows AppInfo expõe o caminho interno `RAiLaunchAdminProcess`, usado para iniciar aplicações UIAccess destinadas à acessibilidade. UIAccess permite interações selecionadas através dos limites do User Interface Privilege Isolation (UIPI); não é um bypass geral de todos os limites de segurança de processos.<sup>[[1]](#references)[[3]](#references)</sup>
- Habilitar UIAccess diretamente exige `NtSetInformationToken(TokenUIAccess)` com **SeTcbPrivilege`; portanto, callers com poucos privilégios dependem do serviço. O serviço realiza três verificações no binário de destino antes de definir UIAccess:
- O manifesto incorporado contém `uiAccess="true"`.
- Assinado por qualquer certificado confiável pelo armazenamento de raízes do Local Machine (sem exigência de EKU/Microsoft).
- Localizado em um caminho que somente administradores podem gravar na unidade do sistema (por exemplo, `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`), excluindo subcaminhos graváveis específicos.
- `RAiLaunchAdminProcess` não exibe prompt de consentimento para inicializações UIAccess (caso contrário, ferramentas de acessibilidade não poderiam interagir com o prompt).<sup>[[1]](#references)</sup>

## Modelagem de token e níveis de integridade
- Se as verificações forem bem-sucedidas, o AppInfo **copia o token do caller**, habilita UIAccess e aumenta o Integrity Level (IL):
- Usuário administrador limitado (o usuário está no grupo Administrators, mas executa com filtragem) ➜ **High IL**.
- Usuário não administrador ➜ IL aumentado em **+16 níveis**, até o limite **High** (System IL nunca é atribuído).
- Se o token do caller já tiver UIAccess, o IL permanece inalterado.
- Truque de “Ratchet”: um processo UIAccess pode desabilitar UIAccess em si mesmo, ser reiniciado via `RAiLaunchAdminProcess` e obter outro incremento de +16 no IL. Medium➜High exige 255 relançamentos (barulhento, mas funciona).<sup>[[1]](#references)</sup>

## Por que UIAccess permite escapar da proteção de administradores
- UIAccess permite que um processo com IL inferior envie mensagens de janela para janelas com IL superior (contornando filtros do UIPI). Com **IL igual**, primitivas clássicas de UI, como `SetWindowsHookEx`, **permitem injeção de código/carregamento de DLL** em qualquer processo que possua uma janela (incluindo **message-only windows** usadas pelo COM).
- A proteção de administradores inicia o processo UIAccess com a identidade do **usuário limitado**, mas com **High IL**, silenciosamente. Quando um código arbitrário é executado dentro desse processo UIAccess com High IL, o atacante pode injetar código em outros processos com High IL na área de trabalho (mesmo pertencentes a usuários diferentes), quebrando a separação pretendida.<sup>[[1]](#references)</sup>

## Primitiva de handle de processo a partir de HWND (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- No Windows 10 1803+, a API foi movida para o Win32k (`NtUserGetWindowProcessHandle`) e pode abrir um handle de processo usando um `DesiredAccess` fornecido pelo caller. O caminho do kernel usa `ObOpenObjectByPointer(..., KernelMode, ...)`, que contorna as verificações normais de acesso no user-mode.<sup>[[2]](#references)</sup>
- Pré-condições na prática: a janela de destino deve estar na mesma área de trabalho, e as verificações do UIPI devem ser aprovadas. Historicamente, um caller com UIAccess podia contornar a falha do UIPI e ainda obter um handle em kernel-mode (corrigido como CVE-2023-41772).
- Impacto histórico: um handle de janela se tornava uma **capability** para acesso ao processo, como `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE` ou `PROCESS_VM_OPERATION`, que o caller normalmente não poderia obter. Antes das correções documentadas, isso podia atravessar limites de sandbox e de protected process quando um destino expunha uma janela, incluindo uma message-only window.<sup>[[2]](#references)</sup>
- Fluxo prático de abuso: enumerar ou localizar HWNDs (por exemplo, `EnumWindows`/`FindWindowEx`), resolver o PID proprietário (`GetWindowThreadProcessId`), chamar `GetProcessHandleFromHwnd` e usar o handle retornado para leitura/escrita de memória ou primitivas de code hijacking.
- Comportamento após a correção: UIAccess não concede mais aberturas em kernel-mode quando há falha do UIPI, e os direitos de acesso permitidos são restritos ao conjunto de hooks legado; o Windows 11 24H2 adiciona verificações de proteção de processos e caminhos mais seguros controlados por feature flags. Desabilitar o UIPI em todo o sistema (`EnforceUIPI=0`) enfraquece essas proteções.<sup>[[2]](#references)</sup>

## Fragilidades na validação de diretórios seguros (AppInfo `AiCheckSecureApplicationDirectory`)
O AppInfo resolve o caminho fornecido via `GetFinalPathNameByHandle` e então aplica **verificações de strings de permissão/bloqueio** contra raízes/exclusões hardcoded. Várias classes de bypass resultam dessa validação simplista:
- **Named streams de diretórios**: diretórios graváveis excluídos (por exemplo, `C:\Windows\tracing`) podem ser contornados com um named stream no próprio diretório, como `C:\Windows\tracing:file.exe`. As verificações de strings identificam `C:\Windows\` e não detectam o subcaminho excluído.
- **Arquivo/diretório gravável dentro de uma raiz permitida**: `CreateProcessAsUser` **não exige uma extensão `.exe`**. Sobrescrever qualquer arquivo gravável dentro de uma raiz permitida com um payload executável funciona; alternativamente, copiar um EXE assinado com `uiAccess="true"` para qualquer subdiretório gravável (por exemplo, sobras de atualizações como `Tasks_Migrated`, quando presentes) permite que ele passe pela verificação de caminho seguro.
- **MSIX em `C:\Program Files\WindowsApps` (corrigido)**: usuários não administradores podiam instalar pacotes MSIX assinados que eram colocados em `WindowsApps`, caminho que não era excluído. Empacotar um binário UIAccess dentro do MSIX e iniciá-lo via `RAiLaunchAdminProcess` produzia um **processo UIAccess com High IL, sem prompt**. A Microsoft mitigou isso excluindo esse caminho; a própria capability restrita `uiAccess` do MSIX já exige instalação por um administrador.<sup>[[1]](#references)</sup>

## Fluxo do ataque (High IL sem prompt)
1. Obtenha/construa um **binário UIAccess assinado** (manifesto `uiAccess="true"`). Para uma avaliação realista, teste com material de confiança e caminhos explicitamente autorizados para o lab; não adicione um certificado do atacante ao armazenamento de raízes do Local Machine de uma máquina de produção.
2. Coloque-o onde a allowlist do AppInfo o aceite (ou abuse de uma edge case de validação de caminho/artefato gravável, conforme descrito acima).
3. Chame `RAiLaunchAdminProcess` para iniciá-lo **silenciosamente** com UIAccess + IL elevado.
4. A partir desse foothold com High IL, atinja outro processo com High IL na área de trabalho usando **hooks de janela/injeção de DLL** ou outras primitivas de mesmo IL para comprometer totalmente o contexto do administrador.<sup>[[1]](#references)</sup>

## Enumerando caminhos graváveis candidatos
Execute o helper do PowerShell para descobrir objetos graváveis/sobrescrevíveis dentro de raízes nominalmente seguras a partir da perspectiva de um token escolhido:<sup>[[1]](#references)</sup>
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Execute como Administrador para obter maior visibilidade; defina `-ProcessId` como um processo com poucos privilégios para espelhar o acesso desse token.
- Filtre manualmente para excluir subdiretórios sabidamente proibidos antes de usar os candidatos com `RAiLaunchAdminProcess`.

## Relacionados

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## References

- [1] [Contornando a proteção do Administrador abusando de UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [Análise aprofundada de GetProcessHandleFromHwnd (GPHFH)](https://projectzero.google/2026/02/gphfh-deep-dive.html)
- [3] [Microsoft Learn — aplicações UIAccess](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works#uiaccess-applications)
{{#include ../../banners/hacktricks-training.md}}
