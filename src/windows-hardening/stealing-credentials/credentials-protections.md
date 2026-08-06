# Proteções de Credenciais do Windows

{{#include ../../banners/hacktricks-training.md}}

## WDigest

O protocolo [WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>), introduzido com o Windows XP, foi projetado para autenticação via protocolo HTTP e é **habilitado por padrão no Windows XP até o Windows 8.0 e no Windows Server 2003 até o Windows Server 2012**. Essa configuração padrão resulta no **armazenamento de senhas em texto simples no LSASS** (Local Security Authority Subsystem Service). Um atacante pode usar o Mimikatz para **extrair essas credenciais** executando:<sup>[[8]](#references)</sup>
```bash
sekurlsa::wdigest
```
Para **desativar ou ativar este recurso**, as chaves de registro _**UseLogonCredential**_ e _**Negotiate**_ em _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ devem ser definidas como "1". Se essas chaves estiverem **ausentes ou definidas como "0"**, o WDigest estará **desabilitado**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## Proteção LSA (processos protegidos por PP e PPL)

**Protected Process (PP)** e **Protected Process Light (PPL)** são **proteções em nível de kernel do Windows** projetadas para impedir o acesso não autorizado a processos sensíveis, como o **LSASS**. Introduzido no **Windows Vista**, o **modelo PP** foi originalmente criado para a aplicação de **DRM** e permitia que apenas binários assinados com um **certificado de mídia especial** fossem protegidos. Um processo marcado como **PP** só pode ser acessado por outros processos que também sejam **PP** e tenham um **nível de proteção igual ou superior** e, mesmo assim, **apenas com direitos de acesso limitados**, salvo quando permitido especificamente.

O **PPL**, introduzido no **Windows 8.1**, é uma versão mais flexível do PP. Ele permite **casos de uso mais amplos** (por exemplo, LSASS e Defender) ao introduzir **"níveis de proteção"** baseados no campo **EKU (Enhanced Key Usage)** da **assinatura digital**. O nível de proteção é armazenado no campo `EPROCESS.Protection`, que é uma estrutura `PS_PROTECTION` com:
- **Type** (`Protected` ou `ProtectedLight`)
- **Signer** (por exemplo, `WinTcb`, `Lsa`, `Antimalware`, etc.)

Essa estrutura é compactada em um único byte e determina **quem pode acessar quem**:
- **Valores de signer mais altos podem acessar valores mais baixos**
- **PPLs não podem acessar PPs**
- **Processos não protegidos não podem acessar nenhum PPL/PP**

### O que você precisa saber sob uma perspectiva ofensiva

- Quando o **LSASS é executado como PPL**, as tentativas de abri-lo usando `OpenProcess(PROCESS_VM_READ | QUERY_INFORMATION)` a partir de um contexto administrativo normal **falham com `0x5 (Access Denied)`**, mesmo que `SeDebugPrivilege` esteja habilitado.
- Você pode **verificar o nível de proteção do LSASS** usando ferramentas como o Process Hacker ou programaticamente, lendo o valor `EPROCESS.Protection`.
- O LSASS normalmente terá `PsProtectedSignerLsa-Light` (`0x41`), que só pode ser acessado por processos assinados com um signer de nível superior, como `WinTcb` (`0x61` ou `0x62`).
- O PPL é uma **restrição somente do Userland**; código em **nível de kernel pode ignorá-la completamente**.
- O fato de o LSASS ser PPL **não impede o credential dumping se você puder executar shellcode no kernel** ou **usar um processo altamente privilegiado com o acesso adequado**.
- **Definir ou remover o PPL** exige uma reinicialização ou configurações de **Secure Boot/UEFI**, que podem manter a configuração do PPL mesmo depois que as alterações no registro forem revertidas.

### Criar um processo PPL na inicialização (API documentada)

O Windows fornece uma forma documentada de solicitar um nível Protected Process Light para um processo filho durante a criação, usando a lista de atributos de inicialização estendida. Isso não ignora os requisitos de assinatura — a imagem de destino deve estar assinada para a classe de signer solicitada.

Fluxo mínimo em C/C++:
```c
// Request a PPL protection level for the child process at creation time
// Requires Windows 8.1+ and a properly signed image for the selected level
#include <windows.h>

int wmain(int argc, wchar_t **argv) {
STARTUPINFOEXW si = {0};
PROCESS_INFORMATION pi = {0};
si.StartupInfo.cb = sizeof(si);

SIZE_T attrSize = 0;
InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrSize);
if (!si.lpAttributeList) return 1;

if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attrSize)) return 1;

DWORD level = PROTECTION_LEVEL_ANTIMALWARE_LIGHT; // or WINDOWS_LIGHT/LSA_LIGHT/WINTCB_LIGHT
if (!UpdateProcThreadAttribute(
si.lpAttributeList, 0,
PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL,
&level, sizeof(level), NULL, NULL)) {
return 1;
}

DWORD flags = EXTENDED_STARTUPINFO_PRESENT;
if (!CreateProcessW(L"C\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE,
flags, NULL, NULL, &si.StartupInfo, &pi)) {
// If the image isn't signed appropriately for the requested level,
// CreateProcess will fail with ERROR_INVALID_IMAGE_HASH (577).
return 1;
}

// cleanup
DeleteProcThreadAttributeList(si.lpAttributeList);
HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
CloseHandle(pi.hThread);
CloseHandle(pi.hProcess);
return 0;
}
```
Notas e restrições:
- Use `STARTUPINFOEX` with `InitializeProcThreadAttributeList` and `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL, ...)`, then passe `EXTENDED_STARTUPINFO_PRESENT` para `CreateProcess*`.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- O `DWORD` de proteção pode ser definido como constantes como `PROTECTION_LEVEL_WINTCB_LIGHT`, `PROTECTION_LEVEL_WINDOWS`, `PROTECTION_LEVEL_WINDOWS_LIGHT`, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` ou `PROTECTION_LEVEL_LSA_LIGHT`.
- O processo filho só é iniciado como PPL se sua imagem estiver assinada para essa classe de signer; caso contrário, a criação do processo falha, geralmente com `ERROR_INVALID_IMAGE_HASH (577)` / `STATUS_INVALID_IMAGE_HASH (0xC0000428)`.
- Isso não é um bypass — é uma API compatível destinada a imagens devidamente assinadas. É útil para hardenizar ferramentas ou validar configurações protegidas por PPL.

Exemplo de CLI usando um loader mínimo:<sup>[[1]](#references)</sup>
- Antimalware signer: `CreateProcessAsPPL.exe 3 C:\Tools\agent.exe --svc`
- LSA-light signer: `CreateProcessAsPPL.exe 4 C:\Windows\System32\notepad.exe`

**Opções para bypass das proteções PPL:**

Se você quiser fazer dump do LSASS apesar do PPL, existem 3 opções principais:
1. **Usar um signed kernel driver (por exemplo, Mimikatz + mimidrv.sys)** para **remover a flag de proteção do LSASS**:

![Saída do driver mimidrv do Mimikatz mostrando a interação com a proteção de credenciais](../../images/mimidrv.png)

2. **Bring Your Own Vulnerable Driver (BYOVD)** para executar código de kernel personalizado e desabilitar a proteção. Ferramentas como **PPLKiller**, **gdrv-loader** ou **kdmapper** tornam isso viável.
3. **Roubar um handle existente do LSASS** de outro processo que o tenha aberto (por exemplo, um processo de AV) e então **duplicá-lo** no seu processo. Essa é a base da técnica `pypykatz live lsa --method handledup`.
4. **Abusar de algum processo privilegiado** que permita carregar código arbitrário em seu espaço de endereçamento ou dentro de outro processo privilegiado, efetivamente contornando as restrições do PPL. Você pode consultar um exemplo em [bypassing-lsa-protection-in-userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/) ou [https://github.com/itm4n/PPLdump](https://github.com/itm4n/PPLdump).

**Verificar o status atual da proteção LSA (PPL/PP) do LSASS**:
```bash
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
Ao executar **`mimikatz privilege::debug sekurlsa::logonpasswords`**, provavelmente falhará com o código de erro `0x00000005` por causa disso.

- Para mais informações sobre essa verificação, consulte [https://itm4n.github.io/lsass-runasppl/](https://itm4n.github.io/lsass-runasppl/)<sup>[[5]](#references)</sup>


## Credential Guard

O **Credential Guard**, um recurso exclusivo do **Windows 10 (edições Enterprise e Education)**, aumenta a segurança das credenciais da máquina usando o **Virtual Secure Mode (VSM)** e a **Virtualization Based Security (VBS)**. Ele utiliza extensões de virtualização da CPU para isolar processos importantes em um espaço de memória protegido, fora do alcance do sistema operacional principal. Esse isolamento garante que até mesmo o kernel não possa acessar a memória no VSM, protegendo efetivamente as credenciais contra ataques como **pass-the-hash**. A **Local Security Authority (LSA)** opera nesse ambiente seguro como um trustlet, enquanto o processo **LSASS** no sistema operacional principal atua apenas como comunicador com a LSA do VSM.

Por padrão, o **Credential Guard** não está ativo e requer ativação manual dentro de uma organização. Ele é essencial para aumentar a segurança contra ferramentas como o **Mimikatz**, que têm sua capacidade de extrair credenciais limitada. No entanto, vulnerabilidades ainda podem ser exploradas por meio da adição de **Security Support Providers (SSP)** personalizados para capturar credenciais em texto claro durante tentativas de login.

Para verificar o status de ativação do **Credential Guard**, é possível inspecionar a chave do registro _**LsaCfgFlags**_ em _**HKLM\System\CurrentControlSet\Control\LSA**_. Um valor de "**1**" indica ativação com **UEFI lock**, "**2**" indica ativação sem bloqueio, e "**0**" indica que o recurso não está habilitado. Essa verificação do registro, embora seja um forte indicador, não é a única etapa necessária para habilitar o Credential Guard. Orientações detalhadas e um script do PowerShell para habilitar esse recurso estão disponíveis online.
```bash
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Para uma compreensão abrangente e instruções sobre como habilitar o **Credential Guard** no Windows 10 e sua ativação automática em sistemas compatíveis do **Windows 11 Enterprise e Education (versão 22H2)**, consulte a [documentação da Microsoft](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).<sup>[[9]](#references)</sup>

Mais detalhes sobre a implementação de SSPs personalizados para captura de credenciais são fornecidos [neste guia](../active-directory-methodology/custom-ssp.md).

## RDP RestrictedAdmin Mode

O **Windows 8.1 e o Windows Server 2012 R2** introduziram vários novos recursos de segurança, incluindo o _**Restricted Admin mode for RDP**_. Esse modo foi projetado para aumentar a segurança, reduzindo os riscos associados a ataques de [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/).

Tradicionalmente, ao se conectar a um computador remoto via RDP, suas credenciais são armazenadas na máquina de destino. Isso representa um risco significativo à segurança, especialmente ao usar contas com privilégios elevados. No entanto, com a introdução do _**Restricted Admin mode**_, esse risco é substancialmente reduzido.

Ao iniciar uma conexão RDP usando o comando **mstsc.exe /RestrictedAdmin**, a autenticação no computador remoto é realizada sem armazenar suas credenciais nele. Essa abordagem garante que, caso ocorra uma infecção por malware ou um usuário mal-intencionado obtenha acesso ao servidor remoto, suas credenciais não sejam comprometidas, pois não estão armazenadas no servidor.

É importante observar que, no **Restricted Admin mode**, as tentativas de acessar recursos de rede a partir da sessão RDP não usarão suas credenciais pessoais; em vez disso, será utilizada a **identidade da máquina**.

Esse recurso representa um avanço significativo na proteção de conexões de área de trabalho remota e de informações confidenciais contra exposição em caso de uma violação de segurança.

![Diagrama da memória RAM do Windows no contexto de extração de credenciais](../../images/RAM.png)

Para obter informações mais detalhadas, visite [este recurso](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).<sup>[[6]](#references)</sup>

## Cached Credentials

O Windows protege as **credenciais de domínio** por meio da **Autoridade de Segurança Local (LSA)**, oferecendo suporte aos processos de logon com protocolos de segurança como **Kerberos** e **NTLM**. Um recurso importante do Windows é sua capacidade de armazenar em cache os **últimos dez logins de domínio**, garantindo que os usuários ainda possam acessar seus computadores mesmo quando o **controlador de domínio estiver offline** — uma vantagem para usuários de laptops que frequentemente estão fora da rede da empresa.

A quantidade de logins armazenados em cache pode ser ajustada por meio de uma **chave do registro ou política de grupo** específica. Para visualizar ou alterar essa configuração, utiliza-se o seguinte comando:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
O acesso a essas credenciais armazenadas em cache é rigorosamente controlado, com apenas a conta **SYSTEM** tendo as permissões necessárias para visualizá-las. Os administradores que precisarem acessar essas informações devem fazê-lo com privilégios do usuário SYSTEM. As credenciais são armazenadas em: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

O **Mimikatz** pode ser utilizado para extrair essas credenciais armazenadas em cache usando o comando `lsadump::cache`.

Para obter mais detalhes, a [fonte original](http://juggernaut.wikidot.com/cached-credentials) fornece informações abrangentes.<sup>[[7]](#references)</sup>

## Protected Users

A associação ao **Protected Users group** introduz várias melhorias de segurança para os usuários, garantindo níveis mais elevados de proteção contra roubo e uso indevido de credenciais:

- **Credential Delegation (CredSSP)**: Mesmo que a configuração de Group Policy **Allow delegating default credentials** esteja habilitada, as credenciais em texto simples dos usuários Protected Users não serão armazenadas em cache.
- **Windows Digest**: A partir do **Windows 8.1 e Windows Server 2012 R2**, o sistema não armazenará em cache as credenciais em texto simples dos usuários Protected Users, independentemente do status do Windows Digest.
- **NTLM**: O sistema não armazenará em cache as credenciais em texto simples nem as funções unidirecionais NT (NTOWF) dos usuários Protected Users.
- **Kerberos**: Para usuários Protected Users, a autenticação Kerberos não gerará chaves **DES** ou **RC4**, nem armazenará em cache credenciais em texto simples ou chaves de longo prazo além da aquisição inicial do Ticket-Granting Ticket (TGT).
- **Offline Sign-In**: Um verificador armazenado em cache não será criado para usuários Protected Users durante o sign-in ou desbloqueio, o que significa que o sign-in offline não é compatível com essas contas.

Essas proteções são ativadas no momento em que um usuário membro do **Protected Users group** faz sign-in no dispositivo. Isso garante que medidas críticas de segurança estejam em vigor para proteger contra vários métodos de comprometimento de credenciais.

Para obter informações mais detalhadas, consulte a [documentação oficial](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group).<sup>[[10]](#references)</sup>

**Tabela da** [**documentação**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**<sup>[[11]](#references)</sup>

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators           | Administrators                                                                | Administrators                |
| Backup Operators        | Backup Operators         | Backup Operators                                                              | Backup Operators             |
| Cert Publishers         |                          |                                                                               |                              |
| Domain Admins            | Domain Admins            | Domain Admins                                                                 | Domain Admins                |
| Domain Controllers       | Domain Controllers       | Domain Controllers                                                            | Domain Controllers           |
| Enterprise Admins        | Enterprise Admins        | Enterprise Admins                                                             | Enterprise Admins            |
|                         |                          |                                                                               | Enterprise Key Admins        |
|                         |                          |                                                                               | Key Admins                   |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Print Operators         | Print Operators          | Print Operators                                                               | Print Operators              |
|                         |                          | Read-only Domain Controllers                                                  | Read-only Domain Controllers |
| Replicator              | Replicator               | Replicator                                                                    | Replicator                   |
| Schema Admins            | Schema Admins            | Schema Admins                                                                 | Schema Admins                |
| Server Operators        | Server Operators        | Server Operators                                                              | Server Operators             |

## Referências

- [1] [CreateProcessAsPPL – minimal PPL process launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [2] [STARTUPINFOEX structure (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexw)
- [3] [InitializeProcThreadAttributeList (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist)
- [4] [UpdateProcThreadAttribute (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [5] [LSASS RunAsPPL – background and internals](https://itm4n.github.io/lsass-runasppl/)
- [6] [Restricted Admin Mode for RDP](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/)
- [7] [Cached Credentials - Juggernaut AppSec Wiki](http://juggernaut.wikidot.com/cached-credentials)
- [8] [WDigest Authentication (Microsoft TechNet)](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>)
- [9] [Manage Windows Defender Credential Guard (Microsoft Learn)](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage)
- [10] [Protected Users Security Group (Microsoft Learn)](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [11] [Appendix C: Protected Accounts and Groups in Active Directory (Microsoft Learn)](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)

{{#include ../../banners/hacktricks-training.md}}
