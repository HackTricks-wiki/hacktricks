# Proteções de Credenciais do Windows

{{#include ../../banners/hacktricks-training.md}}

## WDigest

The [WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>) protocol, introduced with Windows XP, is designed for authentication via the HTTP Protocol and is **enabled by default on Windows XP through Windows 8.0 and Windows Server 2003 to Windows Server 2012**. This default setting results in **plain-text password storage in LSASS** (Local Security Authority Subsystem Service). An attacker can use Mimikatz to **extract these credentials** by executing:
```bash
sekurlsa::wdigest
```
Para **ativar ou desativar esse recurso**, as chaves de registro _**UseLogonCredential**_ e _**Negotiate**_ em _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ devem ser definidas como "1". Se essas chaves estiverem **ausentes ou definidas como "0"**, o WDigest está **desativado**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## Proteção LSA (PP & PPL protected processes)

**Protected Process (PP)** and **Protected Process Light (PPL)** são **proteções em nível de kernel do Windows** projetadas para impedir acesso não autorizado a processos sensíveis como **LSASS**. Introduzido no **Windows Vista**, o **modelo PP** foi originalmente criado para a aplicação de **DRM** e só permitia que binários assinados com um **certificado de mídia especial** fossem protegidos. Um processo marcado como **PP** só pode ser acessado por outros processos que sejam **também PP** e tenham um **nível de proteção igual ou superior**, e mesmo assim, **apenas com direitos de acesso limitados**, salvo permissão explícita.

**PPL**, introduzido no **Windows 8.1**, é uma versão mais flexível do PP. Permite **casos de uso mais amplos** (por exemplo, LSASS, Defender) ao introduzir **"protection levels"** baseados no campo **EKU (Enhanced Key Usage)** da assinatura digital. O nível de proteção é armazenado no campo `EPROCESS.Protection`, que é uma estrutura `PS_PROTECTION` com:
- **Tipo** (`Protected` or `ProtectedLight`)
- **Assinante** (por exemplo, `WinTcb`, `Lsa`, `Antimalware`, etc.)

Essa estrutura é empacotada em um único byte e determina **quem pode acessar quem**:
- **Valores de signer mais altos podem acessar os mais baixos**
- **PPLs não conseguem acessar PPs**
- **Processos não protegidos não podem acessar nenhum PPL/PP**

### O que você precisa saber do ponto de vista ofensivo

- Quando **LSASS roda como PPL**, tentativas de abri-lo usando `OpenProcess(PROCESS_VM_READ | QUERY_INFORMATION)` a partir de um contexto admin normal **falham com `0x5 (Access Denied)`**, mesmo que `SeDebugPrivilege` esteja habilitado.
- Você pode **verificar o nível de proteção do LSASS** usando ferramentas como Process Hacker ou programaticamente lendo o valor `EPROCESS.Protection`.
- LSASS normalmente terá `PsProtectedSignerLsa-Light` (`0x41`), que só pode ser acessado **por processos assinados com um signer de nível superior**, como `WinTcb` (`0x61` ou `0x62`).
- PPL é uma **restrição apenas no Userland**; **código em nível de kernel pode contorná-la completamente**.
- O fato de LSASS ser PPL **não impede o credential dumping** se você puder executar kernel shellcode ou **alavancar um processo com altos privilégios e acesso apropriado**.
- **Definir ou remover PPL** requer reboot ou configurações de **Secure Boot/UEFI**, o que pode persistir a configuração de PPL mesmo após alterações no registro serem revertidas.

### Create a PPL process at launch (documented API)

Windows expõe uma forma documentada de solicitar um nível Protected Process Light para um processo filho durante a criação usando a lista estendida de atributos de startup. Isso não contorna os requisitos de assinatura — a imagem alvo deve estar assinada para a classe de signer solicitada.

Minimal flow in C/C++:
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
- Use `STARTUPINFOEX` com `InitializeProcThreadAttributeList` e `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL, ...)`, então passe `EXTENDED_STARTUPINFO_PRESENT` para `CreateProcess*`.
- O `DWORD` de proteção pode ser definido para constantes como `PROTECTION_LEVEL_WINTCB_LIGHT`, `PROTECTION_LEVEL_WINDOWS`, `PROTECTION_LEVEL_WINDOWS_LIGHT`, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, ou `PROTECTION_LEVEL_LSA_LIGHT`.
- O processo filho só inicia como PPL se sua imagem estiver assinada para aquela classe de assinante; caso contrário a criação do processo falha, comumente com `ERROR_INVALID_IMAGE_HASH (577)` / `STATUS_INVALID_IMAGE_HASH (0xC0000428)`.
- Isto não é um bypass — é uma API suportada destinada a imagens devidamente assinadas. Útil para hardenizar ferramentas ou validar configurações protegidas por PPL.

Exemplo de CLI usando um loader mínimo:
- Antimalware signer: `CreateProcessAsPPL.exe 3 C:\Tools\agent.exe --svc`
- LSA-light signer: `CreateProcessAsPPL.exe 4 C:\Windows\System32\notepad.exe`

**Bypass PPL protections options:**

Se você quer dump LSASS apesar do PPL, tem 3 opções principais:
1. **Use um driver de kernel assinado (e.g., Mimikatz + mimidrv.sys)** para **remover a flag de proteção do LSASS**:

![](../../images/mimidrv.png)

2. **Bring Your Own Vulnerable Driver (BYOVD)** para executar código kernel customizado e desabilitar a proteção. Ferramentas como **PPLKiller**, **gdrv-loader**, ou **kdmapper** tornam isso viável.
3. **Roubar um handle existente do LSASS** de outro processo que o tenha aberto (e.g., um processo AV), então **duplicá-lo** para o seu processo. Esta é a base da técnica `pypykatz live lsa --method handledup`.
4. **Abusar de algum processo privilegiado** que permita carregar código arbitrário em seu espaço de endereçamento ou dentro de outro processo privilegiado, efetivamente contornando as restrições PPL. Você pode ver um exemplo disso em [bypassing-lsa-protection-in-userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/) ou [https://github.com/itm4n/PPLdump](https://github.com/itm4n/PPLdump).

**Check current status of LSA protection (PPL/PP) for LSASS**:
```bash
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
When you running **`mimikatz privilege::debug sekurlsa::logonpasswords`** it'll probably fail with the error code `0x00000005` becasue of this.

- For more information about this check [https://itm4n.github.io/lsass-runasppl/](https://itm4n.github.io/lsass-runasppl/)


## Credential Guard

**Credential Guard**, a feature exclusive to **Windows 10 (Enterprise and Education editions)**, enhances the security of machine credentials using **Virtual Secure Mode (VSM)** and **Virtualization Based Security (VBS)**. It leverages CPU virtualization extensions to isolate key processes within a protected memory space, away from the main operating system's reach. This isolation ensures that even the kernel cannot access the memory in VSM, effectively safeguarding credentials from attacks like **pass-the-hash**. The **Local Security Authority (LSA)** operates within this secure environment as a trustlet, while the **LSASS** process in the main OS acts merely as a communicator with the VSM's LSA.

Por padrão, o **Credential Guard** não está ativo e requer ativação manual dentro de uma organização. É crítico para melhorar a segurança contra ferramentas como **Mimikatz**, que ficam limitadas em sua capacidade de extrair credenciais. No entanto, ainda é possível explorar vulnerabilidades através da adição de **Security Support Providers (SSP)** customizados para capturar credenciais em texto claro durante tentativas de login.

Para verificar o status de ativação do **Credential Guard**, a chave de registro _**LsaCfgFlags**_ em _**HKLM\System\CurrentControlSet\Control\LSA**_ pode ser inspecionada. Um valor de "**1**" indica ativação com **UEFI lock**, "**2**" sem lock, e "**0**" indica que não está habilitado. Essa verificação do registro, embora seja um forte indicativo, não é o único passo para habilitar o Credential Guard. Orientações detalhadas e um script PowerShell para habilitar esse recurso estão disponíveis online.
```bash
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
For a comprehensive understanding and instructions on enabling **Credential Guard** in Windows 10 and its automatic activation in compatible systems of **Windows 11 Enterprise and Education (version 22H2)**, visit [Microsoft's documentation](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

Further details on implementing custom SSPs for credential capture are provided in [this guide](../active-directory-methodology/custom-ssp.md).

## RDP RestrictedAdmin Mode

**Windows 8.1 and Windows Server 2012 R2** introduziram várias novas funcionalidades de segurança, incluindo o _**Restricted Admin mode for RDP**_. Este modo foi projetado para aumentar a segurança mitigando os riscos associados a ataques [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/).

Tradicionalmente, ao conectar-se a um computador remoto via RDP, suas credenciais são armazenadas na máquina alvo. Isso representa um risco de segurança significativo, especialmente ao usar contas com privilégios elevados. Entretanto, com a introdução do _**Restricted Admin mode**_, esse risco é substancialmente reduzido.

Ao iniciar uma conexão RDP usando o comando **mstsc.exe /RestrictedAdmin**, a autenticação ao computador remoto é realizada sem armazenar suas credenciais nele. Essa abordagem garante que, em caso de infecção por malware ou se um usuário malicioso obtiver acesso ao servidor remoto, suas credenciais não sejam comprometidas, pois não estão armazenadas no servidor.

É importante notar que, no **Restricted Admin mode**, tentativas de acessar recursos de rede a partir da sessão RDP não usarão suas credenciais pessoais; em vez disso, a **identidade da máquina** é usada.

Esse recurso representa um avanço significativo na proteção de conexões de área de trabalho remota e na proteção de informações sensíveis contra exposição em caso de violação de segurança.

![](../../images/RAM.png)

For more detailed information on visit [this resource](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).

## Cached Credentials

O Windows protege as **credenciais de domínio** por meio da **Local Security Authority (LSA)**, suportando processos de logon com protocolos de segurança como **Kerberos** e **NTLM**. Uma funcionalidade chave do Windows é a capacidade de armazenar em cache os **últimos dez logons de domínio** para garantir que os usuários ainda possam acessar seus computadores mesmo se o **controlador de domínio estiver offline** — uma vantagem para usuários de laptop que frequentemente estão fora da rede da empresa.

O número de logons em cache é ajustável através de uma **chave do registro ou política de grupo** específica. Para visualizar ou alterar essa configuração, o seguinte comando é utilizado:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
O acesso a essas credenciais em cache é estritamente controlado, com apenas a conta **SYSTEM** possuindo as permissões necessárias para visualizá-las. Administradores que precisarem acessar essa informação devem fazê-lo com privilégios de usuário SYSTEM. As credenciais são armazenadas em: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** pode ser usado para extrair essas credenciais em cache usando o comando `lsadump::cache`.

Para mais detalhes, a [fonte original](http://juggernaut.wikidot.com/cached-credentials) fornece informações abrangentes.

## Usuários Protegidos

A filiação ao **Protected Users group** introduz várias melhorias de segurança para usuários, garantindo níveis mais altos de proteção contra roubo e uso indevido de credenciais:

- **Credential Delegation (CredSSP)**: Mesmo que a configuração de Group Policy **Allow delegating default credentials** esteja habilitada, as credenciais em texto plano dos usuários do **Protected Users group** não serão armazenadas em cache.
- **Windows Digest**: A partir do **Windows 8.1 and Windows Server 2012 R2**, o sistema não armazenará em cache credenciais em texto plano dos usuários do **Protected Users group**, independentemente do status do Windows Digest.
- **NTLM**: O sistema não armazenará em cache credenciais em texto plano dos usuários do **Protected Users group** nem funções unidirecionais NT (NTOWF).
- **Kerberos**: Para usuários do **Protected Users group**, a autenticação Kerberos não gerará chaves **DES** ou **RC4**, nem armazenará em cache credenciais em texto plano ou chaves de longo prazo além da aquisição inicial do Ticket-Granting Ticket (TGT).
- **Offline Sign-In**: Usuários do **Protected Users group** não terão um verificador em cache criado no momento do sign-in ou do unlock, o que significa que o sign-in offline não é suportado para essas contas.

Essas proteções são ativadas no momento em que um usuário, que é membro do **Protected Users group**, faz sign-in no dispositivo. Isso garante que medidas críticas de segurança estejam em vigor para proteger contra vários métodos de comprometimento de credenciais.

Para informações mais detalhadas, consulte a [documentação oficial](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group).

**Tabela de** [**the docs**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators           | Administrators                                                                | Administrators               |
| Backup Operators        | Backup Operators         | Backup Operators                                                              | Backup Operators             |
| Cert Publishers         |                          |                                                                               |                              |
| Domain Admins           | Domain Admins            | Domain Admins                                                                 | Domain Admins                |
| Domain Controllers      | Domain Controllers       | Domain Controllers                                                            | Domain Controllers           |
| Enterprise Admins       | Enterprise Admins        | Enterprise Admins                                                             | Enterprise Admins            |
|                         |                          |                                                                               | Enterprise Key Admins        |
|                         |                          |                                                                               | Key Admins                   |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Print Operators         | Print Operators          | Print Operators                                                               | Print Operators              |
|                         |                          | Read-only Domain Controllers                                                  | Read-only Domain Controllers |
| Replicator              | Replicator               | Replicator                                                                    | Replicator                   |
| Schema Admins           | Schema Admins            | Schema Admins                                                                 | Schema Admins                |
| Server Operators        | Server Operators         | Server Operators                                                              | Server Operators             |

## Referências

- [CreateProcessAsPPL – minimal PPL process launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [STARTUPINFOEX structure (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexw)
- [InitializeProcThreadAttributeList (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist)
- [UpdateProcThreadAttribute (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [LSASS RunAsPPL – background and internals](https://itm4n.github.io/lsass-runasppl/)

{{#include ../../banners/hacktricks-training.md}}
