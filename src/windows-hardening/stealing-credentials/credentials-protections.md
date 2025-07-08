# Proteções de Credenciais do Windows

{{#include ../../banners/hacktricks-training.md}}

## WDigest

O protocolo [WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>), introduzido com o Windows XP, é projetado para autenticação via o Protocolo HTTP e está **ativado por padrão no Windows XP até o Windows 8.0 e no Windows Server 2003 até o Windows Server 2012**. Essa configuração padrão resulta em **armazenamento de senhas em texto simples no LSASS** (Serviço de Subsistema de Autoridade de Segurança Local). Um atacante pode usar o Mimikatz para **extrair essas credenciais** executando:
```bash
sekurlsa::wdigest
```
Para **ativar ou desativar este recurso**, as chaves de registro _**UseLogonCredential**_ e _**Negotiate**_ dentro de _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ devem ser definidas como "1". Se essas chaves estiverem **ausentes ou definidas como "0"**, o WDigest está **desativado**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## Proteção LSA (Processos protegidos PP e PPL)

**Processo Protegido (PP)** e **Processo Protegido Leve (PPL)** são **proteções a nível de kernel do Windows** projetadas para evitar acesso não autorizado a processos sensíveis como **LSASS**. Introduzido no **Windows Vista**, o **modelo PP** foi originalmente criado para a aplicação de **DRM** e permitia apenas que binários assinados com um **certificado de mídia especial** fossem protegidos. Um processo marcado como **PP** só pode ser acessado por outros processos que também são **PP** e têm um **nível de proteção igual ou superior**, e mesmo assim, **apenas com direitos de acesso limitados** a menos que especificamente permitido.

**PPL**, introduzido no **Windows 8.1**, é uma versão mais flexível do PP. Ele permite **casos de uso mais amplos** (por exemplo, LSASS, Defender) ao introduzir **"níveis de proteção"** baseados no campo **EKU (Enhanced Key Usage)** da assinatura digital. O nível de proteção é armazenado no campo `EPROCESS.Protection`, que é uma estrutura `PS_PROTECTION` com:
- **Tipo** (`Protected` ou `ProtectedLight`)
- **Signatário** (por exemplo, `WinTcb`, `Lsa`, `Antimalware`, etc.)

Essa estrutura é compactada em um único byte e determina **quem pode acessar quem**:
- **Valores de signatário mais altos podem acessar os mais baixos**
- **PPLs não podem acessar PPs**
- **Processos não protegidos não podem acessar nenhum PPL/PP**

### O que você precisa saber de uma perspectiva ofensiva

- Quando **LSASS é executado como PPL**, tentativas de abri-lo usando `OpenProcess(PROCESS_VM_READ | QUERY_INFORMATION)` a partir de um contexto de administrador normal **falham com `0x5 (Acesso Negado)`**, mesmo que `SeDebugPrivilege` esteja habilitado.
- Você pode **verificar o nível de proteção do LSASS** usando ferramentas como Process Hacker ou programaticamente lendo o valor `EPROCESS.Protection`.
- O LSASS normalmente terá `PsProtectedSignerLsa-Light` (`0x41`), que pode ser acessado **apenas por processos assinados com um signatário de nível superior**, como `WinTcb` (`0x61` ou `0x62`).
- PPL é uma **restrição apenas de Userland**; **código a nível de kernel pode contorná-la completamente**.
- O LSASS sendo PPL **não impede o despejo de credenciais se você puder executar shellcode de kernel** ou **aproveitar um processo de alta privilégio com acesso adequado**.
- **Definir ou remover PPL** requer reinicialização ou **configurações de Secure Boot/UEFI**, que podem persistir a configuração PPL mesmo após as alterações no registro serem revertidas.

**Opções para contornar as proteções PPL:**

Se você quiser despejar LSASS apesar do PPL, você tem 3 opções principais:
1. **Usar um driver de kernel assinado (por exemplo, Mimikatz + mimidrv.sys)** para **remover a flag de proteção do LSASS**:

![](../../images/mimidrv.png)

2. **Trazer seu próprio driver vulnerável (BYOVD)** para executar código de kernel personalizado e desabilitar a proteção. Ferramentas como **PPLKiller**, **gdrv-loader** ou **kdmapper** tornam isso viável.
3. **Roubar um handle existente do LSASS** de outro processo que o tenha aberto (por exemplo, um processo de AV), então **duplicá-lo** em seu processo. Esta é a base da técnica `pypykatz live lsa --method handledup`.
4. **Abusar de algum processo privilegiado** que permitirá que você carregue código arbitrário em seu espaço de endereço ou dentro de outro processo privilegiado, contornando efetivamente as restrições do PPL. Você pode verificar um exemplo disso em [bypassing-lsa-protection-in-userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/) ou [https://github.com/itm4n/PPLdump](https://github.com/itm4n/PPLdump).

**Verifique o status atual da proteção LSA (PPL/PP) para LSASS**:
```bash
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
Quando você executa **`mimikatz privilege::debug sekurlsa::logonpasswords`**, provavelmente falhará com o código de erro `0x00000005` por causa disso.

- Para mais informações sobre isso, verifique [https://itm4n.github.io/lsass-runasppl/](https://itm4n.github.io/lsass-runasppl/)

## Credential Guard

**Credential Guard**, uma funcionalidade exclusiva do **Windows 10 (edições Enterprise e Education)**, aprimora a segurança das credenciais da máquina usando **Virtual Secure Mode (VSM)** e **Virtualization Based Security (VBS)**. Ele aproveita as extensões de virtualização da CPU para isolar processos-chave dentro de um espaço de memória protegido, longe do alcance do sistema operacional principal. Essa isolação garante que até mesmo o kernel não possa acessar a memória no VSM, protegendo efetivamente as credenciais de ataques como **pass-the-hash**. A **Local Security Authority (LSA)** opera dentro desse ambiente seguro como um trustlet, enquanto o processo **LSASS** no sistema operacional principal atua apenas como um comunicador com a LSA do VSM.

Por padrão, **Credential Guard** não está ativo e requer ativação manual dentro de uma organização. É crítico para melhorar a segurança contra ferramentas como **Mimikatz**, que são dificultadas em sua capacidade de extrair credenciais. No entanto, vulnerabilidades ainda podem ser exploradas através da adição de **Security Support Providers (SSP)** personalizados para capturar credenciais em texto claro durante tentativas de login.

Para verificar o status de ativação do **Credential Guard**, a chave de registro _**LsaCfgFlags**_ sob _**HKLM\System\CurrentControlSet\Control\LSA**_ pode ser inspecionada. Um valor de "**1**" indica ativação com **UEFI lock**, "**2**" sem bloqueio, e "**0**" denota que não está habilitado. Essa verificação de registro, embora um forte indicador, não é o único passo para habilitar o Credential Guard. Orientações detalhadas e um script PowerShell para habilitar essa funcionalidade estão disponíveis online.
```bash
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Para uma compreensão abrangente e instruções sobre como habilitar o **Credential Guard** no Windows 10 e sua ativação automática em sistemas compatíveis do **Windows 11 Enterprise e Education (versão 22H2)**, visite [a documentação da Microsoft](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

Mais detalhes sobre a implementação de SSPs personalizados para captura de credenciais estão disponíveis [neste guia](../active-directory-methodology/custom-ssp.md).

## Modo RestrictedAdmin do RDP

O **Windows 8.1 e o Windows Server 2012 R2** introduziram várias novas funcionalidades de segurança, incluindo o _**modo Restricted Admin para RDP**_. Este modo foi projetado para aumentar a segurança, mitigando os riscos associados a ataques de [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/).

Tradicionalmente, ao conectar-se a um computador remoto via RDP, suas credenciais são armazenadas na máquina alvo. Isso representa um risco significativo de segurança, especialmente ao usar contas com privilégios elevados. No entanto, com a introdução do _**modo Restricted Admin**_, esse risco é substancialmente reduzido.

Ao iniciar uma conexão RDP usando o comando **mstsc.exe /RestrictedAdmin**, a autenticação no computador remoto é realizada sem armazenar suas credenciais nele. Essa abordagem garante que, no caso de uma infecção por malware ou se um usuário malicioso ganhar acesso ao servidor remoto, suas credenciais não sejam comprometidas, pois não estão armazenadas no servidor.

É importante notar que no **modo Restricted Admin**, tentativas de acessar recursos de rede a partir da sessão RDP não usarão suas credenciais pessoais; em vez disso, a **identidade da máquina** é utilizada.

Esse recurso marca um avanço significativo na segurança das conexões de desktop remoto e na proteção de informações sensíveis contra exposição em caso de uma violação de segurança.

![](../../images/RAM.png)

Para mais informações detalhadas, visite [este recurso](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).

## Credenciais em Cache

O Windows protege as **credenciais de domínio** através da **Local Security Authority (LSA)**, suportando processos de logon com protocolos de segurança como **Kerberos** e **NTLM**. Uma característica chave do Windows é sua capacidade de armazenar em cache os **últimos dez logons de domínio** para garantir que os usuários ainda possam acessar seus computadores mesmo se o **controlador de domínio estiver offline**—uma vantagem para usuários de laptops que frequentemente estão longe da rede da empresa.

O número de logons em cache é ajustável por meio de uma **chave de registro ou política de grupo** específica. Para visualizar ou alterar essa configuração, o seguinte comando é utilizado:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
O acesso a essas credenciais em cache é rigidamente controlado, com apenas a conta **SYSTEM** tendo as permissões necessárias para visualizá-las. Administradores que precisam acessar essas informações devem fazê-lo com privilégios de usuário SYSTEM. As credenciais são armazenadas em: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** pode ser utilizado para extrair essas credenciais em cache usando o comando `lsadump::cache`.

Para mais detalhes, a [fonte](http://juggernaut.wikidot.com/cached-credentials) original fornece informações abrangentes.

## Usuários Protegidos

A adesão ao **grupo de Usuários Protegidos** introduz várias melhorias de segurança para os usuários, garantindo níveis mais altos de proteção contra roubo e uso indevido de credenciais:

- **Delegação de Credenciais (CredSSP)**: Mesmo que a configuração de Política de Grupo para **Permitir delegar credenciais padrão** esteja habilitada, as credenciais em texto simples dos Usuários Protegidos não serão armazenadas em cache.
- **Windows Digest**: A partir do **Windows 8.1 e Windows Server 2012 R2**, o sistema não armazenará em cache credenciais em texto simples dos Usuários Protegidos, independentemente do status do Windows Digest.
- **NTLM**: O sistema não armazenará em cache as credenciais em texto simples dos Usuários Protegidos ou funções unidirecionais NT (NTOWF).
- **Kerberos**: Para Usuários Protegidos, a autenticação Kerberos não gerará **DES** ou **chaves RC4**, nem armazenará em cache credenciais em texto simples ou chaves de longo prazo além da aquisição inicial do Ticket-Granting Ticket (TGT).
- **Login Offline**: Usuários Protegidos não terão um verificador em cache criado no login ou desbloqueio, o que significa que o login offline não é suportado para essas contas.

Essas proteções são ativadas no momento em que um usuário, que é membro do **grupo de Usuários Protegidos**, faz login no dispositivo. Isso garante que medidas de segurança críticas estejam em vigor para proteger contra vários métodos de comprometimento de credenciais.

Para informações mais detalhadas, consulte a [documentação oficial](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group).

**Tabela de** [**documentos**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

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

{{#include ../../banners/hacktricks-training.md}}
