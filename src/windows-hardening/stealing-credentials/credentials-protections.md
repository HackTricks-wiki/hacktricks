# Proteções de Credenciais do Windows

## Proteções de Credenciais

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
## Proteção LSA

A partir do **Windows 8.1**, a Microsoft aprimorou a segurança do LSA para **bloquear leituras de memória não autorizadas ou injeções de código por processos não confiáveis**. Esse aprimoramento dificulta o funcionamento típico de comandos como `mimikatz.exe sekurlsa:logonpasswords`. Para **ativar essa proteção aprimorada**, o valor _**RunAsPPL**_ em _**HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**_ deve ser ajustado para 1:
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### Bypass

É possível contornar essa proteção usando o driver do Mimikatz mimidrv.sys:

![](../../images/mimidrv.png)

## Credential Guard

**Credential Guard**, uma funcionalidade exclusiva do **Windows 10 (edições Enterprise e Education)**, melhora a segurança das credenciais da máquina usando **Virtual Secure Mode (VSM)** e **Virtualization Based Security (VBS)**. Ele aproveita as extensões de virtualização da CPU para isolar processos-chave dentro de um espaço de memória protegido, longe do alcance do sistema operacional principal. Essa isolação garante que até mesmo o kernel não possa acessar a memória no VSM, protegendo efetivamente as credenciais de ataques como **pass-the-hash**. A **Local Security Authority (LSA)** opera dentro desse ambiente seguro como um trustlet, enquanto o processo **LSASS** no sistema operacional principal atua apenas como um comunicador com a LSA do VSM.

Por padrão, **Credential Guard** não está ativo e requer ativação manual dentro de uma organização. É crítico para melhorar a segurança contra ferramentas como **Mimikatz**, que são dificultadas em sua capacidade de extrair credenciais. No entanto, vulnerabilidades ainda podem ser exploradas através da adição de **Security Support Providers (SSP)** personalizados para capturar credenciais em texto claro durante tentativas de login.

Para verificar o status de ativação do **Credential Guard**, a chave de registro _**LsaCfgFlags**_ sob _**HKLM\System\CurrentControlSet\Control\LSA**_ pode ser inspecionada. Um valor de "**1**" indica ativação com **UEFI lock**, "**2**" sem bloqueio, e "**0**" denota que não está habilitado. Essa verificação de registro, embora um forte indicador, não é o único passo para habilitar o Credential Guard. Orientações detalhadas e um script PowerShell para habilitar essa funcionalidade estão disponíveis online.
```powershell
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Para uma compreensão abrangente e instruções sobre como habilitar o **Credential Guard** no Windows 10 e sua ativação automática em sistemas compatíveis do **Windows 11 Enterprise e Education (versão 22H2)**, visite [a documentação da Microsoft](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

Mais detalhes sobre a implementação de SSPs personalizados para captura de credenciais estão disponíveis [neste guia](../active-directory-methodology/custom-ssp.md).

## Modo RestrictedAdmin do RDP

O **Windows 8.1 e o Windows Server 2012 R2** introduziram vários novos recursos de segurança, incluindo o _**modo Restricted Admin para RDP**_. Este modo foi projetado para aumentar a segurança, mitigando os riscos associados a [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/) ataques.

Tradicionalmente, ao conectar-se a um computador remoto via RDP, suas credenciais são armazenadas na máquina alvo. Isso representa um risco significativo de segurança, especialmente ao usar contas com privilégios elevados. No entanto, com a introdução do _**modo Restricted Admin**_, esse risco é substancialmente reduzido.

Ao iniciar uma conexão RDP usando o comando **mstsc.exe /RestrictedAdmin**, a autenticação no computador remoto é realizada sem armazenar suas credenciais nele. Essa abordagem garante que, no caso de uma infecção por malware ou se um usuário malicioso ganhar acesso ao servidor remoto, suas credenciais não sejam comprometidas, pois não estão armazenadas no servidor.

É importante notar que no **modo Restricted Admin**, tentativas de acessar recursos de rede a partir da sessão RDP não usarão suas credenciais pessoais; em vez disso, a **identidade da máquina** é utilizada.

Esse recurso marca um avanço significativo na segurança das conexões de desktop remoto e na proteção de informações sensíveis contra exposição em caso de uma violação de segurança.

![](../../images/RAM.png)

Para mais informações detalhadas, visite [este recurso](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).

## Credenciais em Cache

O Windows protege as **credenciais de domínio** através da **Local Security Authority (LSA)**, suportando processos de logon com protocolos de segurança como **Kerberos** e **NTLM**. Um recurso chave do Windows é sua capacidade de armazenar em cache os **últimos dez logons de domínio** para garantir que os usuários ainda possam acessar seus computadores mesmo se o **controlador de domínio estiver offline**—uma vantagem para usuários de laptops que frequentemente estão fora da rede da empresa.

O número de logons em cache é ajustável através de uma **chave de registro específica ou política de grupo**. Para visualizar ou alterar essa configuração, o seguinte comando é utilizado:
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

Para informações mais detalhadas, consulte a [documentação](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group) oficial.

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
