## Proteções de Credenciais do Windows

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## WDigest

O protocolo [WDigest](https://technet.microsoft.com/pt-pt/library/cc778868\(v=ws.10\).aspx?f=255\&MSPPError=-2147217396) foi introduzido no Windows XP e foi projetado para ser usado com o protocolo HTTP para autenticação. A Microsoft tem este protocolo **ativado por padrão em várias versões do Windows** (Windows XP - Windows 8.0 e Windows Server 2003 - Windows Server 2012), o que significa que **senhas em texto simples são armazenadas no LSASS** (Local Security Authority Subsystem Service). O **Mimikatz** pode interagir com o LSASS permitindo que um atacante **recupere essas credenciais** por meio do seguinte comando:
```
sekurlsa::wdigest
```
Este comportamento pode ser **desativado/ativado definindo o valor como 1** em _**UseLogonCredential**_ e _**Negotiate**_ em _**HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_.\
Se essas chaves de registro **não existirem** ou o valor for **"0"**, então o WDigest será **desativado**.
```
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## Proteção LSA

A Microsoft em **Windows 8.1 e posterior** forneceu proteção adicional para o LSA para **impedir** que processos não confiáveis possam **ler sua memória** ou injetar código. Isso impedirá que o `mimikatz.exe sekurlsa:logonpasswords` funcione corretamente.\
Para **ativar essa proteção**, você precisa definir o valor _**RunAsPPL**_ em _**HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**_ como 1.
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### Bypassar

É possível contornar essa proteção usando o driver Mimikatz mimidrv.sys:

![](../../.gitbook/assets/mimidrv.png)

## Guarda de Credenciais

**Guarda de Credenciais** é um novo recurso no Windows 10 (Enterprise e Education edition) que ajuda a proteger suas credenciais em uma máquina de ameaças como pass the hash. Isso funciona por meio de uma tecnologia chamada Modo Virtual Seguro (VSM) que utiliza extensões de virtualização da CPU (mas não é uma máquina virtual real) para fornecer **proteção a áreas de memória** (você pode ouvir isso referido como Segurança Baseada em Virtualização ou VBS). O VSM cria uma "bolha" separada para **processos** chave que estão **isolados** dos processos regulares do **sistema operacional**, até mesmo o kernel e **apenas processos confiáveis específicos podem se comunicar com os processos** (conhecidos como **trustlets**) no VSM. Isso significa que um processo no sistema operacional principal não pode ler a memória do VSM, mesmo processos do kernel. A **Autoridade de Segurança Local (LSA) é um dos trustlets** no VSM, além do processo padrão **LSASS** que ainda é executado no sistema operacional principal para garantir suporte a processos existentes, mas está realmente atuando como um proxy ou stub para se comunicar com a versão no VSM, garantindo que as credenciais reais sejam executadas na versão no VSM e, portanto, protegidas contra ataques. A Guarda de Credenciais deve ser ativada e implantada em sua organização, pois não é habilitada por padrão.\
De [https://www.itprotoday.com/windows-10/what-credential-guard](https://www.itprotoday.com/windows-10/what-credential-guard)\
Mais informações e um script PS1 para habilitar a Guarda de Credenciais [podem ser encontrados aqui](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

Nesse caso, **Mimikatz não pode fazer muito para contornar** isso e extrair as hashes do LSASS. Mas você sempre pode adicionar seu **SSP personalizado** e **capturar as credenciais** quando um usuário tenta fazer login em **texto claro**.\
Mais informações sobre [**SSP e como fazer isso aqui**](../active-directory-methodology/custom-ssp.md).

A Guarda de Credenciais pode ser **ativada de diferentes maneiras**. Para verificar se foi ativada usando o registro, você pode verificar o valor da chave _**LsaCfgFlags**_ em _**HKLM\System\CurrentControlSet\Control\LSA**_. Se o valor for **"1"**, está ativo com bloqueio UEFI, se **"2"** estiver ativo sem bloqueio e se **"0"** não estiver habilitado.\
Isso **não é suficiente para habilitar a Guarda de Credenciais** (mas é um forte indicador).\
Mais informações e um script PS1 para habilitar a Guarda de Credenciais [podem ser encontrados aqui](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).
```
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
## Modo RestrictedAdmin do RDP

Com o Windows 8.1 e o Windows Server 2012 R2, novos recursos de segurança foram introduzidos. Um desses recursos de segurança é o _modo Restricted Admin para RDP_. Este novo recurso de segurança é introduzido para mitigar o risco de ataques [pass the hash](https://blog.ahasayen.com/pass-the-hash/).

Quando você se conecta a um computador remoto usando o RDP, suas credenciais são armazenadas no computador remoto em que você se conecta. Geralmente, você está usando uma conta poderosa para se conectar a servidores remotos, e ter suas credenciais armazenadas em todos esses computadores é uma ameaça à segurança.

Usando o _modo Restricted Admin para RDP_, quando você se conecta a um computador remoto usando o comando **mstsc.exe /RestrictedAdmin**, você será autenticado no computador remoto, mas **suas credenciais não serão armazenadas nesse computador remoto**, como teriam sido no passado. Isso significa que se um malware ou até mesmo um usuário mal-intencionado estiver ativo nesse servidor remoto, suas credenciais não estarão disponíveis nesse servidor de desktop remoto para o malware atacar.

Observe que, como suas credenciais não estão sendo salvas na sessão RDP, se **você tentar acessar recursos de rede**, suas credenciais não serão usadas. **A identidade da máquina será usada em vez disso**.

![](../../.gitbook/assets/ram.png)

De [aqui](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).

## Credenciais em cache

As **credenciais de domínio** são usadas pelos componentes do sistema operacional e são **autenticadas** pela **Autoridade de Segurança Local** (LSA). Normalmente, as credenciais de domínio são estabelecidas para um usuário quando um pacote de segurança registrado autentica os dados de logon do usuário. Este pacote de segurança registrado pode ser o protocolo **Kerberos** ou **NTLM**.

**O Windows armazena as últimas dez credenciais de login de domínio no caso de o controlador de domínio ficar offline**. Se o controlador de domínio ficar offline, um usuário ainda poderá fazer login em seu computador. Esse recurso é principalmente para usuários de laptops que não fazem login regularmente no domínio da empresa. O número de credenciais que o computador armazena pode ser controlado pela seguinte **chave do registro ou via política de grupo**:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
As credenciais são ocultadas dos usuários normais, mesmo das contas de administrador. O usuário **SYSTEM** é o único usuário que tem **privilégios** para **visualizar** essas **credenciais**. Para que um administrador possa visualizar essas credenciais no registro, ele deve acessar o registro como um usuário SYSTEM.\
As credenciais em cache são armazenadas no registro no seguinte local do registro:
```
HKEY_LOCAL_MACHINE\SECURITY\Cache
```
## Proteções de Credenciais

Quando o usuário logado é um membro do grupo de Usuários Protegidos, as seguintes proteções são aplicadas:

* A delegação de credenciais (CredSSP) não armazenará em cache as credenciais em texto simples do usuário, mesmo quando a configuração de política de grupo **Permitir a delegação de credenciais padrão** estiver habilitada.
* A partir do Windows 8.1 e do Windows Server 2012 R2, o Windows Digest não armazenará em cache as credenciais em texto simples do usuário, mesmo quando o Windows Digest estiver habilitado.
* O **NTLM** não armazenará em cache as credenciais em texto simples do usuário ou a função unidirecional NT (NTOWF).
* O **Kerberos** não criará mais chaves **DES** ou **RC4**. Além disso, ele não armazenará em cache as credenciais em texto simples do usuário ou as chaves de longo prazo após a aquisição do TGT inicial.
* Um verificador em cache não é criado no login ou desbloqueio, portanto, o login offline não é mais suportado.

Depois que a conta do usuário é adicionada ao grupo de Usuários Protegidos, a proteção começará quando o usuário fizer login no dispositivo. **De** [**aqui**](https://docs.microsoft.com/pt-br/windows-server/security/credentials-protection-and-management/protected-users-security-group)**.**

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

**Tabela de** [**aqui**](https://docs.microsoft.com/pt-br/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**
