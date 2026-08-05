# Red Teaming em macOS

{{#include ../../banners/hacktricks-training.md}}


## Abusando de MDMs

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

Se você conseguir **comprometer credenciais de administrador** para acessar a plataforma de gerenciamento, poderá **potencialmente comprometer todos os computadores** distribuindo seu malware nas máquinas.

Para red teaming em ambientes MacOS, é altamente recomendado ter algum conhecimento sobre como os MDMs funcionam:


{{#ref}}
macos-mdm/
{{#endref}}

### Usando MDM como C2

Um MDM terá permissão para instalar, consultar ou remover profiles, instalar applications, criar contas locais de administrador, definir a senha do firmware, alterar a chave do FileVault...

Para executar seu próprio MDM, você precisa que **seu CSR seja assinado por um vendor**, o que você pode tentar obter em [**https://mdmcert.download/**](https://mdmcert.download/). Para executar seu próprio MDM para dispositivos Apple, você pode usar o [**MicroMDM**](https://github.com/micromdm/micromdm).

No entanto, para instalar uma application em um dispositivo enrolled, ela ainda precisa ser assinada por uma developer account... porém, durante o enrolment no MDM, o **dispositivo adiciona o SSL cert do MDM como uma CA confiável**, então agora você pode assinar qualquer coisa.<sup>[4]</sup>

Para fazer o enrolment do dispositivo em um MDM, você precisa instalar um arquivo **`mobileconfig`** como root, que pode ser entregue por meio de um arquivo **pkg** (você pode compactá-lo em zip e, quando baixado pelo Safari, ele será descompactado).

O **Mythic agent Orthrus** usa essa técnica.

### Abusando do JAMF PRO

O JAMF pode executar **custom scripts** (scripts desenvolvidos pelo sysadmin), **native payloads** (criação de contas locais, definição da senha EFI, monitoramento de arquivos/processos...) e **MDM** (configurações de dispositivos, certificados de dispositivos...).<sup>[5]</sup>

#### Auto-enrolment do JAMF

Acesse uma página como `https://<company-name>.jamfcloud.com/enroll/` para verificar se o **self-enrolment está habilitado**. Se estiver, talvez **solicite credenciais para acesso**.

Você pode usar o script [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) para realizar um ataque de password spraying.

Além disso, após encontrar credenciais válidas, você poderá fazer brute-force de outros nomes de usuário usando o formulário a seguir:

![Abusando do JAMF PRO - Auto-enrolment do JAMF: Além disso, após encontrar credenciais válidas, você poderá fazer brute-force de outros nomes de usuário usando o formulário a seguir](<../../images/image (107).png>)

#### Authentication de dispositivos JAMF

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

O binário **`jamf`** continha o secret para abrir o keychain que, no momento da descoberta, era **compartilhado entre todos** e era: **`jk23ucnq91jfu9aj`**.<sup>[5]</sup>\
Além disso, o jamf **persiste** como um **LaunchDaemon** em **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### Device Takeover do JAMF

A **URL** do **JSS** (Jamf Software Server) que o **`jamf`** usará está localizada em **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
Esse arquivo basicamente contém a URL:
```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
<key>is_virtual_machine</key>
<false/>
<key>jss_url</key>
<string>https://subdomain-company.jamfcloud.com/</string>
<key>last_management_framework_change_id</key>
<integer>4</integer>
[...]
```
Portanto, um atacante poderia implantar um pacote malicioso (`pkg`) que **sobrescrevesse este arquivo** ao ser instalado, definindo a **URL para um listener Mythic C2 de um agente Typhon**, podendo então abusar do JAMF como C2.
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
#### Impersonation do JAMF

Para **impersonar a comunicação** entre um dispositivo e o JMF, você precisa de:

- O **UUID** do dispositivo: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- O **keychain do JAMF** de: `/Library/Application\ Support/Jamf/JAMF.keychain`, que contém o certificado do dispositivo

Com essas informações, **crie uma VM** com o **UUID** de Hardware **roubado** e com o **SIP desabilitado**, coloque o **keychain do JAMF**, faça **hook** no **agent** do Jamf e roube as informações dele.

#### Roubo de secrets

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Você também pode monitorar o local `/Library/Application Support/Jamf/tmp/` em busca dos **custom scripts** que os administradores podem querer executar via Jamf, pois eles são **colocados aqui, executados e removidos**. Esses scripts **podem conter credenciais**.

No entanto, **credenciais** podem ser passadas para esses scripts como **parâmetros**, portanto, você precisaria monitorar `ps aux | grep -i jamf` (sem sequer ser root).

O script [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) pode escutar novos arquivos adicionados e novos argumentos de processos.

### Acesso remoto ao macOS

E também sobre os **protocolos** de **rede** "especiais" do **MacOS**:


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

Em algumas ocasiões, você descobrirá que o computador **MacOS está conectado a um AD**. Nesse cenário, você deve tentar **enumerar** o Active Directory como já está acostumado. Encontre alguma **ajuda** nas páginas a seguir:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}


{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}


{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

Alguma **ferramenta local para MacOS** que também pode ajudar é `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Também existem algumas ferramentas preparadas para MacOS para enumerar automaticamente o AD e interagir com kerberos:

- [**Machound**](https://github.com/XMCyber/MacHound): MacHound é uma extensão da ferramenta de auditoria Bloodhound que permite coletar e ingerir relações do Active Directory em hosts MacOS.<sup>[2]</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost é um projeto Objective-C desenvolvido para interagir com as APIs krb5 do Heimdal no macOS. O objetivo do projeto é possibilitar melhores testes de segurança relacionados ao Kerberos em dispositivos macOS usando APIs nativas, sem exigir qualquer outro framework ou pacote no alvo.
- [**Orchard**](https://github.com/its-a-feature/Orchard): Ferramenta JavaScript for Automation (JXA) para realizar enumeração do Active Directory.

### Informações do Domínio
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Usuários

Os três tipos de usuários do MacOS são:

- **Usuários locais** — Gerenciados pelo serviço local OpenDirectory, eles não estão conectados de nenhuma forma ao Active Directory.
- **Usuários de rede** — Usuários voláteis do Active Directory que precisam de uma conexão com o servidor DC para se autenticar.
- **Usuários móveis** — Usuários do Active Directory com um backup local de suas credenciais e arquivos.

As informações locais sobre usuários e grupos são armazenadas na pasta _/var/db/dslocal/nodes/Default._\
Por exemplo, as informações sobre o usuário chamado _mark_ são armazenadas em _/var/db/dslocal/nodes/Default/users/mark.plist_ e as informações sobre o grupo _admin_ estão em _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Além de usar as edges HasSession e AdminTo, o **MacHound adiciona três novas edges** ao banco de dados do Bloodhound:<sup>[2]</sup>

- **CanSSH** - entidade autorizada a usar SSH no host
- **CanVNC** - entidade autorizada a usar VNC no host
- **CanAE** - entidade autorizada a executar scripts AppleEvent no host
```bash
#User enumeration
dscl . ls /Users
dscl . read /Users/[username]
dscl "/Active Directory/TEST/All Domains" ls /Users
dscl "/Active Directory/TEST/All Domains" read /Users/[username]
dscacheutil -q user

#Computer enumeration
dscl "/Active Directory/TEST/All Domains" ls /Computers
dscl "/Active Directory/TEST/All Domains" read "/Computers/[compname]$"

#Group enumeration
dscl . ls /Groups
dscl . read "/Groups/[groupname]"
dscl "/Active Directory/TEST/All Domains" ls /Groups
dscl "/Active Directory/TEST/All Domains" read "/Groups/[groupname]"

#Domain Information
dsconfigad -show
```
Mais informações em [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

### Senha do Computer$

Obtenha senhas usando:
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
É possível acessar a **senha do `Computer$`** dentro do chaveiro do sistema.

### Over-Pass-The-Hash

Obtenha um TGT para um usuário e serviço específicos:
```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
--hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```
Depois que o TGT for coletado, é possível injetá-lo na sessão atual com:
```bash
bifrost --action asktgt --username test_lab_admin \
--hash CF59D3256B62EE655F6430B0F80701EE05A0885B8B52E9C2480154AFA62E78 \
--enctype aes256 --domain test.lab.local
```
### Kerberoasting
```bash
bifrost --action asktgs --spn [service] --domain [domain.com] \
--username [user] --hash [hash] --enctype [enctype]
```
Com os service tickets obtidos, é possível tentar acessar compartilhamentos em outros computadores:
```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```
## Acessando o Keychain

O Keychain muito provavelmente contém informações sensíveis que, se acessadas sem gerar um prompt, poderiam ajudar a avançar em um exercício de red team:


{{#ref}}
macos-keychain.md
{{#endref}}

## Serviços Externos

O MacOS Red Teaming é diferente de um Red Teaming comum de Windows, pois geralmente o **MacOS é integrado diretamente a várias plataformas externas**. Uma configuração comum do MacOS é acessar o computador usando **credenciais sincronizadas do OneLogin e acessar vários serviços externos** (como github, aws...) via OneLogin.

## Técnicas diversas de Red Team

### Safari

Quando um arquivo é baixado no Safari, se for um arquivo "seguro", ele será **aberto automaticamente**. Por exemplo, se você **baixar um zip**, ele será descompactado automaticamente:

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>

## Referências

- [1] [Gone Apple Pickin': Red Teaming MacOS Environments in 2021 - Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [Introducing MacHound: A Solution to macOS Active Directory Based Attacks](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature - Domain Enumeration Commands (dscl / net / ldapsearch equivalents)](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [Come to the Dark Side, We Have Apples: Turning macOS Management Evil](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)


{{#include ../../banners/hacktricks-training.md}}
