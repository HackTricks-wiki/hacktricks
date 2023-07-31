# Red Teaming no macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Abusando dos MDMs

* JAMF Pro: `jamf checkJSSConnection`
* Kandji

Se você conseguir **comprometer as credenciais de administrador** para acessar a plataforma de gerenciamento, você pode **potencialmente comprometer todos os computadores** distribuindo seu malware nas máquinas.

Para o red teaming em ambientes macOS, é altamente recomendado ter algum entendimento de como os MDMs funcionam:

{% content-ref url="macos-mdm/" %}
[macos-mdm](macos-mdm/)
{% endcontent-ref %}

### Usando MDM como C2

Um MDM terá permissão para instalar, consultar ou remover perfis, instalar aplicativos, criar contas de administrador local, definir senha do firmware, alterar a chave do FileVault...

Para executar seu próprio MDM, você precisa **do seu CSR assinado por um fornecedor**, que você pode tentar obter em [**https://mdmcert.download/**](https://mdmcert.download/). E para executar seu próprio MDM para dispositivos Apple, você pode usar [**MicroMDM**](https://github.com/micromdm/micromdm).

No entanto, para instalar um aplicativo em um dispositivo inscrito, você ainda precisa que ele seja assinado por uma conta de desenvolvedor... no entanto, ao se inscrever no MDM, o **dispositivo adiciona o certificado SSL do MDM como uma CA confiável**, então agora você pode assinar qualquer coisa.

Para inscrever o dispositivo em um MDM, você precisa instalar um arquivo **`mobileconfig`** como root, que pode ser entregue por meio de um arquivo **pkg** (você pode compactá-lo em zip e, quando baixado do Safari, ele será descompactado).

O agente **Mythic Orthrus** usa essa técnica.

### Abusando do JAMF PRO

O JAMF pode executar **scripts personalizados** (scripts desenvolvidos pelo sysadmin), **cargas úteis nativas** (criação de contas locais, definição de senha EFI, monitoramento de arquivos/processos...) e **MDM** (configurações de dispositivo, certificados de dispositivo...).

#### Autoinscrição do JAMF

Acesse uma página como `https://<nome-da-empresa>.jamfcloud.com/enroll/` para ver se eles têm a **autoinscrição ativada**. Se eles tiverem, pode **solicitar credenciais para acessar**.

Você pode usar o script [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) para realizar um ataque de pulverização de senhas.

Além disso, depois de encontrar as credenciais corretas, você pode ser capaz de fazer força bruta em outros nomes de usuário com o formulário a seguir:

![](<../../.gitbook/assets/image (7).png>)

#### Autenticação de dispositivo JAMF

<figure><img src="../../.gitbook/assets/image (2) (1).png" alt=""><figcaption></figcaption></figure>

O binário **`jamf`** continha o segredo para abrir o keychain que, na época da descoberta, era **compartilhado** entre todos e era: **`jk23ucnq91jfu9aj`**.\
Além disso, o jamf **persiste** como um **LaunchDaemon** em **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### Assumindo o controle do dispositivo JAMF

A URL do **JSS** (Jamf Software Server) que o **`jamf`** usará está localizada em **`/Library/Preferences/com.jamfsoftware.jamf.plist`**. \
Este arquivo basicamente contém a URL:

{% code overflow="wrap" %}
```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
<key>is_virtual_machine</key>
<false/>
<key>jss_url</key>
<string>https://halbornasd.jamfcloud.com/</string>
<key>last_management_framework_change_id</key>
<integer>4</integer>
[...]
```
{% endcode %}

Portanto, um invasor poderia inserir um pacote malicioso (`pkg`) que **sobrescreve esse arquivo** quando instalado, definindo a **URL para um ouvinte Mythic C2 de um agente Typhon** para agora poder abusar do JAMF como C2.

{% code overflow="wrap" %}
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
{% endcode %}

#### Impersonação do JAMF

Para **impersonar a comunicação** entre um dispositivo e o JMF, você precisa de:

* O **UUID** do dispositivo: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
* O **keychain do JAMF** em: `/Library/Application\ Support/Jamf/JAMF.keychain` que contém o certificado do dispositivo

Com essas informações, **crie uma VM** com o **UUID** de Hardware **roubado** e com o **SIP desabilitado**, copie o **keychain do JAMF**, **intercepte** o **agente** do Jamf e roube suas informações.

#### Roubo de segredos

<figure><img src="../../.gitbook/assets/image (11).png" alt=""><figcaption><p>a</p></figcaption></figure>

Você também pode monitorar o local `/Library/Application Support/Jamf/tmp/` para os **scripts personalizados** que os administradores podem querer executar via Jamf, pois eles são **colocados aqui, executados e removidos**. Esses scripts **podem conter credenciais**.

No entanto, as **credenciais** podem ser passadas para esses scripts como **parâmetros**, então você precisaria monitorar `ps aux | grep -i jamf` (mesmo sem ser root).

O script [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) pode ouvir novos arquivos sendo adicionados e novos argumentos de processo.

### Acesso Remoto ao macOS

E também sobre **protocolos de rede** **especiais** do **MacOS**:

{% content-ref url="../macos-security-and-privilege-escalation/macos-protocols.md" %}
[macos-protocols.md](../macos-security-and-privilege-escalation/macos-protocols.md)
{% endcontent-ref %}

## Active Directory

Em algumas ocasiões, você descobrirá que o **computador MacOS está conectado a um AD**. Nesse cenário, você deve tentar **enumerar** o active directory como está acostumado. Encontre alguma **ajuda** nas seguintes páginas:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/active-directory-methodology/" %}
[active-directory-methodology](../../windows-hardening/active-directory-methodology/)
{% endcontent-ref %}

{% content-ref url="../../network-services-pentesting/pentesting-kerberos-88/" %}
[pentesting-kerberos-88](../../network-services-pentesting/pentesting-kerberos-88/)
{% endcontent-ref %}

Algumas **ferramentas locais do MacOS** que também podem ajudar são `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Também existem algumas ferramentas preparadas para MacOS para enumerar automaticamente o AD e brincar com o kerberos:

* [**Machound**](https://github.com/XMCyber/MacHound): MacHound é uma extensão da ferramenta de auditoria Bloodhound que permite coletar e ingerir relacionamentos do Active Directory em hosts MacOS.
* [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost é um projeto Objective-C projetado para interagir com as APIs Heimdal krb5 no macOS. O objetivo do projeto é permitir testes de segurança melhores em torno do Kerberos em dispositivos macOS usando APIs nativas sem exigir nenhum outro framework ou pacote no alvo.
* [**Orchard**](https://github.com/its-a-feature/Orchard): Ferramenta JavaScript for Automation (JXA) para enumerar o Active Directory.

### Informações do Domínio
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Usuários

Os três tipos de usuários do MacOS são:

* **Usuários Locais** - Gerenciados pelo serviço local OpenDirectory, eles não estão conectados de forma alguma ao Active Directory.
* **Usuários de Rede** - Usuários voláteis do Active Directory que requerem uma conexão com o servidor DC para autenticação.
* **Usuários Móveis** - Usuários do Active Directory com um backup local de suas credenciais e arquivos.

As informações locais sobre usuários e grupos são armazenadas na pasta _/var/db/dslocal/nodes/Default_.\
Por exemplo, as informações sobre o usuário chamado _mark_ são armazenadas em _/var/db/dslocal/nodes/Default/users/mark.plist_ e as informações sobre o grupo _admin_ estão em _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Além de usar as arestas HasSession e AdminTo, o **MacHound adiciona três novas arestas** ao banco de dados Bloodhound:

* **CanSSH** - entidade permitida a fazer SSH para o host
* **CanVNC** - entidade permitida a fazer VNC para o host
* **CanAE** - entidade permitida a executar scripts AppleEvent no host
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

## Acessando o Keychain

O Keychain provavelmente contém informações sensíveis que, se acessadas sem gerar um prompt, podem ajudar a avançar em um exercício de red team:

{% content-ref url="macos-keychain.md" %}
[macos-keychain.md](macos-keychain.md)
{% endcontent-ref %}

## Serviços Externos

O Red Teaming no MacOS é diferente de um Red Teaming regular no Windows, pois geralmente o MacOS está integrado a várias plataformas externas diretamente. Uma configuração comum do MacOS é acessar o computador usando credenciais sincronizadas do OneLogin e acessar vários serviços externos (como github, aws...) via OneLogin:

![](<../../.gitbook/assets/image (563).png>)

## Técnicas Misc Red Team

### Safari

Quando um arquivo é baixado no Safari, se for um arquivo "seguro", ele será **aberto automaticamente**. Por exemplo, se você **baixar um arquivo zip**, ele será descompactado automaticamente:

<figure><img src="../../.gitbook/assets/image (12) (3).png" alt=""><figcaption></figcaption></figure>

## Referências

* [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
* [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
* [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
* [**Come to the Dark Side, We Have Apples: Turning macOS Management Evil**](https://www.youtube.com/watch?v=pOQOh07eMxY)
* [**OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
