# Red Teaming em macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Métodos comuns de gerenciamento

* JAMF Pro: `jamf checkJSSConnection`
* Kandji

Se você conseguir **comprometer as credenciais de administrador** para acessar a plataforma de gerenciamento, poderá **potencialmente comprometer todos os computadores** distribuindo seu malware nas máquinas.

Para o red teaming em ambientes macOS, é altamente recomendável ter algum entendimento de como os MDMs funcionam:

{% content-ref url="macos-mdm/" %}
[macos-mdm](macos-mdm/)
{% endcontent-ref %}

E também sobre os **protocolos de rede** "especiais" do **MacOS**:

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

## Active Directory

Em algumas ocasiões, você descobrirá que o **computador macOS está conectado a um AD**. Nesse cenário, você deve tentar **enumerar** o Active Directory como está acostumado. Encontre alguma **ajuda** nas seguintes páginas:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/active-directory-methodology/" %}
[active-directory-methodology](../../windows-hardening/active-directory-methodology/)
{% endcontent-ref %}

{% content-ref url="../../network-services-pentesting/pentesting-kerberos-88/" %}
[pentesting-kerberos-88](../../network-services-pentesting/pentesting-kerberos-88/)
{% endcontent-ref %}

Algumas **ferramentas locais do MacOS** que também podem ajudá-lo são `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Também existem algumas ferramentas preparadas para MacOS para enumerar automaticamente o AD e brincar com o kerberos:

* [**Machound**](https://github.com/XMCyber/MacHound): MacHound é uma extensão da ferramenta de auditoria Bloodhound que permite coletar e ingerir relacionamentos do Active Directory em hosts MacOS.
* [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost é um projeto Objective-C projetado para interagir com as APIs Heimdal krb5 no macOS. O objetivo do projeto é permitir testes de segurança melhores em torno do Kerberos em dispositivos macOS usando APIs nativas sem exigir nenhum outro framework ou pacote no alvo.
* [**Orchard**](https://github.com/its-a-feature/Orchard): Ferramenta JavaScript para Automação (JXA) para fazer enumeração do Active Directory.
```
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Usuários

Existem três tipos de usuários do MacOS:

* **Usuários Locais** - Gerenciados pelo serviço local OpenDirectory, eles não estão conectados de nenhuma forma ao Active Directory.
* **Usuários de Rede** - Usuários voláteis do Active Directory que requerem uma conexão com o servidor DC para autenticação.
* **Usuários Móveis** - Usuários do Active Directory com um backup local para suas credenciais e arquivos.

As informações locais sobre usuários e grupos são armazenadas na pasta _/var/db/dslocal/nodes/Default._\
Por exemplo, as informações sobre o usuário chamado _mark_ são armazenadas em _/var/db/dslocal/nodes/Default/users/mark.plist_ e as informações sobre o grupo _admin_ estão em _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Além de usar as bordas HasSession e AdminTo, **MacHound adiciona três novas bordas** ao banco de dados Bloodhound:

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

## Serviços Externos

O Red Teaming do MacOS é diferente do Red Teaming regular do Windows, pois geralmente o **MacOS é integrado diretamente com várias plataformas externas**. Uma configuração comum do MacOS é acessar o computador usando **credenciais sincronizadas do OneLogin e acessar vários serviços externos** (como github, aws...) via OneLogin:

![](<../../.gitbook/assets/image (563).png>)

###

## Referências

* [https://www.youtube.com/watch?v=IiMladUbL6E](https://www.youtube.com/watch?v=IiMladUbL6E)
* [https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
* [https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
