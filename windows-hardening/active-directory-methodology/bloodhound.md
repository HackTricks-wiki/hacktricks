# BloodHound e outras ferramentas de enumeração do AD

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) é da Sysinternal Suite:

> Um visualizador e editor avançado do Active Directory (AD). Você pode usar o AD Explorer para navegar facilmente em um banco de dados do AD, definir locais favoritos, visualizar propriedades de objetos e atributos sem abrir caixas de diálogo, editar permissões, visualizar o esquema de um objeto e executar pesquisas sofisticadas que você pode salvar e reexecutar.

### Snapshots

O AD Explorer pode criar snapshots de um AD para que você possa verificá-lo offline.\
Ele pode ser usado para descobrir vulnerabilidades offline ou para comparar diferentes estados do banco de dados do AD ao longo do tempo.

Será necessário o nome de usuário, senha e direção para se conectar (qualquer usuário do AD é necessário).

Para tirar um snapshot do AD, vá em `Arquivo` --> `Criar Snapshot` e digite um nome para o snapshot.

## ADRecon

****[**ADRecon**](https://github.com/adrecon/ADRecon) é uma ferramenta que extrai e combina vários artefatos de um ambiente AD. As informações podem ser apresentadas em um **relatório** do Microsoft Excel **formatado especialmente** que inclui visualizações de resumo com métricas para facilitar a análise e fornecer uma imagem holística do estado atual do ambiente AD de destino.
```bash
# Run it
.\ADRecon.ps1
```
## BloodHound

> BloodHound é um aplicativo web de página única em Javascript, construído em cima do [Linkurious](http://linkurio.us), compilado com [Electron](http://electron.atom.io), com um banco de dados [Neo4j](https://neo4j.com) alimentado por um ingestor PowerShell.
>
> BloodHound usa a teoria dos grafos para revelar as relações ocultas e muitas vezes não intencionais dentro de um ambiente Active Directory. Atacantes podem usar o BloodHound para identificar facilmente caminhos de ataque altamente complexos que, de outra forma, seriam impossíveis de identificar rapidamente. Defensores podem usar o BloodHound para identificar e eliminar esses mesmos caminhos de ataque. Tanto as equipes azul quanto as vermelhas podem usar o BloodHound para obter facilmente uma compreensão mais profunda das relações de privilégio em um ambiente Active Directory.
>
> BloodHound é desenvolvido por [@\_wald0](https://www.twitter.com/\_wald0), [@CptJesus](https://twitter.com/CptJesus) e [@harmj0y](https://twitter.com/harmj0y).
>
> De [https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)

Então, [Bloodhound](https://github.com/BloodHoundAD/BloodHound) é uma ferramenta incrível que pode enumerar um domínio automaticamente, salvar todas as informações, encontrar possíveis caminhos de escalonamento de privilégios e mostrar todas as informações usando gráficos.

O Bloodhound é composto por 2 partes principais: **ingestores** e o **aplicativo de visualização**.

Os **ingestores** são usados para **enumerar o domínio e extrair todas as informações** em um formato que o aplicativo de visualização entenderá.

O **aplicativo de visualização usa o neo4j** para mostrar como todas as informações estão relacionadas e para mostrar diferentes maneiras de escalar privilégios no domínio.

### Instalação

1. Bloodhound

Para instalar o aplicativo de visualização, você precisará instalar o **neo4j** e o **aplicativo Bloodhound**.\
A maneira mais fácil de fazer isso é apenas fazer:
```
apt-get install bloodhound
```
Você pode **baixar a versão comunitária do neo4j** a partir [daqui](https://neo4j.com/download-center/#community).

1. Ingestores

Você pode baixar os Ingestores de:

* https://github.com/BloodHoundAD/SharpHound/releases
* https://github.com/BloodHoundAD/BloodHound/releases
* https://github.com/fox-it/BloodHound.py

1. Aprenda o caminho a partir do gráfico

O Bloodhound vem com várias consultas para destacar caminhos de comprometimento sensíveis. É possível adicionar consultas personalizadas para aprimorar a pesquisa e correlação entre objetos e muito mais!

Este repositório tem uma boa coleção de consultas: https://github.com/CompassSecurity/BloodHoundQueries

Processo de instalação:
```
$ curl -o "~/.config/bloodhound/customqueries.json" "https://raw.githubusercontent.com/CompassSecurity/BloodHoundQueries/master/BloodHound_Custom_Queries/customqueries.json"
```
### Execução do aplicativo de visualização

Após baixar/instalar as aplicações necessárias, vamos iniciá-las.\
Primeiramente, você precisa **iniciar o banco de dados neo4j**:
```bash
./bin/neo4j start
#or
service neo4j start
```
A primeira vez que você iniciar este banco de dados, precisará acessar [http://localhost:7474/browser/](http://localhost:7474/browser/). Serão solicitadas credenciais padrão (neo4j:neo4j) e você será **obrigado a alterar a senha**, portanto, altere-a e não a esqueça.

Agora, inicie o aplicativo **bloodhound**:
```bash
./BloodHound-linux-x64
#or
bloodhound
```
Você será solicitado a inserir as credenciais do banco de dados: **neo4j:\<Sua nova senha>**

E o Bloodhound estará pronto para receber dados.

![](<../../.gitbook/assets/image (171) (1).png>)

### SharpHound

Eles têm várias opções, mas se você quiser executar o SharpHound a partir de um PC conectado ao domínio, usando seu usuário atual e extrair todas as informações possíveis, você pode fazer:
```
./SharpHound.exe --CollectionMethods All
Invoke-BloodHound -CollectionMethod All
```
Você pode ler mais sobre o **CollectionMethod** e a sessão de loop [aqui](https://bloodhound.readthedocs.io/en/latest/data-collection/sharphound-all-flags.html)

Se você deseja executar o SharpHound usando diferentes credenciais, pode criar uma sessão CMD netonly e executar o SharpHound a partir dela:
```
runas /netonly /user:domain\user "powershell.exe -exec bypass"
```
[**Saiba mais sobre o Bloodhound em ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux)

**Silent do Windows**

### **Python bloodhound**

Se você tiver credenciais de domínio, poderá executar um **ingestor python bloodhound de qualquer plataforma**, portanto, não precisará depender do Windows.\
Baixe-o em [https://github.com/fox-it/BloodHound.py](https://github.com/fox-it/BloodHound.py) ou faça `pip3 install bloodhound`.
```bash
bloodhound-python -u support -p '#00^BlackKnight' -ns 10.10.10.192 -d blackfield.local -c all
```
Se você estiver executando através do proxychains, adicione `--dns-tcp` para que a resolução DNS funcione através do proxy.
```bash
proxychains bloodhound-python -u support -p '#00^BlackKnight' -ns 10.10.10.192 -d blackfield.local -c all --dns-tcp
```
### Python SilentHound

Este script irá **enumerar silenciosamente um domínio Active Directory via LDAP** analisando usuários, administradores, grupos, etc.

Confira em [**SilentHound github**](https://github.com/layer8secure/SilentHound).

### RustHound

BloodHound em Rust, [**confira aqui**](https://github.com/OPENCYBER-FR/RustHound).

## Group3r

[**Group3r**](https://github.com/Group3r/Group3r) **** é uma ferramenta para encontrar **vulnerabilidades** no Active Directory associadas à **Política de Grupo**. \
Você precisa **executar o group3r** a partir de um host dentro do domínio usando **qualquer usuário do domínio**.
```bash
group3r.exe -f <filepath-name.log> 
# -s sends results to stdin
# -f send results to file
```
## PingCastle

O **PingCastle** avalia a postura de segurança de um ambiente AD e fornece um **relatório** agradável com gráficos.

Para executá-lo, você pode executar o binário `PingCastle.exe` e ele iniciará uma **sessão interativa** apresentando um menu de opções. A opção padrão a ser usada é **`healthcheck`**, que estabelecerá uma **visão geral** da **domínio**, e encontrará **configurações incorretas** e **vulnerabilidades**.&#x20;
