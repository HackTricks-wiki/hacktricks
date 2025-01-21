# BloodHound & Outras Ferramentas de Enumeração AD

{{#include ../../banners/hacktricks-training.md}}

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) é da Sysinternal Suite:

> Um visualizador e editor avançado de Active Directory (AD). Você pode usar o AD Explorer para navegar facilmente em um banco de dados AD, definir locais favoritos, visualizar propriedades e atributos de objetos sem abrir caixas de diálogo, editar permissões, visualizar o esquema de um objeto e executar pesquisas sofisticadas que você pode salvar e reexecutar.

### Snapshots

O AD Explorer pode criar snapshots de um AD para que você possa verificá-lo offline.\
Ele pode ser usado para descobrir vulnerabilidades offline ou para comparar diferentes estados do banco de dados AD ao longo do tempo.

Você precisará do nome de usuário, senha e direção para se conectar (qualquer usuário AD é necessário).

Para tirar um snapshot do AD, vá em `File` --> `Create Snapshot` e insira um nome para o snapshot.

## ADRecon

[**ADRecon**](https://github.com/adrecon/ADRecon) é uma ferramenta que extrai e combina vários artefatos de um ambiente AD. As informações podem ser apresentadas em um **relatório** Microsoft Excel **especialmente formatado** que inclui visualizações resumidas com métricas para facilitar a análise e fornecer uma visão holística do estado atual do ambiente AD alvo.
```bash
# Run it
.\ADRecon.ps1
```
## BloodHound

From [https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)

> BloodHound é uma aplicação web Javascript de página única, construída sobre [Linkurious](http://linkurio.us/), compilada com [Electron](http://electron.atom.io/), com um banco de dados [Neo4j](https://neo4j.com/) alimentado por um coletor de dados em C#.

BloodHound usa teoria dos grafos para revelar as relações ocultas e muitas vezes não intencionais dentro de um ambiente Active Directory ou Azure. Atacantes podem usar BloodHound para identificar facilmente caminhos de ataque altamente complexos que, de outra forma, seriam impossíveis de identificar rapidamente. Defensores podem usar BloodHound para identificar e eliminar esses mesmos caminhos de ataque. Tanto equipes azuis quanto vermelhas podem usar BloodHound para obter uma compreensão mais profunda das relações de privilégio em um ambiente Active Directory ou Azure.

Assim, [Bloodhound ](https://github.com/BloodHoundAD/BloodHound) é uma ferramenta incrível que pode enumerar um domínio automaticamente, salvar todas as informações, encontrar possíveis caminhos de escalonamento de privilégios e mostrar todas as informações usando gráficos.

BloodHound é composto por 2 partes principais: **ingestors** e a **aplicação de visualização**.

Os **ingestors** são usados para **enumerar o domínio e extrair todas as informações** em um formato que a aplicação de visualização entenderá.

A **aplicação de visualização usa neo4j** para mostrar como todas as informações estão relacionadas e para mostrar diferentes maneiras de escalar privilégios no domínio.

### Instalação

Após a criação do BloodHound CE, todo o projeto foi atualizado para facilitar o uso com Docker. A maneira mais fácil de começar é usar sua configuração pré-configurada do Docker Compose.

1. Instale o Docker Compose. Isso deve estar incluído na instalação do [Docker Desktop](https://www.docker.com/products/docker-desktop/).
2. Execute:
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
```
3. Localize a senha gerada aleatoriamente na saída do terminal do Docker Compose.  
4. Em um navegador, navegue até http://localhost:8080/ui/login. Faça login com o nome de usuário **`admin`** e uma **`senha gerada aleatoriamente`** que você pode encontrar nos logs do docker compose.

Após isso, você precisará alterar a senha gerada aleatoriamente e terá a nova interface pronta, a partir da qual você pode baixar diretamente os ingestors.

### SharpHound

Eles têm várias opções, mas se você quiser executar o SharpHound de um PC conectado ao domínio, usando seu usuário atual e extrair todas as informações, você pode fazer:
```
./SharpHound.exe --CollectionMethods All
Invoke-BloodHound -CollectionMethod All
```
> Você pode ler mais sobre **CollectionMethod** e a sessão de loop [aqui](https://support.bloodhoundenterprise.io/hc/en-us/articles/17481375424795-All-SharpHound-Community-Edition-Flags-Explained)

Se você deseja executar o SharpHound usando credenciais diferentes, pode criar uma sessão CMD netonly e executar o SharpHound a partir daí:
```
runas /netonly /user:domain\user "powershell.exe -exec bypass"
```
[**Saiba mais sobre Bloodhound em ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux)

## Group3r

[**Group3r**](https://github.com/Group3r/Group3r) é uma ferramenta para encontrar **vulnerabilidades** no Active Directory associadas à **Política de Grupo**. \
Você precisa **executar group3r** a partir de um host dentro do domínio usando **qualquer usuário do domínio**.
```bash
group3r.exe -f <filepath-name.log>
# -s sends results to stdin
# -f send results to file
```
## PingCastle

[**PingCastle**](https://www.pingcastle.com/documentation/) **avalia a postura de segurança de um ambiente AD** e fornece um bom **relatório** com gráficos.

Para executá-lo, pode-se executar o binário `PingCastle.exe` e ele iniciará uma **sessão interativa** apresentando um menu de opções. A opção padrão a ser utilizada é **`healthcheck`** que estabelecerá uma **visão geral** do **domínio**, e encontrará **configurações incorretas** e **vulnerabilidades**.

{{#include ../../banners/hacktricks-training.md}}
