# Segurança do Docker

![](<../../../.gitbook/assets/image (9) (1) (2).png>)

\
Use o [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e **automatizar fluxos de trabalho** com as ferramentas comunitárias mais avançadas do mundo.\
Acesse hoje mesmo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Gostaria de ver sua **empresa anunciada no HackTricks**? Ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **Segurança básica do Docker Engine**

O Docker Engine realiza o trabalho pesado de executar e gerenciar contêineres. O Docker Engine usa recursos do kernel Linux, como **Namespaces** e **Cgroups**, para fornecer isolamento básico entre os contêineres. Ele também usa recursos como **redução de capacidades**, **Seccomp** e **SELinux/AppArmor para obter um melhor isolamento**.

Por fim, um **plugin de autenticação** pode ser usado para **limitar as ações** que os usuários podem executar.

![](<../../../.gitbook/assets/image (625) (1) (1).png>)

### **Acesso seguro ao Docker Engine**

O cliente Docker pode acessar o Docker Engine **localmente usando um soquete Unix ou remotamente usando o mecanismo http**. Para usá-lo remotamente, é necessário usar https e **TLS** para garantir confidencialidade, integridade e autenticação.

Por padrão, o Docker escuta no soquete Unix `unix:///var/`\
`run/docker.sock` e nas distribuições Ubuntu, as opções de inicialização do Docker são especificadas em `/etc/default/docker`. Para permitir que a API e o cliente do Docker acessem o Docker Engine remotamente, precisamos **expor o daemon do Docker usando um soquete http**. Isso pode ser feito através de:
```bash
DOCKER_OPTS="-D -H unix:///var/run/docker.sock -H
tcp://192.168.56.101:2376" -> add this to /etc/default/docker
Sudo service docker restart -> Restart Docker daemon
```
Exporar o daemon do Docker usando http não é uma boa prática e é necessário garantir a segurança da conexão usando https. Existem duas opções: a primeira opção é para o **cliente verificar a identidade do servidor** e a segunda opção é para **ambos, cliente e servidor, verificarem a identidade um do outro**. Certificados estabelecem a identidade de um servidor. Para um exemplo de ambas as opções, [**verifique esta página**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/).

### **Segurança da imagem do contêiner**

As imagens do contêiner são armazenadas em um repositório privado ou público. A Docker fornece as seguintes opções para armazenar imagens de contêiner:

* [Docker hub](https://hub.docker.com) - Este é um serviço de registro público fornecido pela Docker.
* [Docker registry](https://github.com/%20docker/distribution) - Este é um projeto de código aberto que os usuários podem usar para hospedar seu próprio registro.
* [Docker trusted registry](https://www.docker.com/docker-trusted-registry) - Esta é a implementação comercial da Docker do registro Docker e fornece autenticação de usuário baseada em função, juntamente com a integração do serviço de diretório LDAP.

### Verificação de imagem

Os contêineres podem ter **vulnerabilidades de segurança** tanto por causa da imagem base quanto pelo software instalado em cima da imagem base. A Docker está trabalhando em um projeto chamado **Nautilus** que faz a verificação de segurança dos contêineres e lista as vulnerabilidades. O Nautilus funciona comparando cada camada da imagem do contêiner com o repositório de vulnerabilidades para identificar falhas de segurança.

Para mais [**informações, leia isso**](https://docs.docker.com/engine/scan/).

* **`docker scan`**

O comando **`docker scan`** permite que você faça a verificação de imagens do Docker existentes usando o nome ou ID da imagem. Por exemplo, execute o seguinte comando para verificar a imagem hello-world:
```bash
docker scan hello-world

Testing hello-world...

Organization:      docker-desktop-test
Package manager:   linux
Project name:      docker-image|hello-world
Docker image:      hello-world
Licenses:          enabled

✓ Tested 0 dependencies for known issues, no vulnerable paths found.

Note that we do not currently have vulnerability data for your image.
```
* [**`trivy`**](https://github.com/aquasecurity/trivy)
```bash
trivy -q -f json <ontainer_name>:<tag>
```
* [**`clair-scanner`**](https://github.com/arminc/clair-scanner)
```bash
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
### Assinatura de Imagens Docker

As imagens de contêineres Docker podem ser armazenadas em um registro público ou privado. É necessário **assinar** as imagens de contêineres para confirmar que elas não foram adulteradas. O **publicador** de conteúdo é responsável por **assinar** a imagem do contêiner e enviá-la para o registro.\
Aqui estão alguns detalhes sobre a confiança de conteúdo do Docker:

* A confiança de conteúdo do Docker é uma implementação do projeto de código aberto [Notary](https://github.com/docker/notary). O projeto de código aberto Notary é baseado no projeto [The Update Framework (TUF)](https://theupdateframework.github.io).
* A confiança de conteúdo do Docker é habilitada com `export DOCKER_CONTENT_TRUST=1`. A partir da versão 1.10 do Docker, a confiança de conteúdo **não está habilitada por padrão**.
* Quando a confiança de conteúdo está habilitada, só é possível **baixar imagens assinadas**. Ao enviar uma imagem, é necessário inserir a chave de marcação.
* Quando o publicador envia a imagem pela **primeira vez** usando o comando docker push, é necessário inserir uma **senha** para a **chave raiz e chave de marcação**. As outras chaves são geradas automaticamente.
* O Docker também adicionou suporte para chaves de hardware usando o Yubikey e os detalhes estão disponíveis [aqui](https://blog.docker.com/2015/11/docker-content-trust-yubikey/).

Aqui está o **erro** que recebemos quando a **confiança de conteúdo está habilitada e a imagem não está assinada**.
```shell-session
$ docker pull smakam/mybusybox
Using default tag: latest
No trust data for latest
```
O seguinte resultado mostra a **imagem do contêiner sendo enviada para o Docker hub com assinatura** habilitada. Como não é a primeira vez, o usuário é solicitado a inserir apenas a frase secreta para a chave do repositório.
```shell-session
$ docker push smakam/mybusybox:v2
The push refers to a repository [docker.io/smakam/mybusybox]
a7022f99b0cc: Layer already exists
5f70bf18a086: Layer already exists
9508eff2c687: Layer already exists
v2: digest: sha256:8509fa814029e1c1baf7696b36f0b273492b87f59554a33589e1bd6283557fc9 size: 2205
Signing and pushing trust metadata
Enter passphrase for repository key with ID 001986b (docker.io/smakam/mybusybox):
```
É necessário armazenar a chave root, a chave do repositório e a frase secreta em um local seguro. O seguinte comando pode ser usado para fazer backup das chaves privadas:
```bash
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Quando mudei o host do Docker, tive que mover as chaves raiz e as chaves do repositório para operar a partir do novo host.

***

![](<../../../.gitbook/assets/image (9) (1) (2).png>)

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e automatizar facilmente fluxos de trabalho com as ferramentas comunitárias mais avançadas do mundo.\
Acesse hoje mesmo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Recursos de Segurança de Contêineres

<details>

<summary>Resumo dos Recursos de Segurança de Contêineres</summary>

**Namespaces**

Os namespaces são úteis para isolar um projeto dos demais, isolando as comunicações de processos, rede, montagens... É útil isolar o processo do Docker de outros processos (e até mesmo da pasta /proc) para que ele não possa escapar abusando de outros processos.

Poderia ser possível "escapar" ou mais precisamente **criar novos namespaces** usando o binário **`unshare`** (que usa a chamada de sistema **`unshare`**). O Docker, por padrão, impede isso, mas o Kubernetes não (no momento em que este escrito foi feito).\
De qualquer forma, isso é útil para criar novos namespaces, mas **não para voltar aos namespaces padrão do host** (a menos que você tenha acesso a algum `/proc` dentro dos namespaces do host, onde você poderia usar o **`nsenter`** para entrar nos namespaces do host).

**CGroups**

Isso permite limitar recursos e não afeta a segurança do isolamento do processo (exceto pelo `release_agent` que pode ser usado para escapar).

**Descarte de Capacidades**

Considero este um dos recursos **mais importantes** em relação à segurança do isolamento do processo. Isso ocorre porque, sem as capacidades, mesmo que o processo esteja sendo executado como root, **você não poderá executar algumas ações privilegiadas** (porque a chamada de sistema **`syscall`** retornará um erro de permissão porque o processo não possui as capacidades necessárias).

Essas são as **capacidades restantes** após o processo descartar as outras:

{% code overflow="wrap" %}
```
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep
```
{% endcode %}

**Seccomp**

Ele é ativado por padrão no Docker. Ele ajuda a **limitar ainda mais as syscalls** que o processo pode chamar.\
O **perfil Seccomp padrão do Docker** pode ser encontrado em [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)

**AppArmor**

O Docker possui um modelo que você pode ativar: [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

Isso permitirá reduzir as capacidades, syscalls, acesso a arquivos e pastas...

</details>

### Namespaces

**Namespaces** são um recurso do kernel Linux que **particiona os recursos do kernel** de forma que um conjunto de **processos veja** um conjunto de **recursos**, enquanto **outro** conjunto de **processos veja** um conjunto **diferente** de recursos. O recurso funciona tendo o mesmo namespace para um conjunto de recursos e processos, mas esses namespaces se referem a recursos distintos. Os recursos podem existir em vários espaços.

O Docker faz uso dos seguintes Namespaces do kernel Linux para alcançar o isolamento do Container:

* namespace pid
* namespace mount
* namespace network
* namespace ipc
* namespace UTS

Para **mais informações sobre os namespaces**, verifique a seguinte página:

{% content-ref url="namespaces/" %}
[namespaces](namespaces/)
{% endcontent-ref %}

### cgroups

O recurso do kernel Linux **cgroups** fornece a capacidade de **restringir recursos como CPU, memória, IO, largura de banda de rede entre** um conjunto de processos. O Docker permite criar Containers usando o recurso cgroup, que permite o controle de recursos para o Container específico.\
A seguir, temos um Container criado com memória de espaço do usuário limitada a 500m, memória do kernel limitada a 50m, compartilhamento de CPU para 512, peso de blkioweight para 400. O compartilhamento de CPU é uma proporção que controla o uso de CPU do Container. Ele tem um valor padrão de 1024 e varia entre 0 e 1024. Se três Containers têm o mesmo compartilhamento de CPU de 1024, cada Container pode usar até 33% da CPU em caso de contenção de recursos da CPU. blkio-weight é uma proporção que controla o IO do Container. Ele tem um valor padrão de 500 e varia entre 10 e 1000.
```
docker run -it -m 500M --kernel-memory 50M --cpu-shares 512 --blkio-weight 400 --name ubuntu1 ubuntu bash
```
Para obter o cgroup de um contêiner, você pode fazer o seguinte:
```bash
docker run -dt --rm denial sleep 1234 #Run a large sleep inside a Debian container
ps -ef | grep 1234 #Get info about the sleep process
ls -l /proc/<PID>/ns #Get the Group and the namespaces (some may be uniq to the hosts and some may be shred with it)
```
Para mais informações, consulte:

{% content-ref url="cgroups.md" %}
[cgroups.md](cgroups.md)
{% endcontent-ref %}

### Capacidades

As capacidades permitem um **controle mais preciso das capacidades que podem ser permitidas** para o usuário root. O Docker utiliza o recurso de capacidades do kernel Linux para **limitar as operações que podem ser realizadas dentro de um contêiner**, independentemente do tipo de usuário.

Quando um contêiner Docker é executado, o **processo descarta as capacidades sensíveis que o processo poderia usar para escapar do isolamento**. Isso tenta garantir que o processo não seja capaz de realizar ações sensíveis e escapar:

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

### Seccomp no Docker

Este é um recurso de segurança que permite ao Docker **limitar as syscalls** que podem ser usadas dentro do contêiner:

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

### AppArmor no Docker

O **AppArmor** é um aprimoramento do kernel para confinar **contêineres** a um **conjunto limitado de recursos** com **perfis por programa**:

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}

### SELinux no Docker

[SELinux](https://www.redhat.com/en/blog/latest-container-exploit-runc-can-be-blocked-selinux) é um **sistema de rotulagem**. Cada **processo** e cada **objeto do sistema de arquivos** possuem um **rótulo**. As políticas do SELinux definem regras sobre o que um **rótulo de processo pode fazer com todos os outros rótulos** no sistema.

Os motores de contêiner lançam **processos de contêiner com um único rótulo SELinux confinado**, geralmente `container_t`, e em seguida definem o contêiner dentro do contêiner para ser rotulado como `container_file_t`. As regras de política do SELinux basicamente dizem que os **processos `container_t` só podem ler/escrever/executar arquivos rotulados como `container_file_t`**.

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}

### AuthZ & AuthN

Um plugin de autorização **aprova** ou **negam** **solicitações** ao daemon Docker com base no contexto atual de **autenticação** e no contexto de **comando**. O contexto de **autenticação** contém todos os **detalhes do usuário** e o **método de autenticação**. O contexto de **comando** contém todos os dados relevantes da **solicitação**.

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## Interessantes Flags do Docker

### --privileged flag

Na página a seguir, você pode aprender **o que a flag `--privileged` implica**:

{% content-ref url="docker-privileged.md" %}
[docker-privileged.md](docker-privileged.md)
{% endcontent-ref %}

### --security-opt

#### no-new-privileges

Se você estiver executando um contêiner onde um invasor consegue obter acesso como um usuário de baixo privilégio. Se você tiver um **binário suid mal configurado**, o invasor pode abusar dele e **elevar privilégios dentro** do contêiner. O que pode permitir que ele escape dele.

Executar o contêiner com a opção **`no-new-privileges`** habilitada irá **prevenir esse tipo de elevação de privilégios**.
```
docker run -it --security-opt=no-new-privileges:true nonewpriv
```
#### Outros
```bash
#You can manually add/drop capabilities with
--cap-add
--cap-drop

# You can manually disable seccomp in docker with
--security-opt seccomp=unconfined

# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined

# You can manually disable selinux in docker with
--security-opt label:disable
```
Para mais opções **`--security-opt`**, verifique: [https://docs.docker.com/engine/reference/run/#security-configuration](https://docs.docker.com/engine/reference/run/#security-configuration)

## Outras Considerações de Segurança

### Gerenciando Segredos

Primeiro de tudo, **não os coloque dentro da sua imagem!**

Além disso, **não use variáveis de ambiente** para suas informações sensíveis. Qualquer pessoa que possa executar `docker inspect` ou `exec` no contêiner pode encontrar seu segredo.

Volumes do Docker são melhores. Eles são a maneira recomendada de acessar suas informações sensíveis na documentação do Docker. Você pode **usar um volume como sistema de arquivos temporário mantido na memória**. Volumes removem o risco de `docker inspect` e de registro. No entanto, **usuários root ainda podem ver o segredo, assim como qualquer pessoa que possa `exec` no contêiner**.

Ainda **melhor do que volumes, use segredos do Docker**.

Se você apenas precisa do **segredo na sua imagem**, você pode usar o **BuildKit**. O BuildKit reduz significativamente o tempo de construção e possui outros recursos interessantes, incluindo suporte a segredos em tempo de construção.

Existem três maneiras de especificar o backend do BuildKit para que você possa usar seus recursos agora:

1. Defina-o como uma variável de ambiente com `export DOCKER_BUILDKIT=1`.
2. Inicie seu comando `build` ou `run` com `DOCKER_BUILDKIT=1`.
3. Ative o BuildKit por padrão. Defina a configuração em /_etc/docker/daemon.json_ como _true_ com: `{ "features": { "buildkit": true } }`. Em seguida, reinicie o Docker.
4. Em seguida, você pode usar segredos no momento da construção com a flag `--secret` assim:
```bash
docker build --secret my_key=my_value ,src=path/to/my_secret_file .
```
Onde o seu arquivo especifica seus segredos como um par chave-valor.

Esses segredos são excluídos do cache de construção da imagem e da imagem final.

Se você precisa do seu **segredo em seu contêiner em execução**, e não apenas ao construir sua imagem, use **Docker Compose ou Kubernetes**.

Com o Docker Compose, adicione o par chave-valor dos segredos a um serviço e especifique o arquivo de segredo. Agradecimentos à resposta do [Stack Exchange](https://serverfault.com/a/936262/535325) pela dica de segredos do Docker Compose, da qual o exemplo abaixo é adaptado.

Exemplo `docker-compose.yml` com segredos:
```yaml
version: "3.7"

services:

my_service:
image: centos:7
entrypoint: "cat /run/secrets/my_secret"
secrets:
- my_secret

secrets:
my_secret:
file: ./my_secret_file.txt
```
Em seguida, inicie o Compose como de costume com `docker-compose up --build my_service`.

Se você estiver usando [Kubernetes](https://kubernetes.io/docs/concepts/configuration/secret/), ele possui suporte para segredos. O [Helm-Secrets](https://github.com/futuresimple/helm-secrets) pode ajudar a facilitar a gestão de segredos no K8s. Além disso, o K8s possui Controles de Acesso Baseados em Função (RBAC), assim como o Docker Enterprise. O RBAC torna a gestão de acesso aos segredos mais fácil e segura para equipes.

### gVisor

**gVisor** é um kernel de aplicativo, escrito em Go, que implementa uma parte substancial da superfície do sistema Linux. Ele inclui um tempo de execução [Open Container Initiative (OCI)](https://www.opencontainers.org) chamado `runsc` que fornece um **limite de isolamento entre o aplicativo e o kernel do host**. O tempo de execução `runsc` integra-se ao Docker e ao Kubernetes, tornando simples a execução de contêineres isolados.

{% embed url="https://github.com/google/gvisor" %}

### Kata Containers

**Kata Containers** é uma comunidade de código aberto que trabalha para construir um tempo de execução de contêiner seguro com máquinas virtuais leves que têm a sensação e o desempenho de contêineres, mas fornecem **isolamento de carga de trabalho mais forte usando tecnologia de virtualização de hardware** como uma segunda camada de defesa.

{% embed url="https://katacontainers.io/" %}

### Dicas Resumidas

* **Não use a flag `--privileged` ou monte um** [**socket do Docker dentro do contêiner**](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)**.** O socket do Docker permite a criação de contêineres, então é uma maneira fácil de assumir o controle total do host, por exemplo, executando outro contêiner com a flag `--privileged`.
* **Não execute como root dentro do contêiner. Use um** [**usuário diferente**](https://docs.docker.com/develop/develop-images/dockerfile\_best-practices/#user) **e** [**namespaces de usuário**](https://docs.docker.com/engine/security/userns-remap/)**.** O root no contêiner é o mesmo do host, a menos que seja remapeado com namespaces de usuário. Ele é apenas levemente restrito por, principalmente, namespaces, capacidades e cgroups do Linux.
* [**Descarte todas as capacidades**](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) **(`--cap-drop=all`) e habilite apenas as necessárias** (`--cap-add=...`). Muitas cargas de trabalho não precisam de nenhuma capacidade e adicioná-las aumenta o escopo de um possível ataque.
* [**Use a opção de segurança "no-new-privileges"**](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/) para impedir que processos obtenham mais privilégios, por exemplo, por meio de binários suid.
* [**Limite os recursos disponíveis para o contêiner**](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources)**.** Limites de recursos podem proteger a máquina contra ataques de negação de serviço.
* **Ajuste os perfis de** [**seccomp**](https://docs.docker.com/engine/security/seccomp/)**,** [**AppArmor**](https://docs.docker.com/engine/security/apparmor/) **(ou SELinux)** para restringir as ações e chamadas de sistema disponíveis para o contêiner ao mínimo necessário.
* **Use** [**imagens oficiais do Docker**](https://docs.docker.com/docker-hub/official\_images/) **e exija assinaturas** ou construa suas próprias com base nelas. Não herde ou use imagens com [backdoors](https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/). Armazene também as chaves raiz e a frase secreta em um local seguro. O Docker tem planos para gerenciar chaves com o UCP.
* **Reconstrua regularmente** suas imagens para **aplicar patches de segurança no host e nas imagens**.
* Gerencie seus **segredos com sabedoria** para dificultar o acesso do atacante a eles.
* Se você **expõe o daemon do Docker, use HTTPS** com autenticação de cliente e servidor.
* No seu Dockerfile, **prefira COPY em vez de ADD**. ADD extrai automaticamente arquivos compactados e pode copiar arquivos de URLs. COPY não possui essas capacidades. Sempre que possível, evite usar ADD para não ficar suscetível a ataques por meio de URLs remotas e arquivos Zip.
* Tenha **contêineres separados para cada microsserviço**.
* **Não coloque o ssh** dentro do contêiner, "docker exec" pode ser usado para fazer ssh para o contêiner.
* Tenha **imagens de contêiner menores**

## Fuga de Contêiner Docker / Escalação de Privilégios

Se você estiver **dentro de um contêiner Docker** ou tiver acesso a um usuário no **grupo docker**, você pode tentar **escapar e escalar privilégios**:

{% content-ref url="docker-breakout-privilege-escalation/" %}
[docker-breakout-privilege-escalation](docker-breakout-privilege-escalation/)
{% endcontent-ref %}

## Bypass de Plugin de Autenticação do Docker

Se você tiver acesso ao socket do Docker ou tiver acesso a um usuário no **grupo docker, mas suas ações estão sendo limitadas por um plugin de autenticação do Docker**, verifique se você pode **burlá-lo**:

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## Reforçando a Segurança do Docker

* A ferramenta [**docker-bench-security**](https://github.com/docker/docker-bench-security) é um script que verifica dezenas de práticas recomendadas comuns para implantar contêineres Docker em produção. Os testes são todos automatizados e baseados no [CIS Docker Benchmark v1.3.1](https://www.cisecurity.org/benchmark/docker/).\
Você precisa executar a ferramenta no host que executa o Docker ou em um contêiner com privilégios suficientes. Saiba **como executá-la no README:** [**https://github.com/docker/docker-bench-security**](https://github.com/docker/docker-bench-security).

## Referências

* [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
* [https://twitter.com/\_fel1x/status/1151487051986087936](https://twitter.com/\_fel1x/status/1151487051986087936)
* [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-1overview/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-1overview/)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-4container-image/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-4container-image/)
* [https://en.wikipedia.org/wiki/Linux\_namespaces](https://en.wikipedia.org/wiki/Linux\_namespaces)
* [https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57](https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57)

<details>
<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

![](<../../../.gitbook/assets/image (9) (1) (2).png>)

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e **automatizar fluxos de trabalho** com facilidade, utilizando as ferramentas comunitárias mais avançadas do mundo.\
Acesse hoje mesmo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
