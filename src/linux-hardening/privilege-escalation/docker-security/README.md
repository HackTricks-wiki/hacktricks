# Segurança do Docker

{{#include ../../../banners/hacktricks-training.md}}

## **Segurança Básica do Docker Engine**

O **Docker engine** utiliza os **Namespaces** e **Cgroups** do kernel Linux para isolar contêineres, oferecendo uma camada básica de segurança. Proteção adicional é fornecida através da **eliminação de Capacidades**, **Seccomp** e **SELinux/AppArmor**, melhorando o isolamento dos contêineres. Um **plugin de autenticação** pode restringir ainda mais as ações do usuário.

![Segurança do Docker](https://sreeninet.files.wordpress.com/2016/03/dockersec1.png)

### Acesso Seguro ao Docker Engine

O Docker engine pode ser acessado localmente através de um socket Unix ou remotamente usando HTTP. Para acesso remoto, é essencial empregar HTTPS e **TLS** para garantir confidencialidade, integridade e autenticação.

O Docker engine, por padrão, escuta no socket Unix em `unix:///var/run/docker.sock`. Em sistemas Ubuntu, as opções de inicialização do Docker são definidas em `/etc/default/docker`. Para habilitar o acesso remoto à API e ao cliente do Docker, exponha o daemon do Docker através de um socket HTTP adicionando as seguintes configurações:
```bash
DOCKER_OPTS="-D -H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
No entanto, expor o daemon do Docker via HTTP não é recomendado devido a preocupações de segurança. É aconselhável proteger as conexões usando HTTPS. Existem duas abordagens principais para garantir a conexão:

1. O cliente verifica a identidade do servidor.
2. Tanto o cliente quanto o servidor autenticam mutuamente a identidade um do outro.

Certificados são utilizados para confirmar a identidade de um servidor. Para exemplos detalhados de ambos os métodos, consulte [**este guia**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/).

### Segurança das Imagens de Contêiner

As imagens de contêiner podem ser armazenadas em repositórios privados ou públicos. O Docker oferece várias opções de armazenamento para imagens de contêiner:

- [**Docker Hub**](https://hub.docker.com): Um serviço de registro público do Docker.
- [**Docker Registry**](https://github.com/docker/distribution): Um projeto de código aberto que permite aos usuários hospedar seu próprio registro.
- [**Docker Trusted Registry**](https://www.docker.com/docker-trusted-registry): A oferta de registro comercial do Docker, com autenticação de usuário baseada em função e integração com serviços de diretório LDAP.

### Análise de Imagens

Os contêineres podem ter **vulnerabilidades de segurança** tanto por causa da imagem base quanto por causa do software instalado sobre a imagem base. O Docker está trabalhando em um projeto chamado **Nautilus** que faz a análise de segurança de contêineres e lista as vulnerabilidades. O Nautilus funciona comparando cada camada da imagem do contêiner com o repositório de vulnerabilidades para identificar falhas de segurança.

Para mais [**informações leia isso**](https://docs.docker.com/engine/scan/).

- **`docker scan`**

O comando **`docker scan`** permite que você escaneie imagens Docker existentes usando o nome ou ID da imagem. Por exemplo, execute o seguinte comando para escanear a imagem hello-world:
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
- [**`trivy`**](https://github.com/aquasecurity/trivy)
```bash
trivy -q -f json <container_name>:<tag>
```
- [**`snyk`**](https://docs.snyk.io/snyk-cli/getting-started-with-the-cli)
```bash
snyk container test <image> --json-file-output=<output file> --severity-threshold=high
```
- [**`clair-scanner`**](https://github.com/arminc/clair-scanner)
```bash
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
### Assinatura de Imagem Docker

A assinatura de imagem Docker garante a segurança e integridade das imagens usadas em contêineres. Aqui está uma explicação condensada:

- **Docker Content Trust** utiliza o projeto Notary, baseado no The Update Framework (TUF), para gerenciar a assinatura de imagens. Para mais informações, veja [Notary](https://github.com/docker/notary) e [TUF](https://theupdateframework.github.io).
- Para ativar a confiança de conteúdo do Docker, defina `export DOCKER_CONTENT_TRUST=1`. Este recurso está desativado por padrão nas versões do Docker 1.10 e posteriores.
- Com este recurso ativado, apenas imagens assinadas podem ser baixadas. O envio inicial da imagem requer a definição de senhas para as chaves raiz e de tag, com o Docker também suportando Yubikey para segurança aprimorada. Mais detalhes podem ser encontrados [aqui](https://blog.docker.com/2015/11/docker-content-trust-yubikey/).
- Tentar puxar uma imagem não assinada com a confiança de conteúdo ativada resulta em um erro "No trust data for latest".
- Para envios de imagem após o primeiro, o Docker solicita a senha da chave do repositório para assinar a imagem.

Para fazer backup de suas chaves privadas, use o comando:
```bash
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Ao mudar de hosts Docker, é necessário mover as chaves de root e repositório para manter as operações.

## Recursos de Segurança de Contêineres

<details>

<summary>Resumo dos Recursos de Segurança de Contêineres</summary>

**Principais Recursos de Isolamento de Processos**

Em ambientes containerizados, isolar projetos e seus processos é fundamental para a segurança e gerenciamento de recursos. Aqui está uma explicação simplificada dos conceitos-chave:

**Namespaces**

- **Propósito**: Garantir o isolamento de recursos como processos, rede e sistemas de arquivos. Particularmente no Docker, os namespaces mantêm os processos de um contêiner separados do host e de outros contêineres.
- **Uso do `unshare`**: O comando `unshare` (ou a syscall subjacente) é utilizado para criar novos namespaces, proporcionando uma camada adicional de isolamento. No entanto, enquanto o Kubernetes não bloqueia isso inherentemente, o Docker o faz.
- **Limitação**: Criar novos namespaces não permite que um processo retorne aos namespaces padrão do host. Para penetrar nos namespaces do host, normalmente seria necessário acesso ao diretório `/proc` do host, usando `nsenter` para entrada.

**Grupos de Controle (CGroups)**

- **Função**: Usado principalmente para alocar recursos entre processos.
- **Aspecto de Segurança**: Os CGroups em si não oferecem segurança de isolamento, exceto pelo recurso `release_agent`, que, se mal configurado, poderia potencialmente ser explorado para acesso não autorizado.

**Queda de Capacidades**

- **Importância**: É um recurso de segurança crucial para o isolamento de processos.
- **Funcionalidade**: Restringe as ações que um processo root pode realizar, eliminando certas capacidades. Mesmo que um processo seja executado com privilégios de root, a falta das capacidades necessárias impede a execução de ações privilegiadas, pois as syscalls falharão devido a permissões insuficientes.

Estas são as **capacidades restantes** após o processo descartar as outras:
```
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep
```
**Seccomp**

Está habilitado por padrão no Docker. Ajuda a **limitar ainda mais as syscalls** que o processo pode chamar.\
O **perfil padrão do Seccomp do Docker** pode ser encontrado em [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)

**AppArmor**

O Docker tem um template que você pode ativar: [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

Isso permitirá reduzir capacidades, syscalls, acesso a arquivos e pastas...

</details>

### Namespaces

**Namespaces** são um recurso do kernel Linux que **particiona recursos do kernel** de modo que um conjunto de **processos** **vê** um conjunto de **recursos**, enquanto **outro** conjunto de **processos** vê um **conjunto** diferente de recursos. O recurso funciona tendo o mesmo namespace para um conjunto de recursos e processos, mas esses namespaces se referem a recursos distintos. Os recursos podem existir em múltiplos espaços.

O Docker faz uso dos seguintes Namespaces do kernel Linux para alcançar a isolação de Containers:

- pid namespace
- mount namespace
- network namespace
- ipc namespace
- UTS namespace

Para **mais informações sobre os namespaces** consulte a seguinte página:

{{#ref}}
namespaces/
{{#endref}}

### cgroups

O recurso do kernel Linux **cgroups** fornece a capacidade de **restringir recursos como cpu, memória, io, largura de banda de rede entre** um conjunto de processos. O Docker permite criar Containers usando o recurso cgroup, que permite o controle de recursos para o Container específico.\
A seguir está um Container criado com memória de espaço de usuário limitada a 500m, memória do kernel limitada a 50m, compartilhamento de cpu a 512, blkioweight a 400. O compartilhamento de CPU é uma proporção que controla o uso de CPU do Container. Tem um valor padrão de 1024 e varia entre 0 e 1024. Se três Containers tiverem o mesmo compartilhamento de CPU de 1024, cada Container pode usar até 33% da CPU em caso de contenção de recursos de CPU. blkio-weight é uma proporção que controla o IO do Container. Tem um valor padrão de 500 e varia entre 10 e 1000.
```
docker run -it -m 500M --kernel-memory 50M --cpu-shares 512 --blkio-weight 400 --name ubuntu1 ubuntu bash
```
Para obter o cgroup de um contêiner, você pode fazer:
```bash
docker run -dt --rm denial sleep 1234 #Run a large sleep inside a Debian container
ps -ef | grep 1234 #Get info about the sleep process
ls -l /proc/<PID>/ns #Get the Group and the namespaces (some may be uniq to the hosts and some may be shred with it)
```
Para mais informações, consulte:

{{#ref}}
cgroups.md
{{#endref}}

### Capacidades

As capacidades permitem **um controle mais fino sobre as capacidades que podem ser permitidas** para o usuário root. O Docker usa o recurso de capacidade do kernel Linux para **limitar as operações que podem ser realizadas dentro de um Container**, independentemente do tipo de usuário.

Quando um contêiner docker é executado, o **processo descarta capacidades sensíveis que o processo poderia usar para escapar do isolamento**. Isso tenta garantir que o processo não consiga realizar ações sensíveis e escapar:

{{#ref}}
../linux-capabilities.md
{{#endref}}

### Seccomp no Docker

Este é um recurso de segurança que permite ao Docker **limitar as syscalls** que podem ser usadas dentro do contêiner:

{{#ref}}
seccomp.md
{{#endref}}

### AppArmor no Docker

**AppArmor** é uma melhoria do kernel para confinar **contêineres** a um conjunto **limitado** de **recursos** com **perfis por programa**.:

{{#ref}}
apparmor.md
{{#endref}}

### SELinux no Docker

- **Sistema de Rotulagem**: O SELinux atribui um rótulo único a cada processo e objeto de sistema de arquivos.
- **Aplicação de Políticas**: Ele aplica políticas de segurança que definem quais ações um rótulo de processo pode realizar em outros rótulos dentro do sistema.
- **Rótulos de Processos de Contêiner**: Quando os mecanismos de contêiner iniciam processos de contêiner, eles geralmente recebem um rótulo SELinux confinado, comumente `container_t`.
- **Rotulagem de Arquivos dentro de Contêineres**: Arquivos dentro do contêiner geralmente são rotulados como `container_file_t`.
- **Regras de Política**: A política SELinux garante principalmente que processos com o rótulo `container_t` só possam interagir (ler, escrever, executar) com arquivos rotulados como `container_file_t`.

Esse mecanismo garante que, mesmo que um processo dentro de um contêiner seja comprometido, ele esteja confinado a interagir apenas com objetos que tenham os rótulos correspondentes, limitando significativamente o potencial de dano de tais compromissos.

{{#ref}}
../selinux.md
{{#endref}}

### AuthZ & AuthN

No Docker, um plugin de autorização desempenha um papel crucial na segurança, decidindo se deve permitir ou bloquear solicitações ao daemon do Docker. Essa decisão é tomada examinando dois contextos principais:

- **Contexto de Autenticação**: Isso inclui informações abrangentes sobre o usuário, como quem ele é e como se autenticou.
- **Contexto de Comando**: Isso compreende todos os dados pertinentes relacionados à solicitação sendo feita.

Esses contextos ajudam a garantir que apenas solicitações legítimas de usuários autenticados sejam processadas, aumentando a segurança das operações do Docker.

{{#ref}}
authz-and-authn-docker-access-authorization-plugin.md
{{#endref}}

## DoS de um contêiner

Se você não estiver limitando adequadamente os recursos que um contêiner pode usar, um contêiner comprometido pode causar DoS no host onde está sendo executado.

- DoS de CPU
```bash
# stress-ng
sudo apt-get install -y stress-ng && stress-ng --vm 1 --vm-bytes 1G --verify -t 5m

# While loop
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
```
- DoS de Largura de Banda
```bash
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target IP> 4444; done
```
## Flags Interessantes do Docker

### --privileged flag

Na página a seguir, você pode aprender **o que o flag `--privileged` implica**:

{{#ref}}
docker-privileged.md
{{#endref}}

### --security-opt

#### no-new-privileges

Se você estiver executando um contêiner onde um atacante consegue obter acesso como um usuário de baixo privilégio. Se você tiver um **binário suid mal configurado**, o atacante pode abusar dele e **escalar privilégios dentro** do contêiner. O que pode permitir que ele escape dele.

Executar o contêiner com a opção **`no-new-privileges`** habilitada irá **prevenir esse tipo de escalonamento de privilégios**.
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
Para mais opções **`--security-opt`** consulte: [https://docs.docker.com/engine/reference/run/#security-configuration](https://docs.docker.com/engine/reference/run/#security-configuration)

## Outras Considerações de Segurança

### Gerenciamento de Segredos: Melhores Práticas

É crucial evitar embutir segredos diretamente nas imagens do Docker ou usar variáveis de ambiente, pois esses métodos expõem suas informações sensíveis a qualquer um com acesso ao contêiner através de comandos como `docker inspect` ou `exec`.

**Volumes do Docker** são uma alternativa mais segura, recomendada para acessar informações sensíveis. Eles podem ser utilizados como um sistema de arquivos temporário na memória, mitigando os riscos associados ao `docker inspect` e ao registro. No entanto, usuários root e aqueles com acesso `exec` ao contêiner ainda podem acessar os segredos.

**Segredos do Docker** oferecem um método ainda mais seguro para lidar com informações sensíveis. Para instâncias que requerem segredos durante a fase de construção da imagem, **BuildKit** apresenta uma solução eficiente com suporte para segredos em tempo de construção, aumentando a velocidade de construção e fornecendo recursos adicionais.

Para aproveitar o BuildKit, ele pode ser ativado de três maneiras:

1. Através de uma variável de ambiente: `export DOCKER_BUILDKIT=1`
2. Prefixando comandos: `DOCKER_BUILDKIT=1 docker build .`
3. Habilitando-o por padrão na configuração do Docker: `{ "features": { "buildkit": true } }`, seguido de uma reinicialização do Docker.

BuildKit permite o uso de segredos em tempo de construção com a opção `--secret`, garantindo que esses segredos não sejam incluídos no cache de construção da imagem ou na imagem final, usando um comando como:
```bash
docker build --secret my_key=my_value ,src=path/to/my_secret_file .
```
Para segredos necessários em um contêiner em execução, **Docker Compose e Kubernetes** oferecem soluções robustas. O Docker Compose utiliza uma chave `secrets` na definição do serviço para especificar arquivos secretos, como mostrado em um exemplo de `docker-compose.yml`:
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
Esta configuração permite o uso de segredos ao iniciar serviços com Docker Compose.

Em ambientes Kubernetes, segredos são suportados nativamente e podem ser gerenciados com ferramentas como [Helm-Secrets](https://github.com/futuresimple/helm-secrets). Os Controles de Acesso Baseados em Função (RBAC) do Kubernetes aumentam a segurança do gerenciamento de segredos, semelhante ao Docker Enterprise.

### gVisor

**gVisor** é um kernel de aplicativo, escrito em Go, que implementa uma parte substancial da superfície do sistema Linux. Inclui um runtime da [Open Container Initiative (OCI)](https://www.opencontainers.org) chamado `runsc` que fornece uma **fronteira de isolamento entre o aplicativo e o kernel do host**. O runtime `runsc` se integra ao Docker e Kubernetes, facilitando a execução de contêineres em sandbox.

{% embed url="https://github.com/google/gvisor" %}

### Kata Containers

**Kata Containers** é uma comunidade de código aberto que trabalha para construir um runtime de contêiner seguro com máquinas virtuais leves que se comportam e têm desempenho como contêineres, mas fornecem **isolamento de carga de trabalho mais forte usando tecnologia de virtualização de hardware** como uma segunda camada de defesa.

{% embed url="https://katacontainers.io/" %}

### Dicas Resumidas

- **Não use a flag `--privileged` ou monte um** [**socket Docker dentro do contêiner**](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)**.** O socket docker permite a criação de contêineres, então é uma maneira fácil de assumir o controle total do host, por exemplo, executando outro contêiner com a flag `--privileged`.
- **Não execute como root dentro do contêiner. Use um** [**usuário diferente**](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user) **e** [**namespaces de usuário**](https://docs.docker.com/engine/security/userns-remap/)**.** O root no contêiner é o mesmo que no host, a menos que seja remapeado com namespaces de usuário. É apenas levemente restrito por, principalmente, namespaces do Linux, capacidades e cgroups.
- [**Remova todas as capacidades**](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) **(`--cap-drop=all`) e habilite apenas aquelas que são necessárias** (`--cap-add=...`). Muitas cargas de trabalho não precisam de capacidades e adicioná-las aumenta o escopo de um ataque potencial.
- [**Use a opção de segurança “no-new-privileges”**](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/) para evitar que processos ganhem mais privilégios, por exemplo, através de binários suid.
- [**Limite os recursos disponíveis para o contêiner**](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources)**.** Limites de recursos podem proteger a máquina contra ataques de negação de serviço.
- **Ajuste** [**seccomp**](https://docs.docker.com/engine/security/seccomp/)**,** [**AppArmor**](https://docs.docker.com/engine/security/apparmor/) **(ou SELinux)** perfis para restringir as ações e syscalls disponíveis para o contêiner ao mínimo necessário.
- **Use** [**imagens docker oficiais**](https://docs.docker.com/docker-hub/official_images/) **e exija assinaturas** ou construa suas próprias com base nelas. Não herde ou use imagens [backdoored](https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/). Também armazene chaves root e senhas em um lugar seguro. O Docker tem planos para gerenciar chaves com UCP.
- **Reconstrua regularmente** suas imagens para **aplicar patches de segurança ao host e às imagens.**
- Gerencie seus **segredos com sabedoria** para que seja difícil para o atacante acessá-los.
- Se você **expor o daemon docker, use HTTPS** com autenticação de cliente e servidor.
- Em seu Dockerfile, **prefira COPY em vez de ADD**. ADD extrai automaticamente arquivos compactados e pode copiar arquivos de URLs. COPY não tem essas capacidades. Sempre que possível, evite usar ADD para não ficar suscetível a ataques através de URLs remotas e arquivos Zip.
- Tenha **contêineres separados para cada micro-serviço**
- **Não coloque ssh** dentro do contêiner, “docker exec” pode ser usado para ssh no Contêiner.
- Tenha **imagens de contêiner menores**

## Docker Breakout / Escalada de Privilégios

Se você está **dentro de um contêiner docker** ou tem acesso a um usuário no **grupo docker**, você pode tentar **escapar e escalar privilégios**:

{{#ref}}
docker-breakout-privilege-escalation/
{{#endref}}

## Bypass do Plugin de Autenticação do Docker

Se você tem acesso ao socket docker ou tem acesso a um usuário no **grupo docker, mas suas ações estão sendo limitadas por um plugin de autenticação do docker**, verifique se você pode **contorná-lo:**

{{#ref}}
authz-and-authn-docker-access-authorization-plugin.md
{{#endref}}

## Fortalecimento do Docker

- A ferramenta [**docker-bench-security**](https://github.com/docker/docker-bench-security) é um script que verifica dezenas de melhores práticas comuns em torno da implantação de contêineres Docker em produção. Os testes são todos automatizados e são baseados no [CIS Docker Benchmark v1.3.1](https://www.cisecurity.org/benchmark/docker/).\
Você precisa executar a ferramenta a partir do host que executa o docker ou de um contêiner com privilégios suficientes. Descubra **como executá-la no README:** [**https://github.com/docker/docker-bench-security**](https://github.com/docker/docker-bench-security).

## Referências

- [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
- [https://twitter.com/\_fel1x/status/1151487051986087936](https://twitter.com/_fel1x/status/1151487051986087936)
- [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html)
- [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-1overview/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-1overview/)
- [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)
- [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/)
- [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-4container-image/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-4container-image/)
- [https://en.wikipedia.org/wiki/Linux_namespaces](https://en.wikipedia.org/wiki/Linux_namespaces)
- [https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57](https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57)
- [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)
- [https://docs.docker.com/engine/extend/plugins_authorization](https://docs.docker.com/engine/extend/plugins_authorization)
- [https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57](https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57)
- [https://resources.experfy.com/bigdata-cloud/top-20-docker-security-tips/](https://resources.experfy.com/bigdata-cloud/top-20-docker-security-tips/)


{{#include ../../../banners/hacktricks-training.md}}
