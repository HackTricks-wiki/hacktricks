# Forense de Docker

{{#include ../../banners/hacktricks-training.md}}

## Modificação do container

Há suspeitas de que algum container Docker tenha sido comprometido:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Você pode facilmente **encontrar alterações feitas no sistema de arquivos deste container desde que ele foi criado** com:<sup>[[1]](#references)</sup>
```bash
docker diff wordpress
C /var
C /var/lib
C /var/lib/mysql
A /var/lib/mysql/ib_logfile0
A /var/lib/mysql/ib_logfile1
A /var/lib/mysql/ibdata1
A /var/lib/mysql/mysql
A /var/lib/mysql/mysql/time_zone_leap_second.MYI
A /var/lib/mysql/mysql/general_log.CSV
...
```
No comando anterior, **C** significa **Changed** e **A** significa **Added**.<sup>[[1]](#references)</sup>\
Se você descobrir que algum arquivo interessante, como `/etc/shadow`, foi modificado, poderá baixá-lo do container para verificar atividades maliciosas com:<sup>[[2]](#references)</sup>
```bash
docker cp wordpress:/etc/shadow shadow
```
Você também pode **compará-lo com o original** executando um novo container e extraindo o arquivo dele:<sup>[[2]](#references)[[3]](#references)</sup>
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Se você descobrir que **algum arquivo suspeito foi adicionado**, poderá acessar o container e verificá-lo:<sup>[[4]](#references)</sup>
```bash
docker exec -it wordpress bash
```
## Modificações de imagens

Quando receber uma imagem Docker exportada (provavelmente no formato `.tar`), você pode usar [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) para **extrair um resumo das modificações**:<sup>[[5]](#references)[[6]](#references)</sup>
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Então, você pode **descompactar** a imagem e **acessar os blobs** para procurar arquivos suspeitos que possa ter encontrado no histórico de alterações:<sup>[[7]](#references)</sup>
```bash
tar -xf image.tar
```
### Análise básica

Você pode obter **informações básicas** da imagem executando:<sup>[[8]](#references)</sup>
```bash
docker inspect <image>
```
Você também pode obter um resumo do **histórico de alterações** com:<sup>[[9]](#references)</sup>
```bash
docker history --no-trunc <image>
```
Você também pode gerar um **dockerfile a partir de uma imagem** com:<sup>[[10]](#references)</sup>
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers
```
### Dive

Para encontrar arquivos adicionados/modificados em imagens Docker, você também pode usar o utilitário [**dive**](https://github.com/wagoodman/dive) (baixe-o em [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)):<sup>[[11]](#references)[[12]](#references)</sup>

Carregue o arquivo salvo no Docker antes de abrir sua tag de imagem com o dive:<sup>[[11]](#references)[[13]](#references)</sup>
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Isso permite **navegar pelos diferentes blobs das imagens Docker** e verificar quais arquivos foram modificados/adicionados/removidos. Use **tab** para alternar para a outra visualização e **espaço** para recolher/abrir pastas.<sup>[[11]](#references)</sup>

Com o dive, você não poderá acessar o conteúdo dos diferentes estágios da imagem. Para fazer isso, será necessário **descomprimir cada layer e acessá-la**.\
Você pode descomprimir todas as layers de uma imagem a partir do diretório onde a imagem foi descomprimida, executando:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Credenciais da memória

No Linux, o namespace de PID ancestral do host pode visualizar processos no namespace de PID filho de um container, portanto uma listagem de processos do host, como `ps -ef`, pode exibi-los.<sup>[[14]](#references)</sup>

Quando as credenciais, capabilities e a política de LSM/ptrace do host permitem, um investigador do host com privilégios apropriados pode **despejar a memória do processo** e procurar por **credenciais** [**como no exemplo a seguir**](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#process-memory).<sup>[[15]](#references)</sup>

## References

- [1] [Diferenças do container Docker](https://docs.docker.com/reference/cli/docker/container/diff/)
- [2] [Copiar um container Docker](https://docs.docker.com/reference/cli/docker/container/cp/)
- [3] [Executar um container Docker](https://docs.docker.com/reference/cli/docker/container/run)
- [4] [Executar comandos em um container Docker](https://docs.docker.com/reference/cli/docker/container/exec)
- [5] [GoogleContainerTools/container-diff](https://github.com/GoogleContainerTools/container-diff)
- [6] [Definições dos analyzers do container-diff](https://github.com/GoogleContainerTools/container-diff/blob/master/differs/differs.go)
- [7] [Salvar uma imagem Docker](https://docs.docker.com/reference/cli/docker/image/save/)
- [8] [Inspecionar uma imagem Docker](https://docs.docker.com/reference/cli/docker/image/inspect/)
- [9] [Histórico de uma imagem Docker](https://docs.docker.com/reference/cli/docker/image/history/)
- [10] [alpine-docker/dfimage](https://github.com/alpine-docker/dfimage)
- [11] [README do Dive v0.10.0](https://github.com/wagoodman/dive/blob/v0.10.0/README.md)
- [12] [Lançamento do Dive v0.10.0](https://github.com/wagoodman/dive/releases/tag/v0.10.0)
- [13] [Carregar uma imagem Docker](https://docs.docker.com/reference/cli/docker/image/load/)
- [14] [pid_namespaces(7)](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html)
- [15] [ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html)
{{#include ../../banners/hacktricks-training.md}}
