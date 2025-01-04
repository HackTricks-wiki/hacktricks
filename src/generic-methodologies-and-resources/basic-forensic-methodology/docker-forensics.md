# Docker Forensics

{{#include ../../banners/hacktricks-training.md}}


## Modificação de contêiner

Há suspeitas de que algum contêiner docker foi comprometido:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Você pode facilmente **encontrar as modificações feitas a este contêiner em relação à imagem** com:
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
No comando anterior, **C** significa **Mudado** e **A** significa **Adicionado**.\
Se você descobrir que algum arquivo interessante, como `/etc/shadow`, foi modificado, você pode baixá-lo do contêiner para verificar atividades maliciosas com:
```bash
docker cp wordpress:/etc/shadow.
```
Você também pode **compará-lo com o original** executando um novo contêiner e extraindo o arquivo dele:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Se você descobrir que **um arquivo suspeito foi adicionado**, você pode acessar o contêiner e verificá-lo:
```bash
docker exec -it wordpress bash
```
## Modificações de imagens

Quando você recebe uma imagem docker exportada (provavelmente no formato `.tar`), você pode usar [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) para **extrair um resumo das modificações**:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Então, você pode **descompactar** a imagem e **acessar os blobs** para procurar arquivos suspeitos que você pode ter encontrado no histórico de alterações:
```bash
tar -xf image.tar
```
### Análise Básica

Você pode obter **informações básicas** da imagem executando:
```bash
docker inspect <image>
```
Você também pode obter um resumo **histórico de alterações** com:
```bash
docker history --no-trunc <image>
```
Você também pode gerar um **dockerfile a partir de uma imagem** com:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

Para encontrar arquivos adicionados/modificados em imagens docker, você também pode usar o [**dive**](https://github.com/wagoodman/dive) (baixe-o a partir de [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)):
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Isso permite que você **navegue pelos diferentes blobs de imagens docker** e verifique quais arquivos foram modificados/adicionados. **Vermelho** significa adicionado e **amarelo** significa modificado. Use **tab** para mover para a outra visualização e **espaço** para colapsar/abrir pastas.

Com die você não poderá acessar o conteúdo dos diferentes estágios da imagem. Para fazer isso, você precisará **descomprimir cada camada e acessá-la**.\
Você pode descomprimir todas as camadas de uma imagem a partir do diretório onde a imagem foi descomprimida executando:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Credenciais da memória

Note que quando você executa um contêiner docker dentro de um host **você pode ver os processos em execução no contêiner a partir do host** apenas executando `ps -ef`

Portanto (como root) você pode **extrair a memória dos processos** a partir do host e procurar por **credenciais** apenas [**como no seguinte exemplo**](../../linux-hardening/privilege-escalation/index.html#process-memory).


{{#include ../../banners/hacktricks-training.md}}
