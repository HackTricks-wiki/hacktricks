# Analyse forensique de Docker

## Modification du conteneur

Il existe des soupçons selon lesquels un conteneur Docker aurait été compromis :
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Vous pouvez facilement **identifier les modifications apportées au système de fichiers de ce conteneur depuis sa création** avec :<sup>[[1]](#references)</sup>
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
Dans la commande précédente, **C** signifie **Changed** et **A** signifie **Added**.<sup>[[1]](#references)</sup>\
Si vous constatez qu’un fichier intéressant comme `/etc/shadow` a été modifié, vous pouvez le télécharger depuis le container afin de rechercher toute activité malveillante avec&nbsp;:<sup>[[2]](#references)</sup>
```bash
docker cp wordpress:/etc/shadow shadow
```
Vous pouvez également **le comparer à l’original** en exécutant un nouveau conteneur et en en extrayant le fichier :<sup>[[2]](#references)[[3]](#references)</sup>
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Si vous constatez qu’**un fichier suspect a été ajouté**, vous pouvez accéder au conteneur et le vérifier :<sup>[[4]](#references)</sup>
```bash
docker exec -it wordpress bash
```
## Modifications des images

Lorsque vous disposez d’une image Docker exportée (probablement au format `.tar`), vous pouvez utiliser [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) pour **extraire un résumé des modifications** :<sup>[[5]](#references)[[6]](#references)</sup>
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Ensuite, vous pouvez **décompresser** l’image et **accéder aux blobs** afin de rechercher les fichiers suspects que vous avez peut-être trouvés dans l’historique des modifications :<sup>[[7]](#references)</sup>
```bash
tar -xf image.tar
```
### Analyse de base

Vous pouvez obtenir des **informations de base** à partir de l’image en exécutant :<sup>[[8]](#references)</sup>
```bash
docker inspect <image>
```
Vous pouvez également obtenir un **historique récapitulatif des modifications** avec :<sup>[[9]](#references)</sup>
```bash
docker history --no-trunc <image>
```
Vous pouvez également générer un **Dockerfile à partir d’une image** avec :<sup>[[10]](#references)</sup>
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers
```
### Dive

Pour trouver les fichiers ajoutés ou modifiés dans les images Docker, vous pouvez également utiliser l’utilitaire [**dive**](https://github.com/wagoodman/dive) (téléchargez-le depuis les [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0) ) :<sup>[[11]](#references)[[12]](#references)</sup>

Chargez l’archive enregistrée dans Docker avant d’ouvrir son image avec dive :<sup>[[11]](#references)[[13]](#references)</sup>
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Cela vous permet de **parcourir les différents blobs des images Docker** et de vérifier quels fichiers ont été modifiés/ajoutés/supprimés. Utilisez **tab** pour passer à l’autre vue et **espace** pour réduire/développer les dossiers.<sup>[[11]](#references)</sup>

Avec dive, vous ne pourrez pas accéder au contenu des différentes étapes de l’image. Pour ce faire, vous devrez **décompresser chaque layer et y accéder**.\
Vous pouvez décompresser tous les layers d’une image depuis le répertoire où l’image a été décompressée en exécutant :
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Identifiants en mémoire

Sous Linux, l'espace de noms PID ancêtre de l'hôte peut voir les processus de l'espace de noms PID enfant d'un container. Ainsi, une liste des processus de l'hôte telle que `ps -ef` peut les afficher.<sup>[[14]](#references)</sup>

Lorsque les credentials de l'hôte, ses capabilities et la policy LSM/ptrace l'autorisent, un investigateur de l'hôte disposant des privilèges appropriés peut **dump la mémoire des processus** et rechercher des **credentials**, [**comme dans l'exemple suivant**](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#process-memory).<sup>[[15]](#references)</sup>

## References

- [1] [Diff de container Docker](https://docs.docker.com/reference/cli/docker/container/diff/)
- [2] [Copie de container Docker](https://docs.docker.com/reference/cli/docker/container/cp/)
- [3] [Exécution de container Docker](https://docs.docker.com/reference/cli/docker/container/run)
- [4] [Exécution de commande dans un container Docker](https://docs.docker.com/reference/cli/docker/container/exec)
- [5] [GoogleContainerTools/container-diff](https://github.com/GoogleContainerTools/container-diff)
- [6] [Définitions des analyseurs de container-diff](https://github.com/GoogleContainerTools/container-diff/blob/master/differs/differs.go)
- [7] [Sauvegarde d'image Docker](https://docs.docker.com/reference/cli/docker/image/save/)
- [8] [Inspection d'image Docker](https://docs.docker.com/reference/cli/docker/image/inspect/)
- [9] [Historique d'image Docker](https://docs.docker.com/reference/cli/docker/image/history/)
- [10] [alpine-docker/dfimage](https://github.com/alpine-docker/dfimage)
- [11] [README de Dive v0.10.0](https://github.com/wagoodman/dive/blob/v0.10.0/README.md)
- [12] [Version de Dive v0.10.0](https://github.com/wagoodman/dive/releases/tag/v0.10.0)
- [13] [Chargement d'image Docker](https://docs.docker.com/reference/cli/docker/image/load/)
- [14] [pid_namespaces(7)](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html)
- [15] [ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html)
{{#include ../../banners/hacktricks-training.md}}
