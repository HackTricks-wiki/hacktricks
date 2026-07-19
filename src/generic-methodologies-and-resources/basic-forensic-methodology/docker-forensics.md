# Analyse forensique de Docker

{{#include ../../banners/hacktricks-training.md}}


## Modification du container

Il existe des soupçons selon lesquels un container Docker aurait été compromis :
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Vous pouvez facilement **trouver les modifications effectuées sur ce container par rapport à l’image** avec :
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
Dans la commande précédente, **C** signifie **Modifié** et **A,** **Ajouté**.\
Si vous constatez qu’un fichier intéressant comme `/etc/shadow` a été modifié, vous pouvez le télécharger depuis le conteneur afin de rechercher une activité malveillante avec :
```bash
docker cp wordpress:/etc/shadow.
```
Vous pouvez également **le comparer à l’original** en lançant un nouveau conteneur et en en extrayant le fichier :
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Si vous constatez qu’**un fichier suspect a été ajouté**, vous pouvez accéder au conteneur et l’examiner :
```bash
docker exec -it wordpress bash
```
## Modifications de l’image

Lorsqu’une image Docker exportée vous est fournie (probablement au format `.tar`), vous pouvez utiliser [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) pour **extraire un résumé des modifications** :
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Ensuite, vous pouvez **décompresser** l’image et **accéder aux blobs** pour rechercher les fichiers suspects que vous avez pu trouver dans l’historique des modifications :
```bash
tar -xf image.tar
```
### Analyse de base

Vous pouvez obtenir des **informations de base** à partir de l’image en exécutant :
```bash
docker inspect <image>
```
Vous pouvez également obtenir un résumé de l’**historique des modifications** avec :
```bash
docker history --no-trunc <image>
```
Vous pouvez également générer un **dockerfile à partir d'une image** avec :
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

Pour trouver les fichiers ajoutés ou modifiés dans les images Docker, vous pouvez également utiliser l’utilitaire [**dive**](https://github.com/wagoodman/dive) (téléchargez-le depuis les [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)) :
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Cela vous permet de **naviguer parmi les différents blobs des images Docker** et de vérifier quels fichiers ont été modifiés/ajoutés. Le **rouge** signifie ajouté et le **jaune** signifie modifié. Utilisez **tab** pour passer à l’autre vue et **espace** pour réduire/développer les dossiers.

Avec die, vous ne pourrez pas accéder au contenu des différentes étapes de l’image. Pour cela, vous devrez **décompresser chaque couche et y accéder**.\
Vous pouvez décompresser toutes les couches d’une image depuis le répertoire où l’image a été décompressée en exécutant :
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Identifiants en mémoire

Notez que lorsque vous exécutez un conteneur Docker dans un **hôte**, **vous pouvez voir les processus exécutés dans le conteneur depuis l'hôte** en exécutant simplement `ps -ef`

Par conséquent, (en tant que root), vous pouvez **extraire la mémoire des processus** depuis l'hôte et rechercher des **identifiants** [**comme dans l'exemple suivant**](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#process-memory).


{{#include ../../banners/hacktricks-training.md}}
