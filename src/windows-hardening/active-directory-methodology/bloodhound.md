# BloodHound & Autres Outils d'Enumération AD

{{#include ../../banners/hacktricks-training.md}}

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) est issu de la Sysinternal Suite :

> Un visualiseur et éditeur avancé d'Active Directory (AD). Vous pouvez utiliser AD Explorer pour naviguer facilement dans une base de données AD, définir des emplacements favoris, afficher les propriétés des objets et les attributs sans ouvrir de boîtes de dialogue, modifier les autorisations, voir le schéma d'un objet et exécuter des recherches sophistiquées que vous pouvez enregistrer et réexécuter.

### Instantanés

AD Explorer peut créer des instantanés d'un AD afin que vous puissiez le vérifier hors ligne.\
Il peut être utilisé pour découvrir des vulnérabilités hors ligne, ou pour comparer différents états de la base de données AD au fil du temps.

Vous aurez besoin du nom d'utilisateur, du mot de passe et de la direction pour vous connecter (tout utilisateur AD est requis).

Pour prendre un instantané de l'AD, allez dans `File` --> `Create Snapshot` et entrez un nom pour l'instantané.

## ADRecon

[**ADRecon**](https://github.com/adrecon/ADRecon) est un outil qui extrait et combine divers artefacts d'un environnement AD. Les informations peuvent être présentées dans un **rapport** Microsoft Excel **spécialement formaté** qui inclut des vues résumées avec des métriques pour faciliter l'analyse et fournir une image holistique de l'état actuel de l'environnement AD cible.
```bash
# Run it
.\ADRecon.ps1
```
## BloodHound

From [https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)

> BloodHound est une application web Javascript à page unique, construite sur [Linkurious](http://linkurio.us/), compilée avec [Electron](http://electron.atom.io/), avec une base de données [Neo4j](https://neo4j.com/) alimentée par un collecteur de données C#.

BloodHound utilise la théorie des graphes pour révéler les relations cachées et souvent non intentionnelles au sein d'un environnement Active Directory ou Azure. Les attaquants peuvent utiliser BloodHound pour identifier facilement des chemins d'attaque hautement complexes qui seraient autrement impossibles à identifier rapidement. Les défenseurs peuvent utiliser BloodHound pour identifier et éliminer ces mêmes chemins d'attaque. Les équipes bleues et rouges peuvent utiliser BloodHound pour acquérir facilement une compréhension plus approfondie des relations de privilège dans un environnement Active Directory ou Azure.

Ainsi, [Bloodhound ](https://github.com/BloodHoundAD/BloodHound) est un outil incroyable qui peut énumérer un domaine automatiquement, sauvegarder toutes les informations, trouver des chemins d'escalade de privilèges possibles et afficher toutes les informations à l'aide de graphes.

BloodHound est composé de 2 parties principales : **ingestors** et l'**application de visualisation**.

Les **ingestors** sont utilisés pour **énumérer le domaine et extraire toutes les informations** dans un format que l'application de visualisation comprendra.

L'**application de visualisation utilise neo4j** pour montrer comment toutes les informations sont liées et pour montrer différentes façons d'escalader les privilèges dans le domaine.

### Installation

Après la création de BloodHound CE, l'ensemble du projet a été mis à jour pour faciliter son utilisation avec Docker. La façon la plus simple de commencer est d'utiliser sa configuration Docker Compose préconfigurée.

1. Installez Docker Compose. Cela devrait être inclus avec l'installation de [Docker Desktop](https://www.docker.com/products/docker-desktop/).
2. Exécutez :
```
curl -L https://ghst.ly/getbhce | docker compose -f - up
```
3. Localisez le mot de passe généré aléatoirement dans la sortie du terminal de Docker Compose.  
4. Dans un navigateur, accédez à http://localhost:8080/ui/login. Connectez-vous avec le nom d'utilisateur admin et le mot de passe généré aléatoirement à partir des journaux.

Après cela, vous devrez changer le mot de passe généré aléatoirement et vous aurez la nouvelle interface prête, à partir de laquelle vous pourrez télécharger directement les ingestors.

### SharpHound

Ils ont plusieurs options, mais si vous souhaitez exécuter SharpHound depuis un PC joint au domaine, en utilisant votre utilisateur actuel et extraire toutes les informations, vous pouvez faire :
```
./SharpHound.exe --CollectionMethods All
Invoke-BloodHound -CollectionMethod All
```
> Vous pouvez en savoir plus sur **CollectionMethod** et la session de boucle [ici](https://support.bloodhoundenterprise.io/hc/en-us/articles/17481375424795-All-SharpHound-Community-Edition-Flags-Explained)

Si vous souhaitez exécuter SharpHound en utilisant des identifiants différents, vous pouvez créer une session CMD netonly et exécuter SharpHound à partir de là :
```
runas /netonly /user:domain\user "powershell.exe -exec bypass"
```
[**En savoir plus sur Bloodhound sur ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux)

## Group3r

[**Group3r**](https://github.com/Group3r/Group3r) est un outil pour trouver des **vulnérabilités** dans Active Directory associées à **Group Policy**. \
Vous devez **exécuter group3r** depuis un hôte à l'intérieur du domaine en utilisant **n'importe quel utilisateur de domaine**.
```bash
group3r.exe -f <filepath-name.log>
# -s sends results to stdin
# -f send results to file
```
## PingCastle

[**PingCastle**](https://www.pingcastle.com/documentation/) **évalue la posture de sécurité d'un environnement AD** et fournit un joli **rapport** avec des graphiques.

Pour l'exécuter, vous pouvez lancer le binaire `PingCastle.exe` et il démarrera une **session interactive** présentant un menu d'options. L'option par défaut à utiliser est **`healthcheck`** qui établira un **aperçu** de base du **domaine**, et trouvera des **mauvais configurations** et des **vulnérabilités**.

{{#include ../../banners/hacktricks-training.md}}
