# WmiExec

{{#include ../../banners/hacktricks-training.md}}

## Comment ça fonctionne

Des processus peuvent être ouverts sur des hôtes où le nom d'utilisateur et soit le mot de passe soit le hash sont connus grâce à l'utilisation de WMI. Les commandes sont exécutées en utilisant WMI par Wmiexec, offrant une expérience de shell semi-interactive.

**dcomexec.py :** En utilisant différents points de terminaison DCOM, ce script offre un shell semi-interactif semblable à wmiexec.py, tirant spécifiquement parti de l'objet DCOM ShellBrowserWindow. Il prend actuellement en charge les objets Application MMC20, Shell Windows et Shell Browser Window. (source : [Hacking Articles](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/))

## Fondamentaux de WMI

### Espace de noms

Structuré dans une hiérarchie de style répertoire, le conteneur de niveau supérieur de WMI est \root, sous lequel des répertoires supplémentaires, appelés espaces de noms, sont organisés.  
Commandes pour lister les espaces de noms :
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
Les classes au sein d'un espace de noms peuvent être listées en utilisant :
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **Classes**

Connaître le nom d'une classe WMI, comme win32_process, et l'espace de noms dans lequel elle se trouve est crucial pour toute opération WMI.  
Commandes pour lister les classes commençant par `win32`:
```bash
Get-WmiObject -Recurse -List -class win32* | more # Defaults to "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```
Invocation d'une classe :
```bash
# Defaults to "root/cimv2" when namespace isn't specified
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```
### Méthodes

Les méthodes, qui sont une ou plusieurs fonctions exécutables des classes WMI, peuvent être exécutées.
```bash
# Class loading, method listing, and execution
$c = [wmiclass]"win32_share"
$c.methods
# To create a share: $c.Create("c:\share\path","name",0,$null,"My Description")
```

```bash
# Method listing and invocation
Invoke-WmiMethod -Class win32_share -Name Create -ArgumentList @($null, "Description", $null, "Name", $null, "c:\share\path",0)
```
## Énumération WMI

### État du service WMI

Commandes pour vérifier si le service WMI est opérationnel :
```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```
### Informations sur le système et le processus

Collecte d'informations sur le système et le processus via WMI :
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
Get-WmiObject win32_process | Select Name, Processid
```
Pour les attaquants, WMI est un outil puissant pour énumérer des données sensibles sur les systèmes ou les domaines.
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
Interroger à distance WMI pour des informations spécifiques, telles que les administrateurs locaux ou les utilisateurs connectés, est réalisable avec une construction de commande soigneuse.

### **Interrogation WMI à distance manuelle**

L'identification discrète des administrateurs locaux sur une machine distante et des utilisateurs connectés peut être réalisée grâce à des requêtes WMI spécifiques. `wmic` prend également en charge la lecture à partir d'un fichier texte pour exécuter des commandes sur plusieurs nœuds simultanément.

Pour exécuter à distance un processus via WMI, comme le déploiement d'un agent Empire, la structure de commande suivante est utilisée, avec une exécution réussie indiquée par une valeur de retour de "0" :
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
Ce processus illustre la capacité de WMI pour l'exécution à distance et l'énumération du système, mettant en évidence son utilité tant pour l'administration système que pour le pentesting.

## Références

- [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## Outils Automatiques

- [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral redwmi HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe
```
{{#include ../../banners/hacktricks-training.md}}
