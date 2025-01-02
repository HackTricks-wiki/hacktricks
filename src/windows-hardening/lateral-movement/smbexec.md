# SmbExec/ScExec

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="/images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Obtenez la perspective d'un hacker sur vos applications web, votre réseau et votre cloud**

**Trouvez et signalez des vulnérabilités critiques et exploitables ayant un impact commercial réel.** Utilisez nos plus de 20 outils personnalisés pour cartographier la surface d'attaque, trouver des problèmes de sécurité qui vous permettent d'escalader les privilèges, et utilisez des exploits automatisés pour collecter des preuves essentielles, transformant votre travail acharné en rapports convaincants.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

## Comment ça fonctionne

**Smbexec** est un outil utilisé pour l'exécution de commandes à distance sur des systèmes Windows, similaire à **Psexec**, mais il évite de placer des fichiers malveillants sur le système cible.

### Points clés sur **SMBExec**

- Il fonctionne en créant un service temporaire (par exemple, "BTOBTO") sur la machine cible pour exécuter des commandes via cmd.exe (%COMSPEC%), sans déposer de binaires.
- Malgré son approche furtive, il génère des journaux d'événements pour chaque commande exécutée, offrant une forme de "shell" non interactif.
- La commande pour se connecter en utilisant **Smbexec** ressemble à ceci :
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### Exécution de commandes sans binaires

- **Smbexec** permet l'exécution directe de commandes via les binPaths de service, éliminant le besoin de binaires physiques sur la cible.
- Cette méthode est utile pour exécuter des commandes ponctuelles sur une cible Windows. Par exemple, l'associer au module `web_delivery` de Metasploit permet l'exécution d'un payload Meterpreter inversé ciblé sur PowerShell.
- En créant un service distant sur la machine de l'attaquant avec binPath configuré pour exécuter la commande fournie via cmd.exe, il est possible d'exécuter le payload avec succès, réalisant un rappel et l'exécution du payload avec l'auditeur Metasploit, même si des erreurs de réponse de service se produisent.

### Exemple de commandes

La création et le démarrage du service peuvent être réalisés avec les commandes suivantes :
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
Pour plus de détails, consultez [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## Références

- [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<figure><img src="/images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Obtenez la perspective d'un hacker sur vos applications web, votre réseau et votre cloud**

**Trouvez et signalez des vulnérabilités critiques et exploitables ayant un impact commercial réel.** Utilisez nos 20+ outils personnalisés pour cartographier la surface d'attaque, trouver des problèmes de sécurité qui vous permettent d'escalader les privilèges, et utilisez des exploits automatisés pour collecter des preuves essentielles, transformant votre travail acharné en rapports convaincants.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

{{#include ../../banners/hacktricks-training.md}}
