# SCMExec

{{#include ../../banners/hacktricks-training.md}}

## Fonctionnement

Le Service Control Manager Remote Protocol (SCMR) est un protocole basé sur RPC permettant de configurer et de contrôler les services Windows sur un ordinateur distant. Avec des permissions suffisantes, un opérateur peut créer ou reconfigurer un service dont le chemin du binaire contient une commande, puis démarrer ce service afin d’exécuter la commande à distance.<sup>[[1]](#references)</sup>

## Outils

**SharpMove** prend en charge l’exécution distante authentifiée via SCM ainsi que plusieurs autres mécanismes Windows. L’exemple suivant sélectionne son action SCM, crée un service nommé `WindowsDebug` et le fait pointer vers un payload déjà présent sur l’hôte distant.<sup>[[2]](#references)</sup>
```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```
## References

- [1] [Microsoft Open Specifications - Vue d’ensemble du protocole distant Service Control Manager](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [2] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
{{#include ../../banners/hacktricks-training.md}}
