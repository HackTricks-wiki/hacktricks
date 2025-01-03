{{#include ../../banners/hacktricks-training.md}}

# Konteynerlerde SELinux

[Redhat belgelerinden giriş ve örnek](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

[SELinux](https://www.redhat.com/en/blog/latest-container-exploit-runc-can-be-blocked-selinux) bir **etiketleme** **sistemidir**. Her **işlem** ve her **dosya** sistemi nesnesinin bir **etiketi** vardır. SELinux politikaları, bir **işlem etiketinin sistemdeki diğer etiketlerle ne yapabileceğine dair kurallar tanımlar**.

Konteyner motorları, genellikle `container_t` olan **tek bir sınırlı SELinux etiketiyle konteyner işlemleri başlatır** ve ardından konteynerin içindeki dosyayı `container_file_t` olarak etiketler. SELinux politika kuralları, **`container_t` işlemlerinin yalnızca `container_file_t` olarak etiketlenmiş dosyaları okuyup/yazabileceğini/çalıştırabileceğini** belirtir. Eğer bir konteyner işlemi konteynerden kaçarsa ve ana makinedeki içeriğe yazmaya çalışırsa, Linux çekirdeği erişimi reddeder ve yalnızca konteyner işleminin `container_file_t` olarak etiketlenmiş içeriğe yazmasına izin verir.
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
# SELinux Kullanıcıları

Normal Linux kullanıcılarına ek olarak SELinux kullanıcıları da vardır. SELinux kullanıcıları bir SELinux politikasının parçasıdır. Her Linux kullanıcısı, politikanın bir parçası olarak bir SELinux kullanıcısına eşlenir. Bu, Linux kullanıcılarının SELinux kullanıcılarına uygulanan kısıtlamaları ve güvenlik kurallarını ve mekanizmalarını miras almasını sağlar.

{{#include ../../banners/hacktricks-training.md}}
