# Простір імен UTS

{{#include ../../../../banners/hacktricks-training.md}}

## Основна інформація

Простір імен UTS (UNIX Time-Sharing System) — це функція ядра Linux, яка забезпечує i**ізоляцію двох системних ідентифікаторів**: **hostname** та **NIS** (Network Information Service) доменне ім'я. Ця ізоляція дозволяє кожному простору імен UTS мати своє **власне незалежне hostname та NIS domain name**, що особливо корисно в сценаріях контейнеризації, де кожен контейнер має виглядати як окрема система зі своїм hostname.

### Як це працює:

1. Коли створюється новий простір імен UTS, він починається з **копії hostname та NIS domain name з батьківського простору імен**. Це означає, що при створенні новий простір імен s**дiлить ті ж ідентифікатори, що й його батьківський**. Однак будь-які подальші зміни hostname або NIS domain name всередині простору імен не впливають на інші простори імен.
2. Процеси в межах простору імен UTS **можуть змінювати hostname та NIS domain name** за допомогою системних викликів `sethostname()` та `setdomainname()` відповідно. Ці зміни локальні для простору імен і не впливають на інші простори імен або хост-систему.
3. Процеси можуть переміщуватися між просторами імен за допомогою системного виклику `setns()` або створювати нові простори імен за допомогою `unshare()` або `clone()` з прапорцем `CLONE_NEWUTS`. Коли процес переходить у новий простір імен або створює його, він починає використовувати hostname та NIS domain name, асоційовані з тим простором імен.

## Лабораторія:

### Створення різних просторів імен

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
By mounting a new instance of the `/proc` filesystem if you use the param `--mount-proc`, you ensure that the new mount namespace has an **accurate and isolated view of the process information specific to that namespace**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

When `unshare` is executed without the `-f` option, an error is encountered due to the way Linux handles new PID (Process ID) namespaces. The key details and the solution are outlined below:

1. **Problem Explanation**:

- The Linux kernel allows a process to create new namespaces using the `unshare` system call. However, the process that initiates the creation of a new PID namespace (referred to as the "unshare" process) does not enter the new namespace; only its child processes do.
- Running `%unshare -p /bin/bash%` starts `/bin/bash` in the same process as `unshare`. Consequently, `/bin/bash` and its child processes are in the original PID namespace.
- The first child process of `/bin/bash` in the new namespace becomes PID 1. When this process exits, it triggers the cleanup of the namespace if there are no other processes, as PID 1 has the special role of adopting orphan processes. The Linux kernel will then disable PID allocation in that namespace.

2. **Consequence**:

- The exit of PID 1 in a new namespace leads to the cleaning of the `PIDNS_HASH_ADDING` flag. This results in the `alloc_pid` function failing to allocate a new PID when creating a new process, producing the "Cannot allocate memory" error.

3. **Solution**:
- The issue can be resolved by using the `-f` option with `unshare`. This option makes `unshare` fork a new process after creating the new PID namespace.
- Executing `%unshare -fp /bin/bash%` ensures that the `unshare` command itself becomes PID 1 in the new namespace. `/bin/bash` and its child processes are then safely contained within this new namespace, preventing the premature exit of PID 1 and allowing normal PID allocation.

By ensuring that `unshare` runs with the `-f` flag, the new PID namespace is correctly maintained, allowing `/bin/bash` and its sub-processes to operate without encountering the memory allocation error.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Перевірте, у якому namespace перебуває ваш процес
```bash
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### Знайти всі UTS-простори імен
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Увійти в UTS namespace
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
## Зловживання спільним використанням UTS хоста

Якщо контейнер запущено з `--uts=host`, він приєднується до простору імен UTS хоста замість отримання ізольованого.

З можливостями, такими як `--cap-add SYS_ADMIN`, код у контейнері може змінити hostname/NIS name хоста через `sethostname()`/`setdomainname()`:
```bash
docker run --rm -it --uts=host --cap-add SYS_ADMIN alpine sh -c "hostname hacked-host && exec sh"
# Hostname on the host will immediately change to "hacked-host"
```
Зміна імені хоста може спотворити логи/сповіщення, заплутати виявлення кластера або пошкодити конфігурації TLS/SSH, що прив'язують ім'я хоста.

### Виявлення контейнерів, які ділять UTS з хостом
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
# Shows "host" when the container uses the host UTS namespace
```
{{#include ../../../../banners/hacktricks-training.md}}
