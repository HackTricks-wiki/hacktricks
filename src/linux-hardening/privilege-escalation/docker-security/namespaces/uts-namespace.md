# UTS Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Basiese Inligting

'n UTS (UNIX Time-Sharing System) namespace is 'n Linux kernel-funksie wat **isolering van twee stelselidentiteite** verskaf: die **hostname** en die **NIS** (Network Information Service) domeinnaam. Hierdie isolering maak dit moontlik dat elke UTS namespace sy **eie onafhanklike hostname en NIS domeinnaam** het, wat veral nuttig is in containerization-scenario's waar elke container as 'n aparte stelsel met sy eie hostname moet voorkom.

### Hoe dit werk:

1. Wanneer 'n nuwe UTS namespace geskep word, begin dit met 'n **kopie van die hostname en NIS domeinnaam van sy ouer-namespace**. Dit beteken dat, by skepping, die nuwe namespace **dieselfde identifiseerders deel as sy ouer**. Enige daaropvolgende veranderinge aan die hostname of NIS domeinnaam binne die namespace sal egter nie ander namespaces beïnvloed nie.
2. Prosesse binne 'n UTS namespace **kan die hostname en NIS domeinnaam verander** met die system calls `sethostname()` en `setdomainname()`, onderskeidelik. Hierdie veranderings is plaaslik tot die namespace en beïnvloed nie ander namespaces of die gasheerstelsel nie.
3. Prosesse kan tussen namespaces beweeg deur die system call `setns()` te gebruik, of nuwe namespaces skep met die `unshare()` of `clone()` system calls met die `CLONE_NEWUTS` vlag. Wanneer 'n proses na 'n nuwe namespace skuif of een skep, begin dit die hostname en NIS domeinnaam gebruik wat aan daardie namespace gekoppel is.

## Laboratorium:

### Skep verskillende Namespaces

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
### Kyk in watter namespace jou proses is
```bash
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### Vind alle UTS-naamruimtes
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Betree ’n UTS-naamruimte
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
## Misbruik van host UTS sharing

As 'n container gestart word met `--uts=host`, sluit dit by die host UTS namespace aan in plaas daarvan om 'n geïsoleerde een te kry. Met capabilities soos `--cap-add SYS_ADMIN`, kan kode in die container die host hostname/NIS name verander via `sethostname()`/`setdomainname()`:
```bash
docker run --rm -it --uts=host --cap-add SYS_ADMIN alpine sh -c "hostname hacked-host && exec sh"
# Hostname on the host will immediately change to "hacked-host"
```
Om die hostnaam te verander, kan logs en waarskuwings manipuleer, cluster-ontdekking verwar of TLS/SSH-konfigurasies wat die hostnaam vaspen, breek.

### Ontdek containers wat UTS met die host deel
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
# Shows "host" when the container uses the host UTS namespace
```
{{#include ../../../../banners/hacktricks-training.md}}
