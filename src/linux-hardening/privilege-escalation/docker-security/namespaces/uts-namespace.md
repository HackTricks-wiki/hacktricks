# UTS prostor imena

{{#include ../../../../banners/hacktricks-training.md}}

## Osnovne informacije

UTS (UNIX Time-Sharing System) namespace je Linux kernel feature koji obezbeđuje **izolaciju dva sistemska identifikatora**: **hostname** i **NIS** (Network Information Service) domain name. Ova izolacija omogućava svakom UTS namespace-u da ima svoj **nezavisan hostname i NIS domain name**, što je posebno korisno u scenarijima containerization gde svaki container treba da izgleda kao zaseban sistem sa sopstvenim hostname-om.

### Kako funkcioniše:

1. Kada se kreira novi UTS namespace, on počinje sa **kopijom hostname-a i NIS domain name-a iz svog roditeljskog namespace-a**. To znači da pri kreiranju novi namespace **deli iste identifikatore kao njegov roditelj**. Međutim, bilo kakve naknadne promene hostname-a ili NIS domain name-a unutar namespace-a neće uticati na druge namespace-ove.
2. Procesi unutar UTS namespace-a **mogu da menjaju hostname i NIS domain name** koristeći sistemske pozive `sethostname()` i `setdomainname()`, respektivno. Te promene su lokalne za namespace i ne utiču na druge namespace-ove ili host sistem.
3. Procesi se mogu premeštati između namespace-ova koristeći sistemski poziv `setns()` ili kreirati nove namespace-ove koristeći `unshare()` ili `clone()` sa flag-om `CLONE_NEWUTS`. Kada se proces premesti u novi namespace ili ga kreira, on će početi da koristi hostname i NIS domain name povezane sa tim namespace-om.

## Lab:

### Kreiranje različitih prostora imena

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
### Proverite u kojem namespace-u se nalazi vaš proces
```bash
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### Pronađite sve UTS namespaces
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Uđite u UTS namespace
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
## Zloupotreba deljenja UTS prostora hosta

Ako je kontejner pokrenut sa `--uts=host`, on se priključuje UTS namespace-u hosta umesto da dobije izolovani. Sa privilegijama kao što su `--cap-add SYS_ADMIN`, kod u kontejneru može promeniti hostname/NIS ime hosta pomoću `sethostname()`/`setdomainname()`:
```bash
docker run --rm -it --uts=host --cap-add SYS_ADMIN alpine sh -c "hostname hacked-host && exec sh"
# Hostname on the host will immediately change to "hacked-host"
```
Promena imena hosta može da manipuliše logovima/alertima, zbuni otkrivanje klastera ili pokvari TLS/SSH konfiguracije koje vezuju ime hosta.

### Otkrivanje kontejnera koji dele UTS sa hostom
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
# Shows "host" when the container uses the host UTS namespace
```
{{#include ../../../../banners/hacktricks-training.md}}
