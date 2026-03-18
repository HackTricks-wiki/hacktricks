# Gebruiker-naamruimte

{{#include ../../../../banners/hacktricks-training.md}}

{{#ref}}
../docker-breakout-privilege-escalation/README.md
{{#endref}}


## Verwysings

- [https://man7.org/linux/man-pages/man7/user_namespaces.7.html](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
- [https://man7.org/linux/man-pages/man2/mount_setattr.2.html](https://man7.org/linux/man-pages/man2/mount_setattr.2.html)



## Basiese inligting

'n gebruiker-naamruimte is 'n Linux-kernfunksie wat **isolering van gebruiker- en groep-ID-karterings bied**, wat elke gebruiker-naamruimte toelaat om sy **eie stel gebruiker- en groep-ID's** te hê. Hierdie isolasie stel prosesse wat in verskillende gebruiker-naamruimtes loop in staat om **verskillende voorregte en eienaarskap te hê**, selfs al deel hulle numeries dieselfde gebruiker- en groep-ID's.

Gebruiker-naamruimtes is veral nuttig in kontenerisering, waar elke kontainer sy eie onafhanklike stel gebruiker- en groep-ID's moet hê, wat beter sekuriteit en isolasie tussen kontainers en die gashereiste stelsel toelaat.

### Hoe dit werk:

1. Wanneer 'n nuwe gebruiker-naamruimte geskep word, **begin dit met 'n leë stel gebruiker- en groep-ID-karterings**. Dit beteken dat enige proses wat in die nuwe gebruiker-naamruimte loop, **aanvanklik geen voorregte buite die naamruimte sal hê nie**.
2. ID-karterings kan gevestig word tussen die gebruiker- en groep-ID's in die nuwe naamruimte en dié in die ouer (of gasheer) naamruimte. Dit **maak dit moontlik dat prosesse in die nuwe naamruimte voorregte en eienaarskap hê wat ooreenstem met gebruiker- en groep-ID's in die ouer naamruimte**. Die ID-karterings kan egter beperk word tot spesifieke reekse en subsets van ID's, wat fynkorrelbeheer oor die voorregte wat aan prosesse in die nuwe naamruimte gegee word, toelaat.
3. Binne 'n gebruiker-naamruimte kan **prosesse volle root-voorregte (UID 0) hê vir operasies binne die naamruimte**, terwyl hulle steeds beperkte voorregte buite die naamruimte het. Dit laat **kontainers toe om binne hul eie naamruimte met root-agtige vermoëns te loop sonder om volle root-voorregte op die gasheerstelsel te hê**.
4. Prosesse kan tussen naamruimtes beweeg met die `setns()` system call of nuwe naamruimtes skep met die `unshare()` of `clone()` system calls met die `CLONE_NEWUSER` vlag. Wanneer 'n proses na 'n nuwe naamruimte beweeg of een skep, sal dit begin om die gebruiker- en groep-ID-karterings wat met daardie naamruimte geassosieer is, te gebruik.

## Laboratorium:

### Skep verskillende naamruimtes

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
```
By mounting a new instance of the `/proc` filesystem if you use the param `--mount-proc`, you ensure that the new mount namespace has an **accurate and isolated view of the process information specific to that namespace**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

When `unshare` is executed without the `-f` option, an error is encountered due to the way Linux handles new PID (Process ID) namespaces. The key details and the solution are outlined below:

1. **Problem Explanation**:

- The Linux kernel allows a process to create new namespaces using the `unshare` system call. However, the process that initiates the creation of a new PID namespace (referred to as the "unshare" process) does not enter the new namespace; only its child processes do.
- Running %unshare -p /bin/bash% starts `/bin/bash` in the same process as `unshare`. Consequently, `/bin/bash` and its child processes are in the original PID namespace.
- The first child process of `/bin/bash` in the new namespace becomes PID 1. When this process exits, it triggers the cleanup of the namespace if there are no other processes, as PID 1 has the special role of adopting orphan processes. The Linux kernel will then disable PID allocation in that namespace.

2. **Consequence**:

- The exit of PID 1 in a new namespace leads to the cleaning of the `PIDNS_HASH_ADDING` flag. This results in the `alloc_pid` function failing to allocate a new PID when creating a new process, producing the "Cannot allocate memory" error.

3. **Solution**:
- The issue can be resolved by using the `-f` option with `unshare`. This option makes `unshare` fork a new process after creating the new PID namespace.
- Executing %unshare -fp /bin/bash% ensures that the `unshare` command itself becomes PID 1 in the new namespace. `/bin/bash` and its child processes are then safely contained within this new namespace, preventing the premature exit of PID 1 and allowing normal PID allocation.

By ensuring that `unshare` runs with the `-f` flag, the new PID namespace is correctly maintained, allowing `/bin/bash` and its sub-processes to operate without encountering the memory allocation error.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
Om user namespace te gebruik, moet die Docker daemon begin word met **`--userns-remap=default`**(In ubuntu 14.04 kan dit gedoen word deur `/etc/default/docker` te wysig en dan `sudo service docker restart` uit te voer)

### Kyk in watter namespace jou proses is
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
Dit is moontlik om die user map vanaf die docker container te nagaan met:
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
Of vanaf die gasheer met:
```bash
cat /proc/<pid>/uid_map
```
### Vind alle User namespaces
```bash
sudo find /proc -maxdepth 3 -type l -name user -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name user -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Betree 'n User namespace
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
Verder kan jy slegs **in 'n ander proses-namespace binnetree as jy root is**. En jy **kan nie** **binnetree** in 'n ander namespace **sonder 'n descriptor** wat daarna wys (soos `/proc/self/ns/user`).

### Skep nuwe User namespace (met mappings)
```bash
unshare -U [--map-user=<uid>|<name>] [--map-group=<gid>|<name>] [--map-root-user] [--map-current-user]
```

```bash
# Container
sudo unshare -U /bin/bash
nobody@ip-172-31-28-169:/home/ubuntu$ #Check how the user is nobody

# From the host
ps -ef | grep bash # The user inside the host is still root, not nobody
root       27756   27755  0 21:11 pts/10   00:00:00 /bin/bash
```
### Onbevoorregte UID/GID-karteringsreëls

Wanneer die proses wat na `uid_map`/`gid_map` skryf **nie CAP_SETUID/CAP_SETGID in die ouer user namespace het nie**, dwing die kernel strenger reëls af: slegs 'n **enkele kartering** is toegelaat vir die oproeper se effektiewe UID/GID, en vir `gid_map` moet jy eers **`setgroups(2)` deaktiveer** deur `deny` na `/proc/<pid>/setgroups` te skryf.
```bash
# Check whether setgroups is allowed in this user namespace
cat /proc/self/setgroups   # allow|deny

# For unprivileged gid_map writes, disable setgroups first
echo deny > /proc/self/setgroups
```
### ID-gemapte Mounts (MOUNT_ATTR_IDMAP)

ID-gemapte mounts **koppel 'n user namespace-toewysing aan 'n mount**, sodat lêereienaarskap hergemap word wanneer dit deur daardie mount geraak word. Dit word algemeen deur container runtimes (veral rootless) gebruik om **host-paaie te deel sonder rekursiewe `chown`**, terwyl steeds die user namespace se UID/GID-vertaling afgedwing word.

Vanaf 'n offensiewe perspektief, **as jy 'n mount namespace kan skep en `CAP_SYS_ADMIN` binne jou user namespace kan hê**, en die filesystem ondersteun ID-gemapte mounts, kan jy eienaarskap *uitsigte* van bind mounts hermap. Dit **verander nie die eienaarskap on-disk nie**, maar dit kan andersins-nie-skrifbare lêers laat verskyn asof hulle deur jou gemapte UID/GID binne die namespace besit word.

### Terugkry van bevoegdhede

In die geval van user namespaces, **wanneer 'n nuwe user namespace geskep word, word die proses wat die namespace betree 'n volledige stel bevoegdhede binne daardie namespace toegedeel**. Hierdie bevoegdhede laat die proses toe om bevoorregte operasies uit te voer soos **mounting** **filesystems**, toestelle te skep, of eienaarskap van lêers te verander, maar **slegs binne die konteks van sy user namespace**.

Byvoorbeeld, wanneer jy die `CAP_SYS_ADMIN` bevoegdheid binne 'n user namespace het, kan jy operasies uitvoer wat gewoonlik hierdie bevoegdheid vereis, soos die mount van filesystems, maar slegs binne die konteks van jou user namespace. Enige operasies wat jy met hierdie bevoegdheid uitvoer sal nie die host-stelsel of ander namespaces beïnvloed nie.

> [!WARNING]
> Daarom, selfs al gee om 'n nuwe proses binne 'n nuwe User namespace te kry jou **al die bevoegdhede terug** (CapEff: 000001ffffffffff), kan jy in werklikheid **slegs diegene gebruik wat met die namespace verwant is** (byvoorbeeld mount) maar nie elkeen nie. Dus, dit op sigself is nie genoeg om uit 'n Docker container te ontsnap nie.
```bash
# There are the syscalls that are filtered after changing User namespace with:
unshare -UmCpf  bash

Probando: 0x067 . . . Error
Probando: 0x070 . . . Error
Probando: 0x074 . . . Error
Probando: 0x09b . . . Error
Probando: 0x0a3 . . . Error
Probando: 0x0a4 . . . Error
Probando: 0x0a7 . . . Error
Probando: 0x0a8 . . . Error
Probando: 0x0aa . . . Error
Probando: 0x0ab . . . Error
Probando: 0x0af . . . Error
Probando: 0x0b0 . . . Error
Probando: 0x0f6 . . . Error
Probando: 0x12c . . . Error
Probando: 0x130 . . . Error
Probando: 0x139 . . . Error
Probando: 0x140 . . . Error
Probando: 0x141 . . . Error
```
{{#ref}}
../docker-breakout-privilege-escalation/README.md
{{#endref}}


## Verwysings

- [https://man7.org/linux/man-pages/man7/user_namespaces.7.html](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
- [https://man7.org/linux/man-pages/man2/mount_setattr.2.html](https://man7.org/linux/man-pages/man2/mount_setattr.2.html)

{{#include ../../../../banners/hacktricks-training.md}}
