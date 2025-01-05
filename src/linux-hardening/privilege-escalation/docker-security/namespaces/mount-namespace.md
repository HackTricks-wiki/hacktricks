# Mount Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

'n mount namespace is 'n Linux-kernfunksie wat isolasie van die lêerstelsel se monteerpunte bied wat deur 'n groep prosesse gesien word. Elke mount namespace het sy eie stel lêerstelsel monteerpunte, en **veranderinge aan die monteerpunte in een namespace beïnvloed nie ander namespaces nie**. Dit beteken dat prosesse wat in verskillende mount namespaces loop, verskillende uitsigte van die lêerstelsel hiërargie kan hê.

Mount namespaces is veral nuttig in containerisering, waar elke houer sy eie lêerstelsel en konfigurasie moet hê, geïsoleer van ander houers en die gasheerstelsel.

### How it works:

1. Wanneer 'n nuwe mount namespace geskep word, word dit geïnitialiseer met 'n **kopie van die monteerpunte van sy ouernamespace**. Dit beteken dat, by skepping, die nuwe namespace dieselfde uitsig van die lêerstelsel as sy ouer deel. egter, enige daaropvolgende veranderinge aan die monteerpunte binne die namespace sal nie die ouer of ander namespaces beïnvloed nie.
2. Wanneer 'n proses 'n monteerpunt binne sy namespace wysig, soos om 'n lêerstelsel te monteer of te demonteer, is die **verandering plaaslik tot daardie namespace** en beïnvloed nie ander namespaces nie. Dit laat elke namespace toe om sy eie onafhanklike lêerstelsel hiërargie te hê.
3. Prosesse kan tussen namespaces beweeg deur die `setns()` stelselskakel te gebruik, of nuwe namespaces te skep met die `unshare()` of `clone()` stelselskakels met die `CLONE_NEWNS` vlag. Wanneer 'n proses na 'n nuwe namespace beweeg of een skep, sal dit begin om die monteerpunte wat met daardie namespace geassosieer is, te gebruik.
4. **Lêerdeskriptoren en inodes word oor namespaces gedeel**, wat beteken dat as 'n proses in een namespace 'n oop lêerdeskriptor het wat na 'n lêer wys, dit kan **daardie lêerdeskriptor** aan 'n proses in 'n ander namespace oorhandig, en **albei prosesse sal toegang tot dieselfde lêer hê**. egter, die lêer se pad mag nie dieselfde wees in albei namespaces nie weens verskille in monteerpunte.

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -m [--mount-proc] /bin/bash
```
Deur 'n nuwe instansie van die `/proc` lêerstelsel te monteer as jy die parameter `--mount-proc` gebruik, verseker jy dat die nuwe monteernaamruimte 'n **akkurate en geïsoleerde weergawe van die prosesinligting spesifiek vir daardie naamruimte** het.

<details>

<summary>Fout: bash: fork: Kan nie geheue toewys nie</summary>

Wanneer `unshare` sonder die `-f` opsie uitgevoer word, word 'n fout ondervind weens die manier waarop Linux nuwe PID (Proses ID) naamruimtes hanteer. Die sleutelbesonderhede en die oplossing word hieronder uiteengesit:

1. **Probleemverklaring**:

- Die Linux-kern laat 'n proses toe om nuwe naamruimtes te skep met die `unshare` stelselaanroep. Die proses wat die skepping van 'n nuwe PID naamruimte inisieer (genoem die "unshare" proses) gaan egter nie in die nuwe naamruimte in nie; slegs sy kindproses gaan.
- Die uitvoering van `%unshare -p /bin/bash%` begin `/bin/bash` in dieselfde proses as `unshare`. Gevolglik is `/bin/bash` en sy kindproses in die oorspronklike PID naamruimte.
- Die eerste kindproses van `/bin/bash` in die nuwe naamruimte word PID 1. Wanneer hierdie proses verlaat, veroorsaak dit die opruiming van die naamruimte as daar geen ander prosesse is nie, aangesien PID 1 die spesiale rol het om weeskindprosesse aan te neem. Die Linux-kern sal dan PID-toewysing in daardie naamruimte deaktiveer.

2. **Gevolg**:

- Die uitgang van PID 1 in 'n nuwe naamruimte lei tot die opruiming van die `PIDNS_HASH_ADDING` vlag. Dit lei tot die `alloc_pid` funksie wat misluk om 'n nuwe PID toe te wys wanneer 'n nuwe proses geskep word, wat die "Kan nie geheue toewys nie" fout veroorsaak.

3. **Oplossing**:
- Die probleem kan opgelos word deur die `-f` opsie saam met `unshare` te gebruik. Hierdie opsie maak dat `unshare` 'n nuwe proses fork nadat die nuwe PID naamruimte geskep is.
- Die uitvoering van `%unshare -fp /bin/bash%` verseker dat die `unshare` opdrag self PID 1 in die nuwe naamruimte word. `/bin/bash` en sy kindproses is dan veilig binne hierdie nuwe naamruimte, wat die voortydige uitgang van PID 1 voorkom en normale PID-toewysing toelaat.

Deur te verseker dat `unshare` met die `-f` vlag loop, word die nuwe PID naamruimte korrek gehandhaaf, wat toelaat dat `/bin/bash` en sy sub-prosesse kan werk sonder om die geheue toewysing fout te ondervind.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Kontroleer in watter naamruimte jou proses is
```bash
ls -l /proc/self/ns/mnt
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/mnt -> 'mnt:[4026531841]'
```
### Vind alle Mount namespaces
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```

```bash
findmnt
```
### Gaan binne 'n Mount namespace in
```bash
nsenter -m TARGET_PID --pid /bin/bash
```
Ook, jy kan slegs **in 'n ander prosesnaamruimte ingaan as jy root is**. En jy **kan nie** **ingaan** in 'n ander naamruimte **sonder 'n beskrywer** wat daarna verwys nie (soos `/proc/self/ns/mnt`).

Omdat nuwe monte slegs binne die naamruimte toeganklik is, is dit moontlik dat 'n naamruimte sensitiewe inligting bevat wat slegs vanaf dit toeganklik is.

### Monteer iets
```bash
# Generate new mount ns
unshare -m /bin/bash
mkdir /tmp/mount_ns_example
mount -t tmpfs tmpfs /tmp/mount_ns_example
mount | grep tmpfs # "tmpfs on /tmp/mount_ns_example"
echo test > /tmp/mount_ns_example/test
ls /tmp/mount_ns_example/test # Exists

# From the host
mount | grep tmpfs # Cannot see "tmpfs on /tmp/mount_ns_example"
ls /tmp/mount_ns_example/test # Doesn't exist
```

```
# findmnt # List existing mounts
TARGET                                SOURCE                                                                                                           FSTYPE     OPTIONS
/                                     /dev/mapper/web05--vg-root

# unshare --mount  # run a shell in a new mount namespace
# mount --bind /usr/bin/ /mnt/
# ls /mnt/cp
/mnt/cp
# exit  # exit the shell, and hence the mount namespace
# ls /mnt/cp
ls: cannot access '/mnt/cp': No such file or directory

## Notice there's different files in /tmp
# ls /tmp
revshell.elf

# ls /mnt/tmp
krb5cc_75401103_X5yEyy
systemd-private-3d87c249e8a84451994ad692609cd4b6-apache2.service-77w9dT
systemd-private-3d87c249e8a84451994ad692609cd4b6-systemd-resolved.service-RnMUhT
systemd-private-3d87c249e8a84451994ad692609cd4b6-systemd-timesyncd.service-FAnDql
vmware-root_662-2689143848

```
## Verwysings

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)
- [https://unix.stackexchange.com/questions/464033/understanding-how-mount-namespaces-work-in-linux](https://unix.stackexchange.com/questions/464033/understanding-how-mount-namespaces-work-in-linux)

{{#include ../../../../banners/hacktricks-training.md}}
