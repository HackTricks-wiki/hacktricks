# IPC Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Osnovne informacije

IPC (Inter-Process Communication) namespace je funkcija Linux kernela koja obezbeđuje **izolaciju** System V IPC objekata, kao što su redovi poruka, segmenti deljene memorije i semafori. Ova izolacija osigurava da procesi u **različitim IPC namespace-ima ne mogu direktno pristupiti ili izmeniti IPC objekte jedni drugih**, pružajući dodatni sloj sigurnosti i privatnosti između grupa procesa.

### Kako to funkcioniše:

1. Kada se kreira novi IPC namespace, počinje sa **potpuno izolovanim skupom System V IPC objekata**. To znači da procesi koji se izvršavaju u novom IPC namespace-u ne mogu pristupiti ili ometati IPC objekte u drugim namespace-ima ili na host sistemu po defaultu.
2. IPC objekti kreirani unutar namespace-a su vidljivi i **pristupačni samo procesima unutar tog namespace-a**. Svaki IPC objekat je identifikovan jedinstvenim ključem unutar svog namespace-a. Iako ključ može biti identičan u različitim namespace-ima, objekti sami su izolovani i ne mogu se pristupiti između namespace-a.
3. Procesi mogu prelaziti između namespace-a koristeći `setns()` sistemski poziv ili kreirati nove namespace-e koristeći `unshare()` ili `clone()` sistemske pozive sa `CLONE_NEWIPC` flagom. Kada proces pređe u novi namespace ili kreira jedan, počeće da koristi IPC objekte povezane sa tim namespace-om.

## Lab:

### Kreirajte različite Namespace-e

#### CLI
```bash
sudo unshare -i [--mount-proc] /bin/bash
```
Montiranjem nove instance `/proc` datotečnog sistema ako koristite parametar `--mount-proc`, osiguravate da nova mount namespace ima **tačan i izolovan prikaz informacija o procesima specifičnim za tu namespace**.

<details>

<summary>Greška: bash: fork: Ne može da dodeli memoriju</summary>

Kada se `unshare` izvrši bez opcije `-f`, dolazi do greške zbog načina na koji Linux upravlja novim PID (Process ID) namespace-ima. Ključni detalji i rešenje su navedeni u nastavku:

1. **Objašnjenje problema**:

- Linux kernel omogućava procesu da kreira nove namespace-e koristeći `unshare` sistemski poziv. Međutim, proces koji inicira kreiranje novog PID namespace-a (poznat kao "unshare" proces) ne ulazi u novi namespace; samo njegovi podprocesi to čine.
- Pokretanjem `%unshare -p /bin/bash%` pokreće se `/bin/bash` u istom procesu kao `unshare`. Kao rezultat, `/bin/bash` i njegovi podprocesi su u originalnom PID namespace-u.
- Prvi podproces `/bin/bash` u novom namespace-u postaje PID 1. Kada ovaj proces izađe, pokreće čišćenje namespace-a ako nema drugih procesa, jer PID 1 ima posebnu ulogu usvajanja siročadi. Linux kernel će tada onemogućiti dodelu PID-a u tom namespace-u.

2. **Posledica**:

- Izlazak PID 1 u novom namespace-u dovodi do čišćenja `PIDNS_HASH_ADDING` oznake. To rezultira neuspehom funkcije `alloc_pid` da dodeli novi PID prilikom kreiranja novog procesa, što proizvodi grešku "Ne može da dodeli memoriju".

3. **Rešenje**:
- Problem se može rešiti korišćenjem opcije `-f` sa `unshare`. Ova opcija čini da `unshare` fork-uje novi proces nakon kreiranja novog PID namespace-a.
- Izvršavanje `%unshare -fp /bin/bash%` osigurava da `unshare` komanda sama postane PID 1 u novom namespace-u. `/bin/bash` i njegovi podprocesi su tada sigurno sadržani unutar ovog novog namespace-a, sprečavajući prevremeni izlazak PID 1 i omogućavajući normalnu dodelu PID-a.

Osiguravanjem da `unshare` radi sa `-f` oznakom, novi PID namespace se ispravno održava, omogućavajući `/bin/bash` i njegovim podprocesima da funkcionišu bez susretanja greške u dodeli memorije.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Proverite u kojem je namespace-u vaš proces
```bash
ls -l /proc/self/ns/ipc
lrwxrwxrwx 1 root root 0 Apr  4 20:37 /proc/self/ns/ipc -> 'ipc:[4026531839]'
```
### Pronađite sve IPC imenske prostore
```bash
sudo find /proc -maxdepth 3 -type l -name ipc -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name ipc -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Uđite u IPC namespace
```bash
nsenter -i TARGET_PID --pid /bin/bash
```
Takođe, možete **ući u drugi procesni namespace samo ako ste root**. I **ne možete** **ući** u drugi namespace **bez deskriptora** koji na njega ukazuje (kao što je `/proc/self/ns/net`).

### Kreirajte IPC objekat
```bash
# Container
sudo unshare -i /bin/bash
ipcmk -M 100
Shared memory id: 0
ipcs -m

------ Shared Memory Segments --------
key        shmid      owner      perms      bytes      nattch     status
0x2fba9021 0          root       644        100        0

# From the host
ipcs -m # Nothing is seen
```
## Reference

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

{{#include ../../../../banners/hacktricks-training.md}}
