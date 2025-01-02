# CGroup Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Osnovne informacije

Cgroup namespace je funkcija Linux jezgra koja pruža **izolaciju cgroup hijerarhija za procese koji se izvršavaju unutar namespace-a**. Cgroups, skraćeno za **kontrolne grupe**, su funkcija jezgra koja omogućava organizovanje procesa u hijerarhijske grupe radi upravljanja i sprovođenja **ograničenja na sistemske resurse** kao što su CPU, memorija i I/O.

Iako cgroup namespace-i nisu poseban tip namespace-a kao što su drugi koje smo ranije diskutovali (PID, mount, network, itd.), oni su povezani sa konceptom izolacije namespace-a. **Cgroup namespace-i virtualizuju pogled na cgroup hijerarhiju**, tako da procesi koji se izvršavaju unutar cgroup namespace-a imaju drugačiji pogled na hijerarhiju u poređenju sa procesima koji se izvršavaju na hostu ili u drugim namespace-ima.

### Kako to funkcioniše:

1. Kada se kreira novi cgroup namespace, **on počinje sa pogledom na cgroup hijerarhiju zasnovanom na cgroup-u procesa koji ga kreira**. To znači da će procesi koji se izvršavaju u novom cgroup namespace-u videti samo podskup cele cgroup hijerarhije, ograničen na cgroup podstablo koje se oslanja na cgroup procesa koji ga kreira.
2. Procesi unutar cgroup namespace-a će **videti svoju vlastitu cgroup kao koren hijerarhije**. To znači da, iz perspektive procesa unutar namespace-a, njihova vlastita cgroup se pojavljuje kao koren, i ne mogu videti ili pristupiti cgroup-ima van svog podstabla.
3. Cgroup namespace-i ne pružaju direktno izolaciju resursa; **oni samo pružaju izolaciju pogleda na cgroup hijerarhiju**. **Kontrola i izolacija resursa se i dalje sprovode od strane cgroup** pod sistema (npr., cpu, memorija, itd.) sami.

Za više informacija o CGroups proverite:

{{#ref}}
../cgroups.md
{{#endref}}

## Laboratorija:

### Kreirajte različite Namespace-e

#### CLI
```bash
sudo unshare -C [--mount-proc] /bin/bash
```
Montiranjem nove instance `/proc` datotečnog sistema ako koristite parametar `--mount-proc`, osiguravate da nova mount namespace ima **tačan i izolovan prikaz informacija o procesima specifičnim za tu namespace**.

<details>

<summary>Greška: bash: fork: Ne može da dodeli memoriju</summary>

Kada se `unshare` izvrši bez opcije `-f`, dolazi do greške zbog načina na koji Linux upravlja novim PID (ID procesa) namespace-ima. Ključni detalji i rešenje su navedeni u nastavku:

1. **Objašnjenje problema**:

- Linux kernel omogućava procesu da kreira nove namespace-e koristeći `unshare` sistemski poziv. Međutim, proces koji inicira kreiranje novog PID namespace-a (poznat kao "unshare" proces) ne ulazi u novi namespace; samo njegovi podprocesi to čine.
- Pokretanjem `%unshare -p /bin/bash%` pokreće se `/bin/bash` u istom procesu kao `unshare`. Kao rezultat, `/bin/bash` i njegovi podprocesi su u originalnom PID namespace-u.
- Prvi podproces `/bin/bash` u novom namespace-u postaje PID 1. Kada ovaj proces izađe, pokreće čišćenje namespace-a ako nema drugih procesa, jer PID 1 ima posebnu ulogu usvajanja siročadi procesa. Linux kernel će tada onemogućiti dodelu PID-a u tom namespace-u.

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
ls -l /proc/self/ns/cgroup
lrwxrwxrwx 1 root root 0 Apr  4 21:19 /proc/self/ns/cgroup -> 'cgroup:[4026531835]'
```
### Pronađite sve CGroup imenske prostore
```bash
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name cgroup -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Uđite u CGroup namespace
```bash
nsenter -C TARGET_PID --pid /bin/bash
```
Takođe, možete **ući u drugi procesni namespace samo ako ste root**. I **ne možete** **ući** u drugi namespace **bez deskriptora** koji na njega ukazuje (kao što je `/proc/self/ns/cgroup`).

## References

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

{{#include ../../../../banners/hacktricks-training.md}}
