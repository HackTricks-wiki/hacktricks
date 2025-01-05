# UTS Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Osnovne informacije

UTS (UNIX Time-Sharing System) namespace je funkcija Linux kernela koja obezbeđuje **izolaciju dva sistemska identifikatora**: **hostname** i **NIS** (Network Information Service) domena. Ova izolacija omogućava svakom UTS namespace-u da ima **svoj nezavistan hostname i NIS domen**, što je posebno korisno u scenarijima kontejnerizacije gde svaki kontejner treba da se pojavljuje kao poseban sistem sa svojim hostname-om.

### Kako to funkcioniše:

1. Kada se kreira novi UTS namespace, on počinje sa **kopijom hostname-a i NIS domena iz svog roditeljskog namespace-a**. To znači da, prilikom kreiranja, novi namespace **deliti iste identifikatore kao njegov roditelj**. Međutim, sve kasnije promene na hostname-u ili NIS domenu unutar namespace-a neće uticati na druge namespace-e.
2. Procesi unutar UTS namespace-a **mogu promeniti hostname i NIS domen** koristeći sistemske pozive `sethostname()` i `setdomainname()`, redom. Ove promene su lokalne za namespace i ne utiču na druge namespace-e ili host sistem.
3. Procesi mogu prelaziti između namespace-a koristeći sistemski poziv `setns()` ili kreirati nove namespace-e koristeći sistemske pozive `unshare()` ili `clone()` sa `CLONE_NEWUTS` flagom. Kada proces pređe u novi namespace ili ga kreira, počeće da koristi hostname i NIS domen koji su povezani sa tim namespace-om.

## Lab:

### Kreirajte različite Namespace-e

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
Montiranjem nove instance `/proc` datotečnog sistema ako koristite parametar `--mount-proc`, osiguravate da nova mount namespace ima **tačan i izolovan prikaz informacija o procesima specifičnim za tu namespace**.

<details>

<summary>Greška: bash: fork: Ne može da alocira memoriju</summary>

Kada se `unshare` izvrši bez opcije `-f`, dolazi do greške zbog načina na koji Linux upravlja novim PID (Process ID) namespace-ima. Ključni detalji i rešenje su navedeni u nastavku:

1. **Objašnjenje problema**:

- Linux kernel omogućava procesu da kreira nove namespace-e koristeći `unshare` sistemski poziv. Međutim, proces koji inicira kreiranje novog PID namespace-a (poznat kao "unshare" proces) ne ulazi u novi namespace; samo njegovi podprocesi to čine.
- Pokretanjem `%unshare -p /bin/bash%` pokreće se `/bin/bash` u istom procesu kao `unshare`. Kao rezultat, `/bin/bash` i njegovi podprocesi su u originalnom PID namespace-u.
- Prvi podproces `/bin/bash` u novom namespace-u postaje PID 1. Kada ovaj proces izađe, pokreće čišćenje namespace-a ako nema drugih procesa, jer PID 1 ima posebnu ulogu usvajanja siročadi. Linux kernel će tada onemogućiti alokaciju PID-a u tom namespace-u.

2. **Posledica**:

- Izlazak PID 1 u novom namespace-u dovodi do čišćenja `PIDNS_HASH_ADDING` oznake. To rezultira neuspehom funkcije `alloc_pid` da alocira novi PID prilikom kreiranja novog procesa, što proizvodi grešku "Ne može da alocira memoriju".

3. **Rešenje**:
- Problem se može rešiti korišćenjem opcije `-f` sa `unshare`. Ova opcija čini da `unshare` fork-uje novi proces nakon kreiranja novog PID namespace-a.
- Izvršavanje `%unshare -fp /bin/bash%` osigurava da sam `unshare` komanda postane PID 1 u novom namespace-u. `/bin/bash` i njegovi podprocesi su tada sigurno sadržani unutar ovog novog namespace-a, sprečavajući prevremeni izlazak PID 1 i omogućavajući normalnu alokaciju PID-a.

Osiguravanjem da `unshare` radi sa `-f` oznakom, novi PID namespace se ispravno održava, omogućavajući `/bin/bash` i njegove podprocese da funkcionišu bez susretanja greške u alokaciji memorije.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Proverite u kojem je namespace-u vaš proces
```bash
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### Pronađite sve UTS imenske prostore
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Uđite unutar UTS imenskog prostora
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
{{#include ../../../../banners/hacktricks-training.md}}
