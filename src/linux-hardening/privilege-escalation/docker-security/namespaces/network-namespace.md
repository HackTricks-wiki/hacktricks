# Mrežni Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Osnovne Informacije

Mrežni namespace je funkcija Linux kernela koja obezbeđuje izolaciju mrežnog steka, omogućavajući **svakom mrežnom namespace-u da ima svoju nezavisnu mrežnu konfiguraciju**, interfejse, IP adrese, tabele rutiranja i pravila vatrozida. Ova izolacija je korisna u raznim scenarijima, kao što je kontejnerizacija, gde svaki kontejner treba da ima svoju mrežnu konfiguraciju, nezavisno od drugih kontejnera i host sistema.

### Kako to funkcioniše:

1. Kada se kreira novi mrežni namespace, počinje sa **potpuno izolovanim mrežnim stekom**, sa **nema mrežnih interfejsa** osim za loopback interfejs (lo). To znači da procesi koji se izvršavaju u novom mrežnom namespace-u ne mogu komunicirati sa procesima u drugim namespace-ima ili host sistemu po defaultu.
2. **Virtuelni mrežni interfejsi**, kao što su veth parovi, mogu se kreirati i premestiti između mrežnih namespace-a. To omogućava uspostavljanje mrežne povezanosti između namespace-a ili između namespace-a i host sistema. Na primer, jedan kraj veth para može biti postavljen u mrežni namespace kontejnera, a drugi kraj može biti povezan sa **mostom** ili drugim mrežnim interfejsom u host namespace-u, obezbeđujući mrežnu povezanost kontejneru.
3. Mrežni interfejsi unutar namespace-a mogu imati svoje **vlastite IP adrese, tabele rutiranja i pravila vatrozida**, nezavisno od drugih namespace-a. To omogućava procesima u različitim mrežnim namespace-ima da imaju različite mrežne konfiguracije i funkcionišu kao da se izvršavaju na odvojenim umreženim sistemima.
4. Procesi mogu prelaziti između namespace-a koristeći `setns()` sistemski poziv, ili kreirati nove namespace-e koristeći `unshare()` ili `clone()` sistemske pozive sa `CLONE_NEWNET` zastavicom. Kada proces pređe u novi namespace ili ga kreira, počeće da koristi mrežnu konfiguraciju i interfejse povezane sa tim namespace-om.

## Laboratorija:

### Kreirajte različite Namespace-e

#### CLI
```bash
sudo unshare -n [--mount-proc] /bin/bash
# Run ifconfig or ip -a
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
# Run ifconfig or ip -a
```
### &#x20;Proverite u kojem je namespace vaš proces
```bash
ls -l /proc/self/ns/net
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/net -> 'net:[4026531840]'
```
### Pronađi sve mrežne imenske prostore
```bash
sudo find /proc -maxdepth 3 -type l -name net -exec readlink {} \; 2>/dev/null | sort -u | grep "net:"
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name net -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Uđite u mrežni prostor imena
```bash
nsenter -n TARGET_PID --pid /bin/bash
```
Takođe, možete **ući u drugi procesni namespace samo ako ste root**. I **ne možete** **ući** u drugi namespace **bez deskriptora** koji na njega ukazuje (kao što je `/proc/self/ns/net`).

## References

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

{{#include ../../../../banners/hacktricks-training.md}}
