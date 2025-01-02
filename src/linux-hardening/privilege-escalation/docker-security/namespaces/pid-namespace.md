# PID Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Osnovne informacije

PID (Process IDentifier) namespace je funkcija u Linux kernelu koja obezbeđuje izolaciju procesa omogućavajući grupi procesa da ima svoj set jedinstvenih PID-ova, odvojenih od PID-ova u drugim namespace-ima. Ovo je posebno korisno u kontejnerizaciji, gde je izolacija procesa ključna za bezbednost i upravljanje resursima.

Kada se kreira novi PID namespace, prvi proces u tom namespace-u dobija PID 1. Ovaj proces postaje "init" proces novog namespace-a i odgovoran je za upravljanje drugim procesima unutar namespace-a. Svaki sledeći proces kreiran unutar namespace-a će imati jedinstven PID unutar tog namespace-a, a ovi PID-ovi će biti nezavisni od PID-ova u drugim namespace-ima.

Sa stanovišta procesa unutar PID namespace-a, može videti samo druge procese u istom namespace-u. Nije svesno procesa u drugim namespace-ima i ne može interagovati s njima koristeći tradicionalne alate za upravljanje procesima (npr., `kill`, `wait`, itd.). Ovo obezbeđuje nivo izolacije koji pomaže u sprečavanju ometanja procesa jednih drugima.

### Kako to funkcioniše:

1. Kada se kreira novi proces (npr., korišćenjem `clone()` sistemskog poziva), proces može biti dodeljen novom ili postojećem PID namespace-u. **Ako se kreira novi namespace, proces postaje "init" proces tog namespace-a**.
2. **Kernel** održava **mapiranje između PID-ova u novom namespace-u i odgovarajućih PID-ova** u roditeljskom namespace-u (tj. namespace-u iz kojeg je novi namespace kreiran). Ovo mapiranje **omogućava kernelu da prevodi PID-ove kada je to potrebno**, kao kada se šalju signali između procesa u različitim namespace-ima.
3. **Procesi unutar PID namespace-a mogu videti i interagovati samo sa drugim procesima u istom namespace-u**. Nisu svesni procesa u drugim namespace-ima, a njihovi PID-ovi su jedinstveni unutar njihovog namespace-a.
4. Kada se **PID namespace uništi** (npr., kada "init" proces namespace-a izađe), **svi procesi unutar tog namespace-a se prekidaju**. Ovo osigurava da se svi resursi povezani sa namespace-om pravilno očiste.

## Lab:

### Kreirajte različite Namespace-e

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>Greška: bash: fork: Ne može da dodeli memoriju</summary>

Kada se `unshare` izvrši bez `-f` opcije, dolazi do greške zbog načina na koji Linux upravlja novim PID (ID procesa) prostorima imena. Ključni detalji i rešenje su navedeni u nastavku:

1. **Objašnjenje problema**:

- Linux kernel omogućava procesu da kreira nove prostore imena koristeći `unshare` sistemski poziv. Međutim, proces koji inicira kreiranje novog PID prostora imena (poznat kao "unshare" proces) ne ulazi u novi prostor imena; samo njegovi podprocesi to čine.
- Pokretanje `%unshare -p /bin/bash%` pokreće `/bin/bash` u istom procesu kao `unshare`. Kao rezultat, `/bin/bash` i njegovi podprocesi su u originalnom PID prostoru imena.
- Prvi podproces `/bin/bash` u novom prostoru imena postaje PID 1. Kada ovaj proces izađe, pokreće čišćenje prostora imena ako nema drugih procesa, jer PID 1 ima posebnu ulogu usvajanja siročadi. Linux kernel će tada onemogućiti dodeljivanje PID-a u tom prostoru imena.

2. **Posledica**:

- Izlazak PID 1 u novom prostoru imena dovodi do čišćenja `PIDNS_HASH_ADDING` oznake. To rezultira neuspehom funkcije `alloc_pid` da dodeli novi PID prilikom kreiranja novog procesa, što proizvodi grešku "Ne može da dodeli memoriju".

3. **Rešenje**:
- Problem se može rešiti korišćenjem `-f` opcije sa `unshare`. Ova opcija čini da `unshare` fork-uje novi proces nakon kreiranja novog PID prostora imena.
- Izvršavanje `%unshare -fp /bin/bash%` osigurava da sam `unshare` komanda postane PID 1 u novom prostoru imena. `/bin/bash` i njegovi podprocesi su tada bezbedno sadržani unutar ovog novog prostora imena, sprečavajući prevremeni izlazak PID 1 i omogućavajući normalno dodeljivanje PID-a.

Osiguravanjem da `unshare` radi sa `-f` oznakom, novi PID prostor imena se ispravno održava, omogućavajući `/bin/bash` i njegovim podprocesima da funkcionišu bez susretanja greške u dodeljivanju memorije.

</details>

Montiranjem nove instance `/proc` datotečnog sistema ako koristite parametar `--mount-proc`, osiguravate da novi prostor imena montiranja ima **tačan i izolovan prikaz informacija o procesima specifičnim za taj prostor imena**.

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Proverite u kojem je namespace vaš proces
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### Pronađite sve PID imenske prostore
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
Napomena da root korisnik iz inicijalnog (podrazumevanog) PID imenskog prostora može videti sve procese, čak i one u novim PID imenskim prostorima, zato možemo videti sve PID imenske prostore.

### Ući unutar PID imenskog prostora
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
Kada uđete u PID namespace iz podrazumevanog namespace-a, i dalje ćete moći da vidite sve procese. A proces iz tog PID ns će moći da vidi novi bash u PID ns.

Takođe, možete **ući u drugi proces PID namespace samo ako ste root**. I **ne možete** **ući** u drugi namespace **bez deskriptora** koji pokazuje na njega (kao što je `/proc/self/ns/pid`)

## References

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

{{#include ../../../../banners/hacktricks-training.md}}
