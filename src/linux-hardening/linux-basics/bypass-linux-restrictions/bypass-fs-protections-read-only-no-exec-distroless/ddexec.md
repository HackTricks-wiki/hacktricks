# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## Kontekst

U Linuxu, da bi se pokrenuo program, on mora da postoji kao fajl i mora na neki način biti dostupan kroz hijerarhiju sistema fajlova (tako `execve()` funkcioniše). Ovaj fajl može da se nalazi na disku ili u RAM-u (tmpfs, memfd), ali je potrebna putanja do fajla. Zbog toga je veoma lako kontrolisati šta se pokreće na Linux sistemu, lako je otkriti pretnje i alatke napadača ili ih potpuno sprečiti da pokušaju da izvrše bilo šta svoje (_npr._ ne dozvoliti neprivilegovanim korisnicima da bilo gde postavljaju izvršne fajlove).

Ali ova tehnika je tu da sve to promeni. Ako ne možete da pokrenete proces koji želite... **onda preuzmete već postojeći**.

Ova tehnika omogućava **zaobilaženje uobičajenih tehnika zaštite kao što su read-only, noexec, whitelisting naziva fajlova, hash whitelisting...**<sup>[[1]](#references)</sup>

## Zavisnosti

Konačna skripta zavisi od sledećih alata da bi radila; oni moraju biti dostupni na sistemu koji napadate (podrazumevano ćete ih svuda pronaći):
```
dd
bash | zsh | ash (busybox)
head
tail
cut
grep
od
readlink
wc
tr
base64
```
## The technique

Ako možete proizvoljno da menjate memoriju procesa, možete ga preuzeti. Ovo se može koristiti za hijacking već postojećeg procesa i njegovu zamenu drugim programom. To možemo postići korišćenjem `ptrace()` syscall-a (što zahteva mogućnost izvršavanja syscall-ova ili dostupnost gdb-a na sistemu) ili, što je zanimljivije, upisivanjem u `/proc/$pid/mem`.<sup>[[1]](#references)</sup>

Fajl `/proc/$pid/mem` predstavlja mapiranje celokupnog adresnog prostora procesa jedan-na-jedan (_npr._ od `0x0000000000000000` do `0x7ffffffffffff000` na x86-64). To znači da je čitanje iz ovog fajla ili upisivanje u njega na offsetu `x` isto što i čitanje ili menjanje sadržaja na virtuelnoj adresi `x`.

Sada moramo da rešimo četiri osnovna problema:

- Uopšteno, samo root i vlasnik programa mogu da ga menjaju.
- ASLR.
- Ako pokušamo da čitamo ili upisujemo na adresu koja nije mapirana u adresnom prostoru programa, dobićemo I/O grešku.

Ovi problemi imaju rešenja koja, iako nisu savršena, dobro funkcionišu:

- Većina shell interpretera omogućava kreiranje file descriptor-a koji će zatim biti nasleđeni od strane child procesa. Možemo kreirati fd koji pokazuje na `mem` fajl shell-a sa write permissions... pa će child procesi koji koriste taj fd moći da menjaju memoriju shell-a.
- ASLR čak nije ni problem; možemo proveriti `maps` fajl shell-a ili bilo koji drugi fajl iz procfs-a kako bismo dobili informacije o adresnom prostoru procesa.
- Dakle, potrebno je izvršiti `lseek()` nad fajlom. Iz shell-a to nije moguće uraditi osim korišćenjem ozloglašenog `dd`-a.

### Detaljnije

Koraci su relativno jednostavni i za njihovo razumevanje nije potrebno nikakvo posebno znanje:<sup>[[1]](#references)</sup>

- Parsirati binary koji želimo da pokrenemo i loader kako bismo utvrdili koja su im mappings potrebna. Zatim napraviti "shell"code koji će, uopšteno govoreći, izvršiti iste korake koje kernel obavlja pri svakom pozivu `execve()`:
- Kreirati navedena mappings.
- Učitati binaries u njih.
- Podesiti permissions.
- Na kraju inicijalizovati stack argumentima za program i postaviti auxiliary vector (koji je potreban loader-u).
- Skočiti u loader i prepustiti mu da obavi ostatak (učitavanje libraries potrebnih programu).
- Iz `syscall` fajla dobiti adresu na koju će se proces vratiti nakon syscall-a koji izvršava.
- Prepisati to mesto, koje će biti executable, našim shellcode-om (putem `mem` možemo menjati unwritable pages).
- Proslediti program koji želimo da pokrenemo na stdin procesa (navedeni "shell"code će ga `read()`-ovati).
- U ovom trenutku loader treba da učita neophodne libraries za naš program i skoči u njega.

**Pogledajte tool na** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)<sup>[[1]](#references)</sup>

## EverythingExec

Postoji nekoliko alternativa za `dd`, od kojih je jedna, `tail`, trenutno podrazumevani program koji se koristi za `lseek()` kroz `mem` fajl (što je bila jedina svrha korišćenja `dd`-a). Navedene alternative su:<sup>[[1]](#references)</sup>
```bash
tail
hexdump
cmp
xxd
```
Podešavanjem promenljive `SEEKER` možete promeniti seeker koji se koristi, _npr._:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Ako pronađete drugi validan seeker koji nije implementiran u skripti, i dalje ga možete koristiti podešavanjem promenljive `SEEKER_ARGS`:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Blokirajte ovo, EDR-ovi.

## Reference

- [1] [DDexec: A technique to run binaries filelessly and stealthily on Linux](https://github.com/arget13/DDexec)

{{#include ../../../../banners/hacktricks-training.md}}
