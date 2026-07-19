# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## Kontekst

U Linuxu, da bi se pokrenuo program, on mora da postoji kao fajl i mora na neki način biti dostupan kroz hijerarhiju sistema datoteka (tako `execve()` funkcioniše). Ovaj fajl može da se nalazi na disku ili u RAM memoriji (tmpfs, memfd), ali vam je potrebna putanja do fajla. Zbog toga je veoma lako kontrolisati šta se pokreće na Linux sistemu, otkrivati pretnje i alate napadača ili ih u potpunosti sprečiti da pokušaju da izvrše bilo šta svoje (_npr._ ne dozvoliti neprivilegovanim korisnicima da bilo gde postavljaju izvršne fajlove).

Ali ova tehnika služi da sve to promeni. Ako ne možete da pokrenete proces koji želite... **onda preuzimate već postojeći**.

Ova tehnika vam omogućava da **zaobiđete uobičajene tehnike zaštite kao što su read-only, noexec, file-name whitelisting, hash whitelisting...**

## Zavisnosti

Konačna skripta zavisi od sledećih alata da bi radila; oni moraju biti dostupni na sistemu koji napadate (podrazumevano ćete ih gotovo svuda pronaći):
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
## Tehnika

Ako možete proizvoljno da menjate memoriju procesa, možete preuzeti kontrolu nad njim. Ovo se može koristiti za hijacking već postojećeg procesa i njegovu zamenu drugim programom. To možemo postići korišćenjem `ptrace()` syscall-a (što zahteva mogućnost izvršavanja syscall-ova ili dostupnost gdb-a na sistemu) ili, još zanimljivije, pisanjem u `/proc/$pid/mem`.

Fajl `/proc/$pid/mem` predstavlja mapiranje celokupnog adresnog prostora procesa jedan-na-jedan (_npr._ od `0x0000000000000000` do `0x7ffffffffffff000` na x86-64). To znači da je čitanje iz ovog fajla ili pisanje u njega na offset-u `x` isto što i čitanje ili menjanje sadržaja na virtuelnoj adresi `x`.

Sada moramo da rešimo četiri osnovna problema:

- Uopšteno, samo root i vlasnik programa mogu da ga menjaju.
- ASLR.
- Ako pokušamo da čitamo ili pišemo na adresu koja nije mapirana u adresnom prostoru programa, dobićemo I/O grešku.

Ovi problemi imaju rešenja koja, iako nisu savršena, funkcionišu dovoljno dobro:

- Većina shell interpreter-a omogućava kreiranje file descriptor-a koji će zatim biti nasleđeni od strane child procesa. Možemo kreirati fd koji pokazuje na `mem` fajl shell-a sa dozvolama za pisanje... tako da child procesi koji koriste taj fd mogu da menjaju memoriju shell-a.
- ASLR čak nije ni problem; možemo proveriti `maps` fajl shell-a ili bilo koji drugi fajl iz procfs-a kako bismo dobili informacije o adresnom prostoru procesa.
- Zato moramo koristiti `lseek()` nad fajlom. Iz shell-a se ovo ne može uraditi osim korišćenjem ozloglašenog `dd`-a.

### Detaljnije

Koraci su relativno jednostavni i za njihovo razumevanje nije potrebno nikakvo posebno stručno znanje:

- Parsirati binary koji želimo da pokrenemo i loader kako bismo utvrdili koja su im mapiranja potrebna. Zatim napraviti "shell"code koji će, uopšteno govoreći, izvršiti iste korake koje kernel izvršava pri svakom pozivu `execve()`:
- Kreirati navedena mapiranja.
- Učitati binary-je u njih.
- Podesiti dozvole.
- Na kraju inicijalizovati stack argumentima za program i postaviti auxiliary vector (potreban loader-u).
- Skočiti u loader i prepustiti mu ostatak posla (učitavanje biblioteka potrebnih programu).
- Iz `syscall` fajla dobiti adresu na koju će se proces vratiti nakon syscall-a koji izvršava.
- Prepisati tu adresu, koja će biti izvršna, našim shellcode-om (preko `mem` možemo menjati stranice koje nisu upisive).
- Proslediti program koji želimo da pokrenemo na stdin procesa (navedeni "shell"code će pozvati `read()` nad njim).
- U ovom trenutku loader treba da učita neophodne biblioteke za naš program i skoči u njega.

**Pogledajte tool na** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

## EverythingExec

Postoji nekoliko alternativa za `dd`, od kojih je `tail` trenutno podrazumevani program koji se koristi za `lseek()` kroz `mem` fajl (što je bila jedina svrha korišćenja `dd`-a). Te alternative su:
```bash
tail
hexdump
cmp
xxd
```
Postavljanjem promenljive `SEEKER` možete promeniti korišćeni seeker, _npr._:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Ako pronađete drugi validan seeker koji nije implementiran u scriptu, i dalje ga možete koristiti tako što ćete podesiti promenljivu `SEEKER_ARGS`:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Blokirajte ovo, EDR-ovi.

## Reference

- [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

{{#include ../../../../banners/hacktricks-training.md}}
