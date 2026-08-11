# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## Kontekst

U Linuxu, da bi se program pokrenuo, mora da postoji kao datoteka i mora na neki način da bude dostupan kroz hijerarhiju sistema datoteka (tako `execve()` funkcioniše). Ova datoteka može da se nalazi na disku ili u RAM-u (tmpfs, memfd), ali je potrebna putanja do datoteke. Zbog toga je veoma lako kontrolisati šta se pokreće na Linux sistemu, lako je otkriti pretnje i alatke napadača ili ih potpuno sprečiti da pokušaju da izvrše bilo šta svoje (_npr._ onemogućavanjem neprivilegovanim korisnicima da bilo gde postavljaju izvršne datoteke).

Ali ova tehnika je tu da sve to promeni. Ako ne možete da pokrenete proces koji želite... **onda preuzmete već postojeći**.

Ova tehnika omogućava **zaobilaženje uobičajenih tehnika zaštite kao što su read-only, noexec, file-name whitelisting i hash whitelisting**.<sup>[[1]](#references)</sup>

## Zavisnosti

Konačna skripta zavisi od sledećih alatki da bi radila; one moraju biti dostupne na sistemu koji napadate (podrazumevano ćete ih sve pronaći gotovo svuda):
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

Ako ste u mogućnosti da proizvoljno menjate memoriju procesa, možete preuzeti kontrolu nad njim. Ovo se može koristiti za otmicu već postojećeg procesa i njegovu zamenu drugim programom. To možemo postići korišćenjem sistemskog poziva `ptrace()` (za šta je potrebno da imate mogućnost izvršavanja sistemskih poziva ili da je `gdb` dostupan na sistemu) ili, što je još zanimljivije, upisivanjem u `/proc/$pid/mem`.<sup>[[1]](#references)</sup>

Datoteka `/proc/$pid/mem` predstavlja mapiranje jedan-na-jedan čitavog adresnog prostora procesa (_npr._ od `0x0000000000000000` do `0x7ffffffffffff000` u x86-64). To znači da je čitanje iz ove datoteke ili upisivanje u nju na offsetu `x` isto što i čitanje ili menjanje sadržaja na virtuelnoj adresi `x`.

Sada moramo da rešimo četiri osnovna problema:

- Uopšteno, samo root i vlasnik programa mogu da je menjaju.
- ASLR.
- Ako pokušamo da čitamo ili upisujemo na adresu koja nije mapirana u adresnom prostoru programa, dobićemo I/O grešku.

Ovi problemi imaju rešenja koja, iako nisu savršena, dobro funkcionišu:

- Većina shell interpretera omogućava kreiranje file descriptor-a koji će zatim biti nasleđeni od strane child procesa. Možemo kreirati fd koji pokazuje na `mem` datoteku shell-a sa dozvolama za upis... tako da child procesi koji koriste taj fd mogu da menjaju memoriju shell-a.
- ASLR čak nije ni problem; možemo proveriti `maps` datoteku shell-a ili bilo koju drugu datoteku iz procfs-a kako bismo dobili informacije o adresnom prostoru procesa.
- Zato moramo koristiti `lseek()` nad datotekom. Iz shell-a to nije moguće uraditi bez korišćenja ozloglašenog `dd`.

### Detaljnije

Koraci su relativno jednostavni i za njihovo razumevanje nije potrebno nikakvo posebno stručno znanje:<sup>[[1]](#references)</sup>

- Parsirati binary koji želimo da pokrenemo i loader kako bismo utvrdili koja su im mapiranja potrebna. Zatim napraviti "shell"code koji će, uopšteno govoreći, izvršiti iste korake koje kernel obavlja pri svakom pozivu `execve()`:
- Kreirati navedena mapiranja.
- Učitati binary-je u njih.
- Podesiti dozvole.
- Na kraju inicijalizovati stack argumentima za program i smestiti auxiliary vector (potreban loader-u).
- Skočiti u loader i prepustiti mu ostatak posla (učitavanje biblioteka potrebnih programu).
- Iz datoteke `syscall` dobaviti adresu na koju će se proces vratiti nakon sistemskog poziva koji izvršava.
- Prepisati to mesto, koje će biti izvršivo, našim shellcode-om (putem `mem` možemo menjati stranice zaštićene od upisa).
- Proslediti program koji želimo da pokrenemo na stdin procesa (navedeni "shell"code će ga preuzeti pomoću `read()`).
- U ovom trenutku loader treba da učita neophodne biblioteke za naš program i da skoči u njega.

**Pogledajte alat na** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec).<sup>[[1]](#references)</sup>

## EverythingExec

Postoji nekoliko alternativa za `dd`, od kojih je jedna, `tail`, trenutno podrazumevani program koji se koristi za `lseek()` kroz `mem` datoteku (što je bila jedina svrha korišćenja `dd`). Navedene alternative su:<sup>[[1]](#references)</sup>
```bash
tail
hexdump
cmp
xxd
```
Podešavanjem promenljive `SEEKER` možete promeniti korišćeni seeker, _npr._:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Ako pronađete drugi validan seeker koji nije implementiran u skripti, i dalje ga možete koristiti tako što ćete postaviti promenljivu `SEEKER_ARGS`:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Blokirajte ovo, EDR-ovi.

## References

- [1] [DDexec: Tehnika za pokretanje binarnih datoteka bez datoteke i prikriveno na Linuxu](https://github.com/arget13/DDexec)
{{#include ../../../../banners/hacktricks-training.md}}
