# DDexec / EverythingExec

## Kontekst

U Linuxu, da bi se program pokrenuo, on mora da postoji kao fajl i mora na neki način da bude dostupan kroz hijerarhiju sistema datoteka (to je jednostavno način na koji `execve()` funkcioniše). Ovaj fajl može da se nalazi na disku ili u RAM memoriji (tmpfs, memfd), ali vam je potrebna putanja do fajla. Zbog toga je veoma lako kontrolisati šta se pokreće na Linux sistemu, lako je otkriti pretnje i alate napadača ili ih potpuno sprečiti da pokušaju da izvrše bilo šta svoje (_npr._ nedozvoljavanjem neprivilegovanim korisnicima da bilo gde postavljaju izvršne fajlove).

Ali ova tehnika je tu da sve to promeni. Ako ne možete da pokrenete proces koji želite... **onda preuzmete već postojeći**.

Ova tehnika omogućava da **zaobiđete uobičajene zaštitne tehnike kao što su read-only, noexec, file-name whitelisting i hash whitelisting**.<sup>[[1]](#references)</sup>

## Dependencies

Završna skripta zavisi od sledećih alata da bi radila; oni moraju biti dostupni na sistemu koji napadate (podrazumevano ćete ih svuda pronaći):
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

Ako možete proizvoljno da menjate memoriju procesa, možete ga preuzeti. Ovo se može koristiti za otmicu već postojećeg procesa i njegovu zamenu drugim programom. To možemo postići korišćenjem `ptrace()` syscall-a (što zahteva mogućnost izvršavanja syscall-ova ili dostupnost gdb-a na sistemu) ili, još interesantnije, pisanjem u `/proc/$pid/mem`.<sup>[[1]](#references)</sup>

Datoteka `/proc/$pid/mem` predstavlja direktno mapiranje celokupnog adresnog prostora procesa (_npr._ od `0x0000000000000000` do `0x7ffffffffffff000` na x86-64). To znači da je čitanje iz ove datoteke ili pisanje u nju na offsetu `x` isto što i čitanje ili menjanje sadržaja na virtuelnoj adresi `x`.

Sada moramo da rešimo četiri osnovna problema:

- Uopšteno, samo root i vlasnik programa mogu da je menjaju.
- ASLR.
- Ako pokušamo da čitamo ili pišemo na adresu koja nije mapirana u adresnom prostoru programa, dobićemo I/O grešku.

Ovi problemi imaju rešenja koja, iako nisu savršena, dobro funkcionišu:

- Većina shell interpretera dozvoljava kreiranje file descriptor-a koji će zatim biti nasleđeni od strane child procesa. Možemo kreirati fd koji pokazuje na `mem` datoteku shell-a sa dozvolama za pisanje... tako da child procesi koji koriste taj fd mogu da menjaju memoriju shell-a.
- ASLR čak nije ni problem; možemo proveriti `maps` datoteku shell-a ili bilo koju drugu datoteku iz procfs-a kako bismo dobili informacije o adresnom prostoru procesa.
- Zato moramo da koristimo `lseek()` nad datotekom. Iz shell-a to nije moguće uraditi bez korišćenja ozloglašenog `dd`-a.

### Detaljnije

Koraci su relativno jednostavni i za njihovo razumevanje nije potrebna nikakva posebna stručnost:<sup>[[1]](#references)</sup>

- Parsirati binary koji želimo da pokrenemo i loader kako bismo utvrdili koja su im mapiranja potrebna. Zatim napraviti "shell"code koji će, uopšteno govoreći, izvršiti iste korake koje kernel obavlja pri svakom pozivu `execve()`:
- Kreirati navedena mapiranja.
- Učitati binary-je u njih.
- Podesiti dozvole.
- Na kraju inicijalizovati stack argumentima za program i postaviti auxiliary vector (koji je potreban loader-u).
- Skočiti u loader i prepustiti mu ostatak posla (učitavanje biblioteka potrebnih programu).
- Iz `syscall` datoteke dobiti adresu na koju će se proces vratiti nakon syscall-a koji izvršava.
- Prepisati to mesto, koje će biti executable, našim shellcode-om (preko `mem` možemo menjati stranice zaštićene od pisanja).
- Proslediti program koji želimo da pokrenemo na stdin procesa (navedeni "shell"code će izvršiti `read()` nad njim).
- U ovom trenutku loader treba da učita neophodne biblioteke za naš program i da skoči u njega.

**Pogledajte alat na** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec).<sup>[[1]](#references)</sup>

## EverythingExec

Postoji nekoliko alternativa za `dd`, od kojih je jedna, `tail`, trenutno podrazumevani program koji se koristi za `lseek()` kroz `mem` datoteku (što je bila jedina svrha korišćenja `dd`-a). Navedene alternative su:<sup>[[1]](#references)</sup>
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
Ako pronađete drugi validan seeker koji nije implementiran u skripti, i dalje ga možete koristiti tako što ćete postaviti promenljivu `SEEKER_ARGS`:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Blokirajte ovo, EDR-ovi.

## References

- [1] [DDexec: Tehnika za pokretanje binarnih datoteka bez datoteka i prikriveno na Linuxu](https://github.com/arget13/DDexec)
{{#include ../../../../banners/hacktricks-training.md}}
