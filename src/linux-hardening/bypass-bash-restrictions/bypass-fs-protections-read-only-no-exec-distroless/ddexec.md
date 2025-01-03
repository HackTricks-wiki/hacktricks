# DDexec / EverythingExec

{{#include ../../../banners/hacktricks-training.md}}

## Kontekst

U Linuxu, da bi se pokrenuo program, mora postojati kao datoteka, mora biti dostupna na neki način kroz hijerarhiju datotečnog sistema (to je jednostavno kako `execve()` funkcioniše). Ova datoteka može biti na disku ili u RAM-u (tmpfs, memfd), ali vam je potreban put do datoteke. To je olakšalo kontrolu onoga što se pokreće na Linux sistemu, olakšava otkrivanje pretnji i alata napadača ili sprečavanje da pokušaju da izvrše bilo šta svoje (_npr._ ne dozvoljavajući korisnicima bez privilegija da postavljaju izvršne datoteke bilo gde).

Ali ova tehnika je ovde da promeni sve to. Ako ne možete da pokrenete proces koji želite... **onda preuzimate već postojeći**.

Ova tehnika vam omogućava da **zaobiđete uobičajene zaštitne tehnike kao što su samo za čitanje, noexec, bela lista imena datoteka, bela lista hešova...**

## Zavisnosti

Konačni skript zavisi od sledećih alata da bi radio, oni moraju biti dostupni u sistemu koji napadate (po defaultu ćete ih pronaći svuda):
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

Ako ste u mogućnosti da proizvoljno modifikujete memoriju procesa, onda ga možete preuzeti. Ovo se može koristiti za preuzimanje već postojećeg procesa i zamenu sa drugim programom. To možemo postići ili korišćenjem `ptrace()` sistemskog poziva (što zahteva da imate mogućnost izvršavanja sistemskih poziva ili da imate gdb dostupan na sistemu) ili, što je zanimljivije, pisanjem u `/proc/$pid/mem`.

Datoteka `/proc/$pid/mem` je jedan-na-jedan mapiranje celog adresnog prostora procesa (_npr._ od `0x0000000000000000` do `0x7ffffffffffff000` u x86-64). To znači da je čitanje ili pisanje u ovu datoteku na offsetu `x` isto kao čitanje ili modifikovanje sadržaja na virtuelnoj adresi `x`.

Sada imamo četiri osnovna problema sa kojima se suočavamo:

- Uopšte, samo root i vlasnik programa datoteke mogu da je modifikuju.
- ASLR.
- Ako pokušamo da čitamo ili pišemo na adresu koja nije mapirana u adresnom prostoru programa, dobićemo I/O grešku.

Ovi problemi imaju rešenja koja, iako nisu savršena, su dobra:

- Većina shell interpretera omogućava kreiranje deskriptora datoteka koji će zatim biti nasledni od strane podprocesa. Možemo kreirati fd koji pokazuje na `mem` datoteku shelle sa dozvolama za pisanje... tako da podprocesi koji koriste taj fd mogu modifikovati memoriju shelle.
- ASLR čak nije ni problem, možemo proveriti `maps` datoteku shelle ili bilo koju drugu iz procfs kako bismo dobili informacije o adresnom prostoru procesa.
- Tako da treba da `lseek()` preko datoteke. Iz shelle to ne može biti urađeno osim korišćenjem infamoznog `dd`.

### Detaljnije

Koraci su relativno laki i ne zahtevaju nikakvu vrstu stručnosti da bi ih razumeli:

- Parsirajte binarni fajl koji želimo da pokrenemo i loader da saznamo koje mape su im potrebne. Zatim kreirajte "shell" kod koji će, u širokom smislu, izvesti iste korake koje kernel preduzima pri svakom pozivu `execve()`:
- Kreirajte pomenute mape.
- Učitajte binarne fajlove u njih.
- Postavite dozvole.
- Na kraju, inicijalizujte stek sa argumentima za program i postavite pomoćni vektor (potreban loader-u).
- Skočite u loader i pustite ga da uradi ostalo (učita biblioteke potrebne programu).
- Dobijte iz `syscall` datoteke adresu na koju će se proces vratiti nakon sistemskog poziva koji izvršava.
- Prepišite to mesto, koje će biti izvršivo, našim shell kodom (kroz `mem` možemo modifikovati nepisive stranice).
- Prosledite program koji želimo da pokrenemo na stdin procesa (biće `read()` od strane pomenutog "shell" koda).
- U ovom trenutku, na loader-u je da učita potrebne biblioteke za naš program i skoči u njega.

**Pogledajte alat na** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

## EverythingExec

Postoji nekoliko alternativa za `dd`, od kojih je jedna, `tail`, trenutno podrazumevani program koji se koristi za `lseek()` kroz `mem` datoteku (što je bio jedini cilj korišćenja `dd`). Te alternative su:
```bash
tail
hexdump
cmp
xxd
```
Podešavanjem promenljive `SEEKER` možete promeniti korišćenog tražioca, _npr._:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Ako pronađete drugog validnog tražioca koji nije implementiran u skripti, još uvek ga možete koristiti postavljanjem promenljive `SEEKER_ARGS`:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Blokirajte ovo, EDR-ove.

## Reference

- [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

{{#include ../../../banners/hacktricks-training.md}}
