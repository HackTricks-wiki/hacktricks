# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## Kontekst

Linux obično izvršava programe iz izvršnih datoteka sačuvanih na disku ili u memoriji. Može da prepozna izvršnu datoteku pomoću putanje ili deskriptora datoteke, tako da uobičajena putanja do datoteke u sistemu datoteka nije uvek neophodna.<sup>[[2]](#references)</sup>

DDexec / EverythingExec koristi memoriju **već pokrenutog procesa**. Stranica [Linux Fileless Execution](../../../post-exploitation/linux-fileless-execution.md) obrađuje izvršavanje iz anonimnih datoteka i srodne metode detekcije i prikupljanja forenzičkih podataka; pregled [Memory Bypasses](index.html#memory-bypasses) takođe sadrži linkove ka alatima MemExec i Memdlopen.<sup>[[1]](#references)</sup>

Ova tehnika vam omogućava da **zaobiđete uobičajene tehnike zaštite kao što su read-only, noexec, whitelisting naziva datoteka i whitelisting hash vrednosti**.<sup>[[1]](#references)</sup>

## Zavisnosti

Da bi radio, završni skript zavisi od sledećih alata, koji moraju biti dostupni u sistemu koji napadate (podrazumevano ćete ih naći svuda):

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

Ako možete proizvoljno da menjate memoriju procesa, možete da ga preuzmete. Ovo se može iskoristiti za preuzimanje kontrole nad već pokrenutim procesom i njegovu zamenu drugim programom. To možemo postići ili korišćenjem `ptrace()` syscall-a (za šta je potrebno da možete da izvršavate syscall-ove ili da je `gdb` dostupan na sistemu) ili, što je zanimljivije, pisanjem u `/proc/$pid/mem`.<sup>[[1]](#references)</sup>

Datoteka `/proc/$pid/mem` predstavlja preslikavanje celokupnog adresnog prostora procesa jedan-na-jedan (_npr._ od `0x0000000000000000` do `0x7ffffffffffff000` na x86-64). To znači da je čitanje iz ove datoteke ili pisanje u nju na pomeraju `x` isto što i čitanje sadržaja na virtuelnoj adresi `x` ili njegovo menjanje.

Sada imamo četiri osnovna problema sa kojima moramo da se suočimo:

- Uopšteno, samo root i vlasnik programa mogu da menjaju ovu datoteku.
- ASLR.
- Ako pokušamo da čitamo sa adrese koja nije mapirana u adresnom prostoru programa ili da pišemo na nju, dobićemo I/O grešku.

Ovi problemi imaju rešenja koja, iako nisu savršena, dobro funkcionišu:

- Većina shell interpretera omogućava kreiranje deskriptora datoteka koje zatim nasleđuju podređeni procesi. Možemo da kreiramo fd koji pokazuje na `mem` datoteku shell-a sa dozvolama za pisanje... tako da podređeni procesi koji koriste taj fd mogu da menjaju memoriju shell-a.
- ASLR čak nije ni problem: možemo da proverimo datoteku `maps` shell-a ili bilo koju drugu datoteku iz procfs-a da bismo dobili informacije o adresnom prostoru procesa.
- Zato moramo da koristimo `lseek()` nad datotekom. To se iz shell-a ne može uraditi osim korišćenjem ozloglašenog `dd`.

### Detaljnije

Koraci su relativno jednostavni i ne zahtevaju nikakvo stručno znanje da bi se razumeli:<sup>[[1]](#references)</sup>

- Parsirajte binarni fajl koji želimo da pokrenemo i loader da biste utvrdili koja su im mapiranja potrebna. Zatim napravite "shell"code koji će, uopšteno govoreći, izvršiti iste korake kao kernel pri svakom pozivu `execve()`:
  - Kreirajte navedena mapiranja.
  - Učitajte binarne fajlove u njih.
  - Podesite dozvole.
  - Na kraju, inicijalizujte stek argumentima za program i postavite pomoćni vektor (koji je potreban loader-u).
  - Pređite na loader i prepustite mu ostatak posla (učitavanje biblioteka koje su potrebne programu).
- Iz datoteke `syscall` pribavite adresu na koju će se proces vratiti nakon syscall-a koji izvršava.
- Prepišite to mesto, koje će biti izvršno, našim shellcode-om (preko `mem` možemo da menjamo stranice na kojima nije dozvoljeno pisanje).
- Prosledite program koji želimo da pokrenemo na stdin procesa (navedeni "shell"code će ga `read()`-ovati).
- U ovom trenutku loader treba da učita potrebne biblioteke za naš program i pređe na njegovo izvršavanje.

**Pogledajte alat na** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec).<sup>[[1]](#references)</sup>

## EverythingExec

Postoji nekoliko alternativa za `dd`. Jedna od njih, `tail`, trenutno je podrazumevani program za korišćenje `lseek()`-a kroz datoteku `mem` (što je bila jedina svrha korišćenja `dd`-a). Te alternative su:<sup>[[1]](#references)</sup>

```bash
tail
hexdump
cmp
xxd
```

Postavljanjem promenljive `SEEKER` možete promeniti seeker koji se koristi, _npr._:

```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```

Ako pronađete drugi validan seeker koji nije implementiran u skripti, ipak ga možete koristiti tako što ćete postaviti promenljivu `SEEKER_ARGS`:

```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```

Blokirajte ovo, EDR-ovi.

## References

- [1] [DDexec: Tehnika za neprimetno pokretanje binarnih datoteka na Linuxu](https://github.com/arget13/DDexec)
- [2] [execveat(2) — stranica priručnika za Linux](https://manpages.debian.org/trixie/manpages-dev/execveat.2.en.html)
{{#include ../../../../banners/hacktricks-training.md}}
