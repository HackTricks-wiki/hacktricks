# Osnove Linux-a

{{#include ../../banners/hacktricks-training.md}}

Ovo je polazna tačka za procenu Linux hosta. Stranice obrađuju širok postupak eskalacije privilegija, praktične komande, promenljive okruženja i uobičajena ograničenja koja utiču na to šta može da se pokrene na hostu.

- [Eskalacija privilegija u Linux-u](linux-privilege-escalation/README.md) vodi kroz enumeraciju i moguće lokalne puteve za eskalaciju. Za kraći spisak zadataka koristite [kontrolnu listu za eskalaciju privilegija](../main-system-information/linux-privilege-escalation-checklist.md).
- [Pokretanje shell-a, aliasi i istorija](shell-startup-aliases-and-history.md) objašnjava razrešavanje komandi, izvršavanje startup fajlova i tragove u istoriji.
- [Korisne Linux komande](useful-linux-commands.md) sadrži komande za pregled fajlova, procesa, servisa i okruženja.
- [Promenljive okruženja u Linux-u](linux-environment-variables.md) objašnjava kako vrednosti okruženja utiču na izvršavanje i gde se mogu pojaviti osetljive vrednosti.
- [Zaobilaženje ograničenja u Linux-u](bypass-linux-restrictions/README.md) obrađuje ograničene shell-ove i okruženja za izvršavanje, uključujući zaštitu sistema fajlova, `noexec` i distroless sisteme.

## Native binary exploitation

Kada procena dovede do ranjivog Linux izvršnog fajla, koristite odgovarajuće materijale u odeljku Binary Exploitation:

- [ELF format i ponašanje loader-a](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md) i [zaštite binarnih fajlova i njihovo zaobilaženje](../../binary-exploitation/common-binary-protections-and-bypasses/README.md) objašnjavaju raspored izvršnog fajla i mere ublažavanja.
- [Eksploatacija steka](../../binary-exploitation/basic-stack-binary-exploitation-methodology/README.md) i [ROP](../../binary-exploitation/rop-return-oriented-programing/README.md) obrađuju napade na kontrolni tok.
- [Eksploatacija Libc heap-a](../../binary-exploitation/libc-heap/README.md) i [format strings](../../binary-exploitation/format-strings/README.md) obrađuju druge uobičajene puteve kroz oštećenje memorije.

Studije slučaja specifične za kernel nalaze se na stranici [Kernel/LPE/CVE materijali](../main-system-information/kernel-lpe-cves/README.md).
{{#include ../../banners/hacktricks-training.md}}
