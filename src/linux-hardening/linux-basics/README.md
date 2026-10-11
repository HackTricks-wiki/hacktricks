# Linux osnove

{{#include ../../banners/hacktricks-training.md}}

Ovo je polazna tačka za procenu Linux hosta. Stranice obrađuju širok tok rada za privilege escalation, praktične komande, promenljive okruženja i uobičajena ograničenja koja utiču na to šta može da se pokrene na hostu.

- [Linux privilege escalation](linux-privilege-escalation/README.md) vodi kroz enumeraciju i potencijalne lokalne putanje za eskalaciju. Za kraću listu zadataka koristite [checklist za privilege escalation](../main-system-information/linux-privilege-escalation-checklist.md).
- [Pokretanje shell-a, aliases i history](shell-startup-aliases-and-history.md) objašnjava razrešavanje komandi, izvršavanje startup fajlova i tragove u history-ju.
- [Korisne Linux komande](useful-linux-commands.md) sadrži komande za pregled fajlova, procesa, servisa i okruženja.
- [Linux promenljive okruženja](linux-environment-variables.md) objašnjava kako vrednosti okruženja utiču na izvršavanje i gde se mogu pojaviti osetljive vrednosti.
- [Zaobilaženje Linux ograničenja](bypass-linux-restrictions/README.md) obrađuje ograničene shell-ove i okruženja za izvršavanje, uključujući zaštitu sistema datoteka, `noexec` i distroless sisteme.

## Eksploatacija nativnih binarnih fajlova

Kada procena dovede do ranjivog Linux izvršnog fajla, koristite odgovarajući materijal iz odeljka Binary Exploitation:

- [ELF format i ponašanje loader-a](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md) i [zaštite binarnih fajlova i njihovo zaobilaženje](../../binary-exploitation/common-binary-protections-and-bypasses/README.md) objašnjavaju raspored izvršnog fajla i mere ublažavanja.
- [Eksploatacija steka](../../binary-exploitation/basic-stack-binary-exploitation-methodology/README.md) i [ROP](../../binary-exploitation/rop-return-oriented-programing/README.md) obrađuju napade na tok upravljanja.
- [Eksploatacija libc heap-a](../../binary-exploitation/libc-heap/README.md) i [format string-ovi](../../binary-exploitation/format-strings/README.md) obrađuju druge uobičajene putanje oštećenja memorije.

Studije slučaja specifične za kernel povezane su u materijalu [Kernel/LPE/CVE](../main-system-information/kernel-lpe-cves/README.md).
{{#include ../../banners/hacktricks-training.md}}
