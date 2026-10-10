# Osnove Linuxa

{{#include ../../banners/hacktricks-training.md}}

Ovo je polazna tačka za procenu Linux hosta. Stranice obrađuju širok postupak za privilege escalation, praktične komande, promenljive okruženja i uobičajena ograničenja koja utiču na to šta može da se pokrene na hostu.

- [Linux privilege escalation](linux-privilege-escalation/README.md) vodi kroz enumeraciju i moguće lokalne puteve za escalation. Za kraću listu zadataka koristite [privilege escalation checklist](../main-system-information/linux-privilege-escalation-checklist.md).
- [Pokretanje shell-a, aliasi i istorija](shell-startup-aliases-and-history.md) objašnjava razrešavanje komandi, izvršavanje startup datoteka i tragove u istoriji.
- [Korisne Linux komande](useful-linux-commands.md) sadrži komande za pregled datoteka, procesa, servisa i okruženja.
- [Linux promenljive okruženja](linux-environment-variables.md) objašnjava kako vrednosti okruženja utiču na izvršavanje i gde se mogu pojaviti osetljive vrednosti.
- [Zaobilaženje Linux ograničenja](bypass-linux-restrictions/README.md) obrađuje ograničene shell-ove i okruženja za izvršavanje, uključujući zaštite sistema datoteka, `noexec` i distroless sisteme.

## Native binary exploitation

Kada procena ukaže na ranjivi Linux izvršni fajl, koristite relevantne materijale iz odeljka Binary Exploitation:

- [ELF format i ponašanje loader-a](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md) i [zaštite binarnih fajlova i njihovo zaobilaženje](../../binary-exploitation/common-binary-protections-and-bypasses/README.md) objašnjavaju raspored izvršnog fajla i mere za ublažavanje.
- [Eksploatacija steka](../../binary-exploitation/basic-stack-binary-exploitation-methodology/README.md) i [ROP](../../binary-exploitation/rop-return-oriented-programing/README.md) obrađuju napade na tok izvršavanja.
- [Eksploatacija libc heap-a](../../binary-exploitation/libc-heap/README.md) i [format strings](../../binary-exploitation/format-strings/README.md) obrađuju druge uobičajene puteve zloupotrebe oštećenja memorije.

Studije slučaja specifične za kernel nalaze se u materijalima [Kernel/LPE/CVE](../main-system-information/kernel-lpe-cves/README.md).
{{#include ../../banners/hacktricks-training.md}}
