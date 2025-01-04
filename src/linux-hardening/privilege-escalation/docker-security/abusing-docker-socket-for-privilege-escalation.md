# Abusing Docker Socket for Privilege Escalation

{{#include ../../../banners/hacktricks-training.md}}

Postoje neki slučajevi kada imate **pristup docker socket-u** i želite da ga iskoristite za **eskalaciju privilegija**. Neke radnje mogu biti veoma sumnjive i možda ćete želeti da ih izbegnete, pa ovde možete pronaći različite zastavice koje mogu biti korisne za eskalaciju privilegija:

### Via mount

Možete **montirati** različite delove **fajl sistema** u kontejneru koji radi kao root i **pristupiti** im.\
Takođe možete **zloupotrebiti montiranje za eskalaciju privilegija** unutar kontejnera.

- **`-v /:/host`** -> Montirajte fajl sistem host-a u kontejneru kako biste mogli da **pročitate fajl sistem host-a.**
- Ako želite da **imajte osećaj da ste na host-u** dok ste u kontejneru, možete onemogućiti druge mehanizme odbrane koristeći zastavice kao što su:
- `--privileged`
- `--cap-add=ALL`
- `--security-opt apparmor=unconfined`
- `--security-opt seccomp=unconfined`
- `-security-opt label:disable`
- `--pid=host`
- `--userns=host`
- `--uts=host`
- `--cgroupns=host`
- \*\*`--device=/dev/sda1 --cap-add=SYS_ADMIN --security-opt apparmor=unconfined` \*\* -> Ovo je slično prethodnoj metodi, ali ovde montiramo **disk uređaj**. Zatim, unutar kontejnera pokrenite `mount /dev/sda1 /mnt` i možete **pristupiti** **fajl sistemu host-a** u `/mnt`
- Pokrenite `fdisk -l` na host-u da pronađete `</dev/sda1>` uređaj za montiranje
- **`-v /tmp:/host`** -> Ako iz nekog razloga možete **samo montirati neki direktorijum** sa host-a i imate pristup unutar host-a. Montirajte ga i kreirajte **`/bin/bash`** sa **suid** u montiranom direktorijumu kako biste mogli **izvršiti ga sa host-a i eskalirati na root**.

> [!NOTE]
> Imajte na umu da možda ne možete montirati folder `/tmp`, ali možete montirati **drugi zapisivi folder**. Možete pronaći zapisive direktorijume koristeći: `find / -writable -type d 2>/dev/null`
>
> **Imajte na umu da ne podržavaju svi direktorijumi na linux mašini suid bit!** Da biste proverili koji direktorijumi podržavaju suid bit, pokrenite `mount | grep -v "nosuid"` Na primer, obično `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` i `/var/lib/lxcfs` ne podržavaju suid bit.
>
> Takođe imajte na umu da ako možete **montirati `/etc`** ili bilo koji drugi folder **koji sadrži konfiguracione fajlove**, možete ih menjati iz docker kontejnera kao root kako biste **zloupotrebili ih na host-u** i eskalirali privilegije (možda menjajući `/etc/shadow`)

### Escaping from the container

- **`--privileged`** -> Sa ovom zastavicom [uklanjate svu izolaciju iz kontejnera](docker-privileged.md#what-affects). Proverite tehnike za [izlazak iz privilegovanih kontejnera kao root](docker-breakout-privilege-escalation/index.html#automatic-enumeration-and-escape).
- **`--cap-add=<CAPABILITY/ALL> [--security-opt apparmor=unconfined] [--security-opt seccomp=unconfined] [-security-opt label:disable]`** -> Da biste [eskalirali zloupotrebom sposobnosti](../linux-capabilities.md), **dodelite tu sposobnost kontejneru** i onemogućite druge metode zaštite koje mogu sprečiti da eksploatacija funkcioniše.

### Curl

Na ovoj stranici smo razgovarali o načinima za eskalaciju privilegija koristeći docker zastavice, možete pronaći **načine da zloupotrebite ove metode koristeći curl** komandu na stranici:

{{#include ../../../banners/hacktricks-training.md}}
