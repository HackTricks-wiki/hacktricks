{{#include ../../banners/hacktricks-training.md}}

## Integritet firmvera

**Prilagođena firmvera i/ili kompajlirani binarni fajlovi mogu se otpremiti kako bi se iskoristile greške u verifikaciji integriteta ili potpisa**. Sledeći koraci se mogu pratiti za kompajlaciju backdoor bind shell-a:

1. Firmvera se može ekstrahovati koristeći firmware-mod-kit (FMK).
2. Treba identifikovati arhitekturu firmvera i endijnost.
3. Može se izgraditi cross compiler koristeći Buildroot ili druge odgovarajuće metode za okruženje.
4. Backdoor se može izgraditi koristeći cross compiler.
5. Backdoor se može kopirati u ekstrahovani firmware /usr/bin direktorijum.
6. Odgovarajući QEMU binarni fajl može se kopirati u korenski sistem ekstrahovane firmvere.
7. Backdoor se može emulirati koristeći chroot i QEMU.
8. Backdoor se može pristupiti putem netcat-a.
9. QEMU binarni fajl treba biti uklonjen iz korenskog sistema ekstrahovane firmvere.
10. Modifikovana firmvera može se ponovo pakovati koristeći FMK.
11. Backdoored firmvera može se testirati emulacijom sa alatom za analizu firmvera (FAT) i povezivanjem na IP adresu i port ciljanog backdoora koristeći netcat.

Ako je već dobijen root shell putem dinamičke analize, manipulacije bootloader-om ili testiranja hardverske sigurnosti, prekompajlirani zlonamerni binarni fajlovi kao što su implanti ili reverzni shell-ovi mogu se izvršiti. Automatizovani alati za payload/implant, kao što je Metasploit framework i 'msfvenom', mogu se iskoristiti koristeći sledeće korake:

1. Treba identifikovati arhitekturu firmvera i endijnost.
2. Msfvenom se može koristiti za specificiranje ciljanog payload-a, IP adrese napadača, broja slušnog porta, tipa fajla, arhitekture, platforme i izlaznog fajla.
3. Payload se može preneti na kompromitovani uređaj i osigurati da ima dozvole za izvršavanje.
4. Metasploit se može pripremiti za obradu dolaznih zahteva pokretanjem msfconsole-a i konfigurisanjem postavki prema payload-u.
5. Meterpreter reverzni shell može se izvršiti na kompromitovanom uređaju.
6. Meterpreter sesije se mogu pratiti dok se otvaraju.
7. Post-exploitation aktivnosti se mogu izvesti.

Ako je moguće, ranjivosti unutar startup skripti mogu se iskoristiti za sticanje trajnog pristupa uređaju tokom ponovnog pokretanja. Ove ranjivosti se javljaju kada startup skripte referenciraju, [simbolički linkuju](https://www.chromium.org/chromium-os/chromiumos-design-docs/hardening-against-malicious-stateful-data) ili zavise od koda smeštenog na nepouzdanim montiranim lokacijama kao što su SD kartice i flash volumeni koji se koriste za skladištenje podataka van root fajl sistema.

## Reference

- Za više informacija proverite [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

{{#include ../../banners/hacktricks-training.md}}
