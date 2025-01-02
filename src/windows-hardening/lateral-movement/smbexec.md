# SmbExec/ScExec

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="/images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Dobijte perspektivu hakera na vaše web aplikacije, mrežu i oblak**

**Pronađite i prijavite kritične, iskoristive ranjivosti sa stvarnim poslovnim uticajem.** Koristite naših 20+ prilagođenih alata za mapiranje napadačke površine, pronalaženje sigurnosnih problema koji vam omogućavaju da eskalirate privilegije, i koristite automatizovane eksploite za prikupljanje suštinskih dokaza, pretvarajući vaš trud u uverljive izveštaje.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

## Kako funkcioniše

**Smbexec** je alat koji se koristi za daljinsko izvršavanje komandi na Windows sistemima, sličan **Psexec**, ali izbegava postavljanje bilo kakvih zlonamernih fajlova na ciljni sistem.

### Ključne tačke o **SMBExec**

- Radi tako što kreira privremenu uslugu (na primer, "BTOBTO") na ciljnim mašinama za izvršavanje komandi putem cmd.exe (%COMSPEC%), bez ispuštanja bilo kakvih binarnih fajlova.
- I pored svog diskretnog pristupa, generiše logove događaja za svaku izvršenu komandu, nudeći oblik neinteraktivnog "shell-a".
- Komanda za povezivanje koristeći **Smbexec** izgleda ovako:
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### Izvršavanje Komandi Bez Binarnih Fajlova

- **Smbexec** omogućava direktno izvršavanje komandi kroz binPaths servisa, eliminišući potrebu za fizičkim binarnim fajlovima na meti.
- Ova metoda je korisna za izvršavanje jednokratnih komandi na Windows meti. Na primer, kombinovanjem sa Metasploit-ovim `web_delivery` modulom omogućava se izvršavanje PowerShell-targetiranog obrnuto Meterpreter payload-a.
- Kreiranjem udaljenog servisa na napadačevoj mašini sa binPath postavljenim da izvrši pruženu komandu kroz cmd.exe, moguće je uspešno izvršiti payload, ostvarujući povratne informacije i izvršavanje payload-a sa Metasploit slušačem, čak i ako dođe do grešaka u odgovoru servisa.

### Primer Komandi

Kreiranje i pokretanje servisa može se ostvariti sledećim komandama:
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
Za više detalja proverite [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## Reference

- [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<figure><img src="/images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Dobijte perspektivu hakera o vašim veb aplikacijama, mreži i oblaku**

**Pronađite i prijavite kritične, eksploatabilne ranjivosti sa stvarnim poslovnim uticajem.** Koristite naših 20+ prilagođenih alata za mapiranje napadačke površine, pronalaženje bezbednosnih problema koji vam omogućavaju da eskalirate privilegije, i koristite automatizovane eksploate za prikupljanje suštinskih dokaza, pretvarajući vaš trud u uverljive izveštaje.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

{{#include ../../banners/hacktricks-training.md}}
