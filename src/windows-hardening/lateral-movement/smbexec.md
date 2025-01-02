# SmbExec/ScExec

{{#include ../../banners/hacktricks-training.md}}


## Kako to funkcioniše

**Smbexec** je alat koji se koristi za daljinsko izvršavanje komandi na Windows sistemima, sličan **Psexec**, ali izbegava postavljanje bilo kojih zlonamernih fajlova na ciljni sistem.

### Ključne tačke o **SMBExec**

- Radi tako što kreira privremenu uslugu (na primer, "BTOBTO") na ciljnem računaru da izvrši komande putem cmd.exe (%COMSPEC%), bez ispuštanja bilo kakvih binarnih fajlova.
- I pored svog diskretnog pristupa, generiše logove događaja za svaku izvršenu komandu, nudeći oblik neinteraktivnog "shell"-a.
- Komanda za povezivanje koristeći **Smbexec** izgleda ovako:
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### Izvršavanje Komandi Bez Binarnih Fajlova

- **Smbexec** omogućava direktno izvršavanje komandi kroz binPaths servisa, eliminišući potrebu za fizičkim binarnim fajlovima na meti.
- Ova metoda je korisna za izvršavanje jednokratnih komandi na Windows meti. Na primer, kombinovanjem sa Metasploit-ovim `web_delivery` modulom omogućava se izvršavanje PowerShell-targetiranog reverznog Meterpreter payload-a.
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


{{#include ../../banners/hacktricks-training.md}}
