# PsExec/Winexec/ScExec

{{#include ../../banners/hacktricks-training.md}}

## Kako funkcionišu

Proces je prikazan u koracima ispod, ilustrujući kako se binarni fajlovi servisa manipulišu da bi se postigla daljinska izvršenja na ciljnim mašinama putem SMB:

1. **Kopiranje binarnog fajla servisa na ADMIN$ deljenje preko SMB** se vrši.
2. **Kreiranje servisa na daljinskoj mašini** se vrši upućivanjem na binarni fajl.
3. Servis se **pokreće na daljinu**.
4. Po izlasku, servis se **zaustavlja, a binarni fajl se briše**.

### **Proces ručnog izvršavanja PsExec**

Pretpostavljajući da postoji izvršni payload (napravljen sa msfvenom i obfuskovan korišćenjem Veil-a da bi se izbegla detekcija antivirusnog softvera), nazvan 'met8888.exe', koji predstavlja meterpreter reverse_http payload, sledeći koraci se preduzimaju:

- **Kopiranje binarnog fajla**: Izvršni fajl se kopira na ADMIN$ deljenje iz komandne linije, iako može biti postavljen bilo gde na datotečnom sistemu da bi ostao skriven.

- **Kreiranje servisa**: Korišćenjem Windows `sc` komande, koja omogućava upit, kreiranje i brisanje Windows servisa na daljinu, kreira se servis nazvan "meterpreter" koji upućuje na otpremljeni binarni fajl.

- **Pokretanje servisa**: Poslednji korak uključuje pokretanje servisa, što će verovatno rezultirati "time-out" greškom zbog toga što binarni fajl nije pravi binarni fajl servisa i ne uspeva da vrati očekivani kod odgovora. Ova greška je beznačajna jer je primarni cilj izvršenje binarnog fajla.

Posmatranje Metasploit slušatelja će otkriti da je sesija uspešno inicirana.

[Saaznajte više o `sc` komandi](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Pronađite detaljnije korake u: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Takođe možete koristiti Windows Sysinternals binarni fajl PsExec.exe:**

![](<../../images/image (165).png>)

Takođe možete koristiti [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{{#include ../../banners/hacktricks-training.md}}
