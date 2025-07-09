# TimeRoasting

{{#include /banners/hacktricks-training.md}}

timeRoasting, glavni uzrok je zastarjeli mehanizam autentifikacije koji je Microsoft ostavio u svom proširenju za NTP servere, poznatom kao MS-SNTP. U ovom mehanizmu, klijenti mogu direktno koristiti bilo koji Relativni Identifikator (RID) računa računara, a kontroler domena će koristiti NTLM hash računa računara (generisan MD4) kao ključ za generisanje **Koda za autentifikaciju poruke (MAC)** paketa odgovora.

Napadači mogu iskoristiti ovaj mehanizam da dobiju ekvivalentne hash vrednosti proizvoljnih računa računara bez autentifikacije. Jasno je da možemo koristiti alate poput Hashcat za brute-forcing.

Specifičan mehanizam može se videti u odeljku 3.1.5.1 "Ponašanje zahteva za autentifikaciju" [službene Windows dokumentacije za MS-SNTP protokol](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf).

U dokumentu, odeljak 3.1.5.1 pokriva Ponašanje zahteva za autentifikaciju.
![](../../images/Pasted%20image%2020250709114508.png)
Može se videti da kada je ExtendedAuthenticatorSupported ADM element postavljen na `false`, originalni Markdown format se zadržava.

>Citirano u originalnom članku：
>>Ako je ExtendedAuthenticatorSupported ADM element lažan, klijent MORA konstruisati poruku Klijent NTP Zahteva. Dužina poruke Klijent NTP Zahteva je 68 bajtova. Klijent postavlja polje Authenticator poruke Klijent NTP Zahteva kao što je opisano u odeljku 2.2.1, upisujući najmanje značajnih 31 bit RID vrednosti u najmanje značajnih 31 bit podpolja Identifikatora ključa autentifikatora, a zatim upisujući vrednost Selektora ključa u najznačajniji bit podpolja Identifikatora ključa.

U odeljku 4 Dokumenta Primeri protokola tačka 3

>Citirano u originalnom članku：
>>3. Nakon primanja zahteva, server proverava da li je veličina primljene poruke 68 bajtova. Ako nije, server ili odbacuje zahtev (ako veličina poruke nije jednaka 48 bajtova) ili ga tretira kao neautentifikovani zahtev (ako je veličina poruke 48 bajtova). Pretpostavljajući da je veličina primljene poruke 68 bajtova, server izvlači RID iz primljene poruke. Server ga koristi da pozove metodu NetrLogonComputeServerDigest (kako je navedeno u [MS-NRPC] odeljku 3.5.4.8.2) da izračuna kripto-čekove i odabere kripto-ček na osnovu najznačajnijeg bita podpolja Identifikatora ključa iz primljene poruke, kako je navedeno u odeljku 3.2.5. Server zatim šalje odgovor klijentu, postavljajući polje Identifikatora ključa na 0 i polje Kripto-ček na izračunati kripto-ček.

Prema opisu u gornjem Microsoftovom zvaničnom dokumentu, korisnici ne trebaju nikakvu autentifikaciju; samo treba da popune RID da pokrenu zahtev, a zatim mogu dobiti kriptografski ček. Kriptografski ček je objašnjen u odeljku 3.2.5.1.1 dokumenta.

>Citirano u originalnom članku：
>>Server preuzima RID iz najmanje značajnih 31 bita podpolja Identifikatora ključa polja Autentifikatora poruke Klijent NTP Zahteva. Server koristi metodu NetrLogonComputeServerDigest (kako je navedeno u [MS-NRPC] odeljku 3.5.4.8.2) da izračuna kripto-čekove sa sledećim ulaznim parametrima:
>>>![](../../images/Pasted%20image%2020250709115757.png)

Kriptografski ček se izračunava koristeći MD5, a specifičan proces se može pogledati u sadržaju dokumenta. Ovo nam daje priliku da izvršimo napad roštiljanja.

## kako napasti

Citat za https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-roasting-timeroasting/

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Skripte za timeroasting od Toma Tervoorta
```
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
{{#include /banners/hacktricks-training.md}}
