# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Uvod <a href="#3f17" id="3f17"></a>

**Pogledajte originalnu objavu za [sve informacije o ovoj tehnici](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**<sup>[[1]](#references)</sup>

Ukratko, kontrola nad atributom **`msDS-KeyCredentialLink`** korisnika ili računara može napadaču omogućiti da doda key credential, autentifikuje se kao taj objekat pomoću PKINIT-a i — kada KDC i nalog podržavaju neophodne tokove — iskoristi dobijenu ulaznicu sa `S4U2Self`/user-to-user da povrati NT hash objekta.<sup>[[1]](#references)</sup>

U objavi je opisana metoda za podešavanje **public-private key authentication credentials** radi dobijanja jedinstvenog **Service Ticket-a** koji sadrži NTLM hash cilja. Ovaj proces uključuje šifrovani NTLM_SUPPLEMENTAL_CREDENTIAL unutar Privilege Attribute Certificate-a (PAC), koji se može dešifrovati.<sup>[[1]](#references)</sup>

### Zahtevi

Da bi se ova tehnika primenila, moraju biti ispunjeni određeni uslovi:<sup>[[1]](#references)</sup>

- Potreban je najmanje jedan Windows Server 2016 Domain Controller.
- Domain Controller mora imati instaliran server authentication digital certificate.
- Šema direktorijuma mora sadržati `msDS-KeyCredentialLink`; Windows Server 2016 ili noviji DC i PKINIT-capable certificate na KDC-u predstavljaju praktične platform requirements opisane u istraživanju. Proverite kombinaciju schema/DC u domenu, umesto da pretpostavite da samo oznaka domain functional-level određuje mogućnost exploit-a.
- Potreban je nalog sa delegated rights za izmenu atributa msDS-KeyCredentialLink ciljnog objekta.

## Zloupotreba

Zloupotreba Key Trust-a za computer objects obuhvata korake koji prevazilaze dobijanje Ticket Granting Ticket-a (TGT) i NTLM hash-a. Opcije uključuju:<sup>[[1]](#references)</sup>

1. Kreiranje **RC4 silver ticket-a** za delovanje kao privileged users na predviđenom hostu.
2. Korišćenje TGT-a sa **S4U2Self** za impersonation **privileged users**, što zahteva izmene Service Ticket-a radi dodavanja service class-a u service name.

Značajna prednost zloupotrebe Key Trust-a jeste to što je ograničena na private key koji je generisao napadač, čime se izbegava delegation ka potencijalno ranjivim nalozima i ne zahteva kreiranje computer account-a, koji bi moglo biti teško ukloniti.<sup>[[1]](#references)</sup>

## Alati

### [**Whisker**](https://github.com/eladshamir/Whisker)

Whisker koristi DSInternals za manipulaciju atributom `msDS-KeyCredentialLink` iz C#-a. Whisker i njegov Python counterpart **pyWhisker** podržavaju dodavanje, izlistavanje, uklanjanje i brisanje key credentials.<sup>[[2]](#references)[[4]](#references)</sup>

Funkcije alata **Whisker** uključuju:

- **Add**: Generiše key pair i dodaje key credential.
- **List**: Prikazuje sve key credential entries.
- **Remove**: Briše navedeni key credential.
- **Clear**: Briše sve key credentials, što potencijalno može prekinuti legitimnu WHfB upotrebu.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

pyWhisker donosi tok rada na **UNIX-like systems** uz Impacket i PyDSInternals, uključujući operacije list/add/remove i JSON import/export.<sup>[[4]](#references)</sup>
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray enumeriše objekte domena nad kojima operator ima prava kao što su `GenericWrite`/`GenericAll`, pokušava da široko doda ključne kredencijale i uključuje cleanup/recursive režime. Široko spraying ponašanje je ometajuće i upadljivo; koristite eksplicitne ciljeve i sačuvajte svaki dodat DeviceID radi preciznog uklanjanja.<sup>[[3]](#references)</sup>

## References

- [1] [Shadow Credentials: Zloupotreba mapiranja naloga putem Key Trust mehanizma za preuzimanje naloga](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker - Alat za preuzimanje AD naloga manipulacijom atributom msDS-KeyCredentialLink](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray - Alat za širenje Shadow Credentials kroz domen](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker - Python verzija Shadow Credentials alata](https://github.com/ShutdownRepo/pywhisker)
{{#include ../../../banners/hacktricks-training.md}}
