# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Uvod <a href="#3f17" id="3f17"></a>

**Pogledajte originalnu objavu za [sve informacije o ovoj tehnici](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**<sup>[[1]](#references)</sup>

Ukratko, kontrola nad atributom **`msDS-KeyCredentialLink`** korisnika ili računara može napadaču omogućiti da doda kredencijal ključa, autentifikuje se kao taj objekat pomoću PKINIT-a i — kada KDC i nalog podržavaju potrebne tokove — upotrebi dobijenu kartu sa `S4U2Self`/user-to-user da bi povratio NT hash objekta.<sup>[[1]](#references)</sup>

U objavi je opisan metod za podešavanje **kredencijala za autentifikaciju pomoću javnog i privatnog ključa** radi pribavljanja jedinstvene **Service Ticket** koja sadrži NTLM hash cilja. Ovaj postupak obuhvata šifrovani NTLM_SUPPLEMENTAL_CREDENTIAL unutar Privilege Attribute Certificate (PAC), koji se može dešifrovati.<sup>[[1]](#references)</sup>

### Zahtevi

Za primenu ove tehnike moraju biti ispunjeni određeni uslovi:<sup>[[1]](#references)</sup>

- Potreban je najmanje jedan Windows Server 2016 Domain Controller.
- Na Domain Controller-u mora biti instaliran digitalni sertifikat za autentifikaciju servera.
- Šema direktorijuma mora da sadrži `msDS-KeyCredentialLink`; Windows Server 2016 ili noviji DC i sertifikat koji podržava PKINIT na KDC-u predstavljaju praktične platformске zahteve opisane u istraživanju. Proverite kombinaciju šeme i DC-ova u domenu, umesto da pretpostavite da mogućnost iskorišćavanja zavisi samo od oznake funkcionalnog nivoa domena.
- Potreban je nalog sa delegiranim pravima za izmenu atributa msDS-KeyCredentialLink ciljnog objekta.

## Zloupotreba

Zloupotreba Key Trust-a za računarske objekte obuhvata i korake koji sledе nakon pribavljanja Ticket Granting Ticket-a (TGT) i NTLM hash-a. Moguće opcije su:<sup>[[1]](#references)</sup>

1. Kreiranje **RC4 silver ticket** ради деловања као привилеговани корисници на предвиђеном хосту.
2. Употреба TGT-а са **S4U2Self** ради имперсонације **привилегованих корисника**, што захтева измену Service Ticket-а ради додавања service class-а имену услуге.

Значајна предност злоупотребе Key Trust-а јесте то што се ослања искључиво на приватни кључ који је генерисао нападач, чиме се избегава делегирање на потенцијално рањиве налоге и уклања потреба за креирањем рачунарског налога, који може бити тешко уклонити.<sup>[[1]](#references)</sup>

## Alati

### [**Whisker**](https://github.com/eladshamir/Whisker)

Whisker koristi DSInternals za manipulisanje atributom `msDS-KeyCredentialLink` iz C#-a. Whisker i njegov Python pandan **pyWhisker** podržavaju dodavanje, prikazivanje, uklanjanje i brisanje kredencijala ključeva.<sup>[[2]](#references)[[4]](#references)</sup>

Funkcije alata **Whisker** obuhvataju:

- **Add**: Generiše par ključeva i dodaje kredencijal ključa.
- **List**: Prikazuje sve unose kredencijala ključeva.
- **Remove**: Briše navedeni kredencijal ključa.
- **Clear**: Briše sve kredencijale ključeva, što može da ometa legitimnu upotrebu WHfB-a.

```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```

### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

pyWhisker donosi ovaj tok rada na **sisteme nalik UNIX-u** uz Impacket i PyDSInternals, uključujući operacije list/add/remove i uvoz/izvoz JSON-a.<sup>[[4]](#references)</sup>

```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```

### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray enumeriše objekte domena nad kojima operator ima prava kao što su `GenericWrite`/`GenericAll`, pokušava da široko doda key credentials i uključuje cleanup/recursive režime. Široko rasprostranjen spraying je ometajući i upadljiv; koristite eksplicitne ciljeve i sačuvajte svaki dodati DeviceID radi preciznog uklanjanja.<sup>[[3]](#references)</sup>

ADWS može da prenese upis key credential-a kada je direktni LDAP filtriran. Pogledajte [SOAPy ADWS workflow](../adws-enumeration.md#shadow-credentials-over-adws).<sup>[[5]](#references)</sup>



## References

- [1] [Shadow Credentials: Zloupotreba mapiranja naloga pomoću Key Trust-a za preuzimanje naloga](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker - Alat za preuzimanje AD naloga manipulacijom atributom msDS-KeyCredentialLink](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray - Alat za raspršivanje Shadow Credentials kroz domen](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker - Python verzija alata Shadow Credentials](https://github.com/ShutdownRepo/pywhisker)
- [5] [SOAPy Wiki – Post-Exploitation](https://github.com/logangoins/SOAPy/wiki/Post%E2%80%90Exploitation)
{{#include ../../../banners/hacktricks-training.md}}
