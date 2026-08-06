# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Uvod <a href="#3f17" id="3f17"></a>

**Pogledajte originalnu objavu za [sve informacije o ovoj tehnici](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**<sup>[[1]](#references)</sup>

**Ukratko**: ako možete da upisujete u svojstvo **msDS-KeyCredentialLink** korisnika ili računara, možete preuzeti **NT hash tog objekta**.<sup>[[1]](#references)</sup>

U objavi je opisana metoda za podešavanje **akreditiva za autentifikaciju pomoću javnog i privatnog ključa**, kako bi se dobio jedinstveni **Service Ticket** koji sadrži NTLM hash cilja. Ovaj proces uključuje šifrovani NTLM_SUPPLEMENTAL_CREDENTIAL unutar Privilege Attribute Certificate-a (PAC), koji se može dešifrovati.<sup>[[1]](#references)</sup>

### Zahtevi

Da bi se ova tehnika primenila, moraju biti ispunjeni određeni uslovi:<sup>[[1]](#references)</sup>

- Potreban je najmanje jedan Windows Server 2016 Domain Controller.
- Domain Controller mora imati instaliran digitalni sertifikat za server authentication.
- Active Directory mora biti na Windows Server 2016 Functional Level-u.
- Potreban je nalog sa delegiranim pravima za izmenu atributa msDS-KeyCredentialLink ciljnog objekta.

## Abuse

Abuse Key Trust-a nad računarskim objektima obuhvata korake koji prevazilaze dobijanje Ticket Granting Ticket-a (TGT) i NTLM hash-a. Dostupne opcije uključuju:<sup>[[1]](#references)</sup>

1. Kreiranje **RC4 silver ticket-a** za delovanje u svojstvu privilegovanih korisnika na predviđenom hostu.
2. Korišćenje TGT-a sa **S4U2Self** za impersonaciju **privilegovanih korisnika**, što zahteva izmene Service Ticket-a radi dodavanja klase servisa nazivu servisa.

Značajna prednost abuse-a Key Trust-a jeste to što je ograničen na privatni ključ koji je generisao attacker, čime se izbegava delegacija potencijalno ranjivim nalozima i ne zahteva kreiranje računarskog naloga, koji bi moglo biti teško ukloniti.<sup>[[1]](#references)</sup>

## Alati

### [**Whisker**](https://github.com/eladshamir/Whisker)

Zasnovan je na DSInternals-u i pruža C# interfejs za ovaj attack. Whisker i njegov Python pandan, **pyWhisker**, omogućavaju manipulaciju atributom `msDS-KeyCredentialLink` radi preuzimanja kontrole nad Active Directory nalozima. Ovi alati podržavaju različite operacije, kao što su dodavanje, prikazivanje, uklanjanje i brisanje key credentials-a iz ciljnog objekta.

Funkcije alata **Whisker** uključuju:

- **Add**: Generiše par ključeva i dodaje key credential.
- **List**: Prikazuje sve unose key credentials-a.
- **Remove**: Briše navedeni key credential.
- **Clear**: Briše sve key credentials-e, što može potencijalno prekinuti legitimnu upotrebu WHfB-a.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

Proširuje funkcionalnost alata Whisker na **sisteme zasnovane na UNIX-u**, koristeći Impacket i PyDSInternals za sveobuhvatne mogućnosti eksploatacije, uključujući izlistavanje, dodavanje i uklanjanje KeyCredentials, kao i njihov uvoz i izvoz u JSON formatu.
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray ima za cilj da **iskoristi GenericWrite/GenericAll dozvole koje široke korisničke grupe mogu imati nad objektima domena** kako bi široko primenio ShadowCredentials. To podrazumeva prijavljivanje na domen, proveru funkcionalnog nivoa domena, enumeraciju objekata domena i pokušaj dodavanja KeyCredentials radi pribavljanja TGT-a i otkrivanja NT hash-a. Opcije čišćenja i rekurzivne taktike eksploatacije dodatno povećavaju njegovu korisnost.

## Reference

- [1] [Shadow Credentials: Zloupotreba Key Trust Account Mapping-a za preuzimanje naloga](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker - Alat za preuzimanje AD naloga manipulisanjem atributom msDS-KeyCredentialLink](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray - Alat za primenu Shadow Credentials-a kroz domen](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker - Python verzija Shadow Credentials alata](https://github.com/ShutdownRepo/pywhisker)

{{#include ../../../banners/hacktricks-training.md}}
