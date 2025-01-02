# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#3f17" id="3f17"></a>

**Kyk na die oorspronklike pos vir [alle inligting oor hierdie tegniek](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**

As **opsomming**: as jy kan skryf na die **msDS-KeyCredentialLink** eienskap van 'n gebruiker/rekenaar, kan jy die **NT hash van daardie objek** verkry.

In die pos word 'n metode uiteengesit om **publiek-private sleutelverifikasie krediete** op te stel om 'n unieke **Service Ticket** te verkry wat die teiken se NTLM hash insluit. Hierdie proses behels die versleutelde NTLM_SUPPLEMENTAL_CREDENTIAL binne die Privilege Attribute Certificate (PAC), wat gedekript kan word.

### Requirements

Om hierdie tegniek toe te pas, moet sekere voorwaardes nagekom word:

- 'n Minimum van een Windows Server 2016 Domeinbeheerder is nodig.
- Die Domeinbeheerder moet 'n digitale sertifikaat vir bedienerverifikasie geïnstalleer hê.
- Die Active Directory moet op die Windows Server 2016 Funksionele Vlak wees.
- 'n Rekening met gedelegeerde regte om die msDS-KeyCredentialLink attribuut van die teiken objek te wysig, is vereis.

## Abuse

Die misbruik van Key Trust vir rekenaarobjekte sluit stappe in wat verder gaan as die verkryging van 'n Ticket Granting Ticket (TGT) en die NTLM hash. Die opsies sluit in:

1. Die skep van 'n **RC4 silwer kaartjie** om as bevoorregte gebruikers op die beoogde gasheer op te tree.
2. Die gebruik van die TGT met **S4U2Self** vir die vervalsing van **bevoorregte gebruikers**, wat veranderinge aan die Service Ticket vereis om 'n diensklas by die diensnaam te voeg.

'n Beduidende voordeel van Key Trust misbruik is die beperking tot die aanvaller-gegenereerde private sleutel, wat delegasie na potensieel kwesbare rekeninge vermy en nie die skep van 'n rekenaarrekening vereis nie, wat moeilik kan wees om te verwyder.

## Tools

### [**Whisker**](https://github.com/eladshamir/Whisker)

Dit is gebaseer op DSInternals wat 'n C#-koppelvlak vir hierdie aanval bied. Whisker en sy Python teenhanger, **pyWhisker**, stel in staat om die `msDS-KeyCredentialLink` attribuut te manipuleer om beheer oor Active Directory rekeninge te verkry. Hierdie gereedskap ondersteun verskeie operasies soos om sleutel krediete by te voeg, op te lys, te verwyder en te skoon te maak van die teiken objek.

**Whisker** funksies sluit in:

- **Add**: Genereer 'n sleutel paar en voeg 'n sleutel krediet by.
- **List**: Vertoon alle sleutel krediet inskrywings.
- **Remove**: Verwyder 'n spesifieke sleutel krediet.
- **Clear**: Verwyder alle sleutel krediete, wat moontlik wettige WHfB gebruik kan ontwrig.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

Dit brei Whisker se funksionaliteit uit na **UNIX-gebaseerde stelsels**, wat Impacket en PyDSInternals benut vir omvattende eksploitasiemogelijkheden, insluitend die lys, toevoeging en verwydering van KeyCredentials, sowel as die invoer en uitvoer daarvan in JSON-formaat.
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray poog om **GenericWrite/GenericAll toestemmings wat wye gebruikersgroepe oor domeinobjekte mag hê, te benut** om ShadowCredentials breedvoerig toe te pas. Dit behels om in die domein in te teken, die domein se funksionele vlak te verifieer, domeinobjekte te enumeer, en te probeer om KeyCredentials vir TGT verkryging en NT hash onthulling by te voeg. Opruimopsies en rekursiewe uitbuitings taktieke verbeter die nut daarvan.

## References

- [https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [https://github.com/eladshamir/Whisker](https://github.com/eladshamir/Whisker)
- [https://github.com/Dec0ne/ShadowSpray/](https://github.com/Dec0ne/ShadowSpray/)
- [https://github.com/ShutdownRepo/pywhisker](https://github.com/ShutdownRepo/pywhisker)

{{#include ../../../banners/hacktricks-training.md}}
