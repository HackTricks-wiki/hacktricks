# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Inleiding <a href="#3f17" id="3f17"></a>

**Gaan die oorspronklike plasing na vir [al die inligting oor hierdie tegniek](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**<sup>[[1]](#references)</sup>

As 'n **opsomming**: indien jy na die **msDS-KeyCredentialLink**-eienskap van 'n gebruiker/rekenaar kan skryf, kan jy die **NT-hash van daardie objek** herwin.<sup>[[1]](#references)</sup>

In die plasing word 'n metode uiteengesit om **public-private key authentication credentials** op te stel om 'n unieke **Service Ticket** te verkry wat die teiken se NTLM-hash insluit. Hierdie proses behels die geënkripteerde NTLM_SUPPLEMENTAL_CREDENTIAL binne die Privilege Attribute Certificate (PAC), wat gedekripteer kan word.<sup>[[1]](#references)</sup>

### Vereistes

Om hierdie tegniek toe te pas, moet sekere voorwaardes nagekom word:<sup>[[1]](#references)</sup>

- Ten minste een Windows Server 2016 Domain Controller word benodig.
- Die Domain Controller moet 'n server authentication digital certificate geïnstalleer hê.
- Die Active Directory moet op die Windows Server 2016 Functional Level wees.
- 'n Rekening met gedelegeerde regte om die msDS-KeyCredentialLink-kenmerk van die teikenobjek te wysig, word benodig.

## Misbruik

Die misbruik van Key Trust vir rekenaarobjekte behels stappe wat verder gaan as die verkryging van 'n Ticket Granting Ticket (TGT) en die NTLM-hash. Die opsies sluit in:<sup>[[1]](#references)</sup>

1. Die skep van 'n **RC4 silver ticket** om as bevoorregte gebruikers op die beoogde gasheer op te tree.
2. Die gebruik van die TGT met **S4U2Self** vir nabootsing van **bevoorregte gebruikers**, wat wysigings aan die Service Ticket vereis om 'n service class by die service name te voeg.

'n Beduidende voordeel van Key Trust-misbruik is dat dit beperk is tot die private key wat deur die aanvaller gegenereer is. Dit vermy delegering na potensieel kwesbare rekeninge en vereis nie die skep van 'n rekenaarrekening nie, wat moeilik kan wees om te verwyder.<sup>[[1]](#references)</sup>

## Gereedskap

### [**Whisker**](https://github.com/eladshamir/Whisker)

Dit is op DSInternals gebaseer en bied 'n C#-interface vir hierdie aanval. Whisker en sy Python-eweknie, **pyWhisker**, maak manipulasie van die `msDS-KeyCredentialLink`-kenmerk moontlik om beheer oor Active Directory-rekeninge te verkry. Hierdie tools ondersteun verskeie bewerkings, soos die byvoeging, lys, verwydering en skoonmaak van key credentials vanaf die teikenobjek.

**Whisker** se funksies sluit in:

- **Add**: Genereer 'n key pair en voeg 'n key credential by.
- **List**: Vertoon alle key credential-inskrywings.
- **Remove**: Verwyder 'n gespesifiseerde key credential.
- **Clear**: Wis alle key credentials uit, wat moontlik wettige WHfB-gebruik kan ontwrig.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

Dit brei Whisker-funksionaliteit uit na **UNIX-gebaseerde stelsels**, deur Impacket en PyDSInternals te benut vir omvattende exploitation capabilities, insluitend die lys, byvoeging en verwydering van KeyCredentials, asook die invoer en uitvoer daarvan in JSON-formaat.
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray is daarop gemik om **GenericWrite/GenericAll-permissies wat breë gebruikersgroepe oor domeinobjekte kan hê, te exploit** om ShadowCredentials wyd toe te pas. Dit behels om by die domein aan te meld, die domein se funksionele vlak te verifieer, domeinobjekte te enumeriseer, en te probeer om KeyCredentials by te voeg vir TGT-verkryging en NT-hash-onthulling. Opruimingsopsies en rekursiewe exploitation-taktieke verbeter die bruikbaarheid daarvan.

## Verwysings

- [1] [Shadow Credentials: Misbruik van Key Trust Account Mapping vir Account Takeover](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker - Tool om AD-accounts oor te neem deur msDS-KeyCredentialLink te manipuleer](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray - Tool om Shadow Credentials oor ’n domein te spray](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker - Python-weergawe van die Shadow Credentials-tool](https://github.com/ShutdownRepo/pywhisker)

{{#include ../../../banners/hacktricks-training.md}}
