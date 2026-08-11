# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Inleiding <a href="#3f17" id="3f17"></a>

**Lees die oorspronklike plasing vir [al die inligting oor hierdie tegniek](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**<sup>[[1]](#references)</sup>

Kortliks kan beheer oor 'n gebruiker of rekenaar se **`msDS-KeyCredentialLink`** 'n aanvaller in staat stel om 'n sleutelbewys by te voeg, as daardie objek met PKINIT te authenticate, en—wanneer die KDC en rekening die nodige vloeie ondersteun—die gevolglike kaartjie met `S4U2Self`/user-to-user te gebruik om die objek se NT-hash te herwin.<sup>[[1]](#references)</sup>

In die plasing word 'n metode uiteengesit om **public-private key authentication credentials** op te stel om 'n unieke **Service Ticket** te verkry wat die teiken se NTLM-hash insluit. Hierdie proses behels die geënkripteerde NTLM_SUPPLEMENTAL_CREDENTIAL binne die Privilege Attribute Certificate (PAC), wat gedekripteer kan word.<sup>[[1]](#references)</sup>

### Vereistes

Om hierdie tegniek toe te pas, moet sekere voorwaardes nagekom word:<sup>[[1]](#references)</sup>

- Minstens een Windows Server 2016 Domain Controller word benodig.
- Die Domain Controller moet 'n digitale sertifikaat vir bediener-verifikasie geïnstalleer hê.
- Die gidskema moet `msDS-KeyCredentialLink` bevat; 'n Windows Server 2016 of nuwer DC en 'n PKINIT-bevoegde sertifikaat op die KDC is die praktiese platformvereistes wat deur die navorsing beskryf word. Verifieer die domein se skema/DC-samestelling eerder as om aan te neem dat die domein se funksionele-vlak-etiket alleen bepaal of uitbuiting moontlik is.
- 'n Rekening met gedelegeerde regte om die msDS-KeyCredentialLink-kenmerk van die teikenobjek te wysig, word vereis.

## Misbruik

Die misbruik van Key Trust vir rekenaarobjekte omvat stappe verder as die verkryging van 'n Ticket Granting Ticket (TGT) en die NTLM-hash. Die opsies sluit in:<sup>[[1]](#references)</sup>

1. Die skep van 'n **RC4 silver ticket** om as bevoorregte gebruikers op die beoogde gasheer op te tree.
2. Die gebruik van die TGT met **S4U2Self** vir nabootsing van **bevoorregte gebruikers**, wat wysigings aan die Service Ticket vereis om 'n service class by die diensnaam te voeg.

'n Beduidende voordeel van Key Trust-misbruik is dat dit beperk is tot die aanvaller-gegenereerde private sleutel, delegering na potensieel kwesbare rekeninge vermy en nie die skepping van 'n rekenaarrekening vereis nie, wat moeilik kan wees om te verwyder.<sup>[[1]](#references)</sup>

## Nutsmiddels

### [**Whisker**](https://github.com/eladshamir/Whisker)

Whisker gebruik DSInternals om `msDS-KeyCredentialLink` vanuit C# te manipuleer. Whisker en sy Python-eweknie **pyWhisker** ondersteun die byvoeging, lys, verwydering en skoonmaak van sleutelbewyse.<sup>[[2]](#references)[[4]](#references)</sup>

**Whisker**-funksies sluit in:

- **Add**: Genereer 'n sleutelpaar en voeg 'n sleutelbewys by.
- **List**: Vertoon alle sleutelbewysinskrywings.
- **Remove**: Skrap 'n gespesifiseerde sleutelbewys.
- **Clear**: Vee alle sleutelbewyse uit, wat wettige WHfB-gebruik moontlik kan ontwrig.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

pyWhisker bring die workflow na **UNIX-agtige stelsels** met Impacket en PyDSInternals, insluitend list/add/remove- en JSON import/export-bewerkings.<sup>[[4]](#references)</sup>
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray enumerates domeinobjekte waaroor die operateur regte het, soos `GenericWrite`/`GenericAll`, poog om sleutelaanmeldingsbewyse breedweg by te voeg, en sluit opruimings-/rekursiewe modusse in. Breë spraying is ontwrigtend en opvallend; gebruik eksplisiete teikens en behou elke bygevoegde DeviceID vir presiese verwydering.<sup>[[3]](#references)</sup>

## References

- [1] [Shadow Credentials: Misbruik van Key Trust Account Mapping vir Account Takeover](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker - Tool om AD-rekeninge oor te neem deur msDS-KeyCredentialLink te manipuleer](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray - Tool om Shadow Credentials oor ’n domein te spray](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker - Python-weergawe van die Shadow Credentials-tool](https://github.com/ShutdownRepo/pywhisker)
{{#include ../../../banners/hacktricks-training.md}}
