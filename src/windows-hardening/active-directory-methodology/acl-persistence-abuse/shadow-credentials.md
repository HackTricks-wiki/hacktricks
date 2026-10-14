# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Inleiding <a href="#3f17" id="3f17"></a>

**Gaan die oorspronklike plasing na vir [al die inligting oor hierdie tegniek](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**<sup>[[1]](#references)</sup>

Kortliks: beheer oor ’n gebruiker of rekenaar se **`msDS-KeyCredentialLink`** kan ’n aanvaller in staat stel om ’n sleutelsbewys by te voeg, as daardie objek met PKINIT te staaf en—wanneer die KDC en rekening die nodige vloei ondersteun—die resulterende kaartjie met `S4U2Self`/gebruiker-na-gebruiker te gebruik om die objek se NT-hash te herwin.<sup>[[1]](#references)</sup>

In die plasing word ’n metode uiteengesit om **publieke-privaatsleutel-verifikasiebewyse** op te stel en ’n unieke **Service Ticket** te verkry wat die teiken se NTLM-hash insluit. Hierdie proses behels die geënkripteerde NTLM_SUPPLEMENTAL_CREDENTIAL binne die Privilege Attribute Certificate (PAC), wat gedekripteer kan word.<sup>[[1]](#references)</sup>

### Vereistes

Sekere voorwaardes moet nagekom word om hierdie tegniek toe te pas:<sup>[[1]](#references)</sup>

- Minstens een Windows Server 2016-domeinbeheerder is nodig.
- Die domeinbeheerder moet ’n digitale sertifikaat vir bedienerverifikasie geïnstalleer hê.
- Die gidsskema moet `msDS-KeyCredentialLink` bevat; ’n Windows Server 2016- of nuwer DC en ’n PKINIT-geskikte sertifikaat op die KDC is die praktiese platformvereistes wat deur die navorsing beskryf word. Gaan die domein se skema/DC-samestelling na eerder as om aan te neem dat die domeinfunksionele vlak alleen bepaal of dit uitgebuit kan word.
- ’n Rekening met gedelegeerde regte om die msDS-KeyCredentialLink-kenmerk van die teikenobjek te wysig, word vereis.

## Misbruik

Die misbruik van Key Trust vir rekenaarobjekte behels meer stappe as net die verkryging van ’n Ticket Granting Ticket (TGT) en die NTLM-hash. Die opsies sluit die volgende in:<sup>[[1]](#references)</sup>

1. Die skep van ’n **RC4 silver ticket** om as bevoorregte gebruikers op die beoogde gasheer op te tree.
2. Die gebruik van die TGT met **S4U2Self** om **bevoorregte gebruikers** na te boots; dit vereis dat die Service Ticket gewysig word om ’n diensklas by die diensnaam te voeg.

’n Belangrike voordeel van Key Trust-misbruik is dat dit beperk bly tot die aanvaller-gegenereerde private sleutel, en sodoende delegering na moontlik kwesbare rekeninge vermy. Dit vereis ook nie dat ’n rekenaarrekening geskep word nie, wat moeilik kan wees om te verwyder.<sup>[[1]](#references)</sup>

## Gereedskap

### [**Whisker**](https://github.com/eladshamir/Whisker)

Whisker gebruik DSInternals om `msDS-KeyCredentialLink` vanuit C# te manipuleer. Whisker en sy Python-eweknie **pyWhisker** ondersteun die byvoeging, lys, verwydering en skoonmaak van sleutelsbewyse.<sup>[[2]](#references)[[4]](#references)</sup>

**Whisker** se funksies sluit die volgende in:

- **Add**: Genereer ’n sleutelpaar en voeg ’n sleutelsbewys by.
- **List**: Wys alle sleutelsbewysinskrywings.
- **Remove**: Verwyder ’n gespesifiseerde sleutelsbewys.
- **Clear**: Vee alle sleutelsbewyse uit, wat moontlik wettige WHfB-gebruik ontwrig.

```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```

### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

pyWhisker bring die werkvloei na UNIX-agtige stelsels met Impacket en PyDSInternals, insluitend bewerkings om items te lys, by te voeg en te verwyder, en om JSON in te voer en uit te voer.<sup>[[4]](#references)</sup>

```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```

### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray enumerates domeinobjekte waaroor die operateur regte soos `GenericWrite`/`GenericAll` het, probeer om sleutelbewyse op groot skaal by te voeg, en sluit opruim-/rekursiewe modusse in. Grootskaalse spraying is ontwrigtend en opvallend; gebruik eksplisiete teikens en hou elke bygevoegde DeviceID by vir presiese verwydering.<sup>[[3]](#references)</sup>

ADWS kan die skryf van sleutelbewyse hanteer wanneer direkte LDAP gefiltreer word. Sien die [SOAPy ADWS-werkvloei](../adws-enumeration.md#shadow-credentials-over-adws).<sup>[[5]](#references)</sup>



## References

- [1] [Shadow Credentials: Misbruik van Key Trust-rekeningkartering om rekeninge oor te neem](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker - Gereedskap om AD-rekeninge oor te neem deur msDS-KeyCredentialLink te manipuleer](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray - Gereedskap om Shadow Credentials oor ’n domein te versprei](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker - Python-weergawe van die Shadow Credentials-gereedskap](https://github.com/ShutdownRepo/pywhisker)
- [5] [SOAPy Wiki – Na-uitbuiting](https://github.com/logangoins/SOAPy/wiki/Post%E2%80%90Exploitation)
{{#include ../../../banners/hacktricks-training.md}}
