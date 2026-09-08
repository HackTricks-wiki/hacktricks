# Privaatheidsbedryfstelsels

Privaatheidsgefokusde bedryfstelsels verminder routing- en persistentiefoute, maar geen daarvan kan identifiserende gedrag of gekompromitteerde hardeware vergoed nie.

## Kies die isolasiemodel

| Stelsel | Beste gebruik | Persistentie | Netwerkafdwinging | Hoofkompromis |
|---|---|---|---|---|
| **Tor Browser on a maintained OS** | Geleentheidsanonieme webblaai | Blaaiertoestand is normaalweg tot die sessie beperk | Slegs blaaierverkeer | Ander toepassings en die gasheer bly buite Tor |
| **Tails** | Draagbare, amnesiese, enkeldoelsessies | Opsionele geënkripteerde Persistent Storage | Internetverkeer word deur Tor gedwing | Herlaai-/werkvloeiprobleme; firmware-/hardewarevertroue |
| **Whonix** | Persistente toepassings wat gedwonge Tor-routing benodig | Persistente VM's | Gateway/Workstation-verdeling | Gasheer/hypervisor en identiteitsvermenging bly bestaan |
| **Qubes-Whonix** | Sterk kompartementskeiding vir gevorderde gebruikers | Per-qube | Toegewyde netwerk-qubes en Whonix | Hardewarevereistes en operasionele kompleksiteit |

## Tails

Tails begin onafhanklik vanaf verwyderbare media, stuur Internetverkeer deur Tor, en is ontwerp om minimale plaaslike toestand agter te laat. Tails se eie waarskuwings beklemtoon dat dit nie kan beskerm teen 'n gekompromitteerde BIOS/firmware/hardeware, identifiserende openbaarmakings, lêermetadata, of 'n magtige waarnemer wat albei eindpunte korreleer nie.<sup>[[1]](#references)</sup>

### Enkeldoel-Tails-werkvloei

1. Laai Tails vanaf die amptelike webwerf af op 'n vertroude, bygewerkte rekenaar en volg die amptelike verifikasie-/installasieproses.
2. Gebruik 'n ondersteunde USB-stasie slegs om Tails te begin; moenie dit ook as 'n algemene lêeroordragstasie gebruik nie.
3. Begin op hardeware wat jy fisies beheer. 'n Live OS kan nie 'n hardeware-keylogger of kwaadwillige firmware neutraliseer nie.
4. Laat Persistent Storage gedeaktiveer tensy die werkvloei dit werklik benodig. Indien dit geaktiveer is, persisteer slegs die vereiste kategorieë en gebruik 'n sterk wagfrase.
5. Koppel aan 'n wettige netwerk. Indien 'n captive portal onvermydelik is, gebruik Tails' Unsafe Browser slegs vir die portal, openbaar geen onnodige identiteit nie, maak dit onmiddellik toe, en koppel aan Tor voordat enige sensitiewe aktiwiteit begin.<sup>[[2]](#references)</sup>
6. Stel 'n Tor bridge op indien direkte Tor-sigbaarheid of -blokkering saak maak.
7. Voer **een kontekstuele identiteit/doel per sessie** uit. Tails beveel aan dat jy tussen aktiwiteite wat nie aan mekaar gekoppel behoort te word nie, herbegin.<sup>[[1]](#references)</sup>
8. Inspekteer en saniteer lêers voordat jy dit publiseer. Moenie afgelaaide aktiewe dokumente oopmaak in 'n toepassing wat die beoogde konteks kan omseil nie.
9. Skakel volledig af wanneer jy klaar is en hou die USB fisies beveilig.

## Whonix

Whonix skei 'n Tor-routing-**Gateway** van 'n **Workstation** waarvan die toepassings nie die eksterne IP direk kan leer nie. Dit verminder proxy-/DNS-foute betekenisvol, maar die gasheer, hypervisor, gedrag en dokumente kan steeds identiteit openbaar. Whonix waarsku uitdruklik daarteen om een Workstation vir verskeie identiteite te gebruik of anonieme en nie-anonieme aktiwiteite te kombineer.<sup>[[3]](#references)</sup>

### Kompartement-werkvloei

1. Verifieer die Whonix-beeld en virtualiseringsplatform vanaf amptelike bronne.
2. Dateer die gasheer, hypervisor, Gateway en Workstation op voordat jy dit gebruik.
3. Kloon 'n vars Workstation vir elke identiteit of opdrag; moet nooit 'n VM kloon nadat identiteitsdraende toestand bekendgestel is nie.
4. Hou persoonlike rekeninge, gedeelde gasheervouers, klipbordsinchronisasie, USB-toestelle en tyd-/liggingdata uit die Workstation.
5. Gebruik snapshots vir herstel, nie as 'n plaasvervanger vir rugsteune of identiteitskeiding nie.
6. Bevestig dat die Workstation nie die Internet kan bereik wanneer die Gateway gestop is nie.
7. Vir besonder riskante lêers, gebruik 'n weggooibare VM/qube en voer slegs 'n gesaniteerde resultaat uit.

## Qubes OS en Qubes-Whonix

Qubes implementeer sekuriteit deur kompartementalisering met Xen-gesteunde qubes. Die ontwerp beperk dat 'n kompromittering in een domein outomaties ander kan bereik, maar toepassings binne dieselfde **qube** is nie van mekaar geïsoleer nie.<sup>[[4]](#references)</sup> Weggooibare qubes verskaf vars toestand vir onbetroubare webwerwe, lêers en toestelle.<sup>[[5]](#references)</sup>

'n Praktiese uitleg:
```text
vault-offline        keys, recovery codes; no network
personal             real-identity daily accounts
client-red-2026      engagement administration only
client-red-net       approved VPN/bastion routing
anon-research        Qubes-Whonix Workstation
anon-research-net    Whonix Gateway
disp-untrusted       links and document rendering
```
Reëls:

- Gee elke qube een vertrouensvlak en identiteitsdoel.
- Hou geheime in ’n offline vault-qube en gebruik eksplisiete inter-qube-kopieer-/lêerbewerkings.
- Maak ongevraagde lêers en links in disposables oop.
- Roeteer slegs die bedoelde qubes deur Whonix of ’n toegewyde VPN-qube.
- Benoem vensters duidelik en stop onverwante qubes tydens sensitiewe werk.
- Moenie aanvaar dat twee qubes korrelasie voorkom as hulle rekeninge, inhoud, skedules of betalings deel nie.

## Verifikasie en instandhouding

- Verifieer installeerderhandtekeninge/kontrolesomme volgens die amptelike instruksies.
- Werk templates eerste by en herbegin daarna afhanklike qubes/VMs.
- Bevestig netwerk-weiergedrag, DNS, IPv6, klok, knipbord, gedeelde gidse en USB-toewysing.
- Hersien Persistent Storage en VM-snapshots vir ou data wat met ’n identiteit verband hou.
- Hou geënkripteerde offline rugsteunkopieë van seeds/sleutels en toets herstel in ’n geïsoleerde omgewing.
- Bou ’n kompartement weer nadat ’n kompromittering vermoed word; die verandering van sy egress-IP is onvoldoende.

## References

- [1] [Tails — Waarskuwings: Tails is veilig, maar nie magies nie](https://tails.net/doc/about/warnings/index.en.html)
- [2] [Tails — Aanmelding by ’n netwerk met ’n captive portal](https://tails.net/doc/anonymous_internet/unsafe_browser/index.en.html)
- [3] [Whonix — Whonix en Tor-beperkings](https://www.whonix.org/wiki/Warning)
- [4] [Qubes OS — Sekuriteitsontwerpdoelwitte](https://doc.qubes-os.org/en/latest/developer/system/security-design-goals.html)
- [5] [Qubes OS — Hoe om disposables te gebruik](https://doc.qubes-os.org/en/latest/user/how-to-guides/how-to-use-disposables.html)
