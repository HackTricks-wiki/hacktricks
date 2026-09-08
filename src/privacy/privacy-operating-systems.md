# Privaatheid-bedryfstelsels

{{#include ../banners/hacktricks-training.md}}

Privaatheid-gefokusde bedryfstelsels verminder foute met roetering en volharding, maar geen enkele een kan identifiserende gedrag of gekompromitteerde hardeware vergoed nie.

## Kies die isolasiemodel

| Stelsel | Beste gebruik | Volharding | Netwerkafdwinging | Belangrikste kompromis |
|---|---|---|---|---|
| **Tor Browser op 'n onderhoude bedryfstelsel** | Af-en-toe anonieme webblaai | Blaaiertoestand is normaalweg beperk tot die sessie | Slegs blaaierverkeer | Ander toepassings en die gasheer bly buite Tor |
| **Tails** | Draagbare, geheueverliesende, enkeldoel-sessies | Opsionele geënkripteerde Persistent Storage | Internetverkeer word deur Tor gedwing | Herbegin-/werkvloeiprobleme; firmware-/hardewarevertroue |
| **Whonix** | Volhardende toepassings wat gedwonge Tor-roetering benodig | Volhardende VM's | Gateway/workstation-verdeling | Gasheer/hypervisor en identiteitsvermenging bly bestaan |
| **Qubes-Whonix** | Sterk kompartement-skeiding vir gevorderde gebruikers | Per-qube | Toegewyde netwerk-qubes en Whonix | Hardewarevereistes en operasionele kompleksiteit |

## Tails

Tails selflaai onafhanklik vanaf verwyderbare media, roeteer Internetverkeer deur Tor, en is ontwerp om minimale plaaslike toestand agter te laat. Sy eie waarskuwings beklemtoon dat dit nie kan beskerm teen 'n gekompromitteerde BIOS/firmware/hardeware, identifiserende openbaarmakings, lêermetadata, of 'n magtige waarnemer wat albei kante korreleer nie.<sup>[[1]](#references)</sup>

### Enkeldoel-Tails-werkvloei

1. Laai Tails vanaf die amptelike webwerf af op 'n betroubare, opgedateerde rekenaar en volg die amptelike verifikasie-/installasieproses.
2. Gebruik 'n ondersteunde USB-stasie slegs om Tails te selflaai; moenie dit ook as 'n algemene lêeroordragstasie gebruik nie.
3. Selflaai op hardeware wat jy fisies beheer. 'n Live OS kan nie 'n hardeware-keylogger of kwaadwillige firmware neutraliseer nie.
4. Laat Persistent Storage gedeaktiveer tensy die werkvloei dit werklik benodig. Indien geaktiveer, volhard slegs die vereiste kategorieë en gebruik 'n sterk wagwoordfrase.
5. Koppel aan 'n wettige netwerk. Indien 'n captive portal onvermydelik is, gebruik Tails' Unsafe Browser slegs vir die portaal, openbaar geen onnodige identiteit nie, sluit dit onmiddellik, en koppel aan Tor voordat enige sensitiewe aktiwiteit uitgevoer word.<sup>[[2]](#references)</sup>
6. Konfigureer 'n Tor bridge indien direkte Tor-sigbaarheid of blokkering belangrik is.
7. Voer **een kontekstuele identiteit/doel per sessie** uit. Tails beveel aan dat jy tussen aktiwiteite wat nie gekoppel behoort te word nie, herbegin.<sup>[[1]](#references)</sup>
8. Inspekteer en suiwer lêers voordat jy dit publiseer. Moenie afgelaaide aktiewe dokumente oopmaak in 'n toepassing wat die bedoelde konteks kan omseil nie.
9. Skakel volledig af wanneer jy klaar is en hou die USB fisies veilig.

## Whonix

Whonix skei 'n Tor-roeterende **Gateway** van 'n **Workstation** waarvan die toepassings nie die eksterne IP direk kan leer nie. Dit verminder proxy-/DNS-foute betekenisvol, maar die gasheer, hypervisor, gedrag en dokumente kan steeds identiteit openbaar. Whonix waarsku uitdruklik daarteen om een workstation vir veelvuldige identiteite te gebruik of anonieme en nie-anonieme aktiwiteit te kombineer.<sup>[[3]](#references)</sup>

### Kompartement-werkvloei

1. Verifieer die Whonix-beeld en virtualiseringsplatform vanaf amptelike bronne.
2. Werk die gasheer, hypervisor, Gateway en Workstation op voordat jy dit gebruik.
3. Kloon 'n vars Workstation vir elke identiteit of betrokkenheid; moenie ooit 'n VM kloon nadat identiteitsdraende toestand ingestel is nie.
4. Hou persoonlike rekeninge, gedeelde gasheergidse, knipbordsinchronisering, USB-toestelle en tyd-/liggingdata uit die Workstation.
5. Gebruik snapshots vir herstel, nie as 'n plaasvervanger vir rugsteune of identiteitskeiding nie.
6. Bevestig dat die Workstation nie die Internet kan bereik wanneer die Gateway gestop is nie.
7. Gebruik vir besonder riskante lêers 'n weggooibare VM/qube en voer slegs 'n gesuiwerde resultaat uit.

## Qubes OS en Qubes-Whonix

Qubes implementeer sekuriteit deur kompartementalisering met Xen-gesteunde qubes. Die ontwerp beperk dat 'n kompromittering in een domein outomaties ander domeine bereik, maar toepassings binne **dieselfde** qube is nie van mekaar geïsoleer nie.<sup>[[4]](#references)</sup> Weggooibare qubes verskaf vars toestand vir onbetroubare webwerwe, lêers en toestelle.<sup>[[5]](#references)</sup>

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

- Gee elke qube een trust level en identity purpose.
- Hou secrets in ’n offline vault qube en gebruik eksplisiete inter-qube kopieer-/lêerbewerkings.
- Maak ongevraagde lêers en links in disposables oop.
- Roeteer slegs die bedoelde qubes deur Whonix of ’n toegewyde VPN qube.
- Benoem vensters duidelik en stop onverwante qubes tydens sensitiewe werk.
- Moenie aanvaar dat twee qubes korrelasie voorkom as hulle accounts, inhoud, skedules of betalings deel nie.

## Verification and maintenance

- Verifieer installer-handtekeninge/checksums deur amptelike instruksies te gebruik.
- Patch templates eerste, en herbegin dan afhanklike qubes/VMs.
- Bevestig network-deny-gedrag, DNS, IPv6, klok, clipboard, gedeelde gidse en USB-toewysing.
- Hersien Persistent Storage en VM-snapshots vir ou identity-bearing data.
- Hou geënkripteerde offline backups van seeds/keys en toets herstel in ’n geïsoleerde omgewing.
- Bou ’n compartment weer nadat ’n compromise vermoed word; om sy egress IP te verander is onvoldoende.

## References

- [1] [Tails — Waarskuwings: Tails is veilig, maar nie magies nie](https://tails.net/doc/about/warnings/index.en.html)
- [2] [Tails — Meld by ’n netwerk aan deur ’n captive portal te gebruik](https://tails.net/doc/anonymous_internet/unsafe_browser/index.en.html)
- [3] [Whonix — Whonix en Tor-beperkings](https://www.whonix.org/wiki/Warning)
- [4] [Qubes OS — Sekuriteitsontwerpdoelwitte](https://doc.qubes-os.org/en/latest/developer/system/security-design-goals.html)
- [5] [Qubes OS — Hoe om disposables te gebruik](https://doc.qubes-os.org/en/latest/user/how-to-guides/how-to-use-disposables.html)
{{#include ../banners/hacktricks-training.md}}
