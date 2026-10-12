# Verborge Fisiese en Draadlose Toegang

{{#include ../banners/hacktricks-training.md}}

Vir ’n gedetailleerde, eienaar-goedgekeurde implementering wat uitgaande rendezvous, herstel van krag/uplink, minimale geheime wat deur die toestel gehou word, capture-toetsing en monitering vir moontlike ontdekking dek, sien [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md).

Die verandering van die netwerkroete kan ook die skynbare fisiese oorsprong verander. ’n Gesofistikeerde akteur kan ’n nabygeleë gekompromitteerde stelsel, ’n versteekte toestel, publieke toegang, sellulêre backhaul of ’n satellietontvanger gebruik sodat teikenlogboeke na ’n ander plek as die operateur wys. Niks hiervan verwyder fisiese, radio- of verskafferbewyse nie; dit verskuif die toeskrywing na ander datastelle.

## Tegniekmatriks

| Tegniek | Skynbare oorsprong | Noodsaaklike voorwaarde | Bewyse met hoë waarde |
|---|---|---|---|
| Nabygeleë draadlose pivot | ’n besigheid/huis langs die teiken | gekompromitteerde dual-homed gasheer en Wi-Fi-toegang tot die teiken | eindpuntlogboeke van die buurgasheer, RF-assosiasie en teiken se RADIUS/DHCP |
| Publieke/gasnetwerk | venue se NAT of tunnel-uitgang | wettige toegang of omseiling van toegangsbeheer | captive portal, DHCP, AP-assosiasie, CCTV en betalings-/liggingrekords |
| Versteekte drop-toestel | teiken-/nabygeleë bedrade, Wi-Fi- of sellulêre adres | fisiese plasing of aflewering | switchport/USB, RF, voorraad, krag en telemetrie van uitgaande tunnel |
| Sellulêre router/eSIM | draer-NAT of toegewyde APN | modem/SIM/intekening | IMEI/IMSI/eSIM, selfoonsektor, draerrekening en verkeerstydsberekening |
| Misbruik van satellietverbinding | intekenaaradres binne bundeldekking | protokol- en diensspesifieke swakheid | RF-ligging, uplink-vloei, onmoontlike RTT/roetering en verskafferrekords |

## Nearest-neighbor attack

Volexity het ’n APT28/GRU-operasie in 2022 gedokumenteer waarin die akteur op afstand van sy uiteindelike teiken was. Dit het die teiken se publieke diens met password spraying aangeval om geldige credentials te verkry, maar MFA het direkte aanmelding vanaf die Internet verhoed. Die teiken se ondernemings-Wi-Fi het daardie credentials sonder MFA aanvaar. Die akteur het organisasies wat fisies naby die teiken was, gekompromitteer, ’n dual-homed stelsel met draadlose bereik opgespoor en daardie stelsel gebruik om by die teiken se Wi-Fi te autentiseer. Volexity het dit die **Nearest Neighbor Attack** genoem.<sup>[[1]](#references)</sup>

```text
remote operator
      |
compromised organization C
      |
compromised organization B -- Wi-Fi radio --> target organization A
                                               |
                                        internal service
```

Die nuutjie lê in die samestelling. Geen operateur reis na die teiken nie, en die MFA van die diens wat aan die Internet blootgestel is, werk steeds. Die gekompromitteerde buurtoestel verskaf fisiese nabyheid; die gesteelde teikenbewysstuk verskaf logiese toegang; die teiken-Wi-Fi word die pad wat die grens oorsteek.

### Voorvereistes en sigbaarheid

- ’n Stelsel naby die teiken moet op afstand beheerbaar wees en ’n versoenbare radio hê, of toegang tot ’n ander nabygeleë pivot.
- Die teiken-SSID moet daardie stelsel bereik, en Wi-Fi-toelating moet ’n herbruikbare bewysstuk/sertifikaat/toesteltoestand aanvaar.
- Die pivot benodig dikwels twee gelyktydige paaie: een terug na die operateur en een na die teiken-WLAN.
- Die teiken kan ’n nuwe stasie-MAC en ’n geldige gebruikernaam sien, maar geen ooreenstemmende sertifikaat vir ’n bestuurde toestel, postuur, geskiedenis of verwagte gebouinskrywing nie.
- Eindpuntlogboeke op die buurtoestel kan draadlose skanderings, nuwe profiele, koppelvlakveranderings, tonnelverkeer en afstandbeheeraktiwiteit toon.

### Opsporing en voorkoming

1. Vereis EAP-TLS met sertifikate en ’n postuurkontrole vir bestuurde toestelle op ondernemings-Wi-Fi; moenie toelaat dat ’n wagwoord wat MFA op die Internet nie geslaag het nie, voldoende is bloot omdat dit oor die radio aankom nie.
2. Bring RADIUS-verifikasie in verband met MDM/NAC-identiteit, historiese binding tussen stasie en toestel, AP-ligging, fisiese toegangsgebeure en gelyktydige sessies.
3. Skep ’n waarskuwing wanneer ’n rekening vir die eerste keer assosieer, vanaf ’n ongewone AP-rand, sonder ’n sertifikaat vir ’n bestuurde toestel, of terwyl dieselfde identiteit elders aktief is.
4. Monitor eindpunte wat koppelvlakke kan oorbrug. Ondersoek op Windows-, Linux- en netwerktoestelle onverwagte WLAN-profiele, aanstuur-/NAT-konfigurasie, virtuele adapters en aanhoudende tonnels.
5. Verminder onnodige seinverspreiding met deurdagte AP-plasing en kragbeplanning. Dit is ’n aanvullende beheermaatreël, nie verifikasie nie.
6. Koördineer insidentreaksie met naburige huurders: die uiteindelike radiobron kan self ’n slagoffer wees.

Die [laboratorium met twee organisasies in besit](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) boots hierdie waarneembare aktiwiteit na sonder om ’n buurtoestel aan te val.

### Valideer ’n Windows-pivotpad

’n Windows-gasheer met twee netwerkverbindings oorbrug nie sy koppelvlakke outomaties nie. Inventariseer eers sy adapters, roetes en WLAN-toestand, en assosieer dan slegs deur ’n goedgekeurde profiel. Die `name`-argument vir `netsh wlan connect` identifiseer ’n geïnstalleerde profiel, nie ’n arbitrêre SSID en wagwoord nie. Vergelyk die roetetabel voor en ná assosiasie sodat ’n nuwe verstekroete nie die beheerkanaal verbreek of die resultaat ongeldig maak nie. Gaan slegs voort met die [kontroles ná assosiasie](../generic-methodologies-and-resources/pentesting-wifi/wifi-post-association-and-client-isolation-attacks.md) nadat die bedoelde koppelvlak en roete bevestig is.<sup>[[1]](#references)[[6]](#references)</sup>

```powershell
Get-NetAdapter -Physical | Sort-Object Status -Descending
Get-NetIPConfiguration
Get-NetRoute -AddressFamily IPv4 | Sort-Object InterfaceIndex,RouteMetric

netsh wlan show interfaces
netsh wlan show networks mode=bssid
netsh wlan show profiles

# Connect only with an approved profile already installed on the endpoint.
netsh wlan connect name="<approved-profile>" interface="Wi-Fi"
Get-NetConnectionProfile
```

Volexity se vrygestelde insidentartefak toon nog ’n nuttige onderskeid. Die ingebedde C# maak die WLAN API oop, lys koppelvlakke, lees EAP XML vanaf skyf en roep `WlanSetProfileEapXmlUserData` aan vir ’n benoemde profiel op die eerste draadlose koppelvlak. Die API stel EAP-gebruikersbewyse op ’n bestaande 802.1X-profiel in, maar die vrygestelde komponent bevat nóg `WlanConnect` nóg die ontdekkingslogika wat in die verslag beskryf word. Beskou dit as profielvoorsiening eerder as ’n volledige verbindinghulpmiddel, en ondersoek die resulterende profiel as deel van die [client and supplicant assessment](../generic-methodologies-and-resources/pentesting-wifi/wifi-client-and-supplicant-assessment.md).<sup>[[5]](#references)[[7]](#references)</sup>

## Openbare plekke en derdeparty-Wi-Fi

Die gebruik van Wi-Fi by ’n kafee, hotel, lughawe of munisipale plek verander die IP-adres wat ’n bestemming sien. Dit skep nie anonimiteit nie. Die plek of diensverskaffer kan AP-assosiasies, toestel-MAC-adresse, DHCP-huurtoekennings, captive-portal-rekeninge, SMS-/e-posvalidering en verkeerslogboeke behou. Fisieke toegang, CCTV, aankope, selfoonligging en reisrekords kan die digitale gebeurtenis aan ’n persoon koppel.

’n Akteur kan probeer om een identifiseerder te beperk deur ewekansige MAC-adresse, ’n aparte toestel, kontant of ’n tonnel te gebruik. Korrelasie oor verskillende lae heen bly moontlik deur aankomstyd, herhalende besoekpatrone, radiovingerafdrukke, portaalgedrag, verkeerstydsberekening, kamerabeelde en die tonneldiensverskaffer. ’n VPN verskuif ook die bestemming van die plek se logboeke na die VPN-logboeke; dit verwyder nie die plek se kennis dat die toestel daar was nie.

Verdedigers van openbare toegang behoort kliënte te isoleer, laterale verkeer te blokkeer, WPA2/3-Enterprise of sleutels per toestel te gebruik waar haalbaar, proporsionele DHCP/RADIUS-/sekuriteitslogboeke te behou, captive portals te beveilig en ’n proses vir misbruikverslae te publiseer. Red teams behoort so ’n plek slegs te gebruik wanneer die gebruiksvoorwaardes en die opdrag dit toelaat; om ’n portaal te omseil, toegang te steel of ander gaste te teiken, is nie ’n gemagtigde kortpad vir toetsing nie.

## Versteekte drop-toestelle en warshipping

’n Drop is ’n klein stelsel wat op ’n terrein geplaas of daarheen afgelewer word en dan via uitgaande Ethernet, Wi-Fi of sellulêre kommunikasie beheer word. “Warshipping” verpak die toestel so dat gewone aflewering dit binne die radioperimeter bring. Moontlike hardeware wissel van ’n enkelbordrekenaar tot ’n aangepaste laaier, USB-randtoestel, netwerktoestel of battery-aangedrewe modem.

Bedryfsargitektuur:

```text
operator -> controlled rendezvous <- outbound encrypted tunnel <- drop
                                                        |
                                             scoped local interface
```

Die toestel kan ’n afgeleë vastrapplek bied, draadlose metings uitvoer, ’n randtoestel vir ’n gemagtigde oefening naboots of verkeer aanstuur. Dit lyk of dit plaaslik afkomstig is, maar laat fisiese spore: reeksnommers, verpakking, vingerafdrukke, kameras, toegangslogboeke, kragverbruik, USB-beskrywings, skakelpoort-onderhandeling, DHCP-vingerafdrukke, MAC-OUI-/randomiseringsgedrag, RF-uitstralings en herhalende rendezvous-verbindings.

### Verdedigingsmaatreëls

- Handhaaf prosedures vir ontvangskamers en bate-inventarisse; inspekteer onverwagte elektronika en pakkette wat aan niebestaande werknemers geadresseer is.
- Gebruik 802.1X/NAC vir bedrade en draadlose toegang, deaktiveer ongebruikte poorte en plaas onbekende toestelle in ’n beperkte remediëring-VLAN.
- Stel waarskuwings op vir nuwe DHCP-vingerafdrukke, plaaslik geadministreerde MAC-adresse wat bly bestaan, nuwe USB-netwerk-/HID-toestelle, ongemagtigde Wi-Fi Direct/Bluetooth en langlewende uitgaande tonnels.
- Stel basislyne vas vir skakelpoort-, Power-over-Ethernet-, DNS- en TLS-gedrag. ’n Klein gasheer sonder ’n inventarisrekord wat periodieke geënkripteerde verbindings maak, is ’n sterker aanwyser as net ’n “Raspberry Pi OUI”.
- Tydens ’n oefening, inventariseer, merk, beperk omvang, enkripteer, voorsien ’n afgeleë doodskakelaar, stel ’n sperdatum vir terugbesorging en verseker dat verlies nie herbruikbare geloofsbriewe kan blootstel nie.

## Sellulêre en eSIM-terugskakeling

’n Sellulêre modem omseil die teiken se internetpoort en kan ’n drop bereikbaar hou agter draer-NAT deur ’n uitgaande rendezvous. Mobiele adresse kan roteer of gedeel word; die sellulêre operateur hou steeds sterk intekenaar- en netwerkbewyse: SIM-/eSIM-identiteit, IMSI, toestel-IMEI, toegewysde adresse/poorte, sel-/sektor-tydsberekening, rekening-/betalings- en swerfrekords.

Vanuit die onderneming se perspektief kan onverwagte modems en persoonlike hotspots opgespoor word deur draadlose/RF-opnames, USB/PCI-inventarisering van eindpunte, MDM-beperkings, monitering vir skelm SSID’s en fisiese inspeksie. ’n Drop wat sellulêr vir beheer gebruik, kan steeds aan sy plaaslike Ethernet-/Wi-Fi-gedrag en radio-uitstralings uitgeken word.

Vir gemagtigde oefeninge behoort die organisasie die intekening en modem te besit, die identifiseerders saam met die beheerder aan te teken en te bevestig dat die draer-/verskafferbepalings die verkeer toelaat. ’n Voorafbetaalde SIM of aankoop met kriptogeldeenheid wis nie toring-, toestel- of kleinhandelrekords uit nie.

## MAC-randomisering en toestelfingerafdrukke

Moderne stelsels kan ’n plaaslik geadministreerde, ewekansige MAC per netwerk gebruik. Dit verminder passiewe langtermynnasporing deur ’n stabiele fabrieks-MAC; dit verberg nie:

- probe-/assosiasietydsberekening en die stel aangevraagde netwerkeienskappe nie;
- 802.11-inligtingselemente, ondersteunde snelhede en verskafferspesifieke gedrag nie;
- DHCP-opsies/gasheernaam, IPv6-identifiseerders en captive-portal-/blaaier-vingerafdruk nie;
- geverifieerde 802.1X-identiteit of sertifikaat nie;
- hoërlaag-rekening-, tonnel- en verkeerspatrone nie; of
- fisiese waarneming nie.

Verdedigers behoort nie MAC-toelatingslyste as verifikasie te gebruik nie. Koppel radio-identiteit aan sertifikaat-/toestelhouding en behandel veranderende MAC-adresse as normaal, tensy ander konteks abnormaal is.

## Kaping van satellietskakels

Kaspersky het gedokumenteer dat Turla swakhede in ouer eenrigting-DVB-S-satellietinternet benut het. In die gerapporteerde model het ’n wettige afgeleë intekenaar uitgaande versoeke oor ’n terrestriële skakel gestuur, maar stroomafdata ontvang via ’n ongeënkripteerde satellietuitsending oor ’n wye gebied. ’n Akteur binne die satellietdekkingsgebied kon die afskakel waarneem, ’n aktiewe intekenaar-IP kies en reël dat C2-antwoorde aan daardie IP gerig word. Sowel die wettige intekenaar as die akteur het die uitsending ontvang; die akteur het verkeer vir die gekose poort onttrek terwyl die wettige intekenaar ongevraagde pakkette weggegooi het. Die C2-operateur het toe voorgekom asof dit ’n satellietverskafferadres in ’n ander geografiese gebied gebruik.<sup>[[2]](#references)</sup>

```text
actor uplink request -> C2 server -> Internet -> satellite gateway
                                           satellite broadcast
                                  +--------------+-------------+
                                  |                            |
                         legitimate subscriber          actor receiver
```

Dit was spesifiek vir ’n protokol/diens, bandwydtebeperk en nie gelykstaande aan die kompromittering van ’n moderne tweerigting-geënkripteerde satellietterminaal nie. Dit het ook nie die akteur se uitgaande versoekroete vir ’n waarnemer met voldoende vermoëns versteek nie. Geleenthede vir opsporing sluit in asimmetriese/onmoontlike roetering, verkeer na ’n intekenaar wat nie die vloei begin het nie, ongewone bestemmingspoorte, verskaffertelemetrie, ondersoek van die ontvanger se ligging/RF en malware-konfigurasie. Gebruik hierdie geval om die aanname te bevraagteken dat die geolokalisering van ’n C2-IP die ligging van die beheerder bepaal—nie as ’n bouresep nie.

## Werkblad vir fisiese-na-digitale korrelasie

Wanneer ’n skynbaar plaaslike bron verdag is, stel een tydlyn saam:

1. normaliseer die AP-, RADIUS-, DHCP-, DNS-, instaanbediener-, VPN-, EDR-, skakelaar- en fisieke-toegangshorlosies;
2. identifiseer die eerste radio-assosiasie of skakelverbinding, nie net die eerste waarskuwing nie;
3. koppel die stasie aan sertifikaat, toestelhouding, DHCP-vingerafdruk en skakelaar-/AP-ligging;
4. soek na gelyktydige afstandbeheer-/tonnelaktiwiteit op nabygeleë stelsels;
5. hersien aflewerings, besoekers, voorraaduitsonderings, kameras en RF-bevindinge ingevolge toepaslike beleid/wetgewing;
6. bewaar die verdagte toestel en die vlugtige netwerktoestand; moenie dit blindelings af- en aanskakel nie;
7. bepaal of die oënskynlike bron infrastruktuur is wat deur die akteur beheer word, of ’n ander slagoffer.

## References

- [1] [Volexity — Die Nearest Neighbor-aanval: Hoe ’n Russiese APT nabygeleë Wi-Fi-netwerke bewapen het](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [Kaspersky Securelist — Satellite Turla: APT-beheer en -beheer in die lug](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [3] [MITRE ATT&CK — Hardewaretoevoegings (T1200)](https://attack.mitre.org/techniques/T1200/)
- [4] [NIST SP 800-153 — Riglyne vir die beveiliging van draadlose plaaslike-area-netwerke](https://csrc.nist.gov/pubs/sp/800/153/final)
- [5] [Volexity — Geredigeerde PowerShell/C#-WLAN-profielkode](https://github.com/volexity/threat-intel/blob/main/2024/2024-11-22%20GruesomeLarch/wifi_ps1_redacted.cs)
- [6] [Microsoft — netsh wlan](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-wlan)
- [7] [Microsoft — WlanSetProfileEapXmlUserData-funksie](https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlansetprofileeapxmluserdata)
{{#include ../banners/hacktricks-training.md}}
