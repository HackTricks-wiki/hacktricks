# Operasionele privaatheidspeelboeke

{{#include ../banners/hacktricks-training.md}}

Hierdie speelboeke kombineer die kontroles uit die res van hierdie afdeling. Hulle is beginpunte, nie waarborge nie: werk die bedreigingsmodel by wanneer ’n nuwe waarnemer, rekening, toestel, ligging, betaling, lêer of teenparty by die werkvloei betrokke raak.

## Universele voorafkontrole

1. Skryf die wettige doelwit neer en wat privaat moet bly **teenoor wie**.
2. Teken die identiteite, toestelle, netwerke, rekeninge, betalingskanale, teenpartye, fisiese liggings en data aan wat deur die aktiwiteit geraak sal word.
3. Identifiseer die sterkste waarskynlike waarnemer en die gevolg van mislukking.
4. Bevestig magtiging, toepaslike wetgewing, diensverskafferbepalings en organisatoriese beleid.
5. Besluit wat intern toeskryfbaar moet bly vir veiligheid, insidentreaksie, rekeningkunde en oudit.
6. Kies die kleinste werkbare kompartement; stel die herstel- en afskakelroetes daarvan op voordat dit gebruik word.
7. Toets die kompartement teen ’n beheerde diens, insluitend IP/DNS/IPv6, blaaieridentiteit, dokumentmetadata, betalingstaat en kennisgewing-leak.

Gebruik die gedetailleerde model in [Threat Modeling and Identity Separation](threat-modeling-and-identity-separation.md).

## Alledaagse privaatheidsbasislyn

Doelwit: verminder kommersiële opsporing, rekeningoorname en onnodige blootstelling sonder om anoniem te probeer word.

- Gebruik ’n onderhoude OS met volskyf-enkripsie, outomatiese opdaterings, skermsluiting en secure boot waar beskikbaar.
- Stel eers die password manager, herstel-e-pos en phishing-resistant MFA/security keys op.
- Hersien app-toestemmings, ligginggeskiedenis, advertensie-identifiseerders, cloud sync en derdeparty-rekeningverbindings.
- Gebruik ’n algemene blaaier met min extensions, tracking protection, HTTPS, en aparte profiele vir werk/persoonlike/hoërisiko-blaai.
- Gebruik private relay-aliasse of afsonderlike e-posadresse volgens verhouding; moenie ’n persoonlike telefoonnommer gebruik wanneer dit bloot opsioneel is nie.
- Verkies end-to-end encrypted messaging vir inhoud, maar onthou dat deelnemers, tydsberekening, groepe en endpoints metadata bly.
- Verwyder metadata doelbewus uit lêers en inspekteer die uitgevoerde kopie—nie die oorspronklike nie—voordat dit gepubliseer word.
- Gebruik virtual-card- of wallet-tokens vir betalingsbewys-kompartementalisering; moenie dit anonymous noem nie.
- Rugsteun encrypted recovery material en toets herstel.

## Pseudonieme publikasie

Doelwit: voorkom dat toevallige lesers en platforms ’n publikasie maklik aan ’n burgerlike identiteit koppel. Dit verslaan nie ’n bekwame geteikende ondersoek nie.

1. Definieer of die platform, hosting provider, lesers, kontakte, plaaslike netwerk, betalingsverskaffer of regsproses in die threat model is.
2. Skep ’n toegewyde endpoint/account-konteks vanaf ’n skoon basislyn. Deaktiveer persoonlike browser sync, cloud documents, kontakoplaai en notification previews.
3. Skep die pseudonieme rekening deur die gekose netwerkkompartement. Moenie usernames, avatars, recovery channels, writing boilerplate of personal identity-provider login hergebruik nie.
4. Gebruik Tor Browser wanneer destination unlinkability belangriker as spoed is; moenie extensions byvoeg, dit oormatig resize/customize of afgelaaide dokumente oopmaak terwyl jy aanlyn in ’n gewone desktopsessie is nie.
5. Stel konsepte op met ’n proses wat nie persoonlike templatenames, revision authors, printer paths, GPS/EXIF, thumbnails of hidden layers insluit nie. Voer ’n kopie uit en inspekteer dit met toepaslike metadatagereedskap.
6. Kontroleer die inhoud vir selfidentifiserende feite: unieke datums, werkplekbesonderhede, plaaslike weer/tydsone, refleksies, agtergrondklank, taalgewoontes en tekshergebruik uit vorige publikasies.
7. Gebruik ’n aparte antwoordkanaal. Behandel elke direkte kontak, aanhangsel en skakel as ’n moontlike korrelasie- of phishing-poging.
8. Indien geld betrokke is, gebruik die wettige metode wat slegs die nodige data blootstel. Aanvaar dat die platform en gereguleerde tussenganger die ontvanger kan ken, selfs al doen lesers dit nie.
9. Publiseer, en inspekteer dan die openbare resultaat vanuit ’n ander skoon konteks. Teken aan wat die platform bygevoeg of verander het.
10. Handhaaf slegs ’n beplande ritme indien dit nie ’n stabiele gedragsvingerafdruk skep nie; tree eerder uit die kompartement as om dit stilweg te hergebruik.

Vir ernstige joernalistiek, aktivisme, huishoudelike mishandeling of staatsvlakrisiko, verkry pasgemaakte hulp van ’n ervare digital-security-organisasie; ’n statiese kontrolelys kan nie plaaslike wetgewing of ’n aktiewe teenstander modelleer nie.

## Gemagtigde red-team-betrokkenheid

Doelwit: hou operateurs se persoonlike identiteite en tuisnetwerke buite teiken-telemetrie terwyl magtiging, beheer en insidentreaksie behoue bly.

### Voor die begintydvenster

- Finaliseer die ROE-infrastruktuurbylaag, teikens/uitsluitings, bronreekse, datums, noodstop en derdeparty-/provider-toestemmings.
- Wys ’n toegewyde operator-profiel of VM, engagement secrets, evidence store, cloud project, domains en budget toe.
- Verkies client-provided egress of ’n organisasie-beheerde vaste bastion. Toets full-tunnel IPv4/IPv6/DNS-gedrag en fail-closed-beleid.
- Berg die koppeling tussen operateur en openbare infrastruktuur by die exercise controller of ooreengekome escrow-kontak.
- Stel rate limits, destination allowlists en afsonderlike goedkeuring vir vernietigende, wireless-, fisiese, phishing- of credential-collection-aksies op.
- Gebruik ’n organisasie-beheerde betalingskanaal en teken goedkeurings intern aan.

### Tydens die betrokkenheid

- Begin vanaf die goedgekeurde endpoint en tunnel; verifieer waargenome egress voordat assessment-verkeer plaasvind.
- Hou persoonlike rekeninge, toestelle, telefoonnommers, repositories, SSH/GPG keys en cloud sync buite die kompartement.
- Log operator/job, begin/einde, bron, omvangbestemde teiken en konfigurasieverandering sonder om onnodige kliëntinhoud in te samel.
- Stop by onduidelikheid oor omvang, onverwagte derdepartystelsels, provider abuse notification, veiligheidsimpak, verlore toerusting of verlies van kontak met die controller.
- Moet nooit improviseer met ’n buurman se Wi-Fi, gesteelde credentials, ’n niegoedgekeurde SIM/account of hardeware wat by ’n lokaal versteek is nie.

### Einde van betrokkenheid

- Stop jobs en C2; herwin goedgekeurde drop devices; herroep tokens, credentials en certificates.
- Vergelyk infrastruktuur, domains, source addresses, uitgawes, data en provider cases met die inventaris.
- Gee/vee/behou kliëntdata volgens kontrak, bewaar die minimum vereiste ouditbewyse, en laat ’n tweede operateur die afskakeling verifieer.

Sien [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md) vir die volledige build- en teardown-gids.

## Wettige private aankoop of skenking

Doelwit: beperk openbaarmaking aan die handelaar of publiek terwyl daar aan issuer-, rekeningkundige, belasting- en sanksieverpligtinge voldoen word.

1. Lys wie nie wat moet leer nie: openbare gehoor, handelaar, betalingsintermediêr, werkgewer/familierekening-afgevaardigde, afleweringsdiens of blockchain-waarnemer.
2. Kontroleer plaaslike reëls, die ontvanger/teenparty, provider terms, kontantlimiete en rekordhoudingsbehoeftes.
3. Kies die kanaal:
- kontant vir aanvaarde wettige plaaslike betalings sonder ’n betalingsnetwerkrekord;
- ’n gereguleerde virtuele/handelaarspesifieke kaart vir aanlyn credential-separation;
- cryptocurrency slegs nadat acquisition, ledger, wallet backend, network, counterparty en later-spend links ontleed is.
4. Gebruik waarheidsgetroue vereiste besonderhede en laat slegs opsionele lojaliteits-/bemarkingsinligting weg. Moenie iemand anders se identiteit/adres gebruik of ’n transaksie rondom ’n drempel verdeel nie.
5. Skei die handelaar se browser/account-konteks en vermy onverwante social login, lojaliteits- of persoonlike recovery channels.
6. Bevestig wat op statements, kwitansies, notifications, shipping en openbare skenkerlyste verskyn.
7. Berg vereiste kwitansie-/belasting-/magtigingsbewyse encrypted; herroep disposable payment credentials ná die terugbetalingsvenster.

Sien [Private Digital Payments](private-digital-payments.md) en [Cryptocurrency Privacy](cryptocurrency-privacy.md).

## Reis en onbetroubare netwerke

Doelwit: beskerm data en rekeninge op netwerke wat nie deur die gebruiker geadministreer word nie—nie om ongemagtigde aktiwiteit te verberg nie.

- Dateer toestelle op en laai nodige credentials/maps voor die reis af.
- Minimaliseer gestoorde data; gebruik volskyf-enkripsie, sterk ontsluiting, remote-recovery-beplanning en powered-off border/physical-risk-prosedures wat by regsadvies pas.
- Verifieer die lokaal se SSID/captive portal. Verkies ’n persoonlike hotspot waar toepaslik, maar onthou sellulêre intekenaar- en liggingrekords.
- Gebruik ’n volledige/afgedwonge goedgekeurde VPN vir organisatoriese data; verifieer dat tethered devices dit deel en toets IPv6/DNS-gedrag.
- Gebruik ’n travel router vir client isolation en herhaalbare beleid, nie as ’n anonimiteitswaarborg nie.
- Behandel openbare USB-laai, geleende rekenaars, openbare printers en gedeelde vergaderkamerstelsels as afsonderlike bedreigings.
- Aanvaar dat fisiese teenwoordigheid, radio-identifiseerders, portal login, kameras en betaling-/liggingsrekords die besoek kan korreleer.

Die vergelyking en opstellingsbesonderhede is in [Network Privacy and Anonymous Connectivity](network-privacy-and-anonymous-connectivity.md).

## Mislukkings- en blootstellingsreaksie

Wanneer ’n kompartement lek of moontlik gekoppel is:

1. Stop die aktiwiteit indien voortsetting die skade vergroot; gebruik die engagement emergency stop waar van toepassing.
2. Bewaar nodige bewyse sonder om sensitiewe data te versprei. Teken die presiese tyd, waargenome aanduiding en geaffekteerde bates aan.
3. Stel die toepaslike eienaar/controller/security contact in kennis. Moenie ’n insident verberg om ’n privaatheidsnarratief te behou nie.
4. Herroep sessies, tokens, payment credentials en infrastructure access; roteer secrets vanaf ’n bekende-skoon endpoint.
5. Bepaal watter skakels die verbinding gemaak het: endpoint, account recovery, network, payment, metadata, content, behavior, counterparty of physical presence.
6. Behandel die hele geaffekteerde kompartement as burned. Moenie bloot sy username of exit IP verander nie.
7. Voldoen aan breach-, provider-, kliënt-, finansiële en wetlike kennisgewingpligte.
8. Herbou slegs nadat die proses wat die verbinding veroorsaak het, verander is; dokumenteer die beheer en toets dit.

## Periodieke oudit

- [ ] Threat model en wetlike/provider-aannames word volgens ’n gedateerde skedule hersien.
- [ ] Toestelle, rekeninge, aliases, domains, netwerkpaaie en payment credentials is geïnventariseer.
- [ ] Recovery paths kruis nie onverwags kompartemente nie.
- [ ] Full-tunnel-, DNS-, IPv6- en fail-closed-gedrag is getoets.
- [ ] Openbare lêers en profiele is vir metadata-/inhoudhergebruik nagegaan.
- [ ] Wallet nodes/backends en crypto protocol-aannames bly op datum.
- [ ] Logs en kwitansies is minimaal, encrypted, access-controlled en binne die retensietydperk.
- [ ] Ou kompartemente en engagement infrastructure is volledig afgetree.
{{#include ../banners/hacktricks-training.md}}
