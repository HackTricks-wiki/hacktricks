# Operasionele privaatheids-playbooks

Hierdie playbooks kombineer die kontroles uit die res van hierdie afdeling. Hulle is beginpunte, nie waarborge nie: dateer die threat model op wanneer ’n nuwe waarnemer, rekening, toestel, ligging, betaling, lêer of teenparty die workflow betree.

## Universele voorafkontrole

1. Skryf die wettige doelwit neer en wat privaat moet bly **teenoor wie**.
2. Teken die identiteite, toestelle, netwerke, rekeninge, betalingsrails, teenpartye, fisiese liggings en data aan wat die aktiwiteit sal raak.
3. Identifiseer die sterkste waarskynlike waarnemer en die gevolg van mislukking.
4. Bevestig magtiging, toepaslike wetgewing, provider-terme en organisasiebeleid.
5. Besluit wat intern toeskryfbaar moet bly vir veiligheid, incident response, rekeningkunde en oudit.
6. Kies die kleinste werkbare kompartement; stel die recovery- en shutdown-paaie daarvan op voordat dit gebruik word.
7. Toets die kompartement teen ’n beheerde diens, insluitend IP/DNS/IPv6, browser-identiteit, dokumentmetadata, betalingstaat en notification leakage.

Gebruik die gedetailleerde model in [Threat Modeling and Identity Separation](threat-modeling-and-identity-separation.md).

## Alledaagse privaatheidsbasislyn

Doel: verminder kommersiële tracking, account takeover en onnodige blootstelling sonder om anoniem te probeer wees.

- Gebruik ’n onderhoude OS met full-disk encryption, outomatiese updates, screen lock en secure boot waar beskikbaar.
- Stel password manager, recovery email en phishing-resistant MFA/security keys eerste op.
- Hersien app-permissies, location history, advertising identifiers, cloud sync en third-party account connections.
- Gebruik ’n hoofstroom-browser met min extensions, tracking protection, HTTPS en aparte profiele vir werk/persoonlike browsing en hoërisiko-browsing.
- Gebruik private relay aliases of afsonderlike e-posadresse per verhouding; moenie ’n persoonlike telefoonnommer gebruik wanneer dit bloot opsioneel is nie.
- Verkies end-to-end encrypted messaging vir inhoud, maar onthou dat deelnemers, tydsberekening, groepe en endpoints metadata bly.
- Verwyder metadata doelbewus uit lêers en inspekteer die geëksporteerde kopie—nie die oorspronklike nie—voordat dit gepubliseer word.
- Gebruik virtual-card- of wallet-tokens vir betaling-bewysstuk-kompartementalisering; moenie dit anoniem noem nie.
- Maak ’n rugsteun van geënkripteerde recovery-materiaal en toets restoration.

## Pseudonieme publikasie

Doel: voorkom dat toevallige lesers en platforms ’n publikasie maklik aan ’n burgerlike identiteit koppel. Dit keer nie ’n bekwame geteikende ondersoek nie.

1. Definieer of die platform, hosting provider, lesers, kontakte, plaaslike netwerk, payment provider of regsproses in die threat model is.
2. Skep ’n toegewyde endpoint/account-context vanuit ’n skoon basislyn. Deaktiveer persoonlike browser sync, cloud documents, contact upload en notification previews.
3. Skep die pseudonieme rekening deur die gekose netwerkkompartement. Moenie usernames, avatars, recovery channels, writing boilerplate of persoonlike identity-provider login hergebruik nie.
4. Gebruik Tor Browser wanneer destination unlinkability belangriker as spoed is; moenie extensions byvoeg, dit oormatig resize/customize of afgelaaide dokumente oopmaak terwyl jy aanlyn is in ’n gewone desktop-sessie nie.
5. Stel konsepte op met ’n proses wat nie persoonlike templaatname, revision authors, printer paths, GPS/EXIF, thumbnails of hidden layers inbed nie. Eksporteer ’n kopie en inspekteer dit met toepaslike metadata tools.
6. Kontroleer die inhoud vir selfidentifiserende feite: unieke datums, werkplekbesonderhede, plaaslike weer/tydsone, refleksies, agtergrondklank, linguistiese gewoontes en tekshergebruik uit vorige publikasies.
7. Gebruik ’n aparte reply channel. Behandel elke direkte kontak, attachment en link as ’n moontlike korrelasie- of phishing-poging.
8. Indien geld betrokke is, gebruik die wettige metode wat slegs die nodige data blootstel. Aanvaar dat die platform en gereguleerde intermediary moontlik die payee ken, selfs al weet lesers dit nie.
9. Publiseer en inspekteer dan die publieke resultaat vanuit ’n ander skoon konteks. Teken aan wat die platform bygevoeg of verander het.
10. Handhaaf slegs ’n beplande cadence indien dit nie ’n stabiele behavioral fingerprint skep nie; retireer die kompartement eerder as om dit stilweg vir ’n ander doel te hergebruik.

Vir ernstige joernalistiek, activism, domestic abuse of staatsvlak-risiko, verkry aangepaste hulp van ’n ervare digital-security-organisasie; ’n statiese kontrolelys kan nie plaaslike wetgewing of ’n lewende adversary modelleer nie.

## Gemagtigde red-team-betrokkenheid

Doel: hou operateurs se persoonlike identiteite en tuisnetwerke uit target telemetry terwyl authorization, beheer en incident response behoue bly.

### Voor die begintydvenster

- Finaliseer die ROE-infrastruktuur-annex, targets/exclusions, source ranges, datums, emergency stop en third-party/provider permissions.
- Wys ’n toegewyde operator profile of VM, engagement secrets, evidence store, cloud project, domeine en budget toe.
- Verkies client-provided egress of ’n organisasiebeheerde vaste bastion. Toets full-tunnel IPv4/IPv6/DNS-gedrag en fail-closed-beleid.
- Stoor die mapping van operator na openbare infrastruktuur by die exercise controller of ooreengekome escrow-kontak.
- Stel rate limits, destination allowlists en afsonderlike approval op vir destructive, wireless, physical, phishing of credential-collection actions.
- Gebruik ’n organisasiebeheerde payment rail en teken approvals intern aan.

### Tydens die engagement

- Begin vanaf die goedgekeurde endpoint en tunnel; verifieer observed egress voordat assessment traffic gestuur word.
- Hou persoonlike rekeninge, toestelle, telefoonnommers, repositories, SSH/GPG keys en cloud sync uit die kompartement.
- Log operator/job, start/stop, source, scoped destination en configuration change sonder om onnodige client content in te samel.
- Stop by scope ambiguity, onverwagte third-party systems, provider abuse notification, safety impact, verlore toerusting of verlies van kontak met die controller.
- Moet nooit improviseer met ’n buurman se Wi-Fi, gesteelde credentials, ’n unapproved SIM/account of hardware wat by ’n venue versteek is nie.

### Einde van engagement

- Stop jobs en C2; haal goedgekeurde drop devices terug; revoke tokens, credentials en certificates.
- Rekonsilieer infrastructure, domeine, source addresses, expenses, data en provider cases teen die inventory.
- Return/delete/retain client data volgens kontrak, bewaar die minimum vereiste audit evidence en laat ’n tweede operator die shutdown verifieer.

Sien [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md) vir die volledige build- en teardown-gids.

## Wettige private aankoop of donasie

Doel: minimaliseer disclosure aan die merchant of publiek terwyl issuer-, rekeningkundige, belasting- en sanctions-verpligtinge nagekom word.

1. Lys wie nie wat moet uitvind nie: openbare gehoor, merchant, payment intermediary, employer/family account delegate, delivery service of blockchain observer.
2. Kontroleer plaaslike reëls, die recipient/counterparty, provider-terme, kontantlimiete en recordkeeping-behoeftes.
3. Kies die rail:
- kontant vir aanvaarde wettige plaaslike betalings sonder ’n payment-network record;
- ’n gereguleerde virtual/merchant-specific card vir aanlyn credential separation;
- cryptocurrency slegs nadat acquisition, ledger, wallet backend, network, counterparty en later-spend links ontleed is.
4. Gebruik waarheidsgetroue vereiste besonderhede en laat slegs opsionele loyalty/marketing information weg. Moenie ’n ander persoon se identiteit/adres gebruik of ’n transaksie rondom ’n drempelbedrag opdeel nie.
5. Skei die merchant browser/account context en vermy onverwante social login, loyalty of persoonlike recovery channels.
6. Bevestig wat op statements, receipts, notifications, shipping en openbare donor lists verskyn.
7. Stoor vereiste receipt/tax/authorization evidence geënkripteer; revoke disposable payment credentials ná die refund window.

Sien [Private Digital Payments](private-digital-payments.md) en [Cryptocurrency Privacy](cryptocurrency-privacy.md).

## Reis en onvertroude netwerke

Doel: beskerm data en rekeninge op netwerke wat nie deur die gebruiker geadministreer word nie—nie om unauthorized activity te verberg nie.

- Dateer toestelle op en laai nodige credentials/maps af voordat jy reis.
- Minimaliseer gestoorde data; gebruik full-disk encryption, sterk unlock, remote-recovery planning en powered-off border/physical-risk procedures wat by regsadvies pas.
- Verifieer die venue se SSID/captive portal. Verkies ’n persoonlike hotspot wanneer toepaslik, maar onthou cellular subscriber- en location records.
- Gebruik ’n full/forced approved VPN vir organisasiedata; verifieer dat tethered devices dit deel en toets IPv6/DNS-gedrag.
- Gebruik ’n travel router vir client isolation en herhaalbare beleid, nie as ’n anonimiteitswaarborg nie.
- Behandel openbare USB-charging, geleende rekenaars, openbare printers en gedeelde meeting-room systems as afsonderlike threats.
- Aanvaar dat fisiese teenwoordigheid, radio identifiers, portal login, cameras en payment/location records die besoek kan korreleer.

Die vergelyking- en setup-besonderhede is in [Network Privacy and Anonymous Connectivity](network-privacy-and-anonymous-connectivity.md).

## Response op failure en exposure

Wanneer ’n kompartement leaker of moontlik gekoppel word:

1. Stop die aktiwiteit indien voortsetting skade verhoog; gebruik die engagement emergency stop waar van toepassing.
2. Bewaar nodige evidence sonder om sensitive data te versprei. Teken die presiese tyd, waargenome indicator en geraakte assets aan.
3. Stel die toepaslike owner/controller/security contact in kennis. Moenie ’n incident verberg om ’n privaatheidsnarratief te bewaar nie.
4. Revoke sessions, tokens, payment credentials en infrastructure access; rotate secrets vanaf ’n bekende skoon endpoint.
5. Bepaal watter edges gekoppel het: endpoint, account recovery, network, payment, metadata, content, behavior, counterparty of physical presence.
6. Behandel die hele geraakte kompartement as burned. Moenie bloot die username of exit IP verander nie.
7. Kom breach-, provider-, client-, finansiële en wetlike notification duties na.
8. Rebuild eers nadat die proses wat die koppeling veroorsaak het verander is; dokumenteer die control en toets dit.

## Periodieke oudit

- [ ] Threat model en legal/provider assumptions op ’n gedateerde skedule hersien.
- [ ] Devices, accounts, aliases, domains, network paths en payment credentials geïnventariseer.
- [ ] Recovery paths kruis nie onverwags kompartemente nie.
- [ ] Full-tunnel, DNS, IPv6 en fail-closed-gedrag getoets.
- [ ] Openbare lêers en profiele nagegaan vir metadata/content reuse.
- [ ] Wallet nodes/backends en crypto protocol assumptions bly op datum.
- [ ] Logs en receipts is minimaal, geënkripteer, access-controlled en binne retention.
- [ ] Ou kompartemente en engagement infrastructure is volledig retired.
