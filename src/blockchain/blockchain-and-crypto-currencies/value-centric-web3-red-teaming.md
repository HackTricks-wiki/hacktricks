# Web3-rooi-spanwerk gefokus op waarde (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

Die MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT)-raamwerk kategoriseer teenstanderaksies en -tegnieke wat digitale batestelsels teiken.<sup>[[1]](#references)</sup> Gebruik dit as ’n **grondslag vir bedreigingsmodellering**: lys elke komponent wat bates kan skep, prys, magtig of aanstuur, koppel daardie raakpunte aan AADAPT-tegnieke en ontwerp dan rooi-span-scenario’s om te meet of die omgewing onomkeerbare ekonomiese verliese kan weerstaan.

## 1. Inventariseer komponente wat waarde dra
Stel ’n kaart op van alles wat die waardetoestand kan beïnvloed, selfs al is dit off-chain.<sup>[[2]](#references)</sup>

- **Custodial ondertekeningsdienste** (HSM/KMS-klusters, Vault/KMaaS, ondertekenings-API’s wat deur bots of back-office-take gebruik word). Teken sleutel-ID’s, beleide, outomatiseringsidentiteite en goedkeuringswerkvloeie aan.
- **Admin- en opgraderingspaaie** vir kontrakte (proxy-admins, governance-timelocks, noodpouseersleutels, parameterregisters). Sluit in wie/wat hulle kan oproep, en onder watter kworum of vertraging.
- **On-chain-protokollogika** vir uitleen, AMM’s, kluise, staking, brûe of vereffeningsrelings. Dokumenteer die aannames waarop hulle invariantes berus (oracle-pryse, kollateraliseringsverhoudings, herbalanseringsfrekwensie…).
- **Off-chain-outomatisering** wat transaksies bou (markmakende bots, CI/CD-pyplyne, cron-take, serverless-funksies). Hulle bevat dikwels API-sleutels of dienshoofde wat handtekeninge kan aanvra.
- **Oracles en datavoere** (samestelling van aggregators, kworum, afwykingsdrempels, opdateringsfrekwensie). Noteer elke stroomopbron waarop outomatiese risikologika staatmaak.
- **Brûe en cross-chain-routers** (lock/mint-kontrakte, relayers, vereffeningstake) wat kettings of custodial-stapels aan mekaar koppel.

Aflewerbare resultaat: ’n waardevloeidiagram wat wys hoe bates beweeg, wie die beweging magtig en watter eksterne seine besigheidslogika beïnvloed.

## 2. Koppel komponente aan AADAPT-gedrag
Vertaal die AADAPT-taksonomie na konkrete aanvalskandidate per komponent.<sup>[[2]](#references)</sup>

| Komponent | Primêre AADAPT-fokus |
| --- | --- |
| Ondertekening/KMS-omgewings | Credential theft, policy bypass, signing-abuse, governance takeover |
| Oracles/datavoere | Input poisoning, aggregation manipulation, deviation-threshold evasion |
| On-chain-protokolle | Flash-loan-ekonomiese manipulasie, invariant-breaking, parameter-herkonfigurasie |
| Outomatiseringspyplyne | Gekompromitteerde bot-/CI-identiteite, batch-replay, ongemagtigde ontplooiing |
| Brûe/routers | Cross-chain-ontduiking, vinnige hop-wassery, vereffeningsdesinchronisasie |

Hierdie koppeling verseker dat jy nie net die kontrakte toets nie, maar ook elke identiteit/outomatisering wat waarde indirek kan stuur.

## 3. Prioritiseer volgens aanvaller se haalbaarheid teenoor besigheidsimpak

1. **Operasionele swakhede**: blootgestelde CI-geloofsbriewe, IAM-rolle met oormatige voorregte, verkeerd opgestelde KMS-beleide, outomatiseringsrekeninge wat arbitrêre handtekeninge kan aanvra, publieke buckets met brugkonfigurasies, ens.
2. **Waarde-spesifieke swakhede**: brose oracle-parameters, opgradeerbare kontrakte sonder goedkeuring deur verskeie partye, likiditeit wat vatbaar is vir flash loans, governance-aksies wat timelocks omseil.

Werk deur die lys soos ’n teenstander: begin met die operasionele vastrapplekke wat vandag kan slaag, en beweeg dan aan na diep protokol-/ekonomiese manipulasiepaaie.<sup>[[2]](#references)</sup>

## 4. Voer uit in beheerde, produksiegetroue omgewings
- **Geforkte mainnets / geïsoleerde testnets**: herhaal bytecode, berging en likiditeit sodat flash-loan-paaie, oracle-afwykings en brugvloeie end-tot-end uitgevoer kan word sonder om regte fondse aan te raak.<sup>[[2]](#references)</sup>
- **Beplanning van ontploffingsradius**: bepaal stroombrekers, pouseerbare modules, terugrolprosedures en admin-sleutels vir toetsing voordat ’n scenario afgevuur word.
- **Koördinering met belanghebbendes**: stel custodians, oracle-operateurs, brugvennote en compliance in kennis sodat hul moniteringspanne die verkeer verwag.
- **Regsgoedkeuring**: dokumenteer omvang, magtiging en stopvoorwaardes wanneer simulasies gereguleerde relings kan raak.

## 5. Telemetrie in lyn met AADAPT-tegnieke
Instrumenteer telemetriestrome sodat elke scenario bruikbare opsporingsdata oplewer.<sup>[[2]](#references)</sup>

- **Nasporings op kettingvlak**: volledige oproepgrafieke, gasverbruik, transaksienonces, bloktydstempels—om flash-loan-bundels, strukture soortgelyk aan reentrancy en spronge tussen kontrakte te rekonstrueer.
- **Toepassings-/API-logboeke**: koppel elke on-chain-transaksie terug aan ’n menslike of outomatiseringsidentiteit (sessie-ID, OAuth-kliënt, API-sleutel, CI-taak-ID), met IP’s en verifikasiemetodes.
- **KMS/HSM-logboeke**: sleutel-ID, oproeper-prinsipaal, beleidsresultaat, bestemmingsadres en redekodes vir elke handtekening. Stel basislyne vir veranderingsvensters en hoërisiko-bedrywighede op.
- **Oracle-/voermetadata**: samestelling van databronne per opdatering, gerapporteerde waarde, afwyking van rollende gemiddeldes, geaktiveerde drempels en gebruikte terugvalpaaie.
- **Brug-/ruilnasporings**: korreleer lock/mint/unlock-gebeurtenisse oor kettings heen met korrelasie-ID’s, ketting-ID’s, relayer-identiteit en tydsberekening van elke hop.
- **Anomalie-merkers**: afgeleide maatstawwe soos skielike slippage, abnormale kollateraliseringsverhoudings, ongewone gasdigtheid of cross-chain-snelheid.

Merk alles met scenario-ID’s of sintetiese gebruiker-ID’s sodat ontleders waarneembare data kan koppel aan die AADAPT-tegniek wat getoets word.

## 6. Purple-team-siklus en volwassenheidsmaatstawwe
1. Voer die scenario in die beheerde omgewing uit en teken opsporings vas (waarskuwings, dashboards, respondente wat gepageer is).<sup>[[2]](#references)</sup>
2. Koppel elke stap aan die spesifieke AADAPT-tegnieke en die waarneembare data wat in die ketting-/toepassings-/KMS-/oracle-/brugvlakke opgelewer word.
3. Formuleer en ontplooi opsporingshipoteses (drempelreëls, korrelasiesoektogte, invariantkontroles).
4. Herhaal totdat die gemiddelde tyd om op te spoor (MTTD) en die gemiddelde tyd om in te perk (MTTC) binne besigheidstoleransies val en speelboeke die waardeverlies betroubaar stop.

Volg die program se volwassenheid op drie asse na:<sup>[[2]](#references)</sup>
- **Sigbaarheid**: elke kritieke waardepad het telemetrie in elke vlak.
- **Dekking**: die verhouding van geprioritiseerde AADAPT-tegnieke wat end-tot-end getoets is.
- **Reaksie**: die vermoë om kontrakte te pouseer, sleutels te herroep of vloeie te vries voordat onomkeerbare verliese plaasvind.

Tipiese mylpale: (1) voltooide waarde-inventaris en AADAPT-kartering, (2) eerste end-tot-end-scenario met geïmplementeerde opsporings, (3) kwartaallikse purple-team-siklusse wat dekking uitbrei en MTTD/MTTC verminder.<sup>[[2]](#references)</sup>

## 7. Scenarioprototipes
Gebruik hierdie herhaalbare bloudrukke om simulasies te ontwerp wat direk met AADAPT-gedrag ooreenstem.<sup>[[2]](#references)</sup>

### Scenario A – Ekonomiese manipulasie met ’n flash loan
- **Doelwit**: leen tydelike kapitaal binne een transaksie om AMM-pryse/likiditeit te verdraai en verkeerd geprysde lenings, likwidasies of minting te veroorsaak voordat die lening terugbetaal word.
- **Uitvoering**:
  1. Fork die teikenketting en vul poele met produksie-agtige likiditeit.
  2. Leen ’n groot nominale bedrag via ’n flash loan.
  3. Voer gekalibreerde swaps uit om prys-/drempelgrense te oorskry waarop uitleen-, kluis- of afgeleide logika staatmaak.
  4. Roep die slagofferkontrak onmiddellik ná die verdraaiing aan (leen, likwideer, mint) en betaal die flash loan terug.
- **Meting**: Het die inbreuk op ’n invariant geslaag? Is slippage-/prysafwykingsmonitors, stroombrekers of governance-pouseerhakies geaktiveer? Hoe lank het dit geduur voordat ontledings die abnormale gas-/oproepgrafiekpatroon opgemerk het?

### Scenario B – Vergiftiging van oracle/datavoer
- **Doelwit**: bepaal of gemanipuleerde voere vernietigende outomatiese aksies (massa-likwidasies, verkeerde vereffenings) kan veroorsaak.
- **Uitvoering**:
  1. Ontplooi in die fork/testnet ’n kwaadwillige voer, of pas aggregator-gewigte/kworum/opdateringsfrekwensie aan tot buite die aanvaarbare afwyking.
  2. Laat afhanklike kontrakte die vergiftigde waardes gebruik en hul standaardlogika uitvoer.
- **Meting**: Voerwaarskuwings buite normale perke, aktivering van ’n terugval-oracle, afdwinging van minimum-/maksimumgrense en die vertraging tussen die begin van die anomalie en die operateur se reaksie.

### Scenario C – Misbruik van geloofsbriewe/ondertekening
- **Doelwit**: toets of die kompromittering van ’n enkele ondertekenaar of outomatiseringsidentiteit ongemagtigde opgraderings, parameterveranderings of dreinering van die tesourie moontlik maak.
- **Uitvoering**:
  1. Lys identiteite met sensitiewe ondertekeningsregte (operateurs, CI-tokens, diensrekeninge wat KMS/HSM aanroep, multisig-deelnemers).
  2. Simuleer kompromittering (hergebruik hul geloofsbriewe/sleutels binne die laboratoriumomvang).
  3. Probeer bevoorregte aksies: gradeer proxies op, verander risikoparameters, mint/pause bates of begin governance-voorstelle.
- **Meting**: Genereer KMS/HSM-logboeke anomaliewaarskuwings (tyd van die dag, afwyking in bestemming, ’n vlaag hoërisiko-bedrywighede)? Kan beleide of multisig-drempels eensydige misbruik voorkom? Word versnellers/koerslimiete of bykomende goedkeurings afgedwing?

### Scenario D – Cross-chain-ontduiking en leemtes in naspeurbaarheid
- **Doelwit**: evalueer hoe goed verdedigers bates kan naspoor en onderskep wanneer hulle vinnig deur brûe, DEX-routers en privaatheidshops gewas word.
- **Uitvoering**:
  1. Ketting lock/mint-bedrywighede oor algemene brûe aaneen, wissel swaps/mixers by elke hop af en behou korrelasie-ID’s per hop.
  2. Versnel oordragte om moniteringvertraging te beproef (verskeie hops binne minute/blokke).
- **Meting**: Tyd om gebeurtenisse oor telemetrie en kommersiële kettingontledings heen te korreleer, volledigheid van die gerekonstrueerde pad, vermoë om knelpunte vir bevriesing tydens ’n werklike voorval te identifiseer, en waarskuwingsgetrouheid vir abnormale cross-chain-snelheid/-waarde.

## References

- [1] [AADAPT(TM)-kubervoorbedreigingsraamwerk vir digitale bates (MITRE)](https://www.mitre.org/sites/default/files/2025-05/PR-25-1118-aadpt-cyber-threat-framework-for-digital-assets.pdf)
- [2] [Die MITRE AADAPT-raamwerk as ’n rooi-spanpadkaart (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)
{{#include ../../banners/hacktricks-training.md}}
