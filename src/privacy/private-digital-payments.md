# Private Digitale Betalings

{{#include ../banners/hacktricks-training.md}}

Betalingsprivaatheid is die beheerde bekendmaking van transaksiedata. Dit is nie ’n manier om onwettige fondse wettig te laat lyk, belasting of sanksies te ontduik, KYC te omseil, vals identiteite te gebruik of ’n ongemagtigde opdrag te verberg nie. ’n Betaling kan privaat teenoor ’n handelaar wees terwyl dit steeds volledig sigbaar is vir ’n issuer, netwerk, werkgewer, belastingowerheid of ondersoeker.

Die [Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) is die genormaliseerde inventaris met `Pros`, `Cons`, ’n wettige stap-vir-stap-`Procedure` en `Detection` vir elke familie. Hierdie bladsy brei konvensionele betaalmetodes uit.

{% hint style="danger" %}
Moet nooit gesteelde rekeninge, sintetiese identiteite, geldmuile, fiktiewe verblyf of aansprake oor die bron van fondse, transaksieverdeling (“structuring”) of ondeursigtige “no-KYC card”-makelaars gebruik nie. Kontroleer huidige wetgewing en verskafferbepalings in elke relevante jurisdiksie.
{% endhint %}

## Definieer die privaatheidseienskap

Identifiseer die waarnemer voordat jy ’n betaalspoor kies:

| Waarnemer | Tipiese data | Nuttige beheer | Wat oorbly |
|---|---|---|---|
| Handelaar | Naam, e-pos, adres, kaarttoken, IP/toestel, mandjie | Gastetjek, minimum opsionele data, handelaarspesifieke virtuele kaart | Aflewering-, rekening- en bedroganalise |
| Issuer/betalingsverwerker | Wettige identiteit, befondsingsbron, handelaar, bedrag, tyd, toestel | Kies ’n gereguleerde verskaffer met goeie privaatheids-/sekuriteitsbepalings | Die verskaffer verwerk steeds rekords en kan dit behou/openbaar |
| Werkgewer/opdrageienaar | Uitgawe, operateur en doel | Afsonderlike opdragbegroting en toegangsbeheerde grootboek | Wettige bestuur vereis interne toeskrywing |
| Openbare blockchain-waarnemer | Adresse, vloeie, bedrae en tyd, afhangend van die chain | Gepaste protokol en wallet-dissipline | Verkryging, eindpunte en latere besteding kan aktiwiteit weer koppel |
| Netwerk/RPC/node-operateur | IP, wallet-navrae, transaksie-uitsendings | Plaaslike node of geskikte privaatheidsnetwerk | Tydsberekening en eindpuntgedrag kan steeds korreleer |
| Fisiese waarnemer | Gesig, ligging, voertuig, CCTV, kwitansie | Gewone situasionele privaatheid | Kontant maak ’n persoon nie fisies onsigbaar nie |

Die CFPB beskryf betalingsapps as in staat om identiteit-, toestel-, ligging-, kontak-, transaksie- en gedragsdata te versamel; staatsprivaatheidsreëls verhoed nie noodwendig monetisering of alle sekondêre gebruik nie.<sup>[[1]](#references)</sup> Lees die werklike verskafferaankondiging eerder as om privaatheid uit ’n produknaam af te lei.

## Vergelyk betaalmetodes

| Metode | Privaatheidsvoordeel | Belangrikste waarnemers/koppelings | Gepaste gebruik |
|---|---|---|---|
| Kontant | Geen betaalnetwerkgrootboek nie | Ontvanger, kameras, getuies, kontantaangiftereëls | Wettige plaaslike aankope waar dit aanvaar word |
| Ooplus-prepaid-/geskenkkaart | Skei die kaartnommer van ’n hoofkaart | Verkoper, aktiverings-/registrasieverskaffer, befondsingsbron, handelaar | Begroting of beperkte handelaarskompartementalisering |
| Virtuele/eenmalige kaartnommer | Verberg herbruikbare PAN van die handelaar; maklike herroeping | Issuer ken steeds identiteit en transaksie | Kompartementalisering van aanlynhandelaars |
| Mobile-wallet-token | Toestel/handelaar ontvang ’n token in plaas van die onderliggende PAN | Wallet-verskaffer, issuer, betaalnetwerk en handelaar | Credential-sekuriteit, nie anonimiteit nie |
| Bankoorplasing/app | Gerieflike ouditspoor | Bank/app, teenparty en gekoppelde identiteit | Verantwoordbare organisatoriese betalings |
| Cryptocurrency | Wissel volgens protokol; selfbewaring kan blootstelling aan custodian verminder | Openbare grootboek of privaatheidsprotokol, exchange, eindpunt, teenparty | Wettige oorplasings ná protokolspesifieke ontleding |

## Kontant

Kontant word steeds as belangrik vir privaatheid en insluiting beskou, en dit vermy ’n betaalnetwerkrekord.<sup>[[2]](#references)</sup> Dit omseil nie CCTV, getuies, toestelligging, kwitansies, reeksnommeropsporing in spesiale gevalle of wettige verslagdoening nie.

### Wettige werksvloei

1. Kontroleer aanvaarding en plaaslike kontantlimiete voor die transaksie. Limiete verskil volgens land en partytipologie en verander mettertyd.
2. Doen die gewone aankoop in een eerlike transaksie. **Moet dit nooit verdeel nie** om ’n drempel of verslag te vermy.
3. Weier opsionele lojaliteitsopsporing of bemarkingsinsameling. Verskaf data wat vir waarborg, veiligheid, aflewering, belasting of wetgewing vereis word, eerlik.
4. Hou nodige aankoopbewys en vereiste rekeningkundige rekords in geënkripteerde berging met ’n retensiedatum.
5. Vir ’n organisasie: eis vergoeding deur die goedgekeurde proses en teken operateur, magtiging, doel, bedrag, datum en kwitansie aan.

In die Verenigde State dien sekere bedrywe of besighede Form 8300 in vir kontantontvangstes bo $10 000, insluitend verwante transaksies; om transaksies opsetlik op te breek, kan self onwettige structuring wees.<sup>[[3]](#references)</sup> Ander jurisdiksies verskil—Spanje publiseer byvoorbeeld sy eie statutêre beperking op kontantbetalings.<sup>[[4]](#references)</sup>

## Prepaid- en geskenkkaarte

“Prepaid” beteken nie anoniem nie. ’n Winkel, issuer, programbestuurder, befondsingsbank en handelaar kan aankoop, aktivering, toestel, IP, ligging en besteding korreleer. Herlaaiings, ATM-toegang, internasionale gebruik, hoër limiete of verliesbeskerming vereis gewoonlik registrasie.

Amerikaanse verbruikersleiding verduidelik dat issuers identiteitsdata kan versoek vir wettige verifikasie en ’n geregistreerde kaart kan weier wanneer verifikasie misluk.<sup>[[5]](#references)</sup> FinCEN-reëls definieer watter prepaid-programme en deelnemers AML-pligte het.<sup>[[6]](#references)</sup> In die EU is die beperkte anonieme e-geld-uitsonderings deur Directive (EU) 2018/843 verminder; Regulation (EU) 2024/1624 verander die raamwerk weer, maar is oor die algemeen eers vanaf **10 July 2027** van toepassing. Moet dit dus nie beskryf asof dit reeds in 2026 operasioneel is nie.<sup>[[7]](#references)</sup>

Gebruik prepaid-waarde slegs wanneer dit wettiglik van ’n identifiseerbare issuer verkry is, die bepalings die beoogde gebruik toelaat, en die voordeel begroting of skeiding van ’n primêre betaalcredential is. Vermy herverkoopmarkte en makelaars wat onverifieerbare “no-name”-kaarte adverteer: waarde kan gesteel, reeds gebruik, geografies beperk of onderhewig aan beslaglegging wees.

## Virtuele kaarte en wallet-tokens

’n Virtuele kaartnommer (VCN) word gewoonlik agter ’n werklike, geverifieerde rekening uitgereik. Handelaarspesifieke of eenmalige nommers verminder breach- en cross-merchant-PAN-korrelasie; hulle **verberg nie** die transaksie vir die issuer nie. Network tokenization vervang insgelyks ’n kaartcredential met ’n beperkte token.<sup>[[8]](#references)</sup>

### Werksvloei vir handelaarskompartementalisering

1. Open ’n rekening by ’n gereguleerde issuer met akkurate identiteits-, verblyf- en befondsingsdata.
2. Beveilig dit met ’n unieke wagwoord, phishing-resistant MFA waar beskikbaar, aanmeldwaarskuwings en herstelkodes wat offline gestoor word.
3. Genereer ’n handelaar-geslote of eenmalige VCN. Stel ’n redelike bedrag-/tydlimiet indien dit ondersteun word.
4. Gebruik gastetjek en laat slegs **opsionele** profiel-, lojaliteits- en bemarkingsvelde leeg. Verskaf akkurate fakturerings-, aflewerings- en belastingdata wanneer dit vereis word.
5. Vermy aanmelding by onverwante identity providers; gebruik ’n engagement/account-blaaierkompartement en die goedgekeurde netwerkpad.
6. Stoor die kwitansie en die VCN-na-doel-kartering in ’n geënkripteerde interne grootboek.
7. Vries of herroep die nommer ná die terugbetaling/chargeback-venster; monitor die ouerrekening vir onverwagte magtigings.

Capital One en Google dokumenteer dat virtuele nommers aan die onderliggende rekening gekoppel bly, terwyl EMVCo/Visa tokenization as credential-substitusie en domeinbeperking, eerder as betaleranonimiteit, beskryf.<sup>[[8]](#references)</sup>

## Aflewering, rekeninge en terugbetalings

Die betaling is slegs een rand in die skakelingsgrafiek:

- ’n Unieke kaart word verydel deur ’n persoonlike e-pos, telefoonnommer, blaaierprofiel, IP-adres of lojaliteitsrekening te hergebruik.
- Fisiese aflewering benodig gewoonlik ’n wettige ontvanger en ligging. Moenie ’n onbetrokke persoon se adres gebruik of ’n inwoner naboots nie. Goedgekeurde besigheidsontvangsdienste is veiliger as gefabriseerde besonderhede.
- Digitale goedere kan rekeningidentiteit, IP, toestelvingerafdruk, lisensie-aktivering en downloads aanteken.
- Terugbetalings word gewoonlik na die oorspronklike betaalspoor gestuur. Versoeke om fondse te ontvang en dit elders aan te stuur/terug te betaal, is ’n bedrog- en geldmuil-waarskuwing.
- Handelaarbeskrywings, faktuurteks en versendingskennisgewings kan ’n sensitiewe aankoop aan rekeninggedelegeerdes blootstel; stel toegang en waarskuwings doelbewus op.

## Gemagtigde red-team-aankope

’n Opdrag moet ekstern diskreet en intern verantwoordbaar wees:

1. Verkry skriftelike omvang, doel, bestedingsplafon, goedkeurder, toegelate handelaars/bates en vergoedingsreël.
2. Gebruik ’n organisasiebeheerde betaalrekening en ’n afsonderlike VCN of subrekening per opdrag of handelaar.
3. Hou akkurate fakturerings- en registrantbesonderhede by verskaffers. Openbare registrasieprivaatheid kan blootstelling verminder, maar is nie toestemming om te lieg nie.
4. Handhaaf ’n geënkripteerde grootboek van operateur, goedkeuring, doel, datum, bedrag, teenparty, bate-identifiseerder en kwitansie.
5. Sif teenpartye soos vereis en volg verskaffer-, sanksie-, belasting- en verslagdoeningsverpligtinge.
6. Gee finansies slegs die toegang wat dit nodig het; gee operateurs slegs die beperkte bestedingsvermoë wat hulle nodig het.
7. Sluit betaalcredentials of vries dit tydens teardown, rekonsilieer hangende heffings/terugbetalings en behou rekords volgens beleid.

Vir crypto-spesifieke keuses, gaan voort na [Cryptocurrency Privacy](cryptocurrency-privacy.md). Vir die infrastruktuur wat daardie aankope ondersteun, sien [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md).

## Verifikasiekontrolelys

- [ ] Die verlangde privaatheidseienskap en waarnemers is neergeskryf.
- [ ] Verskaffer-, handelaar- en jurisdiksiereëls is onlangs nagegaan.
- [ ] Identiteits- en bron-van-fondse-stellings is waarheidsgetrou.
- [ ] Opsionele handel data is geminimaliseer sonder om vereiste verifikasie te verydel.
- [ ] Befondsings-, toestel-, netwerk-, rekening-, aflewerings- en terugbetalingskoppelings word verstaan.
- [ ] Geen drempelvermyding, verbode teenparty, geldmuil, gesteelde credential of derdeparty-identiteit is betrokke nie.
- [ ] Vereiste kwitansies, goedkeurings, belastingrekords en herstelinligting is geënkripteer en toegangsbeheer.

## References

- [1] [US CFPB — Versoek om inligting rakende die insameling, gebruik en monetisering van verbruikersbetalings- en ander persoonlike finansiële data](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf) and [State Consumer Privacy Laws and the Monetization of Consumer Financial Data](https://www.consumerfinance.gov/data-research/research-reports/state-consumer-privacy-laws-and-the-monetization-of-consumer-financial-data/)
- [2] [European Central Bank — Studie oor verbruikers se betalingshoudings in die eurogebied (SPACE) 2024](https://www.ecb.europa.eu/stats/ecb_surveys/space/html/ecb.space2024~19d46f0f17.en.html)
- [3] [US IRS — Instruksies vir Form 8300](https://www.irs.gov/instructions/i8300) and [FinCEN — Currency Transaction Reporting Requirement](https://www.fincen.gov/fincen-educational-pamphlet-currency-transaction-reporting-requirement)
- [4] [Spanish Tax Agency — Verslagdoening van kontantbetalings](https://sede.agenciatributaria.gob.es/Sede/colaborar-agencia-tributaria/denuncias/denuncia-pagos-efectivo.html)
- [5] US CFPB — [Waarom word ek gevra vir persoonlike inligting om ’n prepaid-kaart te aktiveer of te registreer?](https://www.consumerfinance.gov/ask-cfpb/why-am-i-being-asked-for-personal-information-to-activate-or-register-a-prepaid-card-en-443/) en [Kan ’n prepaid-kaart aan my geweier word?](https://www.consumerfinance.gov/ask-cfpb/can-i-be-declined-for-a-prepaid-card-en-437/)
- [6] [FinCEN — Finale reël oor Prepaid Access](https://www.fincen.gov/resources/statutes-regulations/guidance/final-rule-definitions-and-other-regulations-relating)
- [7] [Directive (EU) 2018/843](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32018L0843) and [Regulation (EU) 2024/1624](https://eur-lex.europa.eu/eli/reg/2024/1624)
- [8] [Capital One — Gebruik van virtuele kredietkaarte](https://www.capitalone.com/help-center/credit-cards/using-virtual-credit-cards/), [Google Pay — Virtual cards](https://support.google.com/googlepay/answer/7643925?hl=en), [EMVCo — Payment Tokenisation](https://www.emvco.com/emv-technologies/payment-tokenisation/), and [Visa — Token Service Provisioning](https://developer.visa.com/capabilities/token-service-provisioning)
{{#include ../banners/hacktricks-training.md}}
