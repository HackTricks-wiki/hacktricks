# Private Digitale Betalings

Betalingsprivaatheid is die beheerde bekendmaking van transaksiedata. Dit is nie 'n manier om onwettige fondse wettig te laat lyk, belasting of sanksies te ontduik, KYC te omseil, vals identiteite te gebruik of 'n ongemagtigde verbintenis te versteek nie. 'n Betaling kan privaat teenoor 'n handelaar wees terwyl dit steeds volledig sigbaar is vir 'n uitreiker, netwerk, werkgewer, belastingowerheid of ondersoeker.

Die [Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) is die genormaliseerde inventaris met `Pros`, `Cons`, 'n wettige stap-vir-stap `Procedure` en `Detection` vir elke familie. Hierdie bladsy brei uit oor konvensionele betaalmetodes.

{% hint style="danger" %}
Moet nooit gesteelde rekeninge, sintetiese identiteite, geldmuile, fiktiewe verblyf- of bron-van-fondse-eise, transaksieverdeling (“structuring”) of ondeursigtige “no-KYC card”-makelaars gebruik nie. Gaan huidige wetgewing en verskafferbepalings in elke relevante jurisdiksie na.
{% endhint %}

## Definieer die privaatheidseienskap

Benoem die waarnemer voordat jy 'n betaalmiddel kies:

| Waarnemer | Tipiese data | Nuttige beheer | Wat oorbly |
|---|---|---|---|
| Handelaar | Naam, e-pos, adres, kaarttoken, IP/toestel, mandjie | Gastetjek, minimum opsionele data, handelaarspesifieke virtuele kaart | Aflewering, rekening- en bedroganalise |
| Uitreiker/betalingsverwerker | Regsidentiteit, befondsingsbron, handelaar, bedrag, tyd, toestel | Kies 'n gereguleerde verskaffer met goeie privaatheids-/sekuriteitsbepalings | Die verskaffer verwerk steeds rekords en kan dit behou of bekend maak |
| Werkgewer/verbinteniseienaar | Uitgawe, operateur en doel | Afsonderlike verbintenisbegroting en toegangsbeheerde grootboek | Wettige bestuur vereis interne toeskrywing |
| Openbare blockchain-waarnemer | Adresse, vloei, bedrae en tyd, afhangend van die chain | Gepaste protokol en wallet-dissipline | Verkryging, eindpunte en latere besteding kan aktiwiteit weer koppel |
| Netwerk/RPC/node-operateur | IP, wallet-navrae, transaksie-uitsendings | Plaaslike node of geskikte privaatheidsnetwerk | Tydsberekening en eindpuntgedrag kan steeds korreleer |
| Fisiese waarnemer | Gesig, ligging, voertuig, CCTV, kwitansie | Gewone situasionele privaatheid | Kontant maak 'n persoon nie fisies onsigbaar nie |

Die CFPB beskryf betalingsapps as in staat om identiteit-, toestel-, ligging-, kontak-, transaksie- en gedragsdata in te samel; staatsprivaatheidsreëls voorkom nie noodwendig monetisering of alle sekondêre gebruik nie.<sup>[[1]](#references)</sup> Lees die werklike verskafferkennisgewing eerder as om privaatheid uit 'n produknaam af te lei.

## Vergelyk betaalmetodes

| Metode | Privaatheidsvoordeel | Belangrikste waarnemers/koppelings | Gepaste gebruik |
|---|---|---|---|
| Kontant | Geen betalingsnetwerk-grootboek nie | Ontvanger, kameras, getuies, kontantaanmeldingsreëls | Wettige plaaslike aankope waar dit aanvaar word |
| Oop-lus voorafbetaalde-/geskenkkaart | Skei die kaartnommer van 'n hoofkaart | Verkoper, aktiverings-/registrasieverskaffer, befondsingsbron, handelaar | Begroting of beperkte handelaarskompartementalisering |
| Virtuele/eenmalige kaartnommer | Verberg herbruikbare PAN van handelaar; maklik om te herroep | Uitreiker ken steeds identiteit en transaksie | Kompartementalisering van aanlynhandelaars |
| Mobiele-wallet-token | Toestel/handelaar ontvang 'n token in plaas van die onderliggende PAN | Wallet-verskaffer, uitreiker, betalingsnetwerk en handelaar | Bewysbriefsekuriteit, nie anonimiteit nie |
| Bankoorplasing/app | Gerieflike ouditspoor | Bank/app, teenparty en gekoppelde identiteit | Verantwoordbare organisatoriese betalings |
| Cryptocurrency | Wissel volgens protokol; selfbewaring kan blootstelling aan custodian verminder | Openbare grootboek of privaatheidsprotokol, exchange, eindpunt, teenparty | Wettige oorplasings ná protokolspesifieke ontleding |

## Kontant

Kontant word steeds as belangrik vir privaatheid en insluiting beskou, en dit vermy 'n betalingsnetwerkrekord.<sup>[[2]](#references)</sup> Dit verslaan nie CCTV, getuies, toestel-ligging, kwitansies, reeksnommeropsporing in spesiale gevalle of wetlike aanmelding nie.

### Wettige werkvloei

1. Kontroleer aanvaarding en plaaslike kontantlimiete voor die transaksie. Limiete verskil volgens land en partytipologie en verander mettertyd.
2. Doen die gewone aankoop in een eerlike transaksie. **Moet dit nooit verdeel nie** om 'n drempel of verslag te vermy.
3. Weier opsionele lojaliteitsopsporing of bemarkingsinsameling. Verskaf data wat vir waarborg, veiligheid, aflewering, belasting of wetgewing vereis word, eerlik.
4. Hou nodige bewys van aankoop en vereiste rekeningkundige rekords in geënkripteerde berging met 'n retensiedatum.
5. Vir 'n organisasie: eis vergoeding deur die goedgekeurde proses en teken operateur, magtiging, doel, bedrag, datum en kwitansie aan.

In die Verenigde State dien sekere ondernemings Form 8300 in vir kontantontvangstes bo $10 000, insluitend verwante transaksies; om transaksies opsetlik op te breek kan self onwettige structuring wees.<sup>[[3]](#references)</sup> Ander jurisdiksies verskil—Spanje publiseer byvoorbeeld sy eie statutêre beperking op kontantbetalings.<sup>[[4]](#references)</sup>

## Voorafbetaalde en geskenkkaarte

“Prepaid” beteken nie anoniem nie. 'n Winkel, uitreiker, programbestuurder, befondsingsbank en handelaar kan aankoop, aktivering, toestel, IP, ligging en besteding korreleer. Herlaaiings, OTM-toegang, internasionale gebruik, hoër limiete of verliesbeskerming vereis gewoonlik registrasie.

Amerikaanse verbruikersleiding verduidelik dat uitreikers identiteitsdata vir wetlike verifikasie kan versoek en 'n geregistreerde kaart kan weier wanneer verifikasie misluk.<sup>[[5]](#references)</sup> FinCEN-reëls definieer watter prepaid-programme en deelnemers AML-pligte het.<sup>[[6]](#references)</sup> In die EU is die eng anonieme e-geld-uitsonderings deur Directive (EU) 2018/843 beperk; Regulation (EU) 2024/1624 verander die raamwerk weer, maar is oor die algemeen eers vanaf **10 Julie 2027** van toepassing. Moet dit dus nie beskryf asof dit reeds in 2026 in werking is nie.<sup>[[7]](#references)</sup>

Gebruik voorafbetaalde waarde slegs wanneer dit wettiglik van 'n identifiseerbare uitreiker verkry is, die bepalings daarvan die beoogde gebruik toelaat, en die voordeel begroting of skeiding van 'n primêre betalingsbewys is. Vermy herverkoopmarkte en makelaars wat onverifieerbare “no-name”-kaarte adverteer: waarde kan gesteel, reeds gebruik, geografies beperk of aan beslaglegging onderhewig wees.

## Virtuele kaarte en wallet-tokens

'n Virtuele kaartnommer (VCN) word gewoonlik agter 'n werklike, geverifieerde rekening uitgereik. Handelaarspesifieke of eenmalige nommers verminder blootstelling deur breaches en PAN-korrelasie tussen handelaars; hulle **verberg nie** die transaksie vir die uitreiker nie. Network tokenization vervang insgelyks 'n kaartbewys met 'n beperkte token.<sup>[[8]](#references)</sup>

### Handelaar-gekompartementaliseerde werkvloei

1. Maak 'n rekening by 'n gereguleerde uitreiker oop met akkurate identiteits-, verblyf- en befondsingsdata.
2. Beveilig dit met 'n unieke wagwoord, phishing-resistant MFA waar beskikbaar, aanmeldingswaarskuwings en recovery codes wat vanlyn gestoor word.
3. Genereer 'n handelaar-geslote of eenmalige VCN. Stel 'n redelike bedrag-/tydlimiet indien dit ondersteun word.
4. Gebruik gastetjek en laat slegs **opsionele** profiel-, lojaliteits- en bemarkingsvelde uit. Verskaf akkurate faktuur-, aflewerings- en belastingdata wanneer dit vereis word.
5. Vermy aanmelding by onverwante identity providers; gebruik 'n verbintenis-/rekeningblaaierkompartement en die goedgekeurde netwerkpad.
6. Stoor die kwitansie en die VCN-na-doel-kartering in 'n geënkripteerde interne grootboek.
7. Vries of herroep die nommer ná die refund/chargeback-venster; monitor die ouerrekening vir onverwagte magtigings.

Capital One en Google dokumenteer dat virtuele nommers aan die onderliggende rekening gekoppel bly, terwyl EMVCo/Visa tokenization beskryf as bewyskragvervanging en domeinbeperking eerder as betaleranonimiteit.<sup>[[8]](#references)</sup>

## Aflewering, rekeninge en refunds

Die betaling is slegs een rand in die koppelingsgrafiek:

- 'n Unieke kaart word verydel deur 'n persoonlike e-posadres, telefoonnommer, blaaierprofiel, IP-adres of lojaliteitsrekening te hergebruik.
- Fisiese aflewering benodig normaalweg 'n wettige ontvanger en ligging. Moet nie 'n onverwante persoon se adres gebruik of 'n inwoner naboots nie. Goedgekeurde besigheidsontvangsdienste is veiliger as vervalste besonderhede.
- Digitale goedere kan rekeningidentiteit, IP, toestelvingerafdruk, lisensie-aktivering en downloads aanteken.
- Refunds word gewoonlik na die oorspronklike betaalmiddel teruggestuur. Versoeke om fondse te ontvang en dit elders aan te stuur/terug te betaal is 'n bedrog- en geldmuilwaarskuwing.
- Handelaarbeskrywings, faktuurteks en versendingskennisgewings kan 'n sensitiewe aankoop aan rekening-afgevaardigdes blootstel; stel toegang en waarskuwings doelbewus.

## Gemagtigde red-team-aankope

'n Verbintenis behoort ekstern diskreet en intern verantwoordbaar te wees:

1. Verkry skriftelike omvang, doel, bestedingsplafon, goedkeurder, toegelate handelaars/bates en vergoedingsreël.
2. Gebruik 'n organisasiebeheerde betaalrekening en 'n afsonderlike VCN of subrekening per verbintenis of handelaar.
3. Hou akkurate faktuur- en registrantbesonderhede by verskaffers. Openbare registrasieprivaatheid kan blootstelling beperk, maar is nie toestemming om te lieg nie.
4. Hou 'n geënkripteerde grootboek van operateur, goedkeuring, doel, datum, bedrag, teenparty, bate-identifiseerder en kwitansie.
5. Sif teenpartye soos vereis en volg verskaffer-, sanksie-, belasting- en aanmeldingsverpligtinge.
6. Gee finansies slegs die toegang wat dit nodig het; gee operateurs slegs die beperkte bestedingsvermoë wat hulle nodig het.
7. Sluit betalingsbewyse tydens teardown of vries dit, versoen hangende heffings/refunds, en behou rekords volgens beleid.

Vir cryptocurrency-spesifieke keuses, gaan voort na [Cryptocurrency Privacy](cryptocurrency-privacy.md). Vir die infrastruktuur wat daardie aankope ondersteun, sien [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md).

## Verifikasiekontrolelys

- [ ] Die gewenste privaatheidseienskap en waarnemers is neergeskryf.
- [ ] Verskaffer-, handelaar- en jurisdiksiereëls is onlangs nagegaan.
- [ ] Identiteits- en bron-van-fondse-verklarings is waarheidsgetrou.
- [ ] Opsionele handel data is geminimaliseer sonder om vereiste verifikasie te verydel.
- [ ] Befondsings-, toestel-, netwerk-, rekening-, aflewerings- en refund-koppelings word verstaan.
- [ ] Geen drempelvermyding, verbode teenparty, geldmuil, gesteelde bewys of derdeparty-identiteit is betrokke nie.
- [ ] Vereiste kwitansies, goedkeurings, belastingrekords en herstel-inligting is geënkripteer en toegangsbeheer.

## References

- [1] [US CFPB — Versoek om inligting rakende die insameling, gebruik en monetisering van verbruikersbetalings- en ander persoonlike finansiële data](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf) and [State Consumer Privacy Laws and the Monetization of Consumer Financial Data](https://www.consumerfinance.gov/data-research/research-reports/state-consumer-privacy-laws-and-the-monetization-of-consumer-financial-data/)
- [2] [Europese Sentrale Bank — Studie oor die betalingshoudings van verbruikers in die eurosone (SPACE) 2024](https://www.ecb.europa.eu/stats/ecb_surveys/space/html/ecb.space2024~19d46f0f17.en.html)
- [3] [US IRS — Instruksies vir Form 8300](https://www.irs.gov/instructions/i8300) and [FinCEN — Currency Transaction Reporting Requirement](https://www.fincen.gov/fincen-educational-pamphlet-currency-transaction-reporting-requirement)
- [4] [Spaanse Belastingagentskap — Aanmelding van kontantbetalings](https://sede.agenciatributaria.gob.es/Sede/colaborar-agencia-tributaria/denuncias/denuncia-pagos-efectivo.html)
- [5] US CFPB — [Waarom word ek vir persoonlike inligting gevra om 'n voorafbetaalde kaart te aktiveer of registreer?](https://www.consumerfinance.gov/ask-cfpb/why-am-i-being-asked-for-personal-information-to-activate-or-register-a-prepaid-card-en-443/) en [Kan 'n voorafbetaalde kaart aan my geweier word?](https://www.consumerfinance.gov/ask-cfpb/can-i-be-declined-for-a-prepaid-card-en-437/)
- [6] [FinCEN — Finale reël oor Prepaid Access](https://www.fincen.gov/resources/statutes-regulations/guidance/final-rule-definitions-and-other-regulations-relating)
- [7] [Directive (EU) 2018/843](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32018L0843) and [Regulation (EU) 2024/1624](https://eur-lex.europa.eu/eli/reg/2024/1624)
- [8] [Capital One — Gebruik van virtuele kredietkaarte](https://www.capitalone.com/help-center/credit-cards/using-virtual-credit-cards/), [Google Pay — Virtual cards](https://support.google.com/googlepay/answer/7643925?hl=en), [EMVCo — Payment Tokenisation](https://www.emvco.com/emv-technologies/payment-tokenisation/), and [Visa — Token Service Provisioning](https://developer.visa.com/capabilities/token-service-provisioning)
