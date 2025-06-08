# AI Risks

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp het die top 10 masjienleer kwesbaarhede geïdentifiseer wat AI stelsels kan beïnvloed. Hierdie kwesbaarhede kan lei tot verskeie sekuriteitskwessies, insluitend data vergiftiging, model inversie, en vyandige aanvalle. Om hierdie kwesbaarhede te verstaan is van kardinale belang vir die bou van veilige AI stelsels.

Vir 'n opgedateerde en gedetailleerde lys van die top 10 masjienleer kwesbaarhede, verwys na die [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) projek.

- **Input Manipulation Attack**: 'n Aanvaller voeg klein, dikwels onsigbare veranderinge by aan **inkomende data** sodat die model die verkeerde besluit neem.\
*Voorbeeld*: 'n Paar verfspikkels op 'n stop‑teken mislei 'n self‑ryende motor om 'n spoed‑limiet teken te "sien".

- **Data Poisoning Attack**: Die **opleidingstel** word doelbewus besoedel met slegte monsters, wat die model skadelike reëls leer.\
*Voorbeeld*: Malware binaries word verkeerdelik as "benigne" gemerk in 'n antivirus opleidingskorpus, wat soortgelyke malware later laat deurkom.

- **Model Inversion Attack**: Deur uitsette te ondersoek, bou 'n aanvaller 'n **omgekeerde model** wat sensitiewe kenmerke van die oorspronklike insette heropbou.\
*Voorbeeld*: Herstel van 'n pasiënt se MRI-beeld uit 'n kanker-detektering model se voorspellings.

- **Membership Inference Attack**: Die vyand toets of 'n **spesifieke rekord** tydens opleiding gebruik is deur vertrouensverskille op te spoor.\
*Voorbeeld*: Bevestiging dat 'n persoon se banktransaksie in 'n bedrog-detektering model se opleidingsdata verskyn.

- **Model Theft**: Herhaalde navrae laat 'n aanvaller toe om besluitgrense te leer en **die model se gedrag te kloon** (en IP).\
*Voorbeeld*: Versameling van genoeg Q&A pare van 'n ML‑as‑'n‑diens API om 'n naby‑gelyke plaaslike model te bou.

- **AI Supply‑Chain Attack**: Kompromitteer enige komponent (data, biblioteke, vooropgeleide gewigte, CI/CD) in die **ML-pyplyn** om afwaartse modelle te korrupteer.\
*Voorbeeld*: 'n Besoedelde afhanklikheid op 'n model-hub installeer 'n backdoored sentiment-analise model oor baie toepassings.

- **Transfer Learning Attack**: Kwaadwillige logika word in 'n **vooropgeleide model** geplant en oorleef fyn-afstemming op die slagoffer se taak.\
*Voorbeeld*: 'n Visie-ruggraat met 'n versteekte sneller draai steeds etikette om nadat dit vir mediese beeldvorming aangepas is.

- **Model Skewing**: Subtiel bevooroordeelde of verkeerdelik gemerkte data **verskuif die model se uitsette** om die aanvaller se agenda te bevoordeel.\
*Voorbeeld*: Inspuiting van "skoon" spam-e-posse wat as ham gemerk is sodat 'n spamfilter soortgelyke toekomstige e-posse deurlaat.

- **Output Integrity Attack**: Die aanvaller **verander modelvoorspellings in oorgang**, nie die model self nie, wat afwaartse stelsels mislei.\
*Voorbeeld*: Draai 'n malware klassifiseerder se "kwaadwillig" oordeel na "benigne" voordat die lêer-quarantaine fase dit sien.

- **Model Poisoning** --- Direkte, geteikende veranderinge aan die **modelparameters** self, dikwels nadat skrywe toegang verkry is, om gedrag te verander.\
*Voorbeeld*: Aanpassing van gewigte op 'n bedrog-detektering model in produksie sodat transaksies van sekere kaarte altyd goedgekeur word.

## Google SAIF Risks

Google se [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) skets verskeie risiko's wat met AI stelsels geassosieer word:

- **Data Poisoning**: Kwaadwillige akteurs verander of inspuit opleidings/tuning data om akkuraatheid te verlaag, agterdeure in te plant, of resultate te skeef, wat die model integriteit oor die hele data-lewe siklus ondermyn.

- **Unauthorized Training Data**: Inname van kopiereg, sensitiewe, of nie-toegestane datastelle skep regslike, etiese, en prestasies verantwoordelikhede omdat die model van data leer wat dit nooit toegelaat is om te gebruik nie.

- **Model Source Tampering**: Verskaffingsketting of insider manipulasie van modelkode, afhanklikhede, of gewigte voor of tydens opleiding kan versteekte logika inbed wat selfs na heropleiding voortduur.

- **Excessive Data Handling**: Swak data-behoud en bestuurbeheer lei stelsels om meer persoonlike data te stoor of te verwerk as wat nodig is, wat blootstelling en nakoming risiko verhoog.

- **Model Exfiltration**: Aanvallers steel model lêers/gewigte, wat verlies van intellektuele eiendom veroorsaak en kopie-dienste of opvolg aanvalle moontlik maak.

- **Model Deployment Tampering**: Vyandige partye verander modelartefakte of bedieningsinfrastruktuur sodat die lopende model verskil van die goedgekeurde weergawe, wat gedrag moontlik verander.

- **Denial of ML Service**: Oorstroming van API's of die stuur van “spons” insette kan rekenaar/energie uitput en die model vanlyn slaan, wat klassieke DoS-aanvalle naboots.

- **Model Reverse Engineering**: Deur groot hoeveelhede inset-uitset pare te oes, kan aanvallers die model kloon of distilleer, wat nabootsprodukte en aangepaste vyandige aanvalle aanwakker.

- **Insecure Integrated Component**: Kwetsbare plugins, agente, of opwaartse dienste laat aanvallers toe om kode in te spuit of bevoegdhede binne die AI-pyplyn te verhoog.

- **Prompt Injection**: Die opstel van prompts (direk of indirek) om instruksies te smokkelen wat die stelselsintensie oortree, wat die model dwing om onbedoelde opdragte uit te voer.

- **Model Evasion**: Versigtig ontwerpde insette aktiveer die model om verkeerd te klassifiseer, te hallusineer, of verbode inhoud uit te voer, wat veiligheid en vertroue ondermyn.

- **Sensitive Data Disclosure**: Die model onthul private of vertroulike inligting uit sy opleidingsdata of gebruikerskonteks, wat privaatheid en regulasies oortree.

- **Inferred Sensitive Data**: Die model deduseer persoonlike eienskappe wat nooit verskaf is nie, wat nuwe privaatheidskade deur afleiding skep.

- **Insecure Model Output**: Ongefilterde antwoorde stuur skadelike kode, verkeerde inligting, of onvanpaste inhoud aan gebruikers of afwaartse stelsels.

- **Rogue Actions**: Outonoom geïntegreerde agente voer onbedoelde werklike operasies uit (lêer skrywe, API oproepe, aankope, ens.) sonder voldoende gebruikers toesig.

## Mitre AI ATLAS Matrix

Die [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) bied 'n omvattende raamwerk vir die verstaan en mitigering van risiko's wat met AI stelsels geassosieer word. Dit kategoriseer verskeie aanvaltegnieke en taktieke wat vyandige partye teen AI modelle kan gebruik en ook hoe om AI stelsels te gebruik om verskillende aanvalle uit te voer.

{{#include ../banners/hacktricks-training.md}}
