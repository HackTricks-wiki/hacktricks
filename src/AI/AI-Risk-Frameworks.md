# AI Risiko's

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp het die top 10 machine learning kwesbaarhede geïdentifiseer wat AI‑stelsels kan raak. Hierdie kwesbaarhede kan tot verskeie veiligheidsondersoeke lei, insluitend data poisoning, model inversion, en adversarial attacks. Om hierdie kwesbaarhede te verstaan is noodsaaklik vir die bou van veilige AI‑stelsels.

For an updated and detailed list of the top 10 machine learning vulnerabilities, refer to the [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) project.

- **Input Manipulation Attack**: ’n Aanvaller voeg klein, dikwels onsigbare veranderinge by die **inkomende data** sodat die model die verkeerde besluit neem.\
*Voorbeeld*: ’n Paar kolle verf op ’n stop‑teken mislei ’n selfbesturende voertuig om ’n snelheidsbeperking‑teken te "sien".

- **Data Poisoning Attack**: Die **training set** word doelbewus besmet met slegte monsters, wat die model skadelike reëls leer.\
*Voorbeeld*: Malware‑binaries word verkeerdelik gemerk as "benign" in ’n antivirus‑opleidingskorpus, wat toelaat dat soortgelyke malware later deurglip.

- **Model Inversion Attack**: Deur uitgangswaardes te ondersoek bou ’n aanvaller ’n **omgekeerde model** wat sensitiewe kenmerke van die oorspronklike insette kan rekonstrueer.\
*Voorbeeld*: Herstel van ’n pasiënt se MRI‑beeld uit ’n kanker‑deteksie‑model se voorspellings.

- **Membership Inference Attack**: Die teenstander toets of ’n **spesifieke rekord** tydens opleiding gebruik is deur verskille in selfvertroue op te spoor.\
*Voorbeeld*: Bevestig dat ’n persoon se banktransaksie in die opleidingdata van ’n fraudedetektiemodel voorkom.

- **Model Theft**: Deurlopende navrae laat ’n aanvaller toe om besluitgrense te leer en die **model se gedrag te kloon** (en IP).\
*Voorbeeld*: Oes genoeg Q&A‑pare van ’n ML‑as‑a‑Service API om ’n naby‑ekwivalente plaaslike model te bou.

- **AI Supply‑Chain Attack**: Kompromiseer enige komponent (data, libraries, pre‑trained weights, CI/CD) in die **ML pipeline** om afgeleë modelle te korrupteer.\
*Voorbeeld*: ’n Gifagtige dependency op ’n model‑hub installeer ’n backdoored sentiment‑analise‑model oor baie toepassings.

- **Transfer Learning Attack**: Kwaadaardige logika word in ’n **pre‑trained model** geplant en oorleef fine‑tuning vir die slagoffer se taak.\
*Voorbeeld*: ’n vision backbone met ’n verborge trigger keer nog steeds etikette om na aanpassing vir mediese beeldvorming.

- **Model Skewing**: Fyn bevooroordeelde of verkeerd gemerkte data **skuif die model se uitsette** om die aanvaller se agenda te bevoordeel.\
*Voorbeeld*: Inspuiting van "skoon" spam‑e‑posse gemerk as ham sodat ’n spamfilter soortgelyke toekomstige e‑posse deurlaat.

- **Output Integrity Attack**: Die aanvaller **verander modelvoorspellings tydens vervoer**, nie die model self nie, en mislei downstream‑stelsels.\
*Voorbeeld*: Die "malicious" uitspraak van ’n malware‑klassifiseerder word na "benign" omgedraai voordat die file‑quarantine‑stap dit sien.

- **Model Poisoning** --- Direkte, geteikende veranderinge aan die **model parameters** self, dikwels na verwerving van skryf‑toegang, om gedrag te verander.\
*Voorbeeld*: Aanpassing van gewigte op ’n fraudedetektiemodel in produksie sodat transaksies van sekere kaarte altyd goedgekeur word.


## Google SAIF Risks

Google se [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) skets verskeie risiko's wat met AI‑stelsels geassosieer word:

- **Data Poisoning**: Kwaadaardige akteurs verander of spuit opleiding/tuning‑data in om akkuraatheid te degradeer, backdoors in te plant, of resultate te skeef, wat modelintegriteit dwarsdeur die data‑lewe‑siklus ondermyn.

- **Unauthorized Training Data**: Insluiting van gekopieerde, sensitiewe of nie‑toegestane datastelle skep regs-, etiese en prestasie‑aanspreeklikhede omdat die model van data leer wat nooit gebruik moes word nie.

- **Model Source Tampering**: Supply‑chain of insider‑manipulasie van modelkode, dependencies, of weights voor of tydens opleiding kan verborge logika inbaken wat selfs na heropleiding voortbestaan.

- **Excessive Data Handling**: Swak data‑bewaring en governance‑kontroles laat stelsels toe om meer persoonlike data te berg of te verwerk as nodig, wat blootstelling en nakomingsrisiko verhoog.

- **Model Exfiltration**: Aanvallers steel modellêers/weights, wat verlies van intellektuele eiendom veroorsaak en copy‑cat dienste of opvolgaanvalle moontlik maak.

- **Model Deployment Tampering**: Teenstanders wysig model‑artefakte of serving‑infrastruktuur sodat die lopende model van die geverifieerde weergawe verskil en moontlik gedrag verander.

- **Denial of ML Service**: Oorlaai van APIs of stuur van “sponge” insette kan rekenaarources/energie uitput en die model afneem, soortgelyk aan klassieke DoS‑aanvalle.

- **Model Reverse Engineering**: Deur groot getalle inset‑uitset pare te oes, kan aanvallers die model kloon of distilleer, wat nabootsprodukte en gekonfigureerde adversarial aanvalle aanwakker.

- **Insecure Integrated Component**: Kwesbare plugins, agents of upstream‑dienste laat aanvallers toe om kode in te spuit of privilegies te eskaleer binne die AI‑pyplyn.

- **Prompt Injection**: Skep van prompts (direk of indirek) om instruksies te smokkel wat stelselintensie oorry, en die model laat onbedoelde opdragte uitvoer.

- **Model Evasion**: Noukeurig ontwerpte insette spoor die model aan om foutief te klassifiseer, te hallucinate, of ontoegelate inhoud te lewer, wat veiligheid en vertroue ondermyn.

- **Sensitive Data Disclosure**: Die model openbaar private of vertroulike inligting uit sy opleidingsdata of gebruikerskonteks, wat privaatheid en regulasies skend.

- **Inferred Sensitive Data**: Die model leiden persoonlike eienskappe af wat nooit verskaf is nie, wat nuwe privaatheidsskade deur inferensie veroorsaak.

- **Insecure Model Output**: Onsaniteerde antwoorde lewer skade‑kode, misinformasie, of ongepaste inhoud aan gebruikers of downstream‑stelsels.

- **Rogue Actions**: Outonoom geïntegreerde agents voer onbedoelde werklike wêreld‑operasies uit (file writes, API calls, aankope, ens.) sonder voldoende gebruikers‑toesig.

## Mitre AI ATLAS Matrix

Die [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) verskaf ’n omvattende raamwerk om risiko's verbonde aan AI‑stelsels te verstaan en te versag. Dit kategoriseer verskeie aanvalstegnieke en taktieke wat teenstanders teen AI‑modelle kan gebruik en ook hoe om AI‑stelsels te gebruik om verskillende aanvalle uit te voer.


## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Aanvallers steel aktiewe sessie‑tokens of cloud API‑credentials en roep betaalde, cloud‑gehoste LLMs aan sonder magtiging. Toegang word dikwels herverkoop via reverse proxies wat die slagoffer se rekening voorsien, bv. "oai-reverse-proxy" deployments. Gevolge sluit in finansiële verlies, modelmisbruik buite beleid, en toewysing na die slagoffer‑tenant.

TTPs:
- Harvest tokens from infected developer machines or browsers; steal CI/CD secrets; buy leaked cookies.
- Stand up a reverse proxy that forwards requests to the genuine provider, hiding the upstream key and multiplexing many customers.
- Abuse direct base-model endpoints to bypass enterprise guardrails and rate limits.

Mitigations:
- Bind tokens to device fingerprint, IP ranges, and client attestation; enforce short expirations and refresh with MFA.
- Scope keys minimally (no tool access, read-only where applicable); rotate on anomaly.
- Terminate all traffic server-side behind a policy gateway that enforces safety filters, per-route quotas, and tenant isolation.
- Monitor for unusual usage patterns (sudden spend spikes, atypical regions, UA strings) and auto-revoke suspicious sessions.
- Prefer mTLS or signed JWTs issued by your IdP over long-lived static API keys.

## References
- [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)

{{#include ../banners/hacktricks-training.md}}
