# Pagamenti digitali privati

{{#include ../banners/hacktricks-training.md}}

La privacy dei pagamenti consiste nella divulgazione controllata dei dati delle transazioni. Non è un modo per rendere legittimi fondi illegali, evadere imposte o sanzioni, eludere il KYC, usare identità false o nascondere un incarico non autorizzato. Un pagamento può essere privato nei confronti di un commerciante pur rimanendo completamente visibile a un emittente, a una rete, a un datore di lavoro, a un'autorità fiscale o a un investigatore.

Il [Catalogo delle tecniche di pagamento anonimo](anonymous-payment-techniques.md) è l'inventario normalizzato con `Pros`, `Cons`, `Procedure` legale passo per passo e `Detection` per ogni famiglia. Questa pagina approfondisce i metodi di pagamento convenzionali.

{% hint style="danger" %}
Non usare mai account rubati, identità sintetiche, money mule, dichiarazioni fittizie di residenza o di provenienza dei fondi, suddivisione delle transazioni (“structuring”) o broker opachi di “no-KYC card”. Verifica la legislazione vigente e i termini dei provider in ogni giurisdizione rilevante.
{% endhint %}

## Definire la proprietà di privacy

Identifica l'osservatore prima di scegliere un canale:

| Osservatore | Dati tipici | Controllo utile | Cosa rimane |
|---|---|---|---|
| Commerciante | Nome, email, indirizzo, token della carta, IP/dispositivo, carrello | Guest checkout, dati opzionali ridotti al minimo, carta virtuale specifica per il commerciante | Dati di consegna, account e telemetria antifrode |
| Emittente/payment processor | Identità legale, fonte dei fondi, commerciante, importo, orario, dispositivo | Scegliere un provider regolamentato con buoni termini di privacy/sicurezza | Il provider elabora comunque i dati e può conservare/divulgare i record |
| Datore di lavoro/proprietario dell'incarico | Spesa, operatore e finalità | Budget separato per l'incarico e ledger con accesso controllato | La governance legittima richiede l'attribuzione interna |
| Osservatore di una blockchain pubblica | Indirizzi, flussi, importi e orari, a seconda della chain | Protocollo appropriato e disciplina nell'uso del wallet | L'acquisizione, gli endpoint e le spese successive possono ricollegare l'attività |
| Operatore di rete/RPC/node | IP, query del wallet, trasmissioni delle transazioni | Local node o rete di privacy adatta | Il comportamento temporale e degli endpoint può comunque correlarsi |
| Osservatore fisico | Volto, posizione, veicolo, CCTV, ricevuta | Privacy situazionale ordinaria | Il contante non rende una persona fisicamente invisibile |

Il CFPB descrive le payment app come capaci di raccogliere dati sull'identità, sul dispositivo, sulla posizione, sui contatti, sulle transazioni e sul comportamento; le norme statali sulla privacy non impediscono necessariamente la monetizzazione o ogni uso secondario.<sup>[[1]](#references)</sup> Leggi l'informativa effettiva del provider invece di dedurre il livello di privacy dal nome del prodotto.

## Confrontare i metodi di pagamento

| Metodo | Vantaggio in termini di privacy | Principali osservatori/collegamenti | Uso appropriato |
|---|---|---|---|
| Contante | Nessun ledger della rete di pagamento | Destinatario, telecamere, testimoni, norme sulla dichiarazione del contante | Acquisti locali legali dove accettato |
| Carta prepaid/gift open-loop | Separa il numero della carta dalla carta principale | Venditore, provider di attivazione/registrazione, fonte dei fondi, commerciante | Budgeting o compartimentazione limitata del commerciante |
| Numero di carta virtuale/monouso | Nasconde il PAN riutilizzabile al commerciante; revoca semplice | L'emittente conosce comunque l'identità e la transazione | Compartimentazione del commerciante online |
| Token del mobile wallet | Il dispositivo/commerciante riceve un token invece del PAN sottostante | Provider del wallet, emittente, rete di pagamento e commerciante | Sicurezza delle credenziali, non anonimato |
| Bonifico bancario/app | Audit trail comodo | Banca/app, controparte e identità collegata | Pagamenti organizzativi soggetti a responsabilità |
| Cryptocurrency | Varia in base al protocollo; la self-custody può ridurre l'esposizione al custodian | Ledger pubblico o protocollo di privacy, exchange, endpoint, controparte | Trasferimenti legali dopo un'analisi specifica del protocollo |

## Contante

Il contante è ancora considerato importante per la privacy e l'inclusione e impedisce la creazione di un record nella rete di pagamento.<sup>[[2]](#references)</sup> Non elude CCTV, testimoni, posizione del dispositivo, ricevute, tracciamento dei numeri di serie in casi particolari o obblighi legali di dichiarazione.

### Workflow legale

1. Verifica l'accettazione e i limiti locali sul contante prima della transazione. I limiti differiscono in base al Paese e al tipo di soggetto e cambiano nel tempo.
2. Effettua l'acquisto ordinario in un'unica transazione onesta. **Non suddividerlo mai** per evitare una soglia o una segnalazione.
3. Rifiuta il tracking opzionale della loyalty o la raccolta per finalità di marketing. Fornisci in modo veritiero i dati richiesti per garanzia, sicurezza, consegna, imposte o legge.
4. Conserva la prova d'acquisto necessaria e i record contabili richiesti in uno storage cifrato con una data di conservazione.
5. Per un'organizzazione, richiedi il rimborso tramite la procedura approvata e registra operatore, autorizzazione, finalità, importo, data e ricevuta.

Negli Stati Uniti, determinate attività commerciali presentano il Form 8300 per incassi in contanti superiori a 10.000 dollari, comprese le transazioni correlate; suddividere intenzionalmente le transazioni può costituire di per sé structuring illecito.<sup>[[3]](#references)</sup> Le altre giurisdizioni differiscono; ad esempio, la Spagna pubblica una propria restrizione normativa sui pagamenti in contanti.<sup>[[4]](#references)</sup>

## Carte prepaid e gift card

“Prepaid” non significa anonimo. Un negozio, un emittente, un program manager, una banca che fornisce i fondi e un commerciante possono correlare acquisto, attivazione, dispositivo, IP, posizione e spese. Reload, accesso ATM, uso internazionale, limiti più elevati o protezione in caso di smarrimento richiedono comunemente la registrazione.

Le indicazioni statunitensi per i consumatori spiegano che gli emittenti possono richiedere dati identificativi per la verifica legale e possono rifiutare una carta registrata quando la verifica non va a buon fine.<sup>[[5]](#references)</sup> Le norme FinCEN definiscono quali programmi prepaid e partecipanti abbiano obblighi AML.<sup>[[6]](#references)</sup> Nell'UE, le ristrette eccezioni per la moneta elettronica anonima sono state ridotte dalla Direttiva (UE) 2018/843; il Regolamento (UE) 2024/1624 modifica nuovamente il quadro, ma in generale si applica dal **10 luglio 2027**, quindi non descriverlo come già operativo nel 2026.<sup>[[7]](#references)</sup>

Usa il valore prepaid solo quando è stato ottenuto legalmente da un emittente identificabile, i suoi termini consentono l'uso previsto e il vantaggio consiste nel budgeting o nella separazione da una credenziale di pagamento principale. Evita i mercati di rivendita e i broker che pubblicizzano carte “no-name” non verificabili: il valore potrebbe essere rubato, già riscattato, limitato geograficamente o soggetto a sequestro.

## Carte virtuali e token dei wallet

Un virtual card number (VCN) viene solitamente emesso all'interno di un account reale e verificato. I numeri specifici per commerciante o monouso riducono il rischio di breach e la correlazione del PAN tra commercianti; **non** nascondono la transazione all'emittente. La tokenization di rete sostituisce analogamente una credenziale della carta con un token vincolato.<sup>[[8]](#references)</sup>

### Workflow con compartimentazione del commerciante

1. Apri un account presso un emittente regolamentato usando dati accurati su identità, residenza e fondi.
2. Proteggilo con una password univoca, MFA resistente al phishing quando disponibile, avvisi di accesso e recovery code conservati offline.
3. Genera un VCN vincolato al commerciante o monouso. Imposta un limite ragionevole di importo/tempo, se supportato.
4. Usa il guest checkout e ometti solo i campi **opzionali** relativi a profilo, loyalty e marketing. Fornisci dati accurati di fatturazione, consegna e fiscali quando richiesto.
5. Evita di accedere a provider di identità non correlati; usa un compartimento browser per l'incarico/account e il percorso di rete approvato.
6. Salva la ricevuta e la corrispondenza tra VCN e finalità in un ledger interno cifrato.
7. Blocca o revoca il numero dopo il termine per rimborsi/chargeback; monitora l'account principale per autorizzazioni inattese.

Capital One e Google documentano che i numeri virtuali rimangono collegati all'account sottostante, mentre EMVCo/Visa descrivono la tokenization come sostituzione della credenziale e restrizione del dominio, non come anonimato del pagatore.<sup>[[8]](#references)</sup>

## Consegne, account e rimborsi

Il pagamento è solo un elemento del grafo dei collegamenti:

- Una carta univoca viene resa inutile dal riutilizzo di email personale, numero di telefono, profilo browser, indirizzo IP o account loyalty personali.
- La consegna fisica richiede normalmente un destinatario e una posizione legali. Non usare l'indirizzo di una persona estranea né impersonare un residente. I servizi di ricezione aziendali approvati sono più sicuri dei dati falsificati.
- I beni digitali possono registrare identità dell'account, IP, dispositivo, fingerprint del dispositivo, attivazione della licenza e download.
- I rimborsi vengono comunemente restituiti sul canale originale. Le richieste di ricevere fondi e inoltrarli/rimborsarli altrove sono un segnale di frode e money mule.
- I descrittori del commerciante, il testo delle fatture e le notifiche di spedizione possono esporre un acquisto sensibile ai delegati dell'account; configura deliberatamente accessi e avvisi.

## Acquisti autorizzati di red-team

Un incarico dovrebbe essere discreto verso l'esterno e soggetto a responsabilità interna:

1. Ottieni ambito, finalità, limite di spesa, approvatore, commercianti/asset autorizzati e regola di rimborso per iscritto.
2. Usa un account di pagamento controllato dall'organizzazione e un VCN o sub-account separato per ogni incarico o commerciante.
3. Mantieni presso i provider dati accurati di fatturazione e registrazione. La privacy della registrazione pubblica può ridurre l'esposizione, ma non autorizza a mentire.
4. Mantieni un ledger cifrato con operatore, approvazione, finalità, data, importo, controparte, identificativo dell'asset e ricevuta.
5. Sottoponi le controparti a screening quando richiesto e rispetta gli obblighi del provider, sulle sanzioni, fiscali e di segnalazione.
6. Concedi al reparto finance solo l'accesso necessario; agli operatori assegna solo la capacità di spesa limitata necessaria.
7. Chiudi o blocca le credenziali di pagamento durante il teardown, riconcilia gli addebiti/rimborsi pendenti e conserva i record secondo la policy.

Per le scelte specifiche relative alle crypto, continua con [Privacy delle Cryptocurrency](cryptocurrency-privacy.md). Per l'infrastruttura supportata da tali acquisti, consulta [Infrastruttura autorizzata per il red-team](authorized-red-team-infrastructure.md).

## Checklist di verifica

- [ ] La proprietà di privacy desiderata e gli osservatori sono stati messi per iscritto.
- [ ] Le regole del provider, del commerciante e della giurisdizione sono state verificate di recente.
- [ ] Le dichiarazioni sull'identità e sulla provenienza dei fondi sono veritiere.
- [ ] I dati opzionali del commerciante sono ridotti al minimo senza impedire la verifica richiesta.
- [ ] I collegamenti tra fondi, dispositivo, rete, account, consegna e rimborso sono compresi.
- [ ] Non sono coinvolti elusione di soglie, controparti vietate, mule, credenziali rubate o identità di terzi.
- [ ] Ricevute, approvazioni, documenti fiscali e informazioni di recupero richiesti sono cifrati e soggetti a controllo degli accessi.

## References

- [1] [US CFPB — Richiesta di informazioni riguardante la raccolta, l'uso e la monetizzazione dei dati dei pagamenti dei consumatori e di altri dati finanziari personali](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf) and [State Consumer Privacy Laws and the Monetization of Consumer Financial Data](https://www.consumerfinance.gov/data-research/research-reports/state-consumer-privacy-laws-and-the-monetization-of-consumer-financial-data/)
- [2] [Banca centrale europea — Studio sugli atteggiamenti dei consumatori dell'area euro nei confronti dei pagamenti (SPACE) 2024](https://www.ecb.europa.eu/stats/ecb_surveys/space/html/ecb.space2024~19d46f0f17.en.html)
- [3] [US IRS — Istruzioni per il Form 8300](https://www.irs.gov/instructions/i8300) and [FinCEN — Currency Transaction Reporting Requirement](https://www.fincen.gov/fincen-educational-pamphlet-currency-transaction-reporting-requirement)
- [4] [Agenzia tributaria spagnola — Segnalazione dei pagamenti in contanti](https://sede.agenciatributaria.gob.es/Sede/colaborar-agencia-tributaria/denuncias/denuncia-pagos-efectivo.html)
- [5] US CFPB — [Perché mi vengono richieste informazioni personali per attivare o registrare una carta prepaid?](https://www.consumerfinance.gov/ask-cfpb/why-am-i-being-asked-for-personal-information-to-activate-or-register-a-prepaid-card-en-443/) e [Posso vedermi rifiutare una carta prepaid?](https://www.consumerfinance.gov/ask-cfpb/can-i-be-declined-for-a-prepaid-card-en-437/)
- [6] [FinCEN — Regola finale sull'accesso prepaid](https://www.fincen.gov/resources/statutes-regulations/guidance/final-rule-definitions-and-other-regulations-relating)
- [7] [Direttiva (UE) 2018/843](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32018L0843) and [Regulation (EU) 2024/1624](https://eur-lex.europa.eu/eli/reg/2024/1624)
- [8] [Capital One — Utilizzo delle carte di credito virtuali](https://www.capitalone.com/help-center/credit-cards/using-virtual-credit-cards/), [Google Pay — Virtual cards](https://support.google.com/googlepay/answer/7643925?hl=en), [EMVCo — Payment Tokenisation](https://www.emvco.com/emv-technologies/payment-tokenisation/), and [Visa — Token Service Provisioning](https://developer.visa.com/capabilities/token-service-provisioning)
{{#include ../banners/hacktricks-training.md}}
