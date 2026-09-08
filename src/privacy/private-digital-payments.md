# Pagamenti digitali privati

La privacy dei pagamenti consiste nella divulgazione controllata dei dati delle transazioni. Non è un modo per rendere legittimi fondi illegali, evadere tasse o sanzioni, eludere il KYC, usare identità false o nascondere un incarico non autorizzato. Un pagamento può essere privato rispetto a un merchant pur rimanendo completamente visibile a un issuer, network, datore di lavoro, autorità fiscale o investigator.

Il [Catalogo delle tecniche di pagamento anonimo](anonymous-payment-techniques.md) è l'inventario normalizzato con `Pros`, `Cons`, `Procedure` passo-passo lecita e `Detection` per ogni famiglia. Questa pagina amplia i metodi di pagamento convenzionali.

{% hint style="danger" %}
Non usare mai account rubati, identità sintetiche, money mule, residenze fittizie o dichiarazioni fittizie sulla provenienza dei fondi, frazionamento delle transazioni ("structuring") o broker opachi di "no-KYC card". Verifica la legge vigente e i termini dei provider in ogni giurisdizione pertinente.
{% endhint %}

## Definire la proprietà di privacy

Identifica l'observer prima di scegliere un rail:

| Observer | Dati tipici | Controllo utile | Cosa rimane |
|---|---|---|---|
| Merchant | Nome, email, indirizzo, card token, IP/device, carrello | Guest checkout, dati opzionali minimi, virtual card specifica per merchant | Telemetria di consegna, account e frodi |
| Issuer/payment processor | Identità legale, fonte dei fondi, merchant, importo, ora, device | Scegliere un provider regolamentato con buoni termini di privacy/security | Il provider elabora comunque i dati e può conservare/divulgare i record |
| Datore di lavoro/proprietario dell'incarico | Spesa, operatore e finalità | Budget separato per l'incarico e ledger con accesso controllato | Una governance legittima richiede l'attribuzione interna |
| Observer della blockchain pubblica | Indirizzi, flussi, importi e ora, a seconda della chain | Protocollo appropriato e disciplina del wallet | Acquisizione, endpoint e spese successive possono ricollegare l'attività |
| Operatore di rete/RPC/node | IP, query del wallet, trasmissioni delle transazioni | Node locale o network di privacy appropriato | Il comportamento temporale e degli endpoint può comunque correlarsi |
| Observer fisico | Volto, posizione, veicolo, CCTV, ricevuta | Privacy situazionale ordinaria | Il contante non rende una persona fisicamente invisibile |

Il CFPB descrive le payment app come capaci di raccogliere dati sull'identità, device, posizione, contatti, transazioni e comportamento; le norme statali sulla privacy non impediscono necessariamente la monetizzazione o ogni uso secondario.<sup>[[1]](#references)</sup> Leggi l'informativa effettiva del provider invece di dedurre la privacy dal nome di un prodotto.

## Confrontare i metodi di pagamento

| Metodo | Vantaggio per la privacy | Principali observer/collegamenti | Uso appropriato |
|---|---|---|---|
| Contante | Nessun ledger del payment network | Destinatario, telecamere, testimoni, norme sulla dichiarazione del contante | Acquisti locali leciti dove accettato |
| Open-loop prepaid/gift card | Separa il numero della card dalla card principale | Seller, provider di attivazione/registrazione, fonte dei fondi, merchant | Budgeting o compartimentazione limitata del merchant |
| Numero di card virtuale/monouso | Nasconde il PAN riutilizzabile al merchant; revoca semplice | L'issuer conosce comunque identità e transazione | Compartimentazione dei merchant online |
| Mobile-wallet token | Device/merchant ricevono un token invece del PAN sottostante | Wallet provider, issuer, payment network e merchant | Sicurezza delle credenziali, non anonimato |
| Bank transfer/app | Audit trail comodo | Bank/app, controparte e identità collegata | Pagamenti organizzativi tracciabili |
| Cryptocurrency | Varia in base al protocollo; la self-custody può ridurre l'esposizione al custodian | Ledger pubblico o protocollo di privacy, exchange, endpoint, controparte | Trasferimenti leciti dopo un'analisi specifica del protocollo |

## Contante

Il contante è ancora considerato importante per la privacy e l'inclusione e impedisce la creazione di un record nel payment network.<sup>[[2]](#references)</sup> Non elude CCTV, testimoni, localizzazione del device, ricevute, tracciamento dei numeri di serie in casi particolari o obblighi legali di dichiarazione.

### Workflow lecito

1. Verifica l'accettazione e i limiti locali sul contante prima della transazione. I limiti variano in base al paese e al tipo di parte e cambiano nel tempo.
2. Effettua l'acquisto ordinario in un'unica transazione veritiera. **Non frazionarlo mai** per evitare una soglia o una segnalazione.
3. Rifiuta il tracking opzionale della loyalty o la raccolta per il marketing. Fornisci in modo veritiero i dati richiesti per garanzia, sicurezza, consegna, imposte o legge.
4. Conserva la prova d'acquisto necessaria e i record contabili obbligatori in uno storage cifrato con una data di conservazione.
5. Per un'organizzazione, richiedi il rimborso tramite il processo approvato e registra operatore, autorizzazione, finalità, importo, data e ricevuta.

Negli Stati Uniti, determinate attività commerciali presentano il Form 8300 per incassi in contanti superiori a 10.000 dollari, comprese le transazioni correlate; separare intenzionalmente le transazioni può costituire di per sé structuring illecito.<sup>[[3]](#references)</sup> Le altre giurisdizioni differiscono: per esempio, la Spagna pubblica una propria restrizione normativa sui pagamenti in contanti.<sup>[[4]](#references)</sup>

## Prepaid e gift card

"Prepaid" non significa anonimo. Un negozio, issuer, program manager, funding bank e merchant possono correlare acquisto, attivazione, device, IP, posizione e spesa. Ricariche, accesso ATM, uso internazionale, limiti più elevati o protezione in caso di perdita richiedono comunemente la registrazione.

Le indicazioni per i consumatori statunitensi spiegano che gli issuer possono richiedere dati identificativi per la verifica legale e possono rifiutare una card registrata quando la verifica fallisce.<sup>[[5]](#references)</sup> Le regole FinCEN definiscono quali programmi prepaid e partecipanti abbiano obblighi AML.<sup>[[6]](#references)</sup> Nell'UE, le ristrette eccezioni per la moneta elettronica anonima sono state ridotte dalla Directive (EU) 2018/843; la Regulation (EU) 2024/1624 modifica nuovamente il quadro, ma generalmente si applica dal **10 luglio 2027**, quindi non descriverla come già operativa nel 2026.<sup>[[7]](#references)</sup>

Usa valore prepaid solo quando è stato ottenuto legalmente da un issuer identificabile, i suoi termini consentono l'uso previsto e il vantaggio consiste nel budgeting o nella separazione da una credenziale di pagamento primaria. Evita mercati di rivendita e broker che pubblicizzano card "no-name" non verificabili: il valore potrebbe essere rubato, già riscattato, limitato geograficamente o soggetto a sequestro.

## Virtual card e wallet token

Un virtual card number (VCN) viene solitamente emesso all'interno di un account reale e verificato. I numeri specifici per merchant o monouso riducono il rischio di breach e la correlazione del PAN tra merchant; **non** nascondono la transazione all'issuer. Anche la network tokenization sostituisce una credenziale della card con un token vincolato.<sup>[[8]](#references)</sup>

### Workflow compartimentato per merchant

1. Apri un account presso un issuer regolamentato usando dati accurati su identità, residenza e finanziamento.
2. Proteggilo con una password unica, MFA resistente al phishing quando disponibile, avvisi di login e recovery code conservati offline.
3. Genera un VCN vincolato al merchant o monouso. Imposta un limite ragionevole di importo/tempo, se supportato.
4. Usa il guest checkout e ometti solo i campi **opzionali** relativi a profilo, loyalty e marketing. Fornisci dati accurati di fatturazione, consegna e imposte quando richiesto.
5. Evita di accedere a identity provider non correlati; usa un browser compartment per l'incarico/account e il network path approvato.
6. Salva la ricevuta e la corrispondenza VCN-finalità in un ledger interno cifrato.
7. Blocca o revoca il numero dopo il periodo per refund/chargeback; monitora l'account principale per autorizzazioni inattese.

Capital One e Google documentano che i numeri virtuali rimangono collegati all'account sottostante, mentre EMVCo/Visa descrivono la tokenization come sostituzione della credenziale e limitazione del dominio, non come anonimato del pagatore.<sup>[[8]](#references)</sup>

## Consegne, account e refund

Il pagamento è solo un collegamento nel grafo delle correlazioni:

- Una card unica viene vanificata dal riutilizzo di un'email personale, numero di telefono, browser profile, indirizzo IP o account loyalty.
- La consegna fisica normalmente richiede un destinatario e una posizione leciti. Non usare l'indirizzo di una persona estranea né impersonare un residente. I servizi di ricezione aziendali approvati sono più sicuri dei dati inventati.
- I beni digitali possono registrare identità dell'account, IP, device fingerprint, attivazione della licenza e download.
- I refund vengono comunemente restituiti al rail originale. Le richieste di ricevere fondi e inoltrarli/rimborsarli altrove sono un segnale di frode e money mule.
- I merchant descriptor, il testo delle fatture e le notifiche di spedizione possono esporre un acquisto sensibile ai delegati dell'account; configura deliberatamente accessi e avvisi.

## Acquisti red-team autorizzati

Un incarico dovrebbe essere discreto all'esterno e tracciabile internamente:

1. Ottieni scope scritto, finalità, limite di spesa, approvatore, merchant/asset consentiti e regola di rimborso.
2. Usa un account di pagamento controllato dall'organizzazione e un VCN o sub-account separato per ogni incarico o merchant.
3. Mantieni dati accurati di fatturazione e registrazione presso i provider. La privacy della registrazione pubblica può ridurre l'esposizione, ma non autorizza a mentire.
4. Mantieni un ledger cifrato con operatore, approvazione, finalità, data, importo, controparte, identificativo dell'asset e ricevuta.
5. Sottoponi le controparti a screening quando richiesto e rispetta gli obblighi del provider, sulle sanzioni, fiscali e di reporting.
6. Concedi al reparto finance solo l'accesso necessario; concedi agli operatori solo la capacità di spesa limitata di cui hanno bisogno.
7. Chiudi o blocca le credenziali di pagamento durante il teardown, riconcilia gli addebiti/refund in sospeso e conserva i record secondo la policy.

Per le scelte specifiche sulle crypto, continua con [Cryptocurrency Privacy](cryptocurrency-privacy.md). Per l'infrastruttura supportata da tali acquisti, consulta [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md).

## Checklist di verifica

- [ ] La proprietà di privacy desiderata e gli observer sono stati messi per iscritto.
- [ ] Le regole del provider, del merchant e della giurisdizione sono state verificate di recente.
- [ ] Le dichiarazioni sull'identità e sulla provenienza dei fondi sono veritiere.
- [ ] I dati opzionali del merchant sono ridotti al minimo senza eludere la verifica obbligatoria.
- [ ] I collegamenti relativi a funding, device, network, account, consegna e refund sono stati compresi.
- [ ] Non sono coinvolti elusione di soglie, controparti vietate, mule, credenziali rubate o identità di terzi.
- [ ] Ricevute, approvazioni, record fiscali e informazioni di recovery richiesti sono cifrati e soggetti ad access control.

## References

- [1] [US CFPB — Richiesta di informazioni relativa alla raccolta, all'uso e alla monetizzazione dei dati dei pagamenti dei consumatori e di altri dati finanziari personali](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf) and [State Consumer Privacy Laws and the Monetization of Consumer Financial Data](https://www.consumerfinance.gov/data-research/research-reports/state-consumer-privacy-laws-and-the-monetization-of-consumer-financial-data/)
- [2] [Banca Centrale Europea — Studio sugli atteggiamenti dei consumatori rispetto ai pagamenti nell'area dell'euro (SPACE) 2024](https://www.ecb.europa.eu/stats/ecb_surveys/space/html/ecb.space2024~19d46f0f17.en.html)
- [3] [US IRS — Istruzioni per il Form 8300](https://www.irs.gov/instructions/i8300) and [FinCEN — Currency Transaction Reporting Requirement](https://www.fincen.gov/fincen-educational-pamphlet-currency-transaction-reporting-requirement)
- [4] [Agenzia Tributaria spagnola — Segnalazione dei pagamenti in contanti](https://sede.agenciatributaria.gob.es/Sede/colaborar-agencia-tributaria/denuncias/denuncia-pagos-efectivo.html)
- [5] US CFPB — [Perché mi vengono richieste informazioni personali per attivare o registrare una prepaid card?](https://www.consumerfinance.gov/ask-cfpb/why-am-i-being-asked-for-personal-information-to-activate-or-register-a-prepaid-card-en-443/) e [Posso vedermi rifiutare una prepaid card?](https://www.consumerfinance.gov/ask-cfpb/can-i-be-declined-for-a-prepaid-card-en-437/)
- [6] [FinCEN — Regola finale sull'accesso Prepaid](https://www.fincen.gov/resources/statutes-regulations/guidance/final-rule-definitions-and-other-regulations-relating)
- [7] [Directive (EU) 2018/843](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32018L0843) and [Regulation (EU) 2024/1624](https://eur-lex.europa.eu/eli/reg/2024/1624)
- [8] [Capital One — Utilizzo delle virtual credit card](https://www.capitalone.com/help-center/credit-cards/using-virtual-credit-cards/), [Google Pay — Virtual cards](https://support.google.com/googlepay/answer/7643925?hl=en), [EMVCo — Payment Tokenisation](https://www.emvco.com/emv-technologies/payment-tokenisation/), and [Visa — Token Service Provisioning](https://developer.visa.com/capabilities/token-service-provisioning)
