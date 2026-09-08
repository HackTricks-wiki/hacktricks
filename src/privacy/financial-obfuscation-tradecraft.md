# Tradecraft di offuscamento finanziario

{{#include ../banners/hacktricks-training.md}}

La privacy dei pagamenti è un problema di attribuzione, non di marchio di pagamento. Un'operazione lascia prove quando il valore viene acquisito, trasferito, convertito, speso e consegnato. Un indirizzo su una public chain può essere pseudonimo, mentre un exchange, un emittente di carte, un commerciante, un dispositivo mobile o una telecamera di spedizione possono identificare la persona che vi sta dietro.

Questa pagina spiega i pattern di offuscamento finanziario utilizzati nella criminalità informatica e nelle operazioni legate a entità statali, affinché i difensori possano riconoscerli. **Non** fornisce una procedura di riciclaggio, elusione delle sanzioni, falsa identità o bypass del KYC.

## Il grafo end-to-end del valore
```text
funding source -> acquisition -> transfer/layering -> conversion -> merchant/host -> delivery/use
|              |                |                 |             |
bank/account     KYC/P2P          blockchain         VASP/OTC    service + device
```
Un attore tenta di impedire a qualsiasi osservatore di vedere entrambe le estremità. Gli investigatori fanno l'opposto: preservano i record a ogni confine, normalizzano tempo/valore/commissioni e identificano il **punto di riconvergenza** in cui persone distinte riutilizzano un facilitatore, dispositivo, account, merchant o destinazione.

## Strumenti e loro reali osservatori

| Strumento | Nascosto al merchant/pubblico | Ancora visibile a |
|---|---|---|
| Carta virtuale/token dell'emittente | numero della carta sottostante | emittente, network/token provider, wallet, merchant account e sistemi di consegna |
| Valore prepagato/gift | talvolta il nome legale durante un acquisto ordinario | retailer/payment rail, servizio di attivazione/riscatto, telecamere, dispositivo e consegna |
| Contanti | registro pubblico ed emittente remoto | controparti, telecamere, controlli su prelievi/seriali ove applicabili, perquisizione fisica |
| Bitcoin/nuovo indirizzo | nome legale diretto | ogni osservatore della blockchain; wallet/peer di rete; servizi di acquisizione/off-ramp |
| CoinJoin/PayJoin | euristiche semplici basate su input comuni/pagamento | transazione pubblica, metadata del coordinator/peer/network e comportamento di spesa successivo |
| Privacy coin | mittente/destinatario/importo pubblico, a seconda del protocollo | acquisition/off-ramp, wallet endpoint, network observer e controparte |
| Centralized mixer | collegamento diretto tra deposito e prelievo | operatore/log del mixer, insiemi di entrata/uscita della blockchain e controparti |
| Cross-chain bridge/swap | continuità su una singola chain | entrambe le chain, bridge/swap service, vincoli di tempistica/valore e liquidità |
| Broker OTC/P2P | account di exchange diretto in alcuni casi | broker, comunicazioni, movimenti bancari/di contanti, controparti e dispositivi |

## Carte, valore prepagato, nominee e mule

### Carte virtuali e masked card

Un emittente può creare un numero di carta vincolato a un merchant o usa e getta. Ciò riduce l'esposizione del merchant e il riutilizzo del numero tra merchant diversi. L'emittente continua comunque a collegarlo al cliente, all'account di finanziamento, al dispositivo, all'IP e alla transazione. I billing descriptor, il merchant account, l'indirizzo di spedizione e i dati del browser restano correlabili.

Il marketing delle carte “senza nome” non implica un settlement anonimo. Gli emittenti e i distributori regolamentati possono effettuare controlli d'identità, conservare record, imporre limiti geografici/di importo e rispondere a procedimenti legali. Una carta ottenuta tramite un'identità rubata aggiunge identity theft; non rimuove la telemetria dell'emittente/dispositivo/merchant.

### Valore prepagato e gift

Le carte prepagate e i gift code separano un riscatto successivo dallo strumento di pagamento originale, ma creano un oggetto numerato con eventi di acquisto, attivazione, verifica del saldo e riscatto. I pattern rilevanti includono acquisti all'ingrosso, denominazioni ripetute appena sotto le soglie di controllo, riscatti rapidi e distanti, un dispositivo che verifica molti saldi oppure molte carte che convergono su un unico merchant/account.

### Nominee, money mule e merchant front

Un nominee o mule fornisce un account e un'identità legale che si interpongono tra l'operatore e un servizio. Le reti possono stratificare recruiter, titolari di account, payment processor, shell merchant e broker di cash-out. Ciò crea distanza, ma ogni partecipante aggiunge comunicazioni, commissioni, incoerenze comportamentali e un potenziale testimone collaboratore. Le front company aggiungono record di costituzione, fiscali, bancari, relativi agli amministratori, alle fatture, all'hosting e alle spedizioni.

I difensori dovrebbero indagare su dispositivi/IP condivisi, riutilizzo dei beneficiari, contraddizioni nella geolocalizzazione, velocità incompatibile con la cronologia dell'account, trasferimenti circolari, più mittenti non correlati che convergono e trasferimenti immediati successivi. Non bisogna presumere che il titolare dell'account indicato sia l'attore che lo controlla; va trattato come un nodo il cui ruolo deve essere determinato.

## Pattern di transaction-obfuscation sulle chain pubbliche

### Rotazione degli indirizzi e coin control

Creare un nuovo indirizzo per ogni ricezione impedisce il semplice riutilizzo degli indirizzi, ma le transazioni possono comunque essere unite in base a input comuni, rilevamento del resto, valore/tempo esatti e consolidamento successivo. **Coin control** consente a un wallet di scegliere quali output spendere e di evitare l'unione tra compartimenti. Migliora l'igiene operativa; non può rimuovere un collegamento già pubblico.

### Peel chain

Una peel chain spende ripetutamente un saldo elevato, inviando un importo più piccolo verso l'esterno e restituendo il resto a un nuovo indirizzo:
```text
100 -> payment 3 + change 97
97 -> payment 4 + change 93
93 -> payment 2 + change 91 -> ...
```
L'indirizzo cambia a ogni passaggio, ma la continuità del valore, la cadenza e la struttura delle transazioni formano spesso una catena riconoscibile. Gli hot wallet di exchange legittimi possono comportarsi in modo simile, quindi l'attribuzione richiede evidenze relative al servizio/contesto. Il DOJ ha utilizzato l'analisi delle peel-chain nei casi di confisca collegati alla DPRK.<sup>[[1]](#references)</sup>

### Structuring e fan-out/fan-in

- **Fan-out:** una fonte si suddivide in molti indirizzi per aumentare il carico di lavoro investigativo o preparare conversioni parallele.
- **Fan-in:** molte fonti si consolidano in un unico collector, rivelando un controllo comune o un servizio.
- **Structuring:** trasferimenti ripetuti di importo ridotto cercano di evitare le soglie di verifica o di confondersi con i volumi ordinari.
- **Commingling:** fondi illeciti e fondi non correlati condividono wallet, pool o servizi, rendendo rischiose le semplicistiche attribuzioni proporzionali.

La forma del grafo è un'indicazione, non una prova. Gli analisti dovrebbero tenere conto delle commissioni, del modello UTXO/account, del comportamento del servizio e delle convenzioni relative al resto.

### CoinJoin e PayJoin

In un CoinJoin tipico, diversi partecipanti contribuiscono con input e ricevono output in un'unica transazione collaborativa, spesso con denominazioni degli output uguali. Questo infrange l'assunzione secondo cui ogni input e output di una transazione appartenga a un unico proprietario. L'anonimity set è limitato dal numero di partecipanti e dal comportamento successivo: resto disuguale, toxic change, consolidamento o attraversamento di un servizio noto possono reintrodurre collegamenti.

PayJoin modifica un pagamento ordinario in modo che sia il pagatore sia il beneficiario contribuiscano con input, invalidando direttamente l'euristica della proprietà comune degli input per quella transazione. È principalmente un protocollo di privacy per i pagamenti, non un servizio di laundering su larga scala. Il rilevamento dovrebbe evitare di dichiarare che tutti gli input siano di proprietà comune e dovrebbe esprimere l'incertezza anziché forzare un cluster falso.

### Mixer e tumbler centralizzati

Un mixer centralizzato accetta depositi e in seguito paga monete diverse attingendo da una riserva condivisa, spesso dopo commissioni e ritardi. La sua privacy dipende dalle dimensioni del pool, dalla politica di withdrawal, dai log, dall'onestà dell'operatore e dalla resistenza al sequestro. L'analisi dei tempi e dei valori di ingresso e uscita, degli indirizzi di deposito, del clustering dei wallet del servizio e dei record può restringere l'insieme. Gli operatori possono rubare i fondi o conservare una mappatura completa.

L'esposizione legale è significativa e varia in base alla giurisdizione. I casi del DOJ contro ChipMixer, Samourai Wallet e gli sviluppatori/operatori di Tornado Cash, così come il contenzioso in evoluzione sulle sanzioni, mostrano che i fatti relativi a protocollo, custodia, controllo e trasmissione di denaro sono rilevanti; un'etichetta come “decentralizzato” non costituisce una conclusione legale.<sup>[[2]](#references)</sup>

### Cross-chain hopping, swap e bridge

Il chain hopping converte un asset o lo trasferisce attraverso un bridge, interrompendo una query su un singolo ledger ma non la continuità economica:
```text
chain A deposit -> bridge/swap event -> chain B issuance/withdrawal
t0, amount A                    t1, amount B - fees
```
Gli analisti correlano i bridge contracts/indirizzi di deposito dei servizi, l'ordine delle transazioni, la finestra temporale, il tasso di cambio, le commissioni, la liquidità e gli importi unici. Gli swap ripetuti possono aumentare l'ambiguità, aggiungendo al contempo telemetry del provider/API/wallet. Il FATF identifica specificamente chain hopping, mixers, servizi peer-to-peer e valute con anonimato avanzato come indicatori di rischio quando combinati con un contesto sospetto.<sup>[[3]](#references)</sup>

### NFT, gambling e acquisti presso merchant

Le transazioni NFT in self-dealing o collusive possono dare ai fondi una narrativa apparente di vendita; il gambling può scambiare depositi con prelievi; i beni possono convertire valore digitale in inventario rivendibile. Questi percorsi lasciano account marketplace, collegamenti a creator/royalty, grafi di wash-trading, cronologia di quote/giocate, log dei dispositivi, prove di consegna e rivendita. Una perdita o una commissione non dimostra che la provenienza sia scomparsa.

## Criptovalute con tutela della privacy

I protocolli per la privacy differiscono tecnicamente:

- **Monero** usa indirizzi monouso, ring signatures e importi riservati, riducendo la visibilità pubblica di mittente/destinatario/importo. L'osservazione della rete, la compromissione del wallet, l'acquisizione/off-ramp e i record delle controparti restano al di fuori di tali protezioni on-chain.
- Gli **shielded pools di Zcash** possono nascondere mittente, destinatario e importo quando vengono utilizzate transazioni shielded; gli indirizzi trasparenti e i passaggi tra pool restano pubblici, e i pattern di utilizzo influenzano l'insieme effettivo di anonimato.
- **Bitcoin** è trasparente per impostazione predefinita. Nuovi indirizzi, CoinJoin, PayJoin e Lightning modificano specifiche ipotesi di collegamento, ma non rendono privati tutti i layer.

La tecnologia per la privacy ha usi legittimi di sicurezza e commerciali. Dal punto di vista investigativo, quando il ledger fornisce meno informazioni, le prove relative a endpoint, servizi, rete e persone diventano più importanti. Non dedurre mai la criminalità dalla sola scelta di un protocollo con tutela della privacy.

## Modello di caso multilayer della DPRK

Le accuse pubbliche del DOJ e le azioni di forfeiture descrivono un processo composto, non un singolo trucco:<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

1. i lavoratori hanno utilizzato materiale identificativo fittizio/rubato e VPN per ottenere impieghi da remoto;
2. i datori di lavoro hanno pagato in criptovaluta, incluse le stablecoin;
3. i fondi sono stati trasferiti in importi più piccoli, hanno attraversato chain o token diversi, sono stati utilizzati per acquistare NFT oppure sono stati commingled;
4. altri fondi rubati sono entrati in mixers;
5. trader OTC e società di comodo hanno convertito il valore in pagamenti fiat o beni;
6. facilitatori, account e percorsi blockchain ricorrenti hanno permesso agli investigatori di ricollegare i layer.

Il Treasury ha dichiarato che Lazarus ha utilizzato Blender.io per processare parte del furto Axie Infinity/Ronin, mentre l'FBI ha pubblicato indirizzi e invitato bridge, exchange, operatori RPC e società di analytics a bloccare i fondi collegati a successivi furti TraderTraitor.<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

La lezione è bidirezionale: gli attori statali utilizzano servizi commerciali/criminali ordinari, e le blockchain pubbliche consentono ai defender di seguire il valore anche quando i nomi sono inizialmente sconosciuti.

## Workflow di rilevamento

1. **Conservare gli identificativi e i record grezzi delle transazioni.** Screenshot e valori fiat arrotondati sono insufficienti.
2. **Normalizzare asset e tempi.** Registrare chain, contratto del token, unità, orario del blocco, fuso orario del servizio, commissioni e fonte del tasso di cambio.
3. **Indicare il livello di affidabilità delle prove.** Distinguere un indirizzo pubblicato da un servizio, un evento deterministico del contratto, un'euristica di clustering e un'intelligence esterna.
4. **Tracciare entrambe le direzioni.** Individuare l'origine dei fondi, la dispersione immediata, la riconvergenza, le uscite dai bridge, i depositi presso servizi e la spesa/consegna.
5. **Unire le prove off-chain.** KYC dell'account, dispositivo, IP, ticket di supporto, API keys, record bancari/dei pagamenti, di spedizione e delle comunicazioni spesso risolvono l'ambiguità.
6. **Verificare spiegazioni alternative.** Exchange, custodian, payroll e protocolli per la privacy possono produrre fan-in/out o co-spends senza una proprietà effettiva comune.
7. **Monitorare invece di chiudere prematuramente.** Un output dormiente può diventare attribuibile quando in seguito raggiunge un servizio.
8. **Applicare gli obblighi correnti in materia di sanzioni/AML con un consulente legale.** Le regole e le designazioni cambiano; un'associazione storica non sostituisce l'analisi legale corrente.

## Modello sicuro di procurement per red team

Un team autorizzato potrebbe aver bisogno che il SOC del target non riconosca il pagamento del proprio hosting, mentre il responsabile dell'engagement mantiene la responsabilità:

- utilizzare una carta dell'organizzazione specifica per l'engagement o un wallet aziendale documentato;
- mantenere accurati i record di fatturazione, fiscali e del provider;
- separare l'operatore dai compiti di procurement e limitare l'accesso alla mappa di attribuzione;
- non utilizzare mai un mule, un'identità falsa, una carta rubata, un workaround alle sanzioni o un exchanger senza licenza;
- registrare asset, importo, proprietario, servizio, data, percorso di rimborso e prove di teardown;
- comunicare al responsabile dell'engagement gli indicatori rilevanti relativi ai pagamenti/provider dopo l'esercizio.

Questo crea **cecità nei confronti del partecipante all'esercizio**, non cecità nei confronti della legge, del provider o della governance.

## References

- [1] [US DOJ — Framework per l'Enforcement delle criptovalute (esempio di peel-chain e indagini sulla DPRK)](https://www.justice.gov/archives/ag/page/file/1326061/dl?inline=)
- [2] [US DOJ — Smantellamento di ChipMixer](https://www.justice.gov/archives/opa/pr/justice-department-investigation-leads-takedown-darknet-cryptocurrency-mixer-processed-over-3)
- [3] [FATF — Indicatori di rischio relativi agli Virtual Assets](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [4] [US DOJ — Rappresentante della Foreign Trade Bank della DPRK incriminato per cospirazioni di riciclaggio di criptovalute](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [5] [US DOJ — Complaint di forfeiture relativa a 7,74 milioni di dollari presumibilmente riciclati per la DPRK](https://www.justice.gov/usao-dc/pr/department-files-civil-forfeiture-complaint-against-more-774-million-laundered-behalf-0)
- [6] [US Treasury — Sanzioni contro Blender.io e fondi di Lazarus](https://home.treasury.gov/news/press-releases/jy0768)
- [7] [FBI — La Corea del Nord è responsabile del furto del 2025 ai danni di Bybit](https://www.fbi.gov/investigate/cyber/alerts/2025/north-korea-responsible-for-1-5-billion-bybit-hack)
- [8] [FinCEN — Applicazione delle normative agli utenti, amministratori ed exchanger di virtual currency](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
{{#include ../banners/hacktricks-training.md}}
