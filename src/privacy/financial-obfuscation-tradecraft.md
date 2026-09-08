# Tecniche di offuscamento finanziario

La privacy dei pagamenti è un problema di attribuzione, non di marchio del metodo di pagamento. Un'operazione lascia tracce quando il valore viene acquisito, trasferito, convertito, speso e consegnato. Un indirizzo su una blockchain pubblica può essere pseudonimo, mentre un exchange, un emittente di carte, un commerciante, un dispositivo mobile o una telecamera di spedizione possono identificare la persona che vi sta dietro.

Questa pagina spiega i pattern di offuscamento finanziario utilizzati nella criminalità informatica e nelle operazioni collegate a Stati, affinché i difensori possano riconoscerli. **Non** fornisce una procedura per il riciclaggio, l'elusione delle sanzioni, l'uso di identità false o l'aggiramento del KYC.

## Il grafo del valore end-to-end
```text
funding source -> acquisition -> transfer/layering -> conversion -> merchant/host -> delivery/use
|              |                |                 |             |
bank/account     KYC/P2P          blockchain         VASP/OTC    service + device
```
Un attore tenta di impedire a qualsiasi osservatore di vedere entrambe le estremità. Gli investigatori fanno il contrario: conservano i record a ogni confine, normalizzano tempo/valore/commissioni e identificano il **punto di riconvergenza** in cui personas separate riutilizzano lo stesso facilitatore, dispositivo, account, esercente o destinazione.

## Strumenti e loro osservatori reali

| Strumento | Nascosto all'esercente/al pubblico | Ancora visibile a |
|---|---|---|
| Carta virtuale/token dell'emittente | numero della carta sottostante | emittente, network/token provider, wallet, account dell'esercente e sistemi di delivery |
| Valore prepagato/gift | talvolta il nome legale nell'acquisto ordinario | retailer/payment rail, servizio di attivazione/riscatto, telecamere, dispositivo e delivery |
| Contanti | registro pubblico ed emittente remoto | controparti, telecamere, controlli su prelievi/seriali ove applicabili, perquisizione fisica |
| Bitcoin/nuovo indirizzo | nome legale diretto | ogni osservatore della blockchain; peer del wallet/network; servizi di acquisition/off-ramp |
| CoinJoin/PayJoin | euristiche semplici basate su input comuni/pagamento | transazione pubblica, metadati del coordinator/peer/network e comportamento di spesa successivo |
| Privacy coin | mittente/destinatario/importo pubblico, a seconda del protocollo | acquisition/off-ramp, endpoint del wallet, osservatore del network e controparte |
| Mixer centralizzato | collegamento diretto tra deposito e prelievo | operatore/log del mixer, insiemi di entrata/uscita della blockchain e controparti |
| Bridge/swap cross-chain | continuità su una singola chain | entrambe le chain, servizio di bridge/swap, vincoli di timing/valore e liquidità |
| Broker OTC/P2P | account di exchange diretto in alcuni casi | broker, comunicazioni, movimenti bancari/di contanti, controparti e dispositivi |

## Carte, valore prepagato, prestanome e mule

### Carte virtuali e masked card

Un emittente può creare un numero di carta vincolato a un esercente o usa-e-getta. Ciò riduce l'esposizione dell'esercente e il riutilizzo del numero presso più esercenti. L'emittente continua comunque a collegarlo al cliente, all'account di funding, al dispositivo, all'IP e alla transazione. I billing descriptor, l'account dell'esercente, l'indirizzo di spedizione e i dati del browser restano correlabili.

Il marketing delle carte “senza nome” non implica un settlement anonimo. Gli emittenti e distributori regolamentati possono effettuare controlli d'identità, conservare record, imporre limiti geografici/di importo e rispondere a richieste legali. Una carta ottenuta tramite un'identità rubata aggiunge identity theft; non rimuove la telemetria dell'emittente/dispositivo/esercente.

### Valore prepagato e gift

Le carte prepagate e i gift code separano un riscatto successivo dallo strumento di pagamento originale, ma creano un oggetto numerato con eventi di acquisto, attivazione, verifica del saldo e riscatto. Tra i pattern rilevanti rientrano acquisti in blocco, denominazioni ripetute appena inferiori alle soglie di controllo, riscatto rapido a distanza, un dispositivo che verifica molti saldi o molte carte che convergono su un unico esercente/account.

### Prestanome, money mule e merchant front

Un prestanome o mule fornisce un account e un'identità legale che si frappongono tra l'operatore e un servizio. Le reti possono sovrapporre recruiter, titolari di account, payment processor, shell merchant e broker di cash-out. Ciò crea distanza, ma ogni partecipante aggiunge comunicazioni, commissioni, incoerenze comportamentali e un potenziale testimone collaboratore. Le front company aggiungono record di costituzione, fiscali, bancari, degli amministratori, delle fatture, dell'hosting e delle spedizioni.

I difensori dovrebbero analizzare dispositivi/IP condivisi, riutilizzo dei beneficiary, contraddizioni di geolocalizzazione, velocity incoerente con la cronologia dell'account, trasferimenti circolari, più mittenti non correlati che convergono e movimento immediato verso terzi. Non presumere che il titolare dell'account indicato sia l'attore che lo controlla; trattarlo come un nodo di cui determinare il ruolo.

## Pattern di obfuscation delle transazioni su chain pubbliche

### Rotazione degli indirizzi e coin control

Creare un nuovo indirizzo per ogni ricezione impedisce il banale riutilizzo dell'indirizzo, ma le transazioni possono comunque essere unite attraverso input comuni, rilevamento del resto, valore/tempo esatti e consolidamento successivo. **Coin control** consente a un wallet di scegliere quali output spendere ed evitare di unire i compartimenti. Migliora l'igiene; non può rimuovere un collegamento già pubblico.

### Peel chain

Una peel chain spende ripetutamente un saldo elevato, inviando un importo minore verso l'esterno e restituendo il resto a un nuovo indirizzo:
```text
100 -> payment 3 + change 97
97 -> payment 4 + change 93
93 -> payment 2 + change 91 -> ...
```
L'indirizzo cambia a ogni passaggio, ma la continuità del valore, la cadenza e la struttura delle transazioni spesso formano una catena riconoscibile. Anche gli hot wallet legittimi degli exchange possono comportarsi in modo simile, quindi l'attribuzione richiede evidenze relative al servizio e al contesto. Il DOJ ha utilizzato l'analisi delle peel-chain nei casi di confisca collegati alla DPRK.<sup>[[1]](#references)</sup>

### Structuring e fan-out/fan-in

- **Fan-out:** una fonte si divide su molti indirizzi per aumentare il carico di lavoro investigativo o preparare conversioni parallele.
- **Fan-in:** molte fonti si consolidano in un unico collector, rivelando un controllo comune o un servizio.
- **Structuring:** trasferimenti ripetuti di importo ridotto cercano di evitare le soglie di revisione o di confondersi con i volumi ordinari.
- **Commingling:** fondi illeciti e fondi non correlati condividono wallet, pool o servizi, rendendo inaffidabili le affermazioni proporzionali semplicistiche.

La forma del grafo è un'indicazione, non una prova. Gli analisti dovrebbero tenere conto delle commissioni, del modello UTXO/account, del comportamento del servizio e delle convenzioni relative al resto.

### CoinJoin e PayJoin

In un CoinJoin tipico, diversi partecipanti conferiscono input e ricevono output in un'unica transazione collaborativa, spesso con denominazioni degli output uguali. Questo invalida l'assunto secondo cui ogni input e output di una transazione abbia un unico proprietario. L'anonimity set è limitato dal numero di partecipanti e dal comportamento successivo: resto disuguale, resto tossico, consolidamento o passaggio attraverso un servizio noto possono ristabilire i collegamenti.

PayJoin modifica un pagamento ordinario in modo che sia il pagatore sia il beneficiario contribuiscano con input, invalidando direttamente l'euristica della proprietà comune degli input per quella transazione. È principalmente un protocollo per la privacy dei pagamenti, non un servizio di laundering su larga scala. Il rilevamento dovrebbe evitare di dichiarare che tutti gli input appartengano allo stesso proprietario ed esprimere l'incertezza, anziché forzare un cluster falso.

### Centralized mixers e tumblers

Un centralized mixer accetta depositi e successivamente paga coin differenti da una riserva comune, spesso dopo l'applicazione di commissioni e ritardi. La sua privacy dipende dalle dimensioni del pool, dalla policy di prelievo, dai log, dall'onestà dell'operatore e dalla resistenza al sequestro. L'analisi di tempistiche e valori di ingresso e uscita, degli indirizzi di deposito, del clustering dei wallet del servizio e dei record può restringere l'insieme. Gli operatori possono rubare i fondi o conservare una mappatura completa.

L'esposizione legale è sostanziale e specifica per giurisdizione. I casi del DOJ contro ChipMixer, Samourai Wallet e gli sviluppatori/operatori di Tornado Cash, insieme all'evoluzione del contenzioso sulle sanzioni, dimostrano che i fatti relativi al protocollo, alla custodia, al controllo e alla trasmissione di denaro sono rilevanti; un'etichetta come “decentralized” non costituisce una conclusione giuridica.<sup>[[2]](#references)</sup>

### Cross-chain hopping, swap e bridge

Il cross-chain hopping converte un asset o lo trasferisce attraverso un bridge, interrompendo una query su un singolo ledger ma non la continuità economica:
```text
chain A deposit -> bridge/swap event -> chain B issuance/withdrawal
t0, amount A                    t1, amount B - fees
```
Gli analisti correlano i contratti bridge/gli indirizzi di deposito dei servizi, l'ordine delle transazioni, la finestra temporale, il tasso di cambio, le commissioni, la liquidità e l'importo univoco. Gli swap ripetuti possono aumentare l'ambiguità, aggiungendo però telemetria del provider/API/wallet. FATF identifica specificamente chain hopping, mixer, servizi peer-to-peer e valute con anonimato avanzato come indicatori di rischio quando combinati con un contesto sospetto.<sup>[[3]](#references)</sup>

### NFT, gambling e acquisti presso merchant

Le operazioni NFT autocontrattate o collusive possono fornire ai fondi una narrativa apparente di vendita; il gambling può scambiare depositi con prelievi; i beni possono convertire valore digitale in inventario rivendibile. Questi percorsi lasciano account marketplace, collegamenti a creator/royalty, grafi di wash trading, cronologia di quote/giocate, log dei dispositivi, prove di consegna e rivendita. Una perdita o una commissione non dimostra che la provenienza sia scomparsa.

## Criptovalute che preservano la privacy

I protocolli per la privacy differiscono tecnicamente:

- **Monero** usa indirizzi monouso, ring signatures e importi confidential, riducendo la visibilità pubblica di mittente/destinatario/importo. L'osservazione della rete, la compromissione del wallet, l'acquisizione/off-ramp e i registri delle controparti restano al di fuori di queste protezioni on-chain.
- Gli **shielded pool di Zcash** possono nascondere mittente, destinatario e importo quando vengono utilizzate transazioni shielded; gli indirizzi trasparenti e i passaggi tra pool rimangono pubblici, e i pattern di utilizzo influenzano l'effettivo anonymity set.
- **Bitcoin** è trasparente per impostazione predefinita. Nuovi indirizzi, CoinJoin, PayJoin e Lightning modificano specifiche ipotesi di collegamento, ma non rendono privati tutti i layer.

La tecnologia per la privacy ha usi legittimi in ambito di sicurezza e commerciale. Dal punto di vista investigativo, quando il ledger fornisce meno informazioni, le evidenze relative a endpoint, servizio, rete e persone diventano più importanti. Non dedurre mai la criminalità dalla sola scelta di un protocollo che preserva la privacy.

## Modello di caso multi-layer della DPRK

Le accuse pubbliche del DOJ e le azioni di forfeiture descrivono un processo composto, non un singolo trucco:<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

1. i lavoratori usavano materiale identificativo fittizio/rubato e VPN per ottenere impieghi da remoto;
2. i datori di lavoro pagavano in criptovaluta, incluse le stablecoin;
3. i fondi si spostavano in importi più piccoli, attraversavano chain o token diversi, acquistavano NFT oppure venivano commingled;
4. altri fondi rubati entravano nei mixer;
5. trader OTC e società di comodo convertivano il valore in pagamenti fiat o beni;
6. facilitatori, account e percorsi blockchain ricorrenti permettevano agli investigatori di ricollegare i layer.

Il Tesoro ha dichiarato che Lazarus ha usato Blender.io per elaborare parte del furto di Axie Infinity/Ronin, mentre l'FBI ha pubblicato indirizzi e sollecitato bridge, exchange, operatori RPC e società di analytics a bloccare i fondi collegati a successivi furti TraderTraitor.<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

La lezione è bidirezionale: gli attori statali usano servizi commerciali/criminali ordinari, e le blockchain pubbliche consentono ai difensori di seguire il valore anche quando i nomi sono inizialmente sconosciuti.

## Workflow di detection

1. **Conservare gli identificativi e i record grezzi delle transazioni.** Screenshot e valori fiat arrotondati sono insufficienti.
2. **Normalizzare asset e tempo.** Registrare chain, contratto del token, unità, block time, fuso orario del servizio, commissioni e fonte del tasso di cambio.
3. **Etichettare il livello di attendibilità delle evidenze.** Distinguere un indirizzo pubblicato da un servizio, un evento deterministico del contratto, un'euristica di clustering e un'intelligence esterna.
4. **Tracciare entrambe le direzioni.** Individuare l'origine dei fondi, la dispersione immediata, la riconvergenza, le uscite dai bridge, i depositi presso i servizi e la spesa/consegna.
5. **Unire le evidenze off-chain.** KYC dell'account, dispositivo, IP, ticket di supporto, chiavi API, dati bancari/dei pagamenti, spedizioni e comunicazioni spesso risolvono l'ambiguità.
6. **Testare spiegazioni alternative.** Exchange, custodian, sistemi di payroll e protocolli per la privacy possono produrre fan-in/out o co-spend senza proprietà beneficiaria comune.
7. **Monitorare invece di chiudere prematuramente.** Un output inattivo può diventare attribuibile quando in seguito raggiunge un servizio.
8. **Applicare gli obblighi correnti in materia di sanzioni/AML con il supporto di un legale.** Regole e designazioni cambiano; l'associazione storica non sostituisce l'analisi legale corrente.

## Modello di procurement red-team sicuro

Un team autorizzato potrebbe aver bisogno che il SOC target non riconosca il pagamento del proprio hosting, mentre il responsabile dell'engagement mantiene la responsabilità:

- usare una carta dell'organizzazione specifica per l'engagement o un wallet aziendale documentato;
- mantenere accurati i record di fatturazione, fiscali e del provider;
- separare l'operatore dai compiti di procurement e limitare l'accesso alla mappa di attribuzione;
- non usare mai un mule, un'identità falsa, una carta rubata, un workaround delle sanzioni o un exchanger senza licenza;
- registrare asset, importo, proprietario, servizio, data, percorso di rimborso e prove di teardown;
- comunicare al responsabile gli indicatori rilevanti di pagamento/provider dopo l'esercizio.

Questo crea **cecità nei confronti del partecipante all'esercizio**, non cecità nei confronti della legge, del provider o della governance.

## References

- [1] [US DOJ — Framework di enforcement delle criptovalute (esempio di peel-chain e indagini sulla DPRK)](https://www.justice.gov/archives/ag/page/file/1326061/dl?inline=)
- [2] [US DOJ — Takedown di ChipMixer](https://www.justice.gov/archives/opa/pr/justice-department-investigation-leads-takedown-darknet-cryptocurrency-mixer-processed-over-3)
- [3] [FATF — Indicatori di rischio per gli asset virtuali](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [4] [US DOJ — Rappresentante della Foreign Trade Bank della DPRK incriminato per cospirazioni di riciclaggio di criptovalute](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [5] [US DOJ — Denuncia di forfeiture relativa a 7,74 milioni di dollari presumibilmente riciclati per la DPRK](https://www.justice.gov/usao-dc/pr/department-files-civil-forfeiture-complaint-against-more-774-million-laundered-behalf-0)
- [6] [US Treasury — Sanzioni contro Blender.io e fondi di Lazarus](https://home.treasury.gov/news/press-releases/jy0768)
- [7] [FBI — La Corea del Nord è responsabile del furto del 2025 ai danni di Bybit](https://www.fbi.gov/investigate/cyber/alerts/2025/north-korea-responsible-for-1-5-billion-bybit-hack)
- [8] [FinCEN — Applicazione delle normative agli utenti, amministratori ed exchanger di valute virtuali](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
