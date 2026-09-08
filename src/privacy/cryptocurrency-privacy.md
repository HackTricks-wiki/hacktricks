# Privacy delle criptovalute

La privacy delle criptovalute è una questione di protocollo e operazioni, non un sinonimo di segretezza o immunità. Ledger pubblici, exchange, server dei wallet, peer di rete, merchant e transazioni successive espongono parti diverse del grafo.

Inizia dal [Catalogo delle tecniche di Anonymous Payment](anonymous-payment-techniques.md) per il formato con pro/contro/procedura/rilevamento di ciascuna tecnica. Questa pagina approfondisce i meccanismi specifici delle criptovalute e i limiti operativi.

{% hint style="danger" %}
Questo capitolo riguarda la self-custody lecita e la minimizzazione dei dati. Non usarlo per riciclare proventi, eludere sanzioni/obblighi fiscali o di reporting, effettuare transazioni con soggetti vietati, ingannare un provider regolamentato o gestire un servizio di trasmissione senza licenza. La tecnologia per la privacy non modifica l'origine legale o la proprietà dei fondi.
{% endhint %}

## Modello di minaccia per livello

| Livello | Osservatore | Divulgazione comune |
|---|---|---|
| Acquisizione/off-ramp | Exchange, banca, broker, controparte P2P | Identità, conto di finanziamento, destinazione, dispositivo, IP, orario |
| Ledger | Chiunque esegua analytics | Indirizzi/output, importi e orari sulle chain trasparenti; metadati specifici del protocollo altrove |
| Backend del wallet | Provider RPC, explorer, remote node | Query degli indirizzi, saldi, IP, broadcast delle transazioni |
| Rete | ISP, peer, ingresso della rete di anonimato | IP, tempistiche, volume e uso del protocollo |
| Controparte | Pagatore/beneficiario | Invoice/indirizzo, consegna, conversazione, account e tempistiche |
| Endpoint | Malware, cloud backup, sequestro fisico | Seed, chiavi, etichette, cronologia, screenshot e clipboard |

La self-custody può rimuovere un custodian dal percorso di controllo, ma non cancella il ledger, il record di acquisizione, i metadati di rete o le evidenze dell'endpoint.

## Confronto tra protocolli

| Metodo | Proprietà di privacy utile | Limiti importanti |
|---|---|---|
| Bitcoin on-chain | Self-custody; gli indirizzi nuovi evitano il semplice riutilizzo degli indirizzi | Grafo pubblico e permanente delle transazioni; euristiche su importi/tempistiche e spesa |
| Bitcoin PayJoin | L'input del ricevente può invalidare l'euristica della proprietà comune degli input | Entrambi i wallet devono supportarlo; la transazione resta pubblica; il supporto è disomogeneo |
| Bitcoin CoinJoin | Crea ambiguità tra i partecipanti coordinati | Pattern riconoscibili, collegamenti pre/post, consolidamento, rischi di policy/legali/provider |
| Lightning | I pagamenti instradati tramite onion non sono pubblicati globalmente come trasferimenti ordinari | I canali vengono aperti/chiusi on-chain; endpoint, peer, probe o custodian possono dedurre dati |
| Monero | Maggiore riservatezza on-chain predefinita per ricevente, importo e insieme dei mittenti | Restano i collegamenti con exchange, node, tempistiche, endpoint e controparte |
| Ethereum/stablecoins | Ampia disponibilità e interoperabilità con smart contract | Stato/azioni pubblici; metadati RPC; gli issuer centralizzati possono bloccare/congelare/segnalare |

## Bitcoin: baseline per la privacy

Bitcoin è pseudonimo, non anonimo. Le transazioni confermate sono pubbliche e persistenti; il riutilizzo degli indirizzi, la proprietà comune degli input, il rilevamento del resto e gli indirizzi identificati pubblicamente possono creare cluster.<sup>[[1]](#references)</sup>

### Workflow

1. **Scegli un wallet di self-custody mantenuto.** Scaricalo dal progetto ufficiale, verifica firme/hash quando disponibili e applica gli aggiornamenti di sicurezza.
2. **Crea il wallet su un endpoint affidabile.** Registra il recovery seed offline; non inserirlo mai in email, chat, screenshot o normali note cloud. Testa il recovery prima di custodire importi significativi.
3. **Mantieni hot solo il valore operativo.** Usa una custodia offline/hardware adeguata per il valore a lungo termine, con un piano di recovery che non esponga il seed a un'unica posizione fragile.
4. **Genera un nuovo indirizzo di ricezione/invoice per ogni transazione.** Non pubblicare un indirizzo statico quando sono possibili un invoice server o una consegna privata autenticata.
5. **Usa il tuo full node quando possibile.** Un explorer/server Electrum di terze parti può apprendere gli indirizzi richiesti e i metadati IP. Configura solo il comportamento Tor/proxy supportato dal wallet; Tor nasconde un'estremità di rete, non il grafo della blockchain.
6. **Etichetta privatamente ogni UTXO** indicando origine, proprietario, scopo e stato di compliance. Abilita il coin control per evitare di spendere insieme contesti di identità non correlati.
7. **Visualizza in anteprima la transazione:** input selezionati, destinazione del resto, importo, fee, controparte e se la spesa unisce compartimenti. Evita consolidamenti non necessari.
8. **Conserva separatamente e in forma cifrata i record leciti.** Mantieni base di acquisizione, invoice, autorizzazioni e informazioni fiscali/di reporting senza pubblicare la corrispondenza.
9. **Considera la spesa successiva parte della stessa decisione di privacy.** Una ricezione ben separata può essere ricollegata quando il suo output viene speso insieme a fondi identificati.

La documentazione sulla privacy di Bitcoin Core spiega che un full node evita di rivelare le query del wallet a server di terze parti, ma che il broadcast delle transazioni e la cronologia pubblica richiedono comunque un'analisi.<sup>[[2]](#references)</sup>

## PayJoin

PayJoin è un pagamento collaborativo in cui il ricevente aggiunge un input. Questo sconfigge l'assunzione semplicistica secondo cui tutti gli input appartengono al mittente. BIP 78 descrive il protocollo interattivo originale; la bozza BIP 77 definisce un design asincrono v2 che usa una mailbox cifrata/OHTTP.<sup>[[3]](#references)</sup>

Uso sicuro:

1. Conferma che entrambi i wallet supportino la stessa versione di PayJoin.
2. Ottieni l'invoice compatibile con PayJoin tramite un canale autenticato; proteggilo come qualsiasi richiesta di pagamento.
3. Controlla l'importo e la destinazione originali, quindi lascia che il wallet convalidi la proposta/PSBT, il contributo alla fee e le sostituzioni vietate.
4. Conferma il riepilogo finale del wallet. Non approvare manualmente un output, importo o fee eccessiva inattesi.
5. Se la negoziazione fallisce, verifica se il wallet effettua un fallback sicuro verso un pagamento ordinario o richiede una nuova invoice.
6. Conserva le ricevute/i record privati necessari per proprietà, contabilità e controversie.

PayJoin migliora un'euristica di chain analysis; non nasconde il pagamento alle parti, alla piattaforma di acquisizione, agli endpoint o al ledger pubblico.

## CoinJoin: vantaggi e limiti

CoinJoin coordina più utenti in un'unica transazione per rendere meno certa la corrispondenza tra input e output. La ricerca su specifici design storici di Wasabi e Samourai ha rilevato transazioni altamente riconoscibili e mostrato che il comportamento pre/post-mix può ridurre sostanzialmente l'anonimato.<sup>[[4]](#references)</sup> Questo risultato non deve essere generalizzato a ogni implementazione o versione futura, ma dimostra perché un numero relativo all'“anonymity set” non costituisca una garanzia.

Prima di qualsiasi uso lecito:

- verifica la legge locale vigente, lo stato delle sanzioni, la policy dell'exchange/custodian e gli obblighi fiscali/di reporting;
- usa software mantenuto e non-custodial ottenuto dal progetto ufficiale;
- comprendi il modello del coordinator, le fee, i controlli contro il denial-of-service e se il servizio attuale è ancora operativo: zkSNACKs ha terminato il proprio coordinator nel 2024, sebbene possano esistere altri coordinator Wasabi;
- conserva privatamente i record relativi alla provenienza dei fondi e alle transazioni;
- non accettare mai fondi sconosciuti per conto di qualcun altro né usare un “mixer” custodial che prometta prelievi non tracciabili;
- mantieni gli output separati per origine/contesto ed evita consolidamenti successivi che distruggano l'ambiguità prevista.

Gli esiti legali dipendono dai fatti e dalla giurisdizione. Le dichiarazioni di colpevolezza del 2025 di Samourai riguardavano la gestione consapevole di un money transmitter senza licenza che movimentava proventi criminali; non stabiliscono che ogni transazione collaborativa o ogni utente interessato alla privacy sia criminale.<sup>[[5]](#references)</sup>

## Lightning Network

L'onion routing Sphinx di Lightning è progettato affinché un hop intermedio conosca il predecessore e il successore, invece dell'intero percorso.<sup>[[6]](#references)</sup> Non fornisce anonimato generalizzato: il finanziamento/la chiusura dei canali è pubblico, i nodi pubblicizzano la topologia, le controparti conoscono gli endpoint, il routing/probing può dedurre saldi o parti e un wallet custodial vede l'attività dell'account dell'utente.

Per una privacy migliore:

1. Preferisci un wallet non-custodial mantenuto se la privacy dell'intermediario è importante; pianifica prima il backup/recovery dei canali.
2. Usa una nuova invoice o offer per ogni pagamento. Verifica se il wallet specifico supporta BOLT 12/route blinding, invece di presumere che lo faccia.
3. Evita di pubblicare alias dei nodi, dati di contatto ed endpoint di rete stabili non necessari.
4. Connettiti tramite una rete per la privacy supportata, se appropriato, comprendendo che i pattern di uptime/tempistiche possono comunque essere correlati.
5. Non presumere che un pagamento off-chain sia privo di record: mittente, ricevente, peer, watchtower, provider di liquidità e servizi wallet possono conservare osservazioni.

La ricerca pubblicata ha dimostrato l'inferenza di mittente/ricevente e del saldo dei canali a partire da dati pubblici e probing attivo, sebbene attacchi e mitigazioni siano in evoluzione.<sup>[[7]](#references)</sup>

## Monero

Monero usa stealth address monouso per gli output, RingCT per nascondere gli importi e ring signature per fornire ambiguità probabilistica sul mittente; le specifiche tecniche attuali documentano una ring size di 16 (15 decoy).<sup>[[8]](#references)</sup> Si tratta di impostazioni predefinite più solide per la riservatezza on-chain rispetto ai ledger trasparenti, non di una protezione magica dagli errori dell'endpoint o operativi.

### Workflow lecito

1. **Acquisisci legalmente.** Un exchange regolamentato può conoscere l'acquisto e il prelievo anche quando i dettagli on-chain successivi sono riservati. Conserva origine, base e record di reporting.
2. **Installa il wallet ufficiale mantenuto** e verifica il download secondo le istruzioni del progetto. Esegui il backup del seed offline e testa il ripristino con un importo ridotto.
3. **Preferisci un node locale** per la massima privacy delle query del wallet. Se non è pratico, scegli un remote node affidabile raggiungibile tramite una configurazione onion/I2P ufficialmente supportata. Un remote node può registrare IP, richieste, tempistiche e ID delle transazioni; alcuni design light divulgano una view key.
4. **Usa una nuova subaddress per ogni pagatore, campagna o invoice.** Un pagatore può correlare l'uso ripetuto della stessa subaddress.<sup>[[9]](#references)</sup>
5. **Etichetta localmente i contesti in entrata.** Evita di unire operativamente ricevute separate quando un pagatore informato potrebbe riconoscere il comportamento successivo.
6. **Proteggi i metadati di rete.** Segui la configurazione ufficiale della rete di anonimato; riconosci i leak documentati derivanti da timestamp, sincronizzazione intermittente, forma della banda e riutilizzo degli stream.<sup>[[10]](#references)</sup>
7. **Mantieni privati i dati di compliance/audit.** Divulga una view key o una prova della transazione solo intenzionalmente, all'auditor/alla parte destinataria, comprendendo esattamente cosa rivela.

Gli studi storici sulla tracciabilità includono bug ed epoche di selezione dei decoy che sono cambiate; non applicare le vecchie percentuali di successo alle transazioni attuali. Allo stesso modo, FCMP++ resta un lavoro di roadmap alla data di riferimento della ricerca di questo capitolo, settembre 2026, e non una protezione implementata.<sup>[[11]](#references)</sup>

## Ethereum e stablecoins

Il materiale sulla privacy di Ethereum osserva che le azioni on-chain sono visibili e che l'infrastruttura wallet/RPC aggiunge esposizione di IP e metadati.<sup>[[12]](#references)</sup> I trasferimenti di token, le approvazioni, le interazioni con smart contract, i name service e il finanziamento del gas possono tutti collegare le identità.

Le stablecoins centralizzate aggiungono il controllo dell'issuer. I termini attuali di USDC e Tether riservano poteri per bloccare/congelare indirizzi o asset e rispettare obblighi legali/procedurali.<sup>[[13]](#references)</sup> Possono essere strumenti di pagamento utili, ma sono scelte inadeguate quando il requisito è la resistenza alla censura o l'anonimato on-chain.

## Limiti di compliance

- Le raccomandazioni FATF sono attuate tramite il diritto nazionale e cambiano nel tempo; l'aggiornamento del 2026 enfatizza la licenza/registrazione dei VASP e l'implementazione della Travel Rule.<sup>[[14]](#references)</sup>
- Negli Stati Uniti, FinCEN distingue una persona che usa convertible virtual currency per i propri beni/servizi da un'attività che la accetta e la trasmette o scambia; i fatti e le regole successive sono rilevanti.<sup>[[15]](#references)</sup>
- Il Regolamento UE sui trasferimenti di fondi richiede informazioni su ordinante/beneficiario quando è coinvolto un crypto-asset service provider e aggiunge regole di verifica per determinati trasferimenti da/verso indirizzi self-hosted.<sup>[[16]](#references)</sup>
- Le sanzioni e gli obblighi fiscali continuano ad applicarsi. Esegui lo screening ove richiesto, rifiuta le parti vietate e conserva i record; gli elenchi e lo stato legale possono cambiare rapidamente.<sup>[[17]](#references)</sup>

Prima di gestire importi rilevanti, attività transfrontaliere, coordinamento con strumenti di privacy o attività di exchange/trasmissione di tipo commerciale, ottieni una consulenza professionale aggiornata per le giurisdizioni interessate.

Per Bitcoin Silent Payments, Zcash completamente shielded, GNU Taler, e-cash Chaumian federato e BOLT 12, continua con [Protocolli di pagamento che preservano la privacy](privacy-preserving-payment-protocols.md).

## References

- [1] [Bitcoin.org — Proteggi la tua privacy](https://bitcoin.org/en/protect-your-privacy) and [Bitcoin Developer Guide — Transactions](https://developer.bitcoin.org/devguide/transactions.html)
- [2] [Bitcoin Core — Funzionalità di privacy](https://bitcoin.org/en/bitcoin-core/features/privacy) and [Bitcoin.org — Secure your wallet](https://bitcoin.org/en/secure-your-wallet)
- [3] [BIP 78 — Una semplice proposta PayJoin](https://bips.dev/78/) and [Draft BIP 77 — Async Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0077.md)
- [4] [Stütz et al. — Adozione e privacy effettiva delle implementazioni CoinJoin decentralizzate in Bitcoin (AFT 2022)](https://arxiv.org/abs/2109.10229) and [Wasabi Wallet — Coin consolidation warning](https://docs.wasabiwallet.io/FAQ/FAQ-UseWasabi.html)
- [5] [US DOJ — I fondatori di Samourai Wallet si dichiarano colpevoli (2025)](https://www.justice.gov/usao-sdny/pr/founders-samourai-wallet-cryptocurrency-mixing-service-plead-guilty) and [Wasabi — coordinator status](https://docs.wasabiwallet.io/FAQ/FAQ-Introduction.html)
- [6] [Lightning BOLT 4 — Protocollo di onion routing](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Kappos et al. — Un'analisi empirica della privacy nella Lightning Network](https://arxiv.org/abs/2003.12470)
- [8] Monero Project — [Stealth address](https://www.getmonero.org/resources/moneropedia/stealthaddress.html), [RingCT](https://www.getmonero.org/resources/moneropedia/ringCT.html), [Ring signature](https://www.getmonero.org/resources/moneropedia/ringsignatures.html) e [Specifiche tecniche](https://docs.getmonero.org/technical-specs/)
- [9] [Monero Docs — Subaddress](https://docs.getmonero.org/public-address/subaddress/)
- [10] [Monero Docs — Reti](https://docs.getmonero.org/infrastructure/networks/), [Running a node with Tor/I2P](https://docs.getmonero.org/running-node/monerod-tori2p/), and [Monero Project — Anonymity networks](https://github.com/monero-project/monero/blob/master/docs/ANONYMITY_NETWORKS.md)
- [11] [Hammad e Victor — Esplorare l'evoluzione della privacy di Monero (2024)](https://arxiv.org/abs/2408.05332) and [Monero Roadmap](https://beta.getmonero.org/resources/roadmap/)
- [12] [Ethereum.org — Privacy su Ethereum](https://ethereum.org/privacy/ethereum)
- [13] [Circle — Termini USDC](https://www.circle.com/legal/usdc-terms) and [Tether — Legal](https://tether.to/en/legal/)
- [14] [FATF — Aggiornamento mirato 2026 su Virtual Asset e VASP](https://www.fatf-gafi.org/en/publications/Fatfrecommendations/targeted-updated-virtualassets-vasps-2026.html)
- [15] [FinCEN — Applicazione dei regolamenti FinCEN alle persone che amministrano, scambiano o usano valute virtuali](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [16] [Regolamento (UE) 2023/1113](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [17] [US OFAC — Linee guida sulla compliance alle sanzioni per il settore delle valute virtuali](https://ofac.treasury.gov/system/files/126/virtual_currency_guidance_brochure.pdf) and [US IRS — Digital asset transaction FAQs](https://www.irs.gov/individuals/international-taxpayers/frequently-asked-questions-on-digital-asset-transactions)
