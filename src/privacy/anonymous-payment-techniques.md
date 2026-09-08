# Catalogo delle tecniche di pagamento anonimo

{{#include ../banners/hacktricks-training.md}}

Questo catalogo tratta le **famiglie** di pagamento, dal contante ordinario all'e-cash con blind signature e all'offuscamento su blockchain pubbliche. “Anonimo” significa sempre anonimo rispetto a un osservatore specifico. Un merchant, issuer, mint, exchange, analista blockchain, provider di rete, datore di lavoro e osservatore fisico vedono fatti diversi.

Le procedure seguenti riguardano fondi leciti, account veritieri e procurement autorizzato. Le tecniche il cui scopo nei casi citati era il riciclaggio, l'elusione delle sanzioni o la frode d'identità vengono spiegate e rilevate, ma la loro procedura è un esercizio forense sintetico, non una guida per commettere il reato.

## Matrice di copertura

| Famiglia | Principale proprietà di privacy | Principale osservatore/trust | Trattamento |
|---|---|---|---|
| Contante ed equivalenti | nessun record remoto della rete di pagamento | destinatario e ambiente fisico | workflow lecito |
| Valore prepaid/gift/voucher | separa il riscatto dalla carta primaria | seller, issuer e servizio di riscatto | workflow lecito, varia per giurisdizione |
| Carta virtuale/tokenizzata | nasconde il PAN riutilizzabile o separa i merchant | issuer/network/wallet identificano comunque il pagatore | workflow lecito |
| App/intermediario di pagamento | il merchant può vedere un alias/intermediario | l'app raccoglie identità/device/transazione | baseline di confronto |
| Igiene Bitcoin/Silent Payments | pseudonimi e non collegabilità del destinatario | grafo pubblico e confine wallet/rete | utilizzabile |
| PayJoin/CoinJoin | indebolisce le euristiche di proprietà comune/linkage | partecipanti/coordinator/rete/grafo pubblico | utilizzabile dove supportato; revisione legale |
| Lightning/BOLT 12 | routing off-chain e riduzione del percorso del ricevente | endpoint, hop, servizi e grafo dei canali | utilizzabile dove supportato |
| Monero/Zcash/MWEB | riservatezza on-chain a livello di protocollo | acquisizione, endpoint, rete e confini restano visibili | utilizzabile dove lecito/supportato |
| Applicazione ZK Ethereum | nasconde uno specifico collegamento tra statement e azione | input pubblici, RPC, relayer e app | specifico dell'applicazione |
| Cashu/Fedimint/Taler | privacy del pagatore tramite blind signature | mint/federation/exchange, custodia e confini | emergente/specifico del deployment |
| Stablecoin | settlement digitale conveniente | chain trasparente più freeze/controllo dell'issuer | non è una baseline anonima |
| Swap/bridge/DEX | sposta valore tra asset/chain | entrambi i grafi, contract e provider | meccaniche forensi; solo swap leciti ordinari |
| Mixer/peel/structuring | aumenta ambiguità/lavoro sul grafo | grafo di ingresso/uscita e record del servizio | solo esercizio sintetico di rilevamento |
| Nominee/mule/OTC/front | inserisce intermediari umani/commerciali | facilitatori, banche, comunicazioni | solo analisi di abuso criminale |
| Indirizzi di pagamento riutilizzabili/stealth | nuovo indirizzo del destinatario per ogni pagamento | annuncio/notifica pubblica e confini wallet | utilizzabile dove supportato |
| Sidechain/state channel confidential | nasconde importo/asset o aggiornamenti intermedi | peer, bridge/federation e settlement finale | specifico del protocollo |
| Carrier/open banking/platform billing | nasconde la carta primaria al merchant | carrier, banca/PISP o platform identifica il cliente | pagamento ordinario identificato |
| Mutual credit/net settlement | meno record di settlement esterni | il gestore del ledger privato ha la mappatura completa | solo partecipanti identificati |

## Contante

**Meccaniche:** il valore fisico al portatore passa di mano senza autorizzazione online dell'issuer o ledger pubblico.

**Vantaggi:** il merchant non deve conoscere l'identità bancaria/della carta; nessun grafo remoto della transazione; ampiamente comprensibile e finale.

**Svantaggi:** solo di persona; furto/smarrimento; controlli su resto/ricevuta/seriale o segnalazioni; prelievo, telecamere, testimoni e luogo collegano comunque il pagatore.

**Procedura:** (1) verificare che il contante sia lecito/accettato e le eventuali regole su importi/segnalazioni; (2) prelevarlo o riceverlo lecitamente e mantenere registri contabili privati; (3) pagare un merchant ordinario senza identificativi loyalty/account non necessari; (4) richiedere solo la ricevuta obbligatoria; (5) evitare dati di spedizione/account se l'acquisto non li richiede; (6) registrare internamente il legittimo scopo commerciale.

**Rilevamento:** riconciliare cassa/ricevute/inventario, telecamere e log di accesso secondo le policy applicabili; esaminare rimborsi in contanti anomali o importi ripetuti appena inferiori alle soglie, senza considerare sospetto l'uso ordinario del contante.

## Vaglia, postal order, assegno circolare e pagamento alla consegna

**Meccaniche:** un issuer regolamentato converte contanti/fondi di account in uno strumento numerato pagabile a un destinatario nominato; il COD rinvia l'incasso alla consegna.

**Vantaggi:** il destinatario può non ricevere il numero della banca/carta primaria del pagatore; utilizzabile quando il contante non può essere trasferito a distanza; ricevuta chiara.

**Svantaggi:** issuer/retailer conservano i dati di acquisto/identità richiesti; tracciamento del seriale; indirizzo del destinatario/consegna; rischio di perdita/frode e restrizioni regionali; generalmente non anonimo.

**Procedura:** (1) controllare regole, limiti, identificazione e accettazione del destinatario; (2) acquistare con informazioni veritiere e fondi leciti; (3) completare immediatamente beneficiario/importo; (4) conservare seriale/ricevuta; (5) usare una consegna tracciata adeguata al valore; (6) riconciliare riscatto/rimborso.

**Rilevamento:** record di acquisto/riscatto dell'issuer, seriale, retailer/telecamera, spedizione e account del destinatario; segnalare alterazioni, seriali duplicati e riscatti rapidi incompatibili geograficamente.

## Carta prepaid open-loop

**Meccaniche:** una credenziale con marchio di rete autorizza transazioni contro un saldo prepaid anziché contro un account di credito primario.

**Vantaggi:** limita l'esposizione e la perdita del merchant; separa il merchant dal PAN principale; utilizzabile online dove accettata.

**Svantaggi:** record di acquisto/attivazione/reload e device; KYC e limiti variabili; errori sull'indirizzo di fatturazione; restrizioni su cash-out/rimborsi; “senza nome” non significa assenza di record dell'issuer.

**Procedura:** (1) verificare identità attuale dell'issuer, costi, KYC, area geografica e supporto online/ricorrente; (2) acquistare tramite seller autorizzato con fondi leciti; (3) registrare i dati veritieri richiesti; (4) usare la carta per un singolo contesto/scopo; (5) non strutturare i load né falsificare la residenza; (6) conservare prove di acquisto/spesa e chiudere/smaltire secondo i termini dell'issuer.

**Rilevamento:** correlare seller/attivazione, funding, device/IP, autorizzazioni merchant, controlli saldo e riscatti/rimborsi. Conta il pattern, non l'etichetta prepaid.

## Gift card closed-loop, voucher e credito di servizio trasferibile

**Meccaniche:** il valore numerato è riscattabile solo presso un merchant/servizio o ecosistema. Crediti airtime/game/store sono varianti.

**Vantaggi:** il merchant destinatario può vedere solo codice/saldo; impatto limitato; facile da regalare e separare per budget.

**Svantaggi:** seller e servizio registrano acquisto/attivazione/riscatto; account/device/consegna collegano comunque l'attività; truffe, sconti di rivendita e limiti di scadenza/area; deboli diritti di rimborso.

**Procedura:** (1) acquistare solo da canali autorizzati; (2) registrare il valore del codice senza esporre il segreto; (3) evitare di associarlo a un account loyalty identificativo se non necessario; (4) riscattarlo tramite un account/context merchant separato e legittimo; (5) conservare la ricevuta fino all'accettazione; (6) non acquistare mai codici in risposta a richieste non sollecitate di “tasse/supporto/riscatto”.

**Rilevamento:** orario di emissione/riscatto, convergenza device/account, acquisti in massa o a soglia, un device che controlla molti saldi e riscatti rapidi a distanza.

## Broker di carte o codici regalo finanziato con cryptocurrency

**Meccaniche:** un intermediario accetta cryptocurrency ed emette una carta, un voucher o un codice merchant. È una conversione cross-rail: il merchant vede un normale valore card/gift, mentre il broker collega il deposito on-chain all'emissione e alla consegna.

**Vantaggi:** il merchant non riceve il wallet di funding; utile per merchant leciti che non accettano crypto; valore custodito limitato.

**Svantaggi:** non anonimo rispetto a broker/issuer; regole KYC, sanzioni, exchange e card program; grafo pubblico del deposito; account/device/email e riscatto del codice ricolelgano i due lati; rischio di truffa/insolvenza.

**Procedura:** (1) verificare entità legale, issuer della carta, giurisdizione supportata, KYC, costi e policy di rimborso; (2) usare solo fondi leciti documentati; (3) provare la denominazione minima; (4) verificare restrizioni di rete/merchant prima dell'acquisto; (5) conservare transazione blockchain e ricevuta del broker per la contabilità; (6) non usare broker che promettono frode d'identità, elusione di sanzioni o cash-out “non tracciabile”.

**Rilevamento:** correlare gli indirizzi di deposito del broker, importo/orario univoci, account/device e autorizzazione della carta o riscatto del codice; i record di issuer e broker collegano la chain pubblica al merchant.

## Carta virtuale o bloccata sul merchant

**Meccaniche:** l'issuer associa un PAN/token generato all'account reale, spesso limitandolo per merchant, importo o scadenza.

**Vantaggi:** impedisce di divulgare il PAN riutilizzabile; compartimentazione per merchant; limiti di spesa e revoca semplice; controllo antifrode maturo.

**Svantaggi:** l'issuer conosce comunque pagatore, funding, merchant, device/IP e orario; il merchant vede account/consegna; alcuni rimborsi/addebiti ricorrenti falliscono; non anonima.

**Procedura:** (1) usare la funzione ufficiale dell'issuer regolamentato; (2) creare una carta per un solo merchant/incarico; (3) impostare il limite minimo utile e la scadenza; (4) usare dati di billing accurati quando richiesto; (5) verificare descriptor e comportamento dei rimborsi; (6) bloccare/eliminare dopo il settlement finale conservando le prove di audit.

**Rilevamento:** mappatura token-account dell'issuer, autorizzazione merchant, device e consegna. I difensori usano riutilizzo specifico del merchant, velocity e segnali di account takeover.

## Network token del mobile wallet

**Meccaniche:** la tokenizzazione dei pagamenti EMV sostituisce il PAN con una credenziale vincolata, spesso associata a device, merchant o scenario di pagamento.<sup>[[1]](#references)</sup>

**Vantaggi:** il merchant non riceve il PAN riutilizzabile; crittografia del device e dati dinamici riducono la clonazione; revocabile senza sostituire la carta.

**Svantaggi:** issuer, token service, wallet platform e network conservano mappature/transazioni; account platform, device e posizione possono identificare il pagatore.

**Procedura:** (1) registrare una carta legittima nel wallet ufficiale; (2) proteggere account platform/device con autenticazione forte; (3) verificare token device/ultime cifre al momento dell'acquisto; (4) disabilitare, dove possibile, posizione/analytics non necessari; (5) rimuovere immediatamente token/device smarriti; (6) controllare i record issuer e wallet.

**Rilevamento:** requestor del token, cryptogram del device e mapping dell'issuer, telemetria wallet/account, terminale merchant e prove fisiche.

## App di pagamento, wallet marketplace e intermediario centralizzato

**Meccaniche:** il servizio mantiene account e trasferisce valore internamente o tramite rail bancari/card; il merchant può vedere un alias mentre il servizio vede entrambe le parti.

**Vantaggi:** comodità, contestazioni/rimborsi, il destinatario non vede necessariamente i dati bancari/della carta.

**Svantaggi:** grafo centralizzato di identità/social/transactions/device; blocchi e procedimenti legali; le controparti possono esporre il profilo; l'uso dei dati può eccedere la necessità del pagamento.<sup>[[2]](#references)</sup>

**Procedura:** (1) leggere termini su identità, privacy, conservazione e protezione acquirente; (2) ridurre la sincronizzazione opzionale di profili/contatti; (3) usare un account separato e veritiero solo quando consentito; (4) attivare MFA/alert; (5) verificare destinatario e privacy di memo/profilo; (6) esportare i record e chiudere i collegamenti inutilizzati.

**Rilevamento:** account del provider, device/IP, grafo contatti, funding/prelievo, memo e record merchant. Un alias è pseudonimia rispetto alla controparte, non anonimato rispetto alla platform.

## Bonifico bancario, ACH, wire e pagamento istantaneo da account

**Meccaniche:** istituzioni regolamentate spostano valore tra account identificati e scambiano i dati richiesti.

**Vantaggi:** rapido, tracciabile, limitatamente reversibile, con record solidi; i virtual account number possono ridurre i dati esposti al merchant.

**Svantaggi:** banche/processori conoscono entrambe le parti; estratti e riferimenti; non anonimo; dati AML/Travel Rule transfrontalieri.

**Procedura:** usarlo solo quando l'accountability è accettabile: verificare indipendentemente il beneficiario, minimizzare i dati opzionali del memo, usare un virtual account/riferimento fornito dalla banca se disponibile, attivare alert, conservare fattura e riconciliare.

**Rilevamento:** record bancari/payment deterministici, titolarità del beneficiario/account, device/sessione e controlli antifrode. È una baseline, non una tecnica di anonimato.

## Compartimentazione di account e merchant

**Meccaniche:** identità, account, alias email, carte e contesti di consegna separati impediscono ai merchant non collegati di unire facilmente l'attività, mentre issuer/controller conservano la mappatura.

**Vantaggi:** riduce leak e collegamenti tra merchant; facile da verificare; compatibile con pagamenti regolamentati.

**Svantaggi:** il provider collega comunque i compartimenti; telefono di recovery/device/IP e spedizione possono ricongiungerli; le policy possono vietare account multipli.

**Procedura:** (1) definire uno scopo; (2) creare solo alias/subaccount conformi ai termini; (3) usare token/carta specifici del merchant; (4) disabilitare contatti e personalizzazione pubblicitaria tra account; (5) conservare un ledger controller cifrato; (6) dismettere gli identificativi dopo la fine delle esigenze di rimborso/conservazione.

**Rilevamento:** i provider uniscono recovery, device, funding e IP; i merchant uniscono consegna, browser e comportamento dell'account. Distinguere la compartimentazione lecita dalla frode d'identità sintetica.

## Procurement controllato di red team

**Meccaniche:** il SOC non conosce un acquisto, mentre un controller dell'esercizio conserva la mappatura tra entità legale, operatore e infrastruttura.

**Vantaggi:** esercizio realistico di rilevamento; nessuna esposizione personale; deconfliction e audit immediati.

**Svantaggi:** non anonimo rispetto a organizzazione/provider; overhead di governance; leak se il ledger del controller è gestito male.

**Procedura:** (1) assegnare carta/wallet/budget dell'organizzazione specifico per l'engagement; (2) separare i ruoli purchaser/operator; (3) registrare asset, importo, servizio, scopo e kill date; (4) conservare la mappatura con accesso limitato al controller; (5) non usare identità false, mule o fondi rubati; (6) rivelare e riconciliare indicatori e rimborsi alla chiusura.

**Rilevamento:** il controller collega fattura del provider e asset; il SOC prova la discovery indipendente tramite dominio, certificato, hosting e traffico, non tramite i dati del titolare della carta.

## Igiene degli indirizzi Bitcoin e coin control

**Meccaniche:** indirizzi di ricezione nuovi, etichette locali e spesa selettiva degli UTXO riducono il riutilizzo e l'unione accidentale dei contesti su un ledger pubblico.

**Vantaggi:** ampiamente supportata; self-custodial; evita il collegamento pubblico più semplice.

**Svantaggi:** tutte le transazioni/importi restano pubblici; euristiche common-input/change, timing e consolidamenti collegano l'attività; restano record di acquisizione/RPC/rete.

**Procedura:** (1) installare/verificare un wallet mantenuto; (2) fare backup e testare il seed recovery; (3) usare un nuovo indirizzo per invoice; (4) etichettare localmente origine/scopo; (5) usare coin control per evitare di unire contesti; (6) preferire un nodo locale o una connessione attenta alla privacy; (7) controllare change/fee e conservare la contabilità lecita.<sup>[[3]](#references)</sup>

**Rilevamento:** address graph, euristiche common-input/change con incertezza, importo/orario esatti, consolidamento, depositi presso servizi, timing di broadcast node/RPC e record off-chain.

## Bitcoin Silent Payments

**Meccaniche:** BIP 352 consente al ricevente di pubblicare un codice statico mentre i sender derivano output Taproot univoci via ECDH; gli osservatori esterni non possono collegare direttamente gli output al codice.<sup>[[4]](#references)</sup>

**Vantaggi:** identificativo pubblico riutilizzabile senza riutilizzare indirizzi; nessuna richiesta interattiva o output di notifica; si confonde con gli output Taproot.

**Svantaggi:** costo di scanning del ricevente; supporto wallet variabile; grafo di importo/sender e spesa restano pubblici; l'index server può osservare le scansioni.

**Procedura:** (1) scegliere un wallet BIP 352 aggiornato; (2) fare backup/testare descriptor e recupero dello scanning; (3) generare il codice etichettato dove supportato; (4) autenticare il codice pubblicato; (5) il sender verifica gli input e invia un piccolo test; (6) il ricevente scansiona preferibilmente tramite il proprio nodo; (7) mantenere separati gli UTXO ricevuti.

**Rilevamento:** per design non è identificabile in modo affidabile dal solo output; gli analisti usano input del sender, importo/orario, spesa successiva, wallet/rete/index e record delle controparti.

## PayJoin

**Meccaniche:** payer e payee contribuiscono input a una transazione, rompendo l'assunzione che tutti gli input abbiano lo stesso proprietario.<sup>[[5]](#references)</sup>

**Vantaggi:** pagamento ordinario con maggiore privacy; indebolisce un'euristica comune dell'intero grafo; non richiede molti output uguali.

**Svantaggi:** requisito interattivo/supporto; disponibilità dell'endpoint del ricevente; importo e transazione finale pubblici; metadata di implementazione e fallback.

**Procedura:** (1) confermare che entrambi i wallet mantenuti supportino la stessa versione PayJoin; (2) autenticare invoice/endpoint; (3) partire dall'URI di pagamento PayJoin del wallet; (4) controllare importo/fee finali e firmare solo gli input attesi; (5) evitare modifiche manuali della transazione; (6) verificare broadcast e ricezione; (7) registrare il fallback se la negoziazione fallisce.

**Rilevamento:** gli analisti blockchain non devono applicare automaticamente il clustering common-input; endpoint/provider possono registrare la negoziazione; usare prove wallet/rete e spese successive, non solo la forma della transazione.

## CoinJoin

**Meccaniche:** più partecipanti creano collaborativamente una transazione con molti input/output, spesso di denominazione uguale, aumentando l'ambiguità della corrispondenza input-output.

**Vantaggi:** maggiore insieme di ambiguità on-chain; esistono design self-custodial; struttura dei round misurabile.

**Svantaggi:** metadata di coordinator/peer/rete; costi/liquidità; forma identificabile; change tossico e consolidamenti successivi annullano i vantaggi; disponibilità legale/provider variabile.

**Procedura:** (1) verificare disponibilità attuale di wallet/coordinator e liceità; (2) installare il wallet ufficiale e fare backup; (3) usare solo UTXO leciti; (4) comprendere denominazioni, fee e modello del coordinator; (5) etichettare/separare change e output mixed; (6) non consolidarli mai insieme; (7) instradare il traffico secondo il supporto ufficiale e conservare la contabilità.

**Rilevamento:** identificare la struttura collaborativa senza presumere un reato; calcolare possibili mappature/insieme di anonimato e osservare poi change/consolidamento, confini dei servizi e record di rete/coordinator.

## Lightning Network

**Meccaniche:** i pagamenti HTLC attraversano canali con onion routing; la maggior parte dei dettagli non viene pubblicata on-chain, mentre funding/closing e informazioni pubbliche sui canali restano visibili.

**Vantaggi:** rapido e poco costoso; gli intermediari vedono normalmente solo gli hop adiacenti; i dettagli ordinari restano off-chain.

**Svantaggi:** sender/receiver e primo/ultimo hop sanno di più; probing, timing, grafo dei canali, liquidità e record wallet/LSP; i wallet custodial identificano gli utenti.

**Procedura:** (1) scegliere consapevolmente self-custodial o custodial; (2) verificare wallet/seed/channel recovery; (3) usare invoice per l'importo esatto; (4) preferire canali privati/funzioni LSP solo dopo averne letto i trade-off; (5) proteggere l'IP del nodo con Tor supportato quando necessario; (6) evitare invoice identificative riutilizzate; (7) mantenere la contabilità di canali e pagamenti.<sup>[[6]](#references)</sup>

**Rilevamento:** log di node/LSP/custodian, grafo e probing dei canali, fallimenti/timing dei pagamenti e funding/closure on-chain; l'assenza di una transazione pubblica non implica assenza di record.

## BOLT 12 offers e route blinding

**Meccaniche:** un offer riutilizzabile produce invoice nuove e può pubblicizzare percorsi blinded, così il payer non deve conoscere nodo/percorso chiari del ricevente.

**Vantaggi:** privacy del ricevente; endpoint riutilizzabile per donazioni/pagamenti senza invoice statica; integrazione con onion routing Lightning.

**Svantaggi:** supporto wallet variabile; endpoint, hop selezionati e funding restano; contatto pubblico o endpoint di rete può reidentificare il ricevente.

**Procedura:** (1) confermare supporto BOLT 12 compatibile; (2) autenticare l'offer; (3) richiedere un'invoice nuova; (4) controllare importo/issuer/ricorrenza; (5) pagare tramite il wallet; (6) verificare ricezione/rimborso; (7) minimizzare alias/contatto del nodo e conservare la contabilità.<sup>[[7]](#references)</sup>

**Rilevamento:** telemetria wallet/LSP e primo/ultimo hop, account di distribuzione dell'offer, timing/valore e grafo del funding; il route blinding limita intenzionalmente la visibilità del payer.

## Monero

**Meccaniche:** gli stealth address one-time nascondono il collegamento al destinatario, RingCT nasconde gli importi e le ring signature forniscono ambiguità sul sender.

**Vantaggi:** privacy predefinita on-chain; riservatezza di sender/receiver/importo; ecosistema maturo di wallet/node dedicati.

**Svantaggi:** record di acquisition/off-ramp, endpoint/rete/controparte; il remote node vede query/IP; supporto degli exchange e trattamento legale variabili; piccoli errori operativi collegano comunque i contesti.

**Procedura:** (1) acquistare lecitamente e conservarne base/origine; (2) installare/verificare il wallet ufficiale mantenuto; (3) fare backup/testare il seed; (4) usare un nodo locale o un percorso documented Tor/I2P verso un remote node; (5) usare una nuova subaddress per payer/invoice; (6) etichettare localmente i contesti; (7) divulgare prova della transazione/accesso view solo deliberatamente.<sup>[[8]](#references)</sup>

**Rilevamento:** concentrarsi su exchange/merchant/device/rete e prove del wallet sequestrato; l'uso del protocollo da solo non è sospetto e la chain pubblica espone deliberatamente meno informazioni.

## Zcash fully shielded Orchard

**Meccaniche:** le zero-knowledge proof validano trasferimenti shielded mentre sender, receiver e importo sono cifrati; pool transparent e transizioni tra pool restano pubblici.

**Vantaggi:** forte riservatezza on-chain shielded; viewing key per audit circoscritti; validità imposta dal protocollo.

**Svantaggi:** supporto effettivo di wallet/exchange e scelta del pool variabili; correlazione di timing/valore ai confini transparent; network/RPC ed endpoint restano.

**Procedura:** (1) scegliere un wallet Orchard mantenuto e shielded-by-default; (2) verificare/fare backup; (3) ottenere ZEC lecitamente; (4) ricevere su Unified Address supportato e confermare il pool; (5) preferire shielded-to-shielded; (6) usare la privacy di rete supportata; (7) testare la divulgazione della viewing key con un piccolo wallet prima dell'audit.<sup>[[9]](#references)</sup>

**Rilevamento:** confini transparent e record dei servizi, metadata wallet/rete e viewing key quando fornite lecitamente; non presumere che tutti i pagamenti Unified Address siano shielded.

## Mimblewimble e Litecoin MWEB

**Meccaniche:** le confidential transaction nascondono gli importi e l'aggregazione in stile Mimblewimble elimina la cronologia convenzionale ricca di indirizzi; Litecoin implementa un extension block opzionale accanto alla chain transparent.

**Vantaggi:** importi riservati e fungibilità migliorata nel dominio privato; pruning/aggregazione efficienti.

**Svantaggi:** il confine opt-in peg-in/out è pubblico e correlabile; supporto wallet/exchange; differenze interattive e nel modello degli indirizzi; record di rete e acquisizione.

**Procedura:** (1) scegliere wallet mantenuto con supporto MWEB esplicito; (2) verificare/fare backup e testare un piccolo importo; (3) acquisire lecitamente; (4) fare peg in MWEB e verificare il dominio del saldo; (5) transare solo con riceventi compatibili; (6) evitare peg-out immediati e distintivi; (7) conservare record di audit privati.<sup>[[10]](#references)</sup>

**Rilevamento:** timing/valore di peg-in/out pubblici, dati exchange/wallet/node e spese transparent successive; i dettagli dei trasferimenti confidential interni sono intenzionalmente ridotti.

## Applicazioni Ethereum privacy con zero-knowledge

**Meccaniche:** un circuit prova uno statement — membership, proprietà di una note o autorizzazione valida — senza rivelare il segreto; un verifier contract controlla la prova. Depositi, prelievi, input pubblici, eventi e gas possono comunque esporre collegamenti.

**Vantaggi:** selective disclosure programmabile; applicazioni con anonymous set; regole verificabili senza rivelare tutti i dati.

**Svantaggi:** bug di contract/circuit; anonymous set ridotto; confini pubblici; RPC/IP/sessione/analytics/gas funding; rischi applicativi, sanzionatori e legali.

**Procedura:** (1) definire esattamente cosa nasconde la prova; (2) usare un'applicazione mantenuta e verificata dove lecita; (3) esaminare input/eventi pubblici e regole di deposito/prelievo; (4) separare action wallet e gas sponsorship come previsto dal protocollo; (5) usare un percorso RPC/rete attento alla privacy; (6) testare con valore ridotto; (7) conservare i record di compliance.<sup>[[11]](#references)</sup>

**Rilevamento:** eventi dei contract, timing/valore deposit/withdraw, relayer/paymaster, RPC/sessione, storage/analytics del frontend e successivo confine exchange/merchant. Non affermare che la prova ZK nasconda campi dichiarati pubblici.

## Stablecoin

**Meccaniche:** i token vengono trasferiti su una chain pubblica; issuer centralizzati possono congelare/inserire in blacklist o riscattare verso account identificati.

**Vantaggi:** stabilità del prezzo, liquidità e supporto merchant; settlement rapido; contabilità semplice.

**Svantaggi:** grafo trasparente di indirizzi/importi/contract; gas funding; identità/controllo di issuer ed exchange; screening sanzionatorio; generalmente scarsa anonimato.

**Procedura:** trattarle come pagamenti identificati: usare un nuovo indirizzo business solo per compartimentazione, verificare contract/network del token, provare un piccolo importo, proteggere il wallet, usare RPC trusted/nodo locale, conservare base/origine e sottoporre le parti richieste a screening.

**Rilevamento:** grafo completo degli eventi token, liste/azioni di freeze dell'issuer, exchange/RPC/device e rapporti di gas funding.

## Cashu Chaumian e-cash

**Meccaniche:** un mint firma ciecamente segreti bearer generati dal client, garantiti dalle riserve Bitcoin/Lightning del mint; può impedire il double-spend senza collegare direttamente emissione e successivo riscatto.

**Vantaggi:** bearer token senza account; trasferimento peer istantaneo; il mint non collega direttamente withdrawal blinded e spesa; i token possono viaggiare come dati/QR.

**Svantaggi:** custodia/solvibilità/censura del mint; perdita/furto dei bearer data; denominazione/timing e confini Lightning; metadata di rete; ecosistema software iniziale.<sup>[[12]](#references)</sup>

**Procedura:** (1) usare prima un test mint ufficiale o un valore minimo disposable; (2) installare un wallet mantenuto e testare limiti di backup/restore; (3) autenticare il mint e verificarne custodia/costi; (4) coniare un piccolo importo; (5) inviare il token su canale/QR privato autenticato; (6) il ricevente scambia il token prima di considerarlo finale; (7) riscattare e riconciliare. Non conservare valore significativo in un mint non trusted.

**Rilevamento:** il mint vede rete, confini issue/redeem/Lightning e insieme dei token spesi, ma il blinding rimuove il collegamento diretto del token; endpoint/messaggi e importi/timing distintivi possono ripristinare i collegamenti.

## Fedimint federated e-cash

**Meccaniche:** una soglia di guardians detiene le riserve e firma ciecamente e-cash; i trasferimenti bearer interni sono privati rispetto ai guardians, mentre i gateway Lightning collegano i pagamenti esterni.

**Vantaggi:** custodia distribuita; trasferimenti interni privati; governance comunitaria; nessun guardian controlla la riserva sotto la soglia.

**Svantaggi:** rischio di quorum/custodia/software; il gateway osserva invoice/timing; confini deposito/prelievo; complessità del recupero dello stato client.

**Procedura:** (1) verificare invite della federation, guardians, quorum e giurisdizione; (2) installare client mantenuto e testare il recovery; (3) depositare un piccolo importo lecito; (4) usare richieste di pagamento interne nuove; (5) considerare il gateway osservatore dei pagamenti Lightning; (6) testare il riscatto; (7) conservare source/tax record fuori dai dati pubblici di pagamento.<sup>[[13]](#references)</sup>

**Rilevamento:** la federation vede emissione/riscatto aggregati, i gateway vedono invoice esterne, Bitcoin/Lightning mostrano i confini e prove di endpoint/comunicazione possono collegare i trasferimenti interni.

## GNU Taler

**Meccaniche:** l'e-cash con blind signature integrato con la banca mira a mantenere anonimo il pagatore rispetto ai merchant, mentre merchant e reddito restano accountable.

**Vantaggi:** privacy del pagatore by design; valuta ordinaria; accountability/rimborsi del merchant; nessun token speculativo necessario.

**Svantaggi:** deployment limitati; exchange/banca vede il funding; merchant vede ordine/consegna; rischio bearer/recovery del wallet; operatori regolamentati.

**Procedura:** (1) trovare exchange/merchant attuale per giurisdizione e valuta; (2) leggere KYC/costi/privacy; (3) installare wallet ufficiale; (4) prelevare legalmente da banca/exchange supportati; (5) controllare il contratto del merchant; (6) pagare e conservare dati di ricevuta/rimborso; (7) evitare identificativi di sessione merchant non necessari.<sup>[[14]](#references)</sup>

**Rilevamento:** withdrawal di banca/exchange e deposito merchant sono confini accountable; ordine/device/consegna e timing del merchant possono correlare anche con coin blinded.

## Bridge cross-chain, atomic swap e decentralized exchange

**Meccaniche:** un contract/servizio blocca/brucia un asset e ne rilascia/crea un altro, oppure le controparti scambiano atomicamente. Interrompe la visione di un singolo ledger, non la continuità economica.

**Vantaggi:** interoperabilità asset/network; possibilità di evitare un custodian centralizzato; uso ordinario di portafoglio/liquidità.

**Svantaggi:** entrambe le chain sono pubbliche; tempo/valore/fee/liquidità e contract correlano; record bridge/relayer/frontend/RPC; rischi di smart contract, controparte e regolamentazione.

**Procedura per swap leciti:** (1) verificare contract/servizio ufficiale e disponibilità legale; (2) esaminare custodia/audit/costi/slippage; (3) eseguire un piccolo test; (4) registrare entrambi gli ID di transazione e il tasso; (5) proteggere le approval; (6) riconciliare l'asset di destinazione e revocare approval non necessarie. Non usare swap per mascherare l'origine dei fondi.

**Rilevamento:** eventi deposit/withdraw del bridge, importo univoco meno fee, ordine temporale, liquidità, record relayer/RPC/frontend e successivi depositi presso servizi.

## Mixer o tumbler centralizzato

**Meccaniche:** un servizio riceve depositi in un pool e restituisce successivamente unità diverse, tentando di oscurare la mappatura diretta input-output.

**Vantaggi:** in teoria può ampliare l'ambiguità delle transazioni.

**Svantaggi:** l'operatore può rubare/registrare; analisi di timing/valore ingresso-uscita; esposizione a sanzioni, money transmission e reati; sequestri che rivelano le mappature; rischio di taint/rifiuto.

**Procedura:** non viene fornita una guida operativa al mixing. Riprodurre il grafo in sicurezza estendendo [Lab 6](authorized-adversary-emulation-labs.md#lab-6-synthetic-peel-chain-and-bridge-graph): creare depositi sintetici, output pooled, fee e ritardi; fornire agli analisti mappature incomplete; misurare quali euristiche funzionano; quindi rivelare la ground truth.

**Rilevamento:** identificazione di wallet/contract del servizio, insiemi candidati ingresso/uscita, importo/fee/timing, riutilizzo dell'indirizzo di deposito, log sequestrati/provider e consolidamento downstream. Etichettare l'attribuzione probabilistica.

## Peel chain, fan-out/fan-in e structuring

**Meccaniche:** transazioni ripetute sottraggono piccoli pagamenti dal change, dividono il valore tra molti indirizzi, ricongiungono collector oppure suddividono importi per evitare controlli.

**Vantaggi:** aumenta il carico dell'analista ingenuo e il numero di indirizzi.

**Svantaggi:** continuità riconoscibile di valore/cadenza/transazioni; consolidamento ed endpoint di servizio; lo structuring può essere illecito; costi ed errori operativi.

**Procedura:** usare solo dati CSV sintetici/testnet: generare una sorgente grande, edge ripetuti di pagamento/change, rami paralleli e un collector; aggiungere esempi benigni simili a exchange; tarare il rilevamento e documentare i falsi positivi.

**Rilevamento:** continuità del grafo, pattern di change ripetuti, cadenza, importi appena inferiori ai controlli, endpoint di servizio comune e record off-chain. Gli hot wallet degli exchange possono assomigliare a questi pattern: il contesto è obbligatorio.<sup>[[15]](#references)</sup>

## Nominee, money mule, broker OTC e front company

**Meccaniche:** un'altra persona/account/company riceve, converte o spende fondi, inserendo strati legali e operativi tra controller e transazione.

**Vantaggi per un adversary:** l'account nominativo non identifica subito il controller; può collegare contante, crypto, beni e giurisdizioni.

**Svantaggi:** esposizione a frode d'identità e riciclaggio; ogni partecipante aggiunge record di comunicazioni, banca/company/tasse/spedizioni, costi, incoerenze e testimoni; il riutilizzo dei facilitatori crea hub.

**Procedura:** non emulare con persone/account reali. Costruire un grafo sintetico con controller, recruiter, mule, OTC, shell merchant e beneficiario; inserire edge device/IP/messaggi/banca; chiedere agli investigatori di distinguere titolare dell'account e controller e registrare la confidenza delle prove.

**Rilevamento:** device/IP/recovery condivisi, beneficiario/velocity anomali, molti sender non correlati, movimento immediato onward, incoerenze di company/director/invoice, comunicazioni e consegna di contante/commodity.

## NFT, gambling, beni merchant e loop di rimborso

**Meccaniche:** il valore viene convertito in asset autovalutati, saldo di scommessa, beni rivendibili o rimborsi per creare una narrazione transazionale diversa.

**Vantaggi per un adversary:** cambia la forma dell'asset e introduce intermediari marketplace/merchant.

**Svantaggi:** grafo marketplace/account/device e wash trade; record di gioco e rimborso; prove di consegna/rivendita; costi/perdite; responsabilità per frode/riciclaggio.

**Procedura:** nessun workflow di occultamento. Usare dati marketplace sintetici con self-trade tra wallet collegati, prezzi implausibili, gioco minimo, strumento di rimborso non corrispondente e spedizione comune; validare il rilevamento contro collezionisti/clienti legittimi.

**Rilevamento:** trade circolari/autofinanziati, proprietà/funding comuni, outlier di prezzo, rivendita/rimborso immediati, attività economica minima, device/consegna condivisi e riconvergenza dei proventi.

## Wallet fisico bearer o trasferimento di token offline

**Meccaniche:** device, carta/QR, hardware bearer instrument o e-cash token trasferisce il controllo di un segreto invece di trasmettere un pagamento durante la consegna.

**Vantaggi:** nessun evento di rete live durante lo scambio; utile offline; custodia fisica simile al contante.

**Svantaggi:** copia/furto/perdita e unicità incerta; il riscatto/broadcast successivo collega l'attività; incontro/spedizione fisici; contraffazione/manomissione.

**Procedura:** (1) usare solo uno strumento/protocollo verificato; (2) inizializzare/verificare privatamente l'autenticità; (3) caricare solo un piccolo valore lecito; (4) trasferire in un contesto autorizzato documentato; (5) il ricevente verifica o fa sweep tempestivo secondo il protocollo; (6) non presumere che il sender non abbia conservato una copia; (7) registrare privatamente prove di proprietà/tasse.

**Rilevamento:** funding/acquisto e sweep/riscatto finale, seriale del device/prove di manomissione, consegna/incontro e record degli endpoint.

## Invoice con scope merchant o richiesta di pagamento one-time

**Meccaniche:** il merchant crea una richiesta monouso con importo, scadenza e riferimento ordine. Il payer la salda tramite un rail supportato senza esporre direttamente al merchant una credenziale riutilizzabile; issuer o payment processor possono comunque identificare entrambe le parti.

**Vantaggi:** limita riutilizzo delle credenziali e identificativi cross-merchant accidentali; importo/scadenza esatti riducono errori; compatibile con contabilità e rimborsi ordinari.

**Svantaggi:** invoice, consegna, browser, processor e issuer collegano ancora l'ordine; importo/orario unici possono rafforzare la correlazione; i payment link malevoli sono comuni.

**Procedura:** (1) autenticare indipendentemente il merchant; (2) richiedere invoice nuova con importo, asset/network e scadenza esatti; (3) controllare destinazione e regole di rimborso; (4) pagare dal compartimento dell'engagement approvato; (5) verificare che il merchant riconosca la stessa invoice; (6) conservare ricevuta e riferimento della transazione; (7) far scadere la richiesta anziché riutilizzarla.

**Rilevamento:** merchant e processor uniscono invoice, sessione e settlement; importi/orari univoci e consegna identificano il payer. **Captured wallet/device:** la cronologia invoice espone controparti e scopi; minimizzare memo non necessari, cifrare il device e conservare la contabilità autorevole nel sistema finance controllato.

## Credito di servizio prepaid e capability token

**Meccaniche:** un servizio converte un pagamento convenzionale in crediti interni limitati o in una capability bearer. L'uso successivo di API/risorse può evitare di presentare la carta originale a ogni richiesta, ma il servizio spesso collega emissione e riscatto.

**Vantaggi:** limita spesa e perdita da compromissione; separa i worker quotidiani dalla credenziale di funding; supporta budget per progetto e revoca.

**Svantaggi:** di solito pseudonimo, non anonimo; database del servizio, IP di riscatto e pattern d'uso univoci collegano l'attività; i bearer token possono essere rubati; i rimborsi possono richiedere il payer originale.

**Procedura:** (1) acquistare crediti tramite account dell'organizzazione; (2) creare un progetto e budget; (3) emettere un token ristretto con vincoli su servizio, importo e scadenza; (4) conservarlo solo nel secret manager approvato o nel percorso workload identity; (5) testare il rifiuto fuori scope e dopo la scadenza; (6) monitorare il consumo; (7) revocare e riconciliare il valore inutilizzato.

**Rilevamento:** il provider collega account di funding, progetto, emissione e uso del token; alert su variazioni geografiche/processo e consumo anomalo. **Captured node:** presumere che la capability restante possa essere spesa; usare scadenza breve, saldo basso, audience binding e revoca server-side immediata.

## Privacy Pass o token di autorizzazione blinded

**Meccaniche:** un issuer produce un token di autorizzazione privacy-preserving che un origin può validare senza collegare il riscatto all'emissione. Può rappresentare entitlement pagato o accesso rate-limited, ma non è valuta generale. L'architettura separa ruoli client, attester, issuer e origin e avverte che IP/timing o collusione possono annullare la non collegabilità.<sup>[[18]](#references)</sup>

**Vantaggi:** riscatto non collegabile per servizi supportati; nessun cookie account riutilizzabile presso l'origin; token cache separano emissione e uso nel tempo.

**Svantaggi:** specifico dell'applicazione; trust issuer/attester e partizionamento dell'anonymity set; metadata IP/browser restano; furto del token o timing distintivo dell'emissione può correlare l'uso.

**Procedura:** (1) usare un'implementazione conforme al tipo di token Privacy Pass pertinente; (2) definire esattamente quale entitlement prova il token; (3) separare amministrazione issuer e origin quando richiesto dal threat model; (4) minimizzare metadata della challenge; (5) emettere token di test e riscattare ciascuno una volta presso origin controllati; (6) confrontare i log cercando identificativi stabili vietati; (7) testare replay, scadenza e controlli di revoca/abuso.

**Rilevamento:** gli origin vedono IP/orario del riscatto e validità del token; issuer/attester vedono il contesto di emissione; gli analisti testano timing e partizioni dei metadata senza presumere una rottura crittografica. **Captured client:** token bearer non spesi possono essere utilizzabili; limitarne valore, durata e audience e non memorizzare la credenziale di funding insieme a essi.

## Procurement organizzativo delegato o fiscal sponsor

**Meccaniche:** un procurement team, reseller o fiscal sponsor autorizzato stipula il contratto e paga mentre il team operativo riceve un servizio limitato. È separazione dei ruoli con record veritieri, non un nominee o un'identità falsa.

**Vantaggi:** i vendor non devono ricevere identità o dati di pagamento personali di ogni operatore; compliance, tasse e rimborsi centralizzati; budget e offboarding chiari.

**Svantaggi:** lo sponsor conosce beneficiario e scopo; contratti, approvazioni, consegna e account restano; ritardi/costi aggiuntivi; separazione debole se la stessa persona amministra ogni livello.

**Procedura:** (1) documentare scopo commerciale, beneficiario e autorità approvante; (2) scegliere un intermediario approvato dall'organizzazione; (3) stipulare il contratto con dati veritieri; (4) fornire un subaccount limitato al progetto senza credenziale di billing personale; (5) separare amministratori finance e operatori; (6) riconciliare fatture e accessi; (7) terminare servizio e accesso delegato alla chiusura.

**Rilevamento:** record procurement, identity provider, vendor e consegna collegano la catena. **Captured operational device:** dovrebbe rivelare il progetto di servizio, non le credenziali finance; conservare invoice e identità del payer nel sistema finance, non sui field node.

## Escrow o settlement condizionale

**Meccaniche:** un escrow agent trusted o uno smart contract custodisce il valore fino al verificarsi di condizioni documentate. Può ridurre la divulgazione diretta tra payer e payee, mentre escrow e rail sottostanti conservano la relazione.

**Vantaggi:** protezione da contestazioni e mancata consegna; payer e merchant possono esporre meno credenziali riutilizzabili; condizioni di rilascio verificabili.

**Svantaggi:** rischio di custodia/contract, costi e obblighi identificativi; contract on-chain pubblici; restano dati su ordine, spedizione e contestazione; non anonimo rispetto all'intermediario.

**Procedura:** (1) verificare entità legale, custodia, costi, foro delle contestazioni e asset supportati; (2) creare milestone scritte esatte e percorso di rimborso; (3) finanziare da account organizzativo approvato; (4) verificare indipendentemente ricezione e autorizzazione al rilascio; (5) rilasciare solo dopo le prove; (6) conservare l'audit completo; (7) chiudere permessi o approval non usati.

**Rilevamento:** eventi dell'account/contract escrow, funding e release time, beneficiario e record delle contestazioni rivelano la transazione. **Captured device:** session token o contract approval possono consentire il rilascio; richiedere approver/MFA separati e revocare le sessioni attive in caso di perdita.

## Settlement organizzativo batch o pooled

**Meccaniche:** molti obblighi approvati vengono aggregati e regolati in meno transazioni bancarie o blockchain, con un ledger interno privato che assegna ciascuna quota. Il batching riduce i dettagli pubblici per acquisto, ma il coordinator mantiene l'attribuzione completa.

**Vantaggi:** fee inferiori; meno edge nel grafo pubblico; nasconde le singole voci a un osservatore pubblico quando gli importi sono aggregati; contabilità interna semplice.

**Svantaggi:** coordinator osservatore completo e target di alto valore; totali/timing distintivi correlabili; rischio di custodia/riconciliazione; può sembrare structuring se abusato.

**Procedura:** (1) definire partecipanti e obblighi leciti nel sistema contabile; (2) impostare una finestra batch regolare e motivata dall'attività, non soglie create per evitare controlli; (3) richiedere doppia approvazione dell'aggregato; (4) regolare verso destinatari autenticati; (5) riconciliare ogni voce interna al batch; (6) trattare i rimborsi come correzioni collegate; (7) proteggere accesso al ledger e conservarlo secondo policy.

**Rilevamento:** ledger, approvazioni e beneficiari del coordinator forniscono la ground truth; gli analisti pubblici usano con cautela clustering input/output/valore/orario. **Captured payer device:** dovrebbe contenere solo la requisition, non signing key del pool o ledger dei partecipanti.

## Account-abstraction paymaster o gas sponsorizzato

**Meccaniche:** un relayer/bundler invia una smart-account operation e un paymaster paga le fee, evitando un edge diretto di native-gas funding dal wallet dell'utente. Migliora una proprietà del grafo, ma operation, contract e telemetria del servizio restano pubblici o osservabili.<sup>[[19]](#references)</sup>

**Vantaggi:** rimuove un comune collegamento di gas funding; supporta sponsorship e rate limit limitati; onboarding migliore per applicazioni privacy lecite.

**Svantaggi:** paymaster/bundler/RPC/frontend possono correlare richieste; eventi contract e input pubblici restano; la policy di sponsorship identifica una coorte; contract o approval malevoli possono rubare asset.

**Procedura:** (1) usare smart account e paymaster mantenuti e verificati sulla rete corretta; (2) esaminare campi pubblici e log dello sponsor; (3) limitare sponsorship per contract, funzione, importo, nonce e scadenza; (4) provare con basso valore; (5) inviare tramite il percorso privacy-aware previsto dall'applicazione; (6) verificare on-chain operation e fee payer; (7) revocare allowance/session key e conservare record di compliance.

**Rilevamento:** correlare log UserOperation, EntryPoint, paymaster, bundler/RPC e applicazione; raggruppare con cautela policy di sponsorship identiche. **Captured wallet:** session key e approval pendenti possono essere utilizzabili anche senza gas; limitarli strettamente e revocarli tramite la policy di recovery dell'account.

## Autorizzazione di pagamento threshold o multisignature

**Meccaniche:** la spesa richiede una soglia di signer indipendenti. Non nasconde la transazione, ma separa l'autorità di pagamento da laptop, field node o singolo operatore compromesso.

**Vantaggi:** forte resistenza a compromissione e insider; approvazione accountable; nessun device operativo contiene l'autorità completa; recovery supportato.

**Svantaggi:** coordinamento/disponibilità; metadata di signer/device/account possono correlare i partecipanti; backup errato causa perdita; pattern multisig pubblici identificabili.

**Procedura:** (1) definire signer, threshold, limiti e recovery prima del funding; (2) inizializzare su hardware/account separati e supportati; (3) verificare indipendentemente indirizzi e backup; (4) assegnare ai workload sul campo solo capacità di requisition non firmata; (5) richiedere revisione out-of-band di destinatario, importo e scopo; (6) testare recovery e perdita di un signer con piccolo valore; (7) ruotare un signer dopo la compromissione.

**Rilevamento:** sistema di approvazione, device del signer e script/contract pubblico forniscono prove; alert su cambiamenti di policy o signer set. **Captured node:** dovrebbe esporre al massimo una session key a bassa autorità o una richiesta non firmata; non memorizzare mai insieme il materiale del quorum.

## Valuta closed-loop comunitaria o per eventi

**Meccaniche:** cooperativa, conferenza o ambiente di test privato emette crediti riscattabili solo tra partecipanti iscritti. Il trasferimento interno può esporre meno alle reti globali di pagamento, mentre l'operatore controlla emissione e riscatto.

**Vantaggi:** dominio economico limitato; test di UX offline o privacy-preserving; minore esposizione della carta esterna; controlli sperimentali chiari.

**Svantaggi:** anonymous set piccolo; operatori e merchant osservano l'attività; accettazione/riscatto limitati; possono applicarsi licenze, tutela dei consumatori e regole fiscali anche al valore locale.

**Procedura:** (1) ottenere revisione legale/compliance e pubblicare i termini dell'issuer; (2) iscrivere partecipanti consenzienti; (3) limitare l'emissione e vietare l'uso simile al contante; (4) usare nuove richieste di pagamento e minimizzare identificativi pubblici dei partecipanti; (5) registrare riserve aggregate e ricevute individuali private; (6) testare perdita/rimborso/riscatto; (7) chiudere il ledger e restituire il valore residuo come promesso.

**Rilevamento:** ledger issuer, iscrizione, merchant e riscatto ricostruiscono i flussi; trasferimenti circolari anomali o cash-out rapidi richiedono revisione. **Captured wallet:** saldo locale e controparti possono essere esposti; limitare il valore, cifrare lo stato e supportare freeze/reissue lato issuer con record verificabile.

## Codici di pagamento Bitcoin riutilizzabili e istruzioni private

**Meccaniche:** i payment code BIP 47 usano un identificativo pubblico riutilizzabile più indirizzi di deposito one-time derivati via ECDH; BIP 351 specifica un design più recente per istruzioni di pagamento private. Riducono il riutilizzo pubblico degli indirizzi consentendo al destinatario di pubblicare istruzioni stabili. Notifica, supporto wallet, funding e successiva selezione delle coin influenzano comunque la privacy.<sup>[[20]](#references)</sup>

**Vantaggi:** una singola istruzione pubblica può produrre indirizzi distinti; il destinatario non deve pubblicare ogni indirizzo invoice; i wallet compatibili possono monitorare i pagamenti derivati; utile per donatori/clienti leciti ricorrenti.

**Svantaggi:** interoperabilità wallet variabile; transazioni di notifica o payment code pubblicato collegano un contesto relazionale; sender, recipient e grafo pubblico vedono comunque le transazioni; consolidamento o change negligenti annullano il beneficio.

**Procedura:** (1) confermare che entrambi i wallet mantenuti supportino la stessa specifica/versione; (2) fare backup e testare il recovery su wallet di basso valore; (3) autenticare out-of-band il payment code del destinatario; (4) inviare un piccolo test lecito; (5) verificare l'uso di un indirizzo derivato nuovo; (6) etichettare localmente la relazione e applicare coin control; (7) testare recovery e rimborsi prima dell'uso operativo.

**Rilevamento:** analizzare pattern di notifica, funding/change, consolidamento successivo e confini dei servizi; la pubblicazione del codice identifica il contesto del destinatario anche con indirizzi di deposito diversi. **Capture-resilient OPSEC:** mantenere le spend key fuori dai field device ed esporre al massimo una vista watch-only della relazione. **Monitoring:** alert su transazioni di notifica inattese, indirizzi derivati riutilizzati, errori gap-limit/recovery e consolidamenti non pianificati.

## Stealth address EVM (ERC-5564)

**Meccaniche:** il sender deriva un account stealth one-time dal meta-address stealth del destinatario e pubblica un announcement con ephemeral public key e view tag. Il destinatario scansiona gli announcement con una viewing key e deriva la spend key corrispondente. Il collegamento del destinatario migliora, ma sender, importo/token, gas, announcement e spesa successiva restano visibili.<sup>[[21]](#references)</sup>

**Vantaggi:** nuovo indirizzo ricevente non interattivo; meta-address riutilizzabile; separazione tra viewing e spending; funziona con asset/applicazioni EVM supportate.

**Svantaggi:** scanning e spam degli announcement; funding del gas per il nuovo address può ricreare il link; il sender conosce il destinatario; token/importo pubblici e consolidamento finale restano; supporto wallet/implementazioni variabile.

**Procedura:** (1) usare prima un'implementazione mantenuta e verificata su test network; (2) generare materiale separato per viewing e spending e fare backup; (3) autenticare il meta-address; (4) inviare un test di basso valore e announcement; (5) scansionare e derivare lo stealth account; (6) provare il gas sponsorship supportato senza edge di funding personale; (7) registrare i campi pubblici e conservare la contabilità lecita.

**Rilevamento:** seguire caller dell'announcement, token/importo, timing, gas sponsor, spesa e consolidamento; una view key può provare la ricezione senza concedere la spesa. **Capture-resilient OPSEC:** uno scanner in rete dovrebbe avere solo il ruolo viewing dove supportato; conservare altrove spend e recovery key. **Monitoring:** alert su announcement malformati/spam, accesso alla view key, derivazione di spese inattese e stealth output spostati senza approvazione.

## Liquid Confidential Transactions

**Meccaniche:** Liquid oscura per default importi e tipi di asset degli output tramite commitment e proof, lasciando visibili grafo, numero di input/output, fee e block time. Peg-in/peg-out e confini dei servizi restano collegabili; gli utenti possono divulgare selettivamente i dati di blinding.<sup>[[22]](#references)</sup>

**Vantaggi:** importo e tipo di asset confidential per default; settlement sidechain rapido; audit selettivo tramite blinding key/descriptor; nasconde valori commercialmente sensibili agli osservatori pubblici.

**Svantaggi:** struttura e timing del grafo restano; trust federation/bridge/exchange; confini peg e output non confidential; record wallet/node/rete; sender e receiver conoscono la transazione.

**Procedura:** (1) scegliere un wallet Liquid mantenuto e verificare il modello di backup; (2) usare testnet o piccolo valore lecito; (3) ricevere su confidential address e verificare che il wallet segni l'output come blinded; (4) inviare una transazione confidential di test; (5) controllare quali campi explorer restano pubblici; (6) esportare solo la prova di blinding necessaria all'audit; (7) documentare confini peg/exchange e riconciliare i fondi.

**Rilevamento:** analizzare grafo/fee/time visibili, record peg/exchange, metadata di rete e successive prove di unblinding; non inferire importo o asset nascosti. **Capture-resilient OPSEC:** separare spend seed, dati blinding/view e operazioni watch-only. **Monitoring:** alert su indirizzi accidentalmente non confidential, peg request sconosciute, modifiche ai descriptor ed export non autorizzato delle unblinding key.

## General payment o state channel

**Meccaniche:** i partecipanti bloccano fondi, scambiano aggiornamenti di stato firmati off-chain e pubblicano on-chain solo apertura, chiusura o stato contestato. I pagamenti intermedi non vengono trasmessi globalmente, ma peer e servizi di routing/intermediazione osservano la propria parte e gli endpoint devono conservare l'ultimo stato applicabile.<sup>[[23]](#references)</sup>

**Vantaggi:** molte interazioni rapide e low-fee tra ledger pubblico e privato; meno dettagli globali; saldo del canale limitato; utile per servizi misurati e controparti ricorrenti.

**Svantaggi:** i peer conoscono le controparti e possono conservare gli update; apertura/chiusura/valore/timing correlano; può servire monitoring online durante le challenge window; rischi di implementazione/liquidità; non crea da solo un anonymous set ampio.

**Procedura:** (1) scegliere un'implementazione mantenuta e verificata comprendendo la dispute window; (2) aprire un canale di test a basso valore tra parti possedute; (3) scambiare state update firmati con nonce unici; (4) fare backup dello stato applicabile più recente; (5) chiudere cooperativamente; (6) provare su testnet il rifiuto di stati obsoleti; (7) conservare contabilità e record delle controparti del canale.

**Rilevamento:** la chain pubblica espone lifecycle/dispute; peer, watch service e transport applicativo espongono timing e parti off-chain. **Capture-resilient OPSEC:** limitare il saldo hot e conservare lo stato firmato più recente in storage cifrato e recuperabile separato dai field node. **Monitoring:** controllare continuamente pubblicazione di stato obsoleto, backup mancante, cambio chiave peer e avvicinamento della challenge deadline.

## Fatturazione del carrier mobile

**Meccaniche:** un servizio online addebita un acquisto su abbonamento mobile o saldo prepaid tramite il sistema di carrier billing. Il merchant può ricevere un'autorizzazione del carrier invece dei dati carta/banca, mentre il carrier conosce subscriber/line, contesto device/rete, merchant, importo e orario.<sup>[[24]](#references)</sup>

**Vantaggi:** nessun numero carta al merchant; ampia disponibilità telefonica; utile per beni digitali di basso valore; il carrier può limitare e stornare addebiti.

**Svantaggi:** fortemente identificato da SIM/account e spesso device; limiti ridotti e fee elevate; restrizioni per categoria merchant; rischio account takeover/SIM swap; carrier e aggregator creano una traccia completa.

**Procedura:** (1) verificare disponibilità, limite, costi e rimborsi con l'account carrier dell'organizzazione; (2) abilitarlo solo su una linea organizzativa dedicata se giustificato; (3) impostare il limite minimo utile; (4) acquistare un articolo di test benigno; (5) verificare ricevute merchant e carrier; (6) disabilitare autorizzazioni ricorrenti; (7) riconciliare e disattivare la funzione dopo l'assessment.

**Rilevamento:** record carrier, aggregator e merchant collegano linea, subscriber, IP/device e addebito; le fatture telecom aziendali lo espongono. **Capture-resilient OPSEC:** non usare un numero personale e richiedere MFA dell'account carrier fuori dal field device. **Monitoring:** attivare alert istantanei su addebiti/cambi SIM e fermarsi in caso di iscrizione inattesa a servizi premium, inoltro o recovery account.

## Payment initiation open banking

**Meccaniche:** con consenso esplicito dell'utente, un PISP regolamentato chiede alla banca che gestisce l'account di iniziare un trasferimento. Il merchant può non ricevere credenziali della carta, ma PISP e banche conservano record regolamentati di payer, payee, consenso, device e transazione.<sup>[[25]](#references)</sup>

**Vantaggi:** nessun numero carta riutilizzabile al checkout; forte autenticazione bancaria; settlement account-to-account esatto; API di consenso/stato; riconciliazione chiara.

**Svantaggi:** non anonimo rispetto a banche/PISP; il payee vede spesso dati legali dell'account o riferimento; rischio phishing/redirect; giurisdizione e rimborsi variabili; il metadata del consenso aggiunge un osservatore.

**Procedura:** (1) verificare che il PISP sia attualmente regolamentato e che il callback domain del merchant sia autentico; (2) iniziare dalla richiesta del merchant; (3) controllare presso la banca payee, importo, riferimento e consenso richiesto; (4) autorizzare solo il singolo pagamento; (5) verificare indipendentemente lo stato finale; (6) revocare eventuale consenso residuo; (7) conservare la ricevuta e riconciliare.

**Rilevamento:** log banca/PISP/merchant e riferimenti del trasferimento forniscono forte attribuzione. **Capture-resilient OPSEC:** mantenere autenticazione bancaria e recovery fuori dai device operativi/field; il device dovrebbe contenere solo l'entitlement al servizio pagato. **Monitoring:** usare alert bancari su transazioni/consensi e investigare nuovi grant PISP, payee modificato o callback di stato fuori dalla sessione prevista.

## Platform wallet, saldo app store o credito in-app

**Meccaniche:** una platform addebita l'utente o riscatta credito account, poi emette una ricevuta firmata o entitlement all'applicazione. Lo sviluppatore può non ricevere lo strumento di funding originale, mentre la platform collega account, device, funding, prodotto e riscatto.<sup>[[26]](#references)</sup>

**Vantaggi:** merchant/developer non riceve il PAN primario; controlli antifrode/rimborso e family/business; piccolo saldo prepaid per limitare l'esposizione; ricevute firmate semplificano la verifica dell'entitlement.

**Svantaggi:** account platform è un forte hub di identità e comportamento; device e geografia dello storefront; traccia di acquisto/riscatto del gift balance; cash-out limitato; i controlli possono congelare i fondi; non è denaro cross-platform.

**Procedura:** (1) usare un account platform gestito dall'organizzazione dove consentito; (2) verificare regole di funding, area, rimborso e trasferibilità; (3) aggiungere solo il budget approvato; (4) acquistare un prodotto benigno dallo store ufficiale; (5) verificare che l'app riceva solo i campi attesi della ricevuta; (6) disabilitare acquisti ricorrenti; (7) riconciliare e rimuovere l'account dall'hardware operativo.

**Rilevamento:** ricevute/notifiche server della platform, login account/device e record di funding ricostruiscono l'acquisto. **Capture-resilient OPSEC:** non autenticare mai un field node in un account store personale; fornire, dove possibile, solo un entitlement app limitato. **Monitoring:** attivare alert su nuovo device/acquisto e investigare replay delle ricevute, modifiche family/account o restore inattesi.

## Mutual credit, clearing o settlement netto periodico

**Meccaniche:** i partecipanti registrano obblighi in un ledger privato e regolano periodicamente solo le posizioni nette. I singoli eventi di servizio non devono creare pagamenti pubblici separati, ma gestore del ledger e controparti conservano attribuzione dettagliata.

**Vantaggi:** meno transazioni esterne e fee; gli osservatori pubblici vedono solo il settlement netto; funziona per organizzazioni ricorrenti; limiti di credito espliciti contengono l'esposizione.

**Svantaggi:** il ledger centralizzato è prova completa e target di frode; rischio controparte/default; obblighi legali, contabili e fiscali; membership ridotta; trasferimenti netti insoliti possono rivelare relazioni.

**Procedura:** (1) usare solo organizzazioni identificate e consenzienti con approvazione legale/contabile; (2) definire unità, limite di credito, intervallo di settlement e regole di disputa; (3) registrare ogni obbligo con approvazione immutabile; (4) lasciare a ruoli finance separati il calcolo e l'approvazione delle posizioni nette; (5) regolare tramite un rail ordinario lecito; (6) riconciliare ogni voce al settlement; (7) chiudere gli accessi e conservare i record secondo policy.

**Rilevamento:** ledger, invoice, approvazioni e settlement finale bancario/chain forniscono ground truth; non inferire attività lorda mancante dal solo trasferimento netto. **Capture-resilient OPSEC:** i device operativi possono inviare requisition limitate, ma non modificare saldi o autorizzare settlement. **Monitoring:** alert su superamento limiti, voci retrodatate, cambi amministratore, mismatch di riconciliazione e settlement verso nuovo beneficiario.

## Matrice di esposizione a cattura/compromissione

Questa matrice applica un test di sequestro/perdita a ogni famiglia. L'obiettivo è limitare autorità di spesa e divulgazione di identità non correlate mantenendo una contabilità lecita, non cancellare transazioni o ostacolare un'indagine.

| Famiglia tecnica | Cosa può rivelare un wallet/device/account catturato | Controllo autorizzato minimo |
|---|---|---|
| Contante, money order/COD, valore bearer fisico | ricevute, seriali, note, valore residuo e contatti fisici | portare solo l'importo approvato; contabilità privata separata; segnalare subito la perdita; nessun record falso |
| Prepaid, gift, voucher, service credit | saldo, issuer, attivazione, riscatto e token account/sessione | saldo basso; uno scopo; registrazione veritiera; freeze/revoca issuer se disponibile |
| Carta virtuale/tokenizzata, wallet token, payment app | account issuer, token device, transazioni, recovery e cronologia merchant | device lock; alert transazioni; scope merchant; sospensione remota issuer; nessun recovery account condiviso |
| Bank compartment, procurement delegato, red-team procurement | organizzazione, approvatori, vendor, invoice e progetto | separazione ruoli; subaccount least-privilege; credenziali finance mai sui field/operational node |
| Invoice, escrow, settlement batch | controparte, scopo, approvazione pendente, coordinator o disputa | richiesta monouso; approver separato; sessione limitata; ledger centrale autorevole |
| Bitcoin, Silent Payments, PayJoin/CoinJoin | seed/key, etichette, indirizzi, grafo transazioni e configurazione di rete | firma hardware/offline; wallet cifrato; limiti passphrase; vista watch-only sul campo; recovery documentato |
| Lightning/BOLT 12 | seed, canali, invoice, peer/LSP e database pagamenti | saldo hot minimo; backup cifrato; identità nodo separata; close/recovery documentati |
| Monero, Zcash, MWEB, applicazioni ZK | spend/view key, cronologia locale, RPC e transazioni di confine | ruoli spend/view separati; supporto hardware dove disponibile; nessuna sessione exchange sul field node |
| Stablecoin, swap, bridge e DEX | grafo trasparente, approval, stato RPC/frontend e asset di destinazione | revocare allowance; contract verificati; test di basso valore; riconciliazione completa |
| Cashu, Fedimint, Taler, Privacy Pass | bearer token, mint/federation/exchange, cache issue/redeem | saldo ridotto; backup cifrato secondo protocollo; redeem/reissue; mai collocare la credenziale di funding |
| Paymaster, multisig/threshold | session key, un signer, operation pendenti e policy sponsor | session key ristretta; quorum indipendente; rotazione signer; field device fuori dal threshold |
| Mixer/peel/structuring, nominee/front, abuso refund/gambling | provider compromesso, comunicazioni, grafo e record partecipanti | nessun uso operativo; solo prove sintetiche/testnet |
| Valuta community/event | iscrizione, saldo locale, controparti e riscatto | valore limitato; freeze/reissue issuer; ledger privato verificabile e consenso |
| Stealth address Bitcoin/EVM riutilizzabile | payment/view/spend key, metadata relazione, announcement e output derivati | ruolo watch/view-only in rete; spend offline/hardware; nessuna sessione di funding personale |
| Liquid confidential/state channel | seed, dati blinding/stato recente, peer, confini e dispute | backup spend/view/state separati; saldo hot basso; monitor disputa indipendente |
| Carrier/open banking/platform billing | account phone/banca/store, consenso, ricevuta, device e fonte funding | account organizzativo; MFA esterno; limite basso; nessun account personale sull'hardware field |
| Mutual-credit clearing | membri, obblighi, limiti, approvazioni e ledger settlement | solo requisition operativa; ledger immutabile separato e doppia approvazione finance |

## Monitoraggio di possibile discovery o compromissione del pagamento

Un rifiuto del pagamento, una revisione di compliance o un wallet offline non provano l'esistenza di un'indagine. Monitorare solo account, ledger e infrastrutture che l'organizzazione è autorizzata a osservare; non sondare mai provider o controparti per verificare se collaborano con investigatori.

| Tecniche coperte | Segnali di monitoraggio sicuri | Condizione di freeze/stop |
|---|---|---|
| Contante, money order/COD, prepaid/gift/voucher, valore bearer fisico | mismatch inventario/ricevuta, seriale duplicato, riscatto/rimborso inatteso o report di perdita | strumento mancante, riscatto fuori ordine approvato, ricevuta alterata o rottura della custodia |
| Carta virtuale/tokenizzata, payment app, bank/ACH/wire, open banking, carrier/platform billing | alert issuer/banca/platform, nuovo device/consenso/payee, riuso token, recovery SIM/account | autorizzazione sconosciuta, cambio payee, nuovo fattore recovery, SIM swap o addebito ricorrente |
| Compartimentazione account/merchant, procurement controllato/delegato, service credit | cambi IdP/vendor project, ruolo/token/budget, invoice e consumo | token cross-project, admin sconosciuto, limite superato, invoice errata o destinazione non supportata |
| Invoice, escrow, settlement pooled, mutual credit | scadenza richiesta, approvazione/rilascio, integrità ledger, riconciliazione e cambio beneficiario | importo/payee alterato, ledger retrodatato, rilascio unilaterale o batch non riconciliato |
| Bitcoin address/coin control, Silent Payments, BIP47/BIP351 | transazioni watch-only, stato notification/scan, riuso indirizzi, etichette UTXO e consolidamento | spesa sconosciuta, output destinatario riutilizzato, errore wallet gap/recovery o merge non approvato |
| PayJoin/CoinJoin | input/output/fee della proposta, disponibilità coordinator, transazione finale | output sostituito, fee eccessiva, divulgazione input inattesa o cambio policy coordinator |
| Lightning/BOLT12/general channels | backup canale, uso invoice/offer, liquidità, peer/LSP e dispute chain | pagamento invoice sconosciuto, cambio chiave peer, close obsoleto o deadline di disputa vicina |
| Monero/Zcash/MWEB/Liquid CT | eventi view/watch, tipo pool/domain/address, descriptor e transazione di confine | spesa non approvata, downgrade transparent/non-confidential, export key o confine sconosciuto |
| Ethereum ZK, stealth address, paymaster, stablecoin | contract/announcement, RPC/bundler, gas sponsor, allowance/session key e azioni issuer | contract/campo pubblico errato, approval/spesa sconosciuta, cambio paymaster o freeze issuer |
| Cashu/Fedimint/Taler/Privacy Pass | salute mint/federation/exchange, double-spend/replay token, gateway e saldo bearer | redemption sconosciuto, cambio chiavi/termini mint, restore fallito o saldo incoerente |
| Swap/bridge/DEX | contract verificato, allowance, conferme su entrambe le chain, rate e destinazione | mismatch contract/route, approval illimitata, destinazione mancante o incidente bridge |
| Multisig/threshold | cambio signer-set/policy, proposta pendente, quorum e audit recovery | proposta/signer sconosciuto, riduzione threshold, recovery attivato o bypass policy |
| Mixer/peel/structuring, nominee/front, NFT/gambling/refund abuse | solo ground truth del laboratorio sintetico e output di rilevamento | qualsiasi account, persona o valore reale nell'emulazione: stop immediato |

## Workflow di selezione e verifica

1. Indicare quale parte non deve conoscere quale campo.
2. Identificare issuer/mint/custodian, ledger pubblico, rete/RPC, merchant e osservatori fisici.
3. Verificare supporto attuale, liceità, limiti, custodia, recovery e rimborsi.
4. Eseguire un piccolo test end-to-end con fondi leciti.
5. Esaminare ricevuta merchant, estratto provider, chain pubblica e log wallet/node.
6. Testare backup/recovery e divulgazione deliberata per audit.
7. Mantenere accurati, ma access-controlled, i record richiesti di origine, proprietà, tasse, sanzioni ed engagement.

## References

- [1] [EMVCo — Tokenizzazione dei pagamenti](https://www.emvco.com/emv-technologies/payment-tokenisation/)
- [2] [US CFPB — Osservazioni sulla raccolta dei dati da parte delle grandi piattaforme di pagamento](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf)
- [3] [Bitcoin.org — Proteggi la tua privacy](https://bitcoin.org/en/protect-your-privacy)
- [4] [BIP 352 — Silent Payments](https://bips.dev/352/)
- [5] [BIP 78 — Una semplice proposta Payjoin](https://bips.dev/78/)
- [6] [Lightning BOLT 4 — Protocollo di onion routing](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Lightning BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
- [8] [Documentazione Monero — Specifiche tecniche e privacy della rete](https://docs.getmonero.org/technical-specs/)
- [9] [ZIP 224 — Protocollo Orchard Shielded](https://zips.z.cash/zip-0224)
- [10] [Litecoin — Mimblewimble Extension Blocks](https://litecoin.com/projects/mweb)
- [11] [Ethereum.org — Creazione di applicazioni privacy con zero-knowledge proof](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [12] [Cashu — Protocollo e limiti di privacy](https://docs.cashu.space/faq)
- [13] [Fedimint — Come funziona](https://fedimint.org/users/how-it-works)
- [14] [Documentazione GNU Taler](https://docs.taler.net/)
- [15] [FATF — Indicatori di rischio per gli asset virtuali](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [16] [US FinCEN — Administrators, exchangers and users of virtual currency](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [17] [Regolamento UE 2023/1113 — informazioni sui trasferimenti e crypto-asset](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [18] [RFC 9576 — Architettura Privacy Pass](https://www.rfc-editor.org/rfc/rfc9576.html) and [RFC 9577 — Privacy Pass HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html)
- [19] [ERC-4337 — Account Abstraction Using an Alternative Mempool](https://eips.ethereum.org/EIPS/eip-4337) and [Ethereum.org — Privacy application architecture](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [20] [BIP 47 — Reusable Payment Codes](https://bips.dev/47/) and [BIP 351 — Private Payments](https://bips.dev/351/)
- [21] [ERC-5564 — Stealth Addresses](https://eips.ethereum.org/EIPS/eip-5564)
- [22] [Liquid — Confidential Transactions](https://docs.liquid.net/docs/confidential-transactions)
- [23] [Ethereum.org — Canali di stato e di pagamento](https://ethereum.org/developers/docs/scaling/state-channels/)
- [24] [GSMA Open Gateway — API di carrier billing](https://open-gateway.gsma.com/docs/carrier-billing/api-reference)
- [25] [Open Banking Standards — Servizi di payment initiation](https://standards.openbanking.org.uk/customer-experience-guidelines/payment-initiation-services/v4-0/)
- [26] [Apple Developer — StoreKit](https://developer.apple.com/documentation/storekit/)
{{#include ../banners/hacktricks-training.md}}
