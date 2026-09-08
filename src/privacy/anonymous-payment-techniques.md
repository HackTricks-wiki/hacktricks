# Catalogo delle tecniche di pagamento anonimo

Questo catalogo tratta le **famiglie** di pagamento, dal contante ordinario fino all'e-cash con blind signature e all'offuscamento su blockchain pubbliche. “Anonimo” significa sempre anonimo rispetto a un osservatore specifico. Un merchant, issuer, mint, exchange, analista blockchain, network provider, datore di lavoro e osservatore fisico vedono fatti diversi.

Le procedure seguenti riguardano fondi leciti, account veritieri e procurement autorizzato. Le tecniche il cui scopo nei casi citati era riciclaggio, elusione delle sanzioni o frode d'identità sono spiegate e rilevate, ma la loro procedura è un esercizio forense sintetico, non una guida per commettere il crimine.

## Matrice di copertura

| Famiglia | Principale proprietà di privacy | Principale osservatore/trust | Trattamento |
|---|---|---|---|
| Contante ed equivalenti | nessun record remoto della payment network | destinatario e ambiente fisico | workflow lecito |
| Valore prepaid/gift/voucher | separa il riscatto dalla carta primaria | seller, issuer e redemption service | workflow lecito, varia per giurisdizione |
| Carta virtuale/tokenizzata | nasconde il PAN riutilizzabile o separa i merchant | issuer/network/wallet identificano comunque il payer | workflow lecito |
| Payment app/intermediary | il merchant può vedere un alias/intermediary | l'app raccoglie identità/device/transazione | baseline di confronto |
| Bitcoin hygiene/Silent Payments | pseudonimi e non-linkability del destinatario | grafo pubblico e confine wallet/network | deployable |
| PayJoin/CoinJoin | indebolisce le euristiche di proprietà comune/linkage | partecipanti/coordinator/network/grafo pubblico | deployable ove supportato; revisione legale |
| Lightning/BOLT 12 | routing off-chain e riduzione del percorso verso il receiver | endpoint, hop, servizi e grafo dei channel | deployable ove supportato |
| Monero/Zcash/MWEB | riservatezza on-chain a livello di protocollo | acquisition, endpoint, network e confini | deployable ove lecito/supportato |
| Ethereum ZK application | nasconde un link specifico tra statement/action | public input, RPC, relayer e app | specifico per applicazione |
| Cashu/Fedimint/Taler | privacy del payer tramite blind signature | custody di mint/federation/exchange e confini | emergente/specifico per deployment |
| Stablecoin | settlement digitale conveniente | chain trasparente più freeze/controllo dell'issuer | non è una baseline anonima |
| Swap/bridge/DEX | sposta valore tra asset/chain | entrambi i grafi, contract e provider | meccanica forense; solo swap leciti ordinari |
| Mixer/peel/structuring | aumenta ambiguità/lavoro sul grafo | grafo entry/exit e record del servizio | solo esercizio sintetico di rilevamento |
| Nominee/mule/OTC/front | inserisce intermediari umani/aziendali | facilitatori, banche, comunicazioni | solo analisi dell'abuso criminale |
| Reusable/stealth payment address | nuovo indirizzo del destinatario per ogni pagamento | announcement/notification pubblici e confini del wallet | deployable ove supportato |
| Confidential sidechain/state channel | nasconde amount/asset o aggiornamenti intermedi | peer, bridge/federation e settlement del ciclo di vita | specifico del protocollo |
| Carrier/open-banking/platform billing | nasconde la carta primaria al merchant | carrier, banca/PISP o platform identificano il cliente | pagamento ordinario identificato |
| Mutual credit/net settlement | meno record di settlement esterni | il private ledger operator conserva la mappatura completa | solo partecipanti identificati |

## Contante

**Meccanica:** il valore fisico al portatore passa di mano senza autorizzazione online dell'issuer o ledger pubblico.

**Vantaggi:** il merchant non deve conoscere l'identità bancaria/della carta; nessun grafo remoto della transazione; ampiamente comprensibile e finale.

**Svantaggi:** solo face-to-face; furto/smarrimento; controlli su resto/ricevuta/seriale/reporting; prelievo, telecamere, testimoni e posizione collegano comunque il payer.

**Procedura:** (1) confermare che il contante sia legale/accettato e verificare eventuali limiti o obblighi di reporting; (2) prelevarlo o riceverlo lecitamente e mantenere registri contabili privati; (3) pagare un merchant ordinario senza identificativi loyalty/account non necessari; (4) richiedere solo la ricevuta obbligatoria; (5) evitare dati di spedizione/account se l'acquisto non li richiede; (6) registrare internamente il legittimo scopo aziendale.

**Rilevamento:** riconciliare cassa/ricevute/inventario, telecamere e access log secondo la policy applicabile; esaminare refund in contanti insoliti o importi ripetuti appena inferiori alle soglie, senza considerare sospetto il normale uso del contante.

## Money order, postal order, cashier instrument e cash on delivery

**Meccanica:** un issuer regolamentato converte contanti/fondi di account in uno strumento numerato pagabile a un destinatario nominativo; il COD rimanda l'incasso alla consegna.

**Vantaggi:** il destinatario potrebbe non ricevere il numero della banca/carta primaria del payer; utilizzabile quando il contante non può essere trasportato da remoto; ricevuta chiara.

**Svantaggi:** issuer/retailer conservano i dati di acquisto/identità secondo necessità; tracciamento del seriale; indirizzo del destinatario/consegna; perdita/frode e restrizioni regionali; generalmente non anonimo.

**Procedura:** (1) verificare regole, limiti, identificazione e accettazione del destinatario; (2) acquistare con informazioni veritiere e fondi leciti; (3) compilare immediatamente payee/importo; (4) conservare seriale/ricevuta; (5) usare una consegna tracciata adeguata al valore; (6) riconciliare redemption/refund.

**Rilevamento:** record di acquisto/redemption dell'issuer, seriale dello strumento, retailer/telecamere, spedizione e account del destinatario; segnalare alterazioni, seriali duplicati e redemption rapide geograficamente incompatibili.

## Open-loop prepaid card

**Meccanica:** una credenziale stored-value con brand di network autorizza transazioni contro un saldo prepaid invece che contro un account di credito primario.

**Vantaggi:** limita l'esposizione del merchant e le perdite; separa il merchant dal PAN principale; utilizzabile online ove accettata.

**Svantaggi:** record di acquisto/attivazione/reload/registrazione e device; KYC e limiti variabili; problemi con billing address; restrizioni su cash-out/refund; “senza nome” non significa assenza di record dell'issuer.

**Procedura:** (1) verificare identità attuale dell'issuer, commissioni, KYC, geografia e supporto online/recurring; (2) acquistare tramite seller autorizzato con fondi leciti; (3) registrare dati veritieri se richiesto; (4) usare la carta per un solo comparto/scopo; (5) non strutturare i load né falsificare la residenza; (6) conservare prove d'acquisto/spesa e chiudere/smaltire secondo i termini dell'issuer.

**Rilevamento:** correlare seller/activation, funding, device/IP, merchant authorization, balance check e redemption/refund. Contano più i pattern che l'etichetta prepaid.

## Closed-loop gift card, voucher e transferable service credit

**Meccanica:** un valore numerato è riscattabile solo presso un merchant/servizio o ecosistema. Airtime/game/store credit sono varianti.

**Vantaggi:** il merchant destinatario può vedere solo codice/saldo; blast radius limitato; facile gifting e separazione del budget.

**Svantaggi:** seller e service registrano acquisto/attivazione/redemption; account/device/delivery collegano comunque l'attività; truffe, sconti di rivendita e limiti di scadenza/regione; deboli diritti di refund.

**Procedura:** (1) acquistare solo da canali autorizzati; (2) registrare il valore del codice senza esporre il segreto; (3) evitare di collegare un account loyalty identificativo se non necessario; (4) riscattare tramite un account/context legittimo separato; (5) conservare la ricevuta finché l'accettazione non è confermata; (6) non acquistare mai codici per richieste non sollecitate di “tax/support/ransom”.

**Rilevamento:** orario di emissione/redemption, convergenza device/account, acquisti bulk o con pattern di soglia, un device che controlla molti saldi e redemption rapide da località distanti.

## Cryptocurrency-funded card o gift-code broker

**Meccanica:** un intermediary accetta cryptocurrency ed emette una card, un voucher o un merchant code. È una conversione cross-rail: il merchant vede normale card/gift value, mentre il broker collega il deposito on-chain all'emissione e alla consegna.

**Vantaggi:** il merchant non riceve il funding wallet; utile per merchant leciti che non accettano crypto; valore stored limitato.

**Svantaggi:** non anonimo rispetto a broker/issuer; regole KYC, sanzioni, exchange e card-program; grafo pubblico del deposito; account/device/email e redemption del codice ricollegano entrambi i lati; rischio di truffa/insolvenza.

**Procedura:** (1) verificare entità legale, card issuer, giurisdizione supportata, KYC, commissioni e policy sui refund; (2) usare solo fondi leciti e documentati; (3) testare la denominazione minima; (4) verificare restrizioni di network/merchant prima dell'acquisto; (5) conservare per la contabilità sia la transaction blockchain sia la ricevuta del broker; (6) non usare broker che promettono frode d'identità, elusione delle sanzioni o cash-out “untraceable”.

**Rilevamento:** correlare gli indirizzi di deposito del broker, importo/orario univoci, account/device e authorization della carta emessa o redemption del gift-code; i record issuer e broker collegano la chain pubblica al merchant.

## Virtual o merchant-locked card

**Meccanica:** l'issuer associa un PAN/token generato all'account reale, spesso limitandolo per merchant, importo o scadenza.

**Vantaggi:** impedisce l'esposizione di un PAN riutilizzabile; compartmentation del merchant; limiti di spesa e revoca semplice; controllo antifrode maturo.

**Svantaggi:** l'issuer conosce comunque payer, funding, merchant, device/IP e orario; il merchant vede account/delivery; alcuni refund/recurring charge falliscono; non anonima.

**Procedura:** (1) usare la funzione ufficiale dell'issuer regolamentato; (2) creare una carta per un solo merchant/engagement; (3) impostare il limite minimo utile e la scadenza; (4) usare dati di billing accurati ove richiesto; (5) verificare descriptor dell'estratto conto e comportamento dei refund; (6) bloccare/eliminare dopo il settlement finale conservando le prove di audit.

**Rilevamento:** mapping issuer token-to-account, authorization del merchant, device e delivery. I defender usano segnali di riutilizzo merchant-specific, velocity e account takeover.

## Mobile-wallet network token

**Meccanica:** la tokenizzazione EMV sostituisce il PAN con una credenziale vincolata, spesso associata a device, merchant o scenario di pagamento.<sup>[[1]](#references)</sup>

**Vantaggi:** il merchant non riceve il PAN riutilizzabile; crittografia del device e dati dinamici riducono la clonazione; revocabile senza sostituire la card.

**Svantaggi:** issuer, token service, wallet platform e network conservano mapping/transazioni; account della platform, device e posizione possono identificare il payer.

**Procedura:** (1) registrare una card legittima nel wallet ufficiale; (2) proteggere account della platform/device con autenticazione forte; (3) verificare device token/ultime cifre all'acquisto; (4) disabilitare location/analytics non necessari ove supportato; (5) rimuovere immediatamente token/device smarriti; (6) verificare i record di issuer e wallet.

**Rilevamento:** requestor del token/cryptogram del device e mapping issuer, telemetry di wallet/account, terminale merchant e prove fisiche.

## Payment app, marketplace wallet e centralized intermediary

**Meccanica:** il servizio mantiene account e trasferisce valore internamente o tramite rail bancari/card; il merchant può vedere un alias mentre il servizio vede entrambe le parti.

**Vantaggi:** comodità, dispute/refund mechanism, il destinatario non deve necessariamente vedere i dati bancari/della carta.

**Svantaggi:** grafo centralizzato di identità/social/transaction/device; freeze e provvedimenti legali; le controparti possono esporre il profilo; l'uso dei dati può superare la necessità del pagamento.<sup>[[2]](#references)</sup>

**Procedura:** (1) leggere termini di identità, privacy, retention e buyer protection; (2) limitare la sincronizzazione opzionale di profilo/contatti; (3) usare un account separato e veritiero solo quando i termini lo consentono; (4) abilitare MFA/alert; (5) verificare destinatario e privacy di memo/profilo; (6) esportare i record e chiudere i link inutilizzati.

**Rilevamento:** account del provider, device/IP, grafo dei contatti, funding/withdrawal, memo e record del merchant. Un alias è pseudonimia rispetto alla controparte, non anonimato rispetto alla platform.

## Bank transfer, ACH, wire e instant-account payment

**Meccanica:** istituzioni regolamentate trasferiscono valore tra account identificati e scambiano i dati richiesti.

**Vantaggi:** rapido, accountable, reversibile in casi limitati, con record solidi; i virtual account number possono ridurre la divulgazione al merchant.

**Svantaggi:** banche e processor conoscono entrambe le parti; estratti conto e riferimenti; non anonimo; dati cross-border e Travel Rule/AML.

**Procedura:** usarlo solo quando l'accountability è accettabile: verificare indipendentemente il beneficiary, ridurre i dati opzionali nel memo, usare un virtual account/reference fornito dalla banca ove disponibile, abilitare alert, conservare fattura e riconciliare.

**Rilevamento:** record bancari/payment deterministici, proprietà di beneficiary/account, device/session e controlli antifrode. È una baseline, non una tecnica di anonimato.

## Account e merchant compartmentation

**Meccanica:** identità/account, email alias, card e contesti di consegna leciti e separati impediscono ai merchant non correlati di unire facilmente l'attività, mentre issuer/controller conservano la mappatura.

**Vantaggi:** riduce breach e linkage tra merchant; facile da auditare; compatibile con pagamenti regolamentati.

**Svantaggi:** il provider collega comunque i comparti; recovery phone/device/IP e shipping possono ricongiungerli; la policy può vietare account multipli.

**Procedura:** (1) definire uno scopo; (2) creare solo alias/subaccount conformi ai termini; (3) usare token/card specifici per merchant; (4) disabilitare contatti e personalizzazione pubblicitaria cross-account; (5) mantenere un controller ledger cifrato; (6) ritirare gli identificativi dopo la fine delle necessità di refund/retention.

**Rilevamento:** i provider uniscono recovery, device, funding e IP; i merchant uniscono delivery, browser e comportamento account. I defender devono distinguere compartmentation lecita da synthetic identity fraud.

## Controlled red-team procurement

**Meccanica:** il SOC non conosce un acquisto mentre un engagement controller conserva la mappatura tra entità legale, operator e infrastruttura.

**Vantaggi:** esercizio realistico di detection; nessuna esposizione personale; deconfliction e audit immediati.

**Svantaggi:** non anonimo rispetto a organization/provider; overhead di governance; leak se il controller ledger è gestito male.

**Procedura:** (1) assegnare una card/wallet/budget organization-specific per l'engagement; (2) separare i ruoli purchaser/operator; (3) registrare asset, importo, servizio, scopo e kill date; (4) conservare la mappatura di attribuzione con accesso limitato al controller; (5) non usare false identity/mule/stolen funds; (6) rivelare e riconciliare indicatori e refund al closeout.

**Rilevamento:** il controller collega invoice del provider e asset; il SOC verifica la scoperta indipendente tramite domain, certificate, hosting e traffic invece dei dati del cardholder.

## Bitcoin address hygiene e coin control

**Meccanica:** nuovi receive address, labeling locale e spesa selettiva degli UTXO riducono il riutilizzo degli address e l'unione accidentale dei comparti su un ledger pubblico.

**Vantaggi:** ampiamente supportato; self-custodial; evita il linkage pubblico più semplice.

**Svantaggi:** tutte le transazioni e gli importi restano pubblici; euristiche common-input/change, timing e consolidamenti successivi collegano l'attività; restano record di acquisition/RPC/network.

**Procedura:** (1) installare/verificare un wallet mantenuto; (2) fare backup e testare il seed recovery; (3) usare un nuovo address per ogni invoice; (4) etichettare localmente source/scopo; (5) usare coin control per evitare l'unione dei contesti; (6) preferire un nodo locale o una connessione privacy-aware; (7) controllare change/fee e conservare la contabilità lecita.<sup>[[3]](#references)</sup>

**Rilevamento:** address graph, euristiche common-input/change con incertezza, importo/orario esatti, consolidamento, service deposit, timing di broadcast node/RPC e record off-chain.

## Bitcoin Silent Payments

**Meccanica:** BIP 352 consente al receiver di pubblicare un codice statico mentre i sender derivano output Taproot univoci tramite ECDH; gli osservatori esterni non possono collegare direttamente gli output al codice.<sup>[[4]](#references)</sup>

**Vantaggi:** identificativo pubblico riutilizzabile senza riutilizzare address; nessuna richiesta interattiva di address o output di notifica; si integra con output Taproot.

**Svantaggi:** costo di scanning per il receiver; supporto wallet variabile; grafo di amount/sender e spesa restano pubblici; un index server può osservare gli scan.

**Procedura:** (1) scegliere un wallet BIP 352 aggiornato; (2) eseguire backup/test di descriptor e recupero dello scanning; (3) generare il codice etichettato ove supportato; (4) autenticare il codice pubblicato; (5) il sender esamina gli input e invia un piccolo test; (6) il receiver esegue lo scanning preferibilmente tramite il proprio nodo; (7) mantenere separati gli UTXO ricevuti.

**Rilevamento:** non identificabile in modo affidabile dal solo output per design; gli analisti usano input del sender, amount/time, spesa successiva, wallet/network/index e record delle controparti.

## PayJoin

**Meccanica:** payer e payee contribuiscono con input a una transazione, rompendo l'assunzione che tutti gli input appartengano allo stesso owner.<sup>[[5]](#references)</sup>

**Vantaggi:** pagamento ordinario con privacy migliorata; beneficia il grafo generale indebolendo un'euristica comune; non richiede gruppi di output uguali.

**Svantaggi:** requisito interattivo/supporto; disponibilità dell'endpoint del receiver; amount e transazione finale pubblici; metadata di implementazione e fallback.

**Procedura:** (1) confermare che entrambi i wallet mantenuti supportino la stessa versione PayJoin; (2) autenticare invoice/endpoint; (3) avviare dal payment URI abilitato al PayJoin del wallet; (4) controllare amount/fee finali e firmare solo gli input attesi; (5) evitare modifiche manuali della transazione; (6) verificare broadcast e ricezione; (7) registrare il fallback se la negoziazione fallisce.

**Rilevamento:** gli analisti blockchain non devono applicare automaticamente il clustering common-input; endpoint/provider possono registrare la negoziazione; usare prove wallet/network e spesa successiva, non solo la forma della transazione.

## CoinJoin

**Meccanica:** più partecipanti creano collaborativamente una transazione con molti input/output, comunemente di denominazione uguale, aumentando l'ambiguità della corrispondenza input-output.

**Vantaggi:** maggiore insieme di ambiguità on-chain; esistono design self-custodial; struttura dei round misurabile.

**Svantaggi:** metadata di coordinator/peer/network; fee/liquidità; forma identificabile della transazione; toxic change e consolidamenti successivi annullano i benefici; disponibilità legale/provider variabile.

**Procedura:** (1) verificare disponibilità e legalità correnti di wallet/coordinator; (2) installare il wallet ufficiale e fare backup; (3) usare solo UTXO leciti; (4) comprendere denominazioni, fee e modello del coordinator; (5) mantenere change e output mixed separati ed etichettati; (6) non consolidarli mai insieme; (7) instradare il traffico secondo il supporto ufficiale e conservare la contabilità.

**Rilevamento:** identificare la struttura collaborativa senza presumere un crimine; calcolare mapping possibili e anonymity set, poi osservare change/consolidation, confini dei servizi e record network/coordinator.

## Lightning Network

**Meccanica:** i pagamenti HTLC attraversano channel onion-routed; la maggior parte dei dettagli non viene pubblicata on-chain, mentre funding/closing e informazioni pubbliche sui channel restano visibili.

**Vantaggi:** rapido, commissioni ridotte; gli intermediary vedono normalmente hop adiacenti; i dettagli dei pagamenti ordinari restano off-chain.

**Svantaggi:** sender/receiver e primo/ultimo hop sanno di più; probing, timing, channel graph, liquidity/wallet/LSP record; i custodial wallet identificano gli utenti.

**Procedura:** (1) scegliere consapevolmente tra self-custodial e custodial; (2) verificare wallet/seed/channel recovery; (3) usare un invoice per l'importo esatto; (4) preferire private channel/LSP feature solo dopo averne letto i tradeoff; (5) proteggere l'IP del nodo con Tor supportato quando necessario; (6) evitare invoice identificativi riutilizzati; (7) mantenere la contabilità di channel e payment.<sup>[[6]](#references)</sup>

**Rilevamento:** log di node/LSP/custodian, channel graph/probe, failure/timing dei pagamenti e funding/closure on-chain; l'assenza di una transazione pubblica non significa assenza di record.

## BOLT 12 offer e route blinding

**Meccanica:** un offer riutilizzabile produce invoice nuovi e può pubblicizzare blinded path, così il payer non deve conoscere node/path in chiaro del receiver.

**Vantaggi:** privacy del receiver; endpoint riutilizzabile per donation/payment senza invoice statico; integrazione con Lightning onion routing.

**Svantaggi:** supporto wallet variabile; endpoint, hop selezionati e funding restano; il contact pubblico o l'endpoint di rete possono reidentificare il receiver.

**Procedura:** (1) confermare supporto BOLT 12 compatibile; (2) autenticare l'offer; (3) richiedere un invoice nuovo; (4) controllare importo/issuer/ricorrenza; (5) pagare tramite wallet; (6) verificare ricezione/refund; (7) minimizzare alias/contact del nodo e conservare la contabilità.<sup>[[7]](#references)</sup>

**Rilevamento:** telemetry di wallet/LSP e primo/ultimo hop, account di distribuzione dell'offer, timing/value e funding graph; il route blinding limita intenzionalmente la visibilità del payer.

## Monero

**Meccanica:** gli stealth address one-time nascondono il collegamento del destinatario, RingCT nasconde gli importi e le ring signature forniscono ambiguità sul sender.

**Vantaggi:** privacy predefinita on-chain; riservatezza di sender/receiver/amount; ecosistema maturo di wallet/node dedicati.

**Svantaggi:** record di acquisition/off-ramp ed endpoint/network/counterparty; il remote node vede query/IP; supporto degli exchange e trattamento legale variabili; piccoli errori operativi collegano ancora i contesti.

**Procedura:** (1) acquisire legalmente e conservare base/source; (2) installare/verificare il wallet ufficiale mantenuto; (3) fare backup/test del seed; (4) usare un nodo locale o un percorso documentato Tor/I2P per remote node; (5) usare un nuovo subaddress per payer/invoice; (6) etichettare localmente i contesti; (7) divulgare transaction proof/view access solo deliberatamente.<sup>[[8]](#references)</sup>

**Rilevamento:** concentrarsi su exchange/merchant/device/network e sulle prove del wallet sequestrato; l'uso del protocollo da solo non è sospetto e la chain pubblica espone deliberatamente meno dati.

## Zcash fully shielded Orchard

**Meccanica:** le zero-knowledge proof validano trasferimenti shielded mentre sender, receiver e amount sono cifrati; transparent pool e transizioni del pool restano pubblici.

**Vantaggi:** forte riservatezza on-chain degli shielded transfer; viewing key per audit limitati; validità garantita dal protocollo.

**Svantaggi:** supporto di wallet/exchange e scelta effettiva del pool variabili; correlazione di timing/value ai confini transparent; network/RPC ed endpoint restano.

**Procedura:** (1) scegliere un wallet Orchard mantenuto e shielded-by-default; (2) verificare e fare backup; (3) ottenere ZEC legalmente; (4) ricevere a un Unified Address supportato e confermare il pool; (5) preferire shielded-to-shielded; (6) usare network privacy supportata; (7) testare la divulgazione della viewing key su un wallet piccolo prima dell'audit.<sup>[[9]](#references)</sup>

**Rilevamento:** confini transparent e record dei servizi, metadata wallet/network e viewing key quando fornite legalmente; non presumere che tutti i pagamenti Unified Address siano shielded.

## Mimblewimble e Litecoin MWEB

**Meccanica:** le confidential transaction nascondono amount e Mimblewimble-style aggregation rimuove la cronologia convenzionale ricca di address; Litecoin implementa un extension block opzionale accanto alla chain trasparente.

**Vantaggi:** amount confidenziali e fungibilità migliorata nel dominio privato; pruning/aggregation efficienti.

**Svantaggi:** il confine opt-in peg-in/out è pubblico e correlabile; supporto wallet/exchange; differenze di modello interactive/address; record di network e acquisition.

**Procedura:** (1) scegliere un wallet mantenuto con supporto MWEB esplicito; (2) verificare/fare backup e testare un piccolo importo; (3) acquisire legalmente; (4) eseguire peg-in a MWEB e verificare il dominio del saldo; (5) transare solo con receiver compatibile; (6) evitare peg-out immediati e distintivi; (7) conservare record privati di audit.<sup>[[10]](#references)</sup>

**Rilevamento:** timing/value dei peg-in/out pubblici, dati exchange/wallet/node e spese trasparenti successive; i dettagli dei trasferimenti confidential interni sono intenzionalmente ridotti.

## Ethereum zero-knowledge privacy applications

**Meccanica:** un circuit dimostra uno statement — membership, valid note ownership o authorization — senza rivelare il segreto; un verifier contract controlla la prova. Deposit, withdrawal, public input, event e gas possono comunque esporre collegamenti.

**Vantaggi:** selective disclosure programmabile; applicazioni con anonymous set; regole verificabili senza rivelare tutti i dati.

**Svantaggi:** bug di contract/circuit; anonymity set piccolo; confini pubblici; RPC/IP/session/analytics/gas funding; rischio applicativo, sanzionatorio e legale.

**Procedura:** (1) definire esattamente cosa nasconde la prova; (2) usare, ove lecito, un'applicazione auditata e mantenuta; (3) esaminare public input/event e regole deposit/withdraw; (4) separare action wallet e gas sponsorship come previsto dal protocollo; (5) usare un percorso RPC/network privacy-aware; (6) testare con valore ridotto; (7) conservare record di compliance.<sup>[[11]](#references)</sup>

**Rilevamento:** contract event, timing/value di deposit/withdraw, relayer/paymaster, RPC/session, storage/analytics del frontend e confine finale exchange/merchant. Non sostenere che la ZK nasconda campi dichiarati pubblici.

## Stablecoin

**Meccanica:** i token trasferiscono valore su una chain pubblica; issuer centralizzati possono congelare/blacklistare o riscattare contro account identificati.

**Vantaggi:** stabilità del prezzo, liquidità e supporto merchant; settlement rapido; contabilità semplice.

**Svantaggi:** grafo trasparente di address/amount/contract; gas funding; identità/controllo di issuer ed exchange; screening sanzioni; anonimato generalmente scarso.

**Procedura:** trattarle come pagamenti identificati: usare un nuovo business address solo per compartmentation, verificare contract token/network, testare un piccolo importo, proteggere il wallet, usare RPC trusted/nodo locale, conservare base/source e sottoporre le parti richieste a screening.

**Rilevamento:** grafo completo degli eventi token, freeze list/azioni dell'issuer, relazioni exchange/RPC/device e gas funding.

## Cashu Chaumian e-cash

**Meccanica:** un mint firma ciecamente segreti bearer generati dal client, garantiti dalle riserve Bitcoin/Lightning del mint; può impedire il double-spend senza collegare direttamente emissione e redemption successive.

**Vantaggi:** bearer token senza account; trasferimento peer istantaneo; il mint non può collegare direttamente withdrawal blindato e spend; i token possono viaggiare come dati/QR.

**Svantaggi:** custody/solvibilità/censorship del mint; perdita/furto dei bearer data; confini di denominazione/timing e Lightning; metadata di rete; ecosistema software iniziale.<sup>[[12]](#references)</sup>

**Procedura:** (1) usare prima un test mint ufficiale o un valore minimo sacrificabile; (2) installare un wallet mantenuto e testare limiti di backup/restore; (3) autenticare il mint e verificare custody/fee; (4) coniare un piccolo importo; (5) inviare il token tramite canale privato/QR autenticato; (6) il receiver scambia il token prima di considerarlo finale; (7) riscattare e riconciliare. Non conservare valore significativo in un mint non trusted.

**Rilevamento:** il mint vede network, confini issue/redeem/Lightning e l'insieme dei token spesi, ma il blinding rimuove il collegamento diretto del token; endpoint/messaggi e amount/timing distintivi possono ripristinare i link.

## Fedimint federated e-cash

**Meccanica:** una soglia di guardians detiene le riserve e firma ciecamente e-cash; i trasferimenti bearer interni sono privati rispetto ai guardians, mentre i gateway Lightning collegano i pagamenti esterni.

**Vantaggi:** custody distribuita; trasferimento interno privato; governance comunitaria; nessun guardian controlla da solo la riserva sotto la soglia.

**Svantaggi:** rischio di quorum/custody/software dei guardian; il gateway osserva invoice/timing; confini deposit/withdraw; complessità del recupero dello stato client.

**Procedura:** (1) verificare invite, guardian, quorum e giurisdizione della federation; (2) installare un client mantenuto e testare il recupero; (3) depositare un piccolo importo lecito; (4) usare fresh internal payment request; (5) considerare il gateway osservatore per Lightning; (6) testare la redemption; (7) conservare source/tax record fuori dai dati pubblici di pagamento.<sup>[[13]](#references)</sup>

**Rilevamento:** la federation vede emissione/redemption aggregate, i gateway vedono invoice esterni, Bitcoin/Lightning mostrano i confini e prove endpoint/comunicazioni possono collegare i trasferimenti interni.

## GNU Taler

**Meccanica:** l'e-cash con blind signature integrato con la banca mira a mantenere anonimo il payer rispetto ai merchant, mentre merchant e reddito restano accountable.

**Vantaggi:** privacy del payer by design; valuta ordinaria; accountability/refund del merchant; nessun token speculativo necessario.

**Svantaggi:** deployment limitati; exchange/banca vedono il funding; il merchant vede order/delivery; rischio bearer/recovery del wallet; operatori regolamentati.

**Procedura:** (1) trovare exchange/merchant attuali per giurisdizione/valuta; (2) leggere KYC/fee/privacy; (3) installare il wallet ufficiale; (4) prelevare legalmente da bank/exchange supportati; (5) esaminare il contratto del merchant; (6) pagare e conservare dati di receipt/refund; (7) evitare identificativi di sessione del merchant non necessari.<sup>[[14]](#references)</sup>

**Rilevamento:** withdrawal da banca/exchange e deposit del merchant sono confini accountable; order/device/delivery e timing del merchant possono correlare anche quando le coin sono blindate.

## Cross-chain bridge, atomic swap e decentralized exchange

**Meccanica:** un contract/service blocca/brucia un asset e ne rilascia/conia un altro, oppure le controparti eseguono uno scambio atomico. Rompe la visione di un singolo ledger, non la continuità economica.

**Vantaggi:** interoperabilità tra asset/network; possibilità di evitare un custodian centralizzato; uso ordinario di portfolio/liquidità.

**Svantaggi:** entrambe le chain sono pubbliche; time/value/fee/liquidità e contract correlano; record bridge/relayer/frontend/RPC; rischio smart-contract/counterparty/regolatorio.

**Procedura per swap leciti:** (1) verificare contract/service ufficiale e disponibilità legale; (2) esaminare custody/audit/fee/slippage; (3) usare un piccolo test; (4) registrare entrambi gli ID di transazione e il rate; (5) proteggere le approval; (6) riconciliare l'asset di destinazione e revocare approval inutili. Non usare swap per mascherare l'origine dei fondi.

**Rilevamento:** eventi bridge deposit/withdraw, importo univoco meno fee, ordine temporale, liquidità, relayer/RPC/frontend e deposit successivi presso i servizi.

## Centralized mixer o tumbler

**Meccanica:** un servizio riceve deposit in un pool e restituisce unità differenti in seguito, tentando di oscurare la mappatura diretta input-output.

**Vantaggi:** in teoria può ampliare l'ambiguità delle transazioni.

**Svantaggi:** l'operator può rubare/registrare; analisi di timing/value entry/exit; esposizione a sanzioni, money-transmission e reati; sequestri che espongono le mappature; rischio di taint/rejection.

**Procedura:** non viene fornita alcuna guida operativa al mixing. Riprodurre il grafo in sicurezza estendendo [Lab 6](authorized-adversary-emulation-labs.md#lab-6-synthetic-peel-chain-and-bridge-graph): creare deposit sintetici, output pooled, fee e delay; fornire agli analisti mapping incompleti; misurare quali euristiche funzionano; quindi rivelare il ground truth.

**Rilevamento:** identificazione di wallet/contract del servizio, candidate set entry/exit, amount/fee/timing, riutilizzo degli indirizzi di deposito, log sequestrati/provider e consolidamenti downstream. Etichettare l'attribuzione probabilistica.

## Peel chain, fan-out/fan-in e structuring

**Meccanica:** transazioni ripetute sottraggono piccoli pagamenti dal change, dividono il valore tra molti address, ricongiungono i collector o dividono gli importi per evitare controlli.

**Vantaggi:** aumenta il lavoro e il numero di address per un analista ingenuo.

**Svantaggi:** continuità riconoscibile di valore/cadenza/transazione; consolidation e service endpoint; lo structuring può essere illegale; fee ed errori operativi.

**Procedura:** usare solo dati CSV/testnet sintetici: generare una source ampia, edge ripetuti payment/change, rami paralleli e un collector; aggiungere esempi benigni simili a exchange; calibrare il rilevamento e documentare i falsi positivi.

**Rilevamento:** continuità del grafo, pattern ripetuti di change, cadenza, importi appena inferiori ai controlli, endpoint comune del servizio e record off-chain. Gli exchange hot wallet possono assomigliare a questi pattern, quindi il contesto è obbligatorio.<sup>[[15]](#references)</sup>

## Nominee, money mule, OTC broker e front company

**Meccanica:** un'altra persona/account/company riceve, converte o spende fondi, inserendo livelli legali e operativi tra controller e transazione.

**Vantaggi per un adversary:** l'account nominativo non identifica immediatamente il controller; può collegare contante, crypto, beni e giurisdizioni.

**Svantaggi:** esposizione a identity fraud/money laundering; ogni partecipante aggiunge record di comunicazioni, banca/company/tax/shipping, commissioni, incoerenze e testimoni; il riutilizzo del facilitator crea hub.

**Procedura:** non emulare con persone/account reali. Costruire un grafo sintetico con controller, recruiter, mule, OTC, shell merchant e beneficiary; inserire edge device/IP/message/bank; chiedere agli investigatori di distinguere account holder e controller e registrare il livello di confidenza delle prove.

**Rilevamento:** device/IP/recovery condivisi, beneficiary/velocity insoliti, molti sender non correlati, movimento onward immediato, incoerenze company/director/invoice, comunicazioni e consegna di contanti/commodity.

## NFT, gambling, merchant goods e refund loop

**Meccanica:** il valore viene convertito in un asset con prezzo autoattribuito, saldo di gioco, beni rivendibili o refund per creare una narrativa transazionale diversa.

**Vantaggi per un adversary:** cambia forma all'asset e introduce intermediary marketplace/merchant.

**Svantaggi:** grafo marketplace/account/device e wash-trade; record di odds/play e refund; prove di delivery/resale; fee/perdite; responsabilità per frode/riciclaggio.

**Procedura:** nessun workflow di occultamento. Usare dati marketplace sintetici con self-trade tra wallet collegati, prezzi implausibili, gioco minimo, strumento di refund incoerente e shipping comune; validare il rilevamento contro collector/clienti legittimi.

**Rilevamento:** trade circolari/autofinanziati, ownership/funding comuni, outlier di prezzo, resale/refund immediati, attività economica minima, device/delivery condivisi e riconvergenza dei proventi.

## Physical bearer wallet o offline token transfer

**Meccanica:** device, paper/QR, hardware bearer instrument o e-cash token trasferisce il controllo di un segreto invece di trasmettere un pagamento al momento della consegna.

**Vantaggi:** nessun evento di rete live durante lo scambio; utile offline; custody fisica simile al contante.

**Svantaggi:** copia/furto/perdita e unicità incerta; redemption/broadcast successivi collegano l'attività; incontro/spedizione fisici; rischio counterfeit/tamper.

**Procedura:** (1) usare solo instrument/protocollo verificato; (2) inizializzare/verificare l'autenticità privatamente; (3) caricare solo un piccolo valore lecito; (4) trasferire in un contesto autorizzato e documentato; (5) il receiver verifica o esegue sweep tempestivamente secondo il protocollo; (6) non presumere che il sender non abbia conservato una copia; (7) registrare privatamente prove di proprietà/tax.

**Rilevamento:** funding/acquisto e sweep/redemption successivi, seriale del device/prove di tamper, delivery/incontro e record degli endpoint.

## Merchant-scoped invoice o one-time payment request

**Meccanica:** il merchant crea una richiesta monouso con importo, scadenza e riferimento dell'ordine. Il payer la salda tramite un rail supportato senza esporre direttamente al merchant una credenziale riutilizzabile; issuer o payment processor possono comunque identificare entrambe le parti.

**Vantaggi:** limita riutilizzo delle credenziali e identificativi cross-merchant accidentali; amount/expiry esatti riducono gli errori; compatibile con contabilità e refund ordinari.

**Svantaggi:** invoice, delivery, browser, processor e issuer collegano ancora l'ordine; amount/time univoci possono rafforzare la correlazione; i payment link malevoli sono comuni.

**Procedura:** (1) autenticare indipendentemente il merchant; (2) richiedere un invoice nuovo con amount, asset/network ed expiry esatti; (3) controllare destinazione e regole di refund; (4) pagare dal compartment approvato dell'engagement; (5) verificare che il merchant riconosca lo stesso invoice; (6) conservare receipt e transaction reference; (7) far scadere la richiesta invece di riutilizzarla.

**Rilevamento:** merchant e processor uniscono invoice, session e settlement; amount/time univoci e delivery identificano il payer. **Captured wallet/device:** la cronologia degli invoice espone controparti e scopi; minimizzare i dati memo, cifrare il device e conservare la contabilità autorevole nel finance system controllato.

## Prepaid service credit e capability token

**Meccanica:** un servizio converte un pagamento convenzionale in credit interni limitati o in una capability bearer. L'uso successivo di API/resource può evitare di presentare la card originale a ogni richiesta, ma il servizio può spesso collegare emissione e redemption.

**Vantaggi:** limita spesa e perdita da compromissione; separa i worker quotidiani dalla credenziale di funding; supporta budget per progetto e revoca.

**Svantaggi:** solitamente pseudonimo, non anonimo; database del servizio, redemption IP e pattern d'uso univoci collegano l'attività; i bearer token possono essere rubati; i refund possono richiedere il payer originale.

**Procedura:** (1) acquistare i credit tramite un account organization; (2) creare un progetto e budget; (3) emettere un token ristretto con vincoli su servizio, importo e scadenza; (4) conservarlo solo nel secret manager approvato o nel percorso workload identity; (5) testare il rifiuto fuori ambito e dopo la scadenza; (6) monitorare il consumo; (7) revocare e riconciliare il valore inutilizzato.

**Rilevamento:** il provider collega funding account, progetto, emissione del token e uso; i defender segnalano cambi geografici/process e consumo anomalo. **Captured node:** assumere che la capability restante possa essere spesa; usare expiry breve, saldo ridotto, audience binding e revoca immediata server-side.

## Privacy Pass o blinded authorization token

**Meccanica:** un issuer produce un authorization token privacy-preserving che un origin può validare senza collegare redemption ed emissione. Può rappresentare un entitlement pagato o un accesso rate-limited, ma non è una valuta generale. L'architettura separa i ruoli client, attester, issuer e origin e avverte che IP/timing o collusione possono annullare la unlinkability.<sup>[[18]](#references)</sup>

**Vantaggi:** redemption non collegabile per servizi supportati; nessun account cookie riutilizzabile presso l'origin; token cached possono separare emissione e uso nel tempo.

**Svantaggi:** specifico dell'applicazione; trust di issuer/attester e partizionamento dell'anonymity set; metadata IP/browser persistono; furto del token o timing distintivo dell'emissione possono correlare l'uso.

**Procedura:** (1) usare un'implementazione conforme al tipo Privacy Pass pertinente; (2) definire esattamente quale entitlement prova il token; (3) separare amministrazione issuer e origin quando richiesto dal threat model; (4) minimizzare i metadata della challenge; (5) emettere diversi token di test e riscattarli una volta ciascuno presso origin controllati; (6) confrontare i log per identificativi stabili vietati; (7) testare replay, expiry e controlli di revocation/abuse.

**Rilevamento:** gli origin vedono IP/orario di redemption e validità del token; issuer/attester vedono il contesto di emissione; gli analisti testano timing e partizioni dei metadata senza presumere una rottura crittografica. **Captured client:** bearer token non spesi possono essere utilizzabili; limitarne valore, durata e audience e non memorizzare mai la credenziale di funding insieme a essi.

## Delegated organization procurement o fiscal sponsor

**Meccanica:** un procurement team, reseller o fiscal sponsor autorizzato stipula il contratto e paga mentre il team operativo riceve un servizio limitato. È separazione dei ruoli con record veritieri, non nominee o falsa identità.

**Vantaggi:** i vendor non devono ricevere l'identità o i dati di pagamento personali di ogni operator; compliance, tax e refund centralizzati; budget e offboarding chiari.

**Svantaggi:** lo sponsor conosce beneficiary e scopo; contratti, approval, delivery e account restano; ritardi/fee aggiuntivi; separazione debole se la stessa persona amministra ogni livello.

**Procedura:** (1) documentare business purpose, beneficiary e autorità approvante; (2) scegliere un intermediary approvato dall'organizzazione; (3) contrattare con dati veritieri; (4) fornire un subaccount limitato al progetto senza credenziale personale di billing; (5) separare finance administrator e operator; (6) riconciliare invoice e accesso; (7) terminare servizio e accesso delegato al closeout.

**Rilevamento:** record procurement, identity-provider, vendor e delivery uniscono la catena. **Captured operational device:** dovrebbe rivelare il progetto di servizio ma non le credenziali finance; conservare invoice e identità del payer nel finance system, non sui field node.

## Escrow o conditional settlement

**Meccanica:** un escrow agent trusted o smart contract detiene il valore finché non sono soddisfatte condizioni documentate. Può ridurre la divulgazione diretta tra payer e payee, mentre escrow e rail di pagamento sottostanti conservano la relazione.

**Vantaggi:** protezione da dispute e mancata consegna; payer e merchant possono esporre meno credenziali riutilizzabili; condizioni di release auditabili.

**Svantaggi:** rischio custody/contract dell'escrow, fee e obblighi di identità; i contract on-chain sono pubblici; order, shipping e dispute data restano; non anonimo rispetto all'intermediary.

**Procedura:** (1) verificare entità legale, custody, fee, foro per le dispute e asset supportati; (2) creare milestone scritta esatta e percorso di refund; (3) finanziare da un account organization approvato; (4) verificare indipendentemente receipt e autorizzazione al release; (5) rilasciare solo dopo le prove; (6) conservare l'audit record completo; (7) chiudere permission o approval inutilizzati.

**Rilevamento:** eventi di escrow account/contract, funding e release time, beneficiary e dispute record rivelano la transazione. **Captured device:** session token o approval del contract possono consentire il release; richiedere approver/MFA separati e revocare session attive in caso di perdita.

## Batched o pooled organization settlement

**Meccanica:** molte obbligazioni approvate sono aggregate e regolate in meno transazioni bancarie o blockchain, con un private ledger interno che assegna ogni quota. Il batching può ridurre il dettaglio pubblico per acquisto, ma il coordinator conserva l'attribuzione completa.

**Vantaggi:** fee inferiori; meno edge nel grafo pubblico; nasconde singole line item a un osservatore pubblico quando gli importi sono aggregati; contabilità interna semplice.

**Svantaggi:** il coordinator è un osservatore completo e un target di alto valore; totali/timing distintivi possono correlare; rischio di custody e riconciliazione; può sembrare structuring se abusato.

**Procedura:** (1) definire partecipanti e obbligazioni lecite nel sistema contabile; (2) impostare una finestra regolare giustificata dal business, non soglie ideate per evitare controlli; (3) richiedere dual approval dell'aggregato; (4) regolare verso destinatari autenticati; (5) riconciliare ogni linea interna al batch; (6) gestire i refund come correzioni collegate; (7) proteggere accesso al ledger e conservarlo secondo policy.

**Rilevamento:** ledger del coordinator e record di approval/beneficiary forniscono il ground truth; gli analisti pubblici usano con cautela clustering di input/output/value/time. **Captured payer device:** dovrebbe contenere solo la requisition, non la signing key del pool o il participant ledger.

## Account-abstraction paymaster o sponsored gas

**Meccanica:** un relayer/bundler invia una smart-account operation e un paymaster paga le fee di transazione, evitando un edge diretto di native-gas funding dal wallet dell'utente. Migliora una proprietà del grafo; operation, contract e telemetry del servizio restano pubblici o osservabili.<sup>[[19]](#references)</sup>

**Vantaggi:** rimuove un comune link di gas funding; supporta sponsorship limitata e rate limit; onboarding migliore per privacy application legittime.

**Svantaggi:** paymaster/bundler/RPC/frontend possono correlare le richieste; contract event e public input restano; la policy di sponsorship identifica una coorte; contract o approval malevoli possono rubare asset.

**Procedura:** (1) usare smart account e paymaster auditati e mantenuti sulla network corretta; (2) esaminare i campi pubblici e cosa registra lo sponsor; (3) limitare sponsorship per contract, function, amount, nonce ed expiry; (4) testare con valore ridotto; (5) inviare tramite il percorso privacy-aware previsto dall'applicazione; (6) verificare on-chain operation e fee payer; (7) revocare allowance/session key e conservare i record di compliance.

**Rilevamento:** unire log UserOperation, EntryPoint, paymaster, bundler/RPC e application; raggruppare con cautela policy di sponsorship identiche. **Captured wallet:** session key e approval pending possono essere utilizzabili anche senza gas; limitarli strettamente e revocarli tramite la recovery policy dell'account.

## Threshold o multisignature payment authorization

**Meccanica:** la spesa richiede una soglia di signer indipendenti. Non nasconde la transazione, ma separa l'autorità di pagamento da laptop catturati, field node o singolo operator.

**Vantaggi:** forte resistenza a compromissione e insider; approval accountable; nessun field device possiede la signing authority completa; supporto al recovery.

**Svantaggi:** coordinamento e disponibilità; metadata di signer/device/account possono correlare i partecipanti; backup errato causa perdita; pattern multisig pubblici possono essere identificabili.

**Procedura:** (1) definire signer, threshold, limiti e recovery prima del funding; (2) inizializzare su hardware/account separati e supportati; (3) verificare indipendentemente address e backup; (4) concedere ai field workload solo capacità di requisition non firmata; (5) richiedere revisione out-of-band di recipient, amount e purpose; (6) testare recovery e perdita di un signer con valore ridotto; (7) ruotare un signer dopo compromissione.

**Rilevamento:** approval system, signer device e public script/contract forniscono prove; i defender segnalano cambi di policy o signer set. **Captured node:** dovrebbe esporre al massimo una session key a bassa autorità o una richiesta non firmata; non memorizzare mai insieme il materiale del quorum.

## Closed-loop community o event currency

**Meccanica:** una cooperativa, conference o private test environment emette credit riscattabili solo tra partecipanti registrati. Il trasferimento interno può esporre meno alle payment network globali, mentre l'operator controlla emissione e redemption.

**Vantaggi:** dominio economico limitato; utile per testare UX di pagamento offline o privacy-preserving; limita l'esposizione della carta esterna; controlli sperimentali chiari.

**Svantaggi:** anonymity set piccolo; operator e merchant osservano l'attività; acceptance/redemption limitate; licenze, tutela del consumatore e regole fiscali possono applicarsi anche al valore locale.

**Procedura:** (1) ottenere revisione legale/compliance e pubblicare i termini dell'issuer; (2) registrare partecipanti consenzienti; (3) limitare l'emissione e vietare abusi simili al contante; (4) usare fresh payment request e minimizzare gli identificativi pubblici dei partecipanti; (5) registrare riserve aggregate e ricevute individuali private; (6) testare perdita/refund/redemption; (7) chiudere il ledger e restituire il valore residuo come promesso.

**Rilevamento:** ledger dell'issuer e record di enrollment, merchant e redemption ricostruiscono i flussi; trasferimenti circolari insoliti o cash-out rapidi richiedono revisione. **Captured wallet:** saldo locale e controparti possono essere esposti; limitare il valore, cifrare lo stato e supportare freeze/reissue lato issuer con record auditabile.

## Bitcoin reusable payment code e private payment instruction

**Meccanica:** i payment code BIP 47 usano un identificativo pubblico riutilizzabile più one-time deposit address derivati via ECDH; BIP 351 specifica un design più recente di private-payment instruction. Riducono il riutilizzo pubblico degli address consentendo al receiver di pubblicare istruzioni stabili. Notification, supporto wallet, funding e successiva coin selection influenzano comunque la privacy.<sup>[[20]](#references)</sup>

**Vantaggi:** una sola istruzione pubblica può produrre address distinti; il receiver non deve pubblicare ogni invoice address; wallet compatibili possono monitorare i pagamenti derivati; utile per donor/clienti leciti ricorrenti.

**Svantaggi:** interoperabilità wallet variabile; notification transaction o payment code pubblicato collegano un contesto relazionale; sender, receiver e grafo pubblico vedono ancora le transazioni; consolidamento o gestione del change negligenti annullano il beneficio.

**Procedura:** (1) confermare che entrambi i wallet mantenuti supportino esattamente la stessa specifica/versione; (2) fare backup e testare il recovery su un wallet di basso valore; (3) autenticare out-of-band il payment code del receiver; (4) inviare un piccolo test lecito; (5) verificare l'uso di un nuovo derived address; (6) etichettare localmente la relazione e applicare coin control; (7) testare recovery e refund prima di affidarsi al sistema.

**Rilevamento:** gli analisti esaminano notification pattern, funding/change, consolidamento successivo e service boundary; la pubblicazione del public code identifica il contesto del receiver anche quando gli address di deposito differiscono. **Capture-resilient OPSEC:** mantenere le spend key fuori dai field device ed esporre al massimo una relazione watch-only. **Monitoring:** segnalare notification transaction inattese, derived address riutilizzati, errori di gap-limit/recovery e consolidamenti non pianificati.

## EVM stealth address (ERC-5564)

**Meccanica:** un sender deriva un account stealth one-time dal meta-address stealth del recipient e pubblica un announcement contenente ephemeral public key e view tag. Il recipient scansiona gli announcement con una viewing key e deriva la spend key corrispondente. Il linkage del recipient migliora, ma sender, amount/token, gas, announcement e spesa successiva restano visibili.<sup>[[21]](#references)</sup>

**Vantaggi:** fresh receiver address non interattivo; meta-address riutilizzabile; separazione tra viewing e spending role; funziona tra asset/applicazioni EVM supportati.

**Svantaggi:** scanning e spam degli announcement; il gas funding del nuovo address può ricollegarlo; il sender conosce il recipient; token/amount pubblici e consolidamento finale persistono; implementazione e supporto wallet variabili.

**Procedura:** (1) usare prima un'implementazione auditata e mantenuta su testnet; (2) generare materiale separato per viewing e spending e fare backup; (3) autenticare il meta-address; (4) inviare un test di basso valore e announcement; (5) eseguire scan e derivare lo stealth account; (6) testare gas sponsorship supportata senza un personal funding edge; (7) registrare i campi pubblici e conservare la contabilità lecita.

**Rilevamento:** seguire caller dell'announcement, token/amount, timing, gas sponsor, spending e consolidation; una view key può dimostrare la ricezione senza concedere la spesa. **Capture-resilient OPSEC:** uno scanner in rete dovrebbe avere solo il viewing role ove supportato; conservare spend e recovery key altrove. **Monitoring:** segnalare announcement malformati/spam, accesso alla view key, derivazioni di spesa inattese e stealth output movimentati senza approvazione.

## Liquid Confidential Transactions

**Meccanica:** Liquid oscura di default amount e asset type degli output tramite commitment e proof, lasciando visibili transaction graph, numero di input/output, fee e block time. Peg-in/peg-out e service boundary restano collegabili, e gli utenti possono divulgare selettivamente i blind data.<sup>[[22]](#references)</sup>

**Vantaggi:** amount e asset type confidential di default; settlement sidechain rapido; audit selettivo tramite blinding key/descriptor; nasconde valori commercialmente sensibili agli osservatori pubblici.

**Svantaggi:** struttura del grafo e timing restano; trust di federation/bridge/exchange; peg boundary e output non confidential; record wallet/node/network; sender e receiver conoscono la transazione.

**Procedura:** (1) selezionare un wallet Liquid mantenuto e verificare il modello di backup; (2) usare testnet o un piccolo importo lecito; (3) ricevere a un confidential address e verificare che il wallet indichi l'output come blinded; (4) inviare una piccola confidential transaction di test; (5) controllare quali campi dell'explorer restano pubblici; (6) esportare solo la blinding proof limitata necessaria per l'audit; (7) documentare peg/exchange boundary e riconciliare i fondi.

**Rilevamento:** analizzare grafo/fee/time visibili, record peg ed exchange, metadata di rete e prove di unblinding successive; non inferire amount o asset nascosti. **Capture-resilient OPSEC:** separare spend seed, blinding/view data e watch-only operation. **Monitoring:** segnalare address accidentalmente non confidential, peg request sconosciuti, cambi di descriptor ed export non autorizzato della unblinding key.

## General payment o state channel

**Meccanica:** i partecipanti bloccano fondi, scambiano aggiornamenti di stato firmati off-chain e pubblicano on-chain solo apertura, chiusura o stato contestato. I pagamenti intermedi non sono trasmessi globalmente, ma peer e servizi di routing/intermediary osservano la loro parte e gli endpoint devono conservare l'ultimo stato eseguibile.<sup>[[23]](#references)</sup>

**Vantaggi:** molte interazioni rapide e low-fee private-to-public-ledger; meno dettagli transazionali globali; channel balance limitato; utile per servizi misurati e controparti ricorrenti.

**Svantaggi:** i channel peer si conoscono e possono conservare gli update; opening/closing/value/timing correlano; può essere richiesto monitoring online durante le challenge window; rischio di implementazione/liquidità; da solo non crea un grande anonymity set.

**Procedura:** (1) scegliere un'implementazione auditata e mantenuta comprendendo la dispute window; (2) aprire un channel di test a basso valore tra parti controllate; (3) scambiare state update firmati con nonce univoci; (4) fare backup dell'ultimo stato eseguibile; (5) chiudere cooperativamente; (6) provare su testnet il rifiuto di stale state; (7) conservare accounting e record dei channel peer.

**Rilevamento:** la public chain espone lifecycle/dispute; peer, watch service e application transport espongono timing e parti off-chain. **Capture-resilient OPSEC:** limitare il saldo hot e conservare l'ultimo stato firmato in uno storage cifrato e recuperabile separato dai field node. **Monitoring:** controllare continuamente pubblicazione di stale state, backup mancanti, cambio di peer key e avvicinamento della challenge deadline.

## Mobile carrier billing

**Meccanica:** un servizio online addebita un acquisto a un abbonamento mobile o saldo prepaid tramite il carrier billing system. Il merchant può ricevere un'autorizzazione carrier invece di dati card/bank, mentre il carrier conosce subscriber/line, contesto device/network, merchant, importo e orario.<sup>[[24]](#references)</sup>

**Vantaggi:** nessun numero di carta al merchant; ampia disponibilità telefonica; utilizzabile per beni digitali di basso valore; il carrier può limitare e stornare gli addebiti.

**Svantaggi:** fortemente identificato da SIM/account e spesso dal device; limiti ridotti e fee elevate; restrizioni per categoria merchant; rischio di account takeover/SIM-swap; carrier e aggregator creano una traccia completa.

**Procedura:** (1) confermare disponibilità, limite, fee e termini di refund con l'organization carrier account; (2) abilitarlo solo su una linea organization dedicata se giustificato; (3) impostare il limite minimo utile; (4) acquistare un benign test item; (5) verificare ricevute merchant e carrier; (6) disabilitare recurring authorization; (7) riconciliare e disattivare la funzione al termine dell'assessment.

**Rilevamento:** record carrier, aggregator e merchant uniscono line, subscriber, IP/device e charge; le fatture telecom aziendali lo espongono. **Capture-resilient OPSEC:** non usare un numero personale e richiedere MFA dell'account carrier fuori dal field device. **Monitoring:** abilitare alert immediati su charge/SIM change e interrompere in caso di premium-service enrollment, forwarding o account recovery inattesi.

## Open-banking payment initiation

**Meccanica:** con consenso esplicito dell'utente, un regulated payment-initiation service provider (PISP) chiede alla banca che gestisce l'account di avviare un trasferimento. Il merchant può non ricevere credenziali della carta, ma PISP e banche conservano record regolamentati di payer, payee, consenso, device e transazione.<sup>[[25]](#references)</sup>

**Vantaggi:** nessun numero di carta riutilizzabile al checkout; forte autenticazione bancaria; settlement account-to-account esatto; API di consenso e stato; riconciliazione chiara.

**Svantaggi:** non anonimo rispetto a banche/PISP; il payee vede spesso dati legali dell'account o reference; rischio phishing/redirect; giurisdizione e protezione refund variabili; i metadata del consenso aggiungono un altro osservatore.

**Procedura:** (1) verificare che il PISP sia attualmente regolamentato e che il callback domain del merchant sia autentico; (2) partire dalla richiesta del merchant; (3) controllare presso la banca payee, amount, reference e consenso richiesto; (4) autorizzare solo il singolo pagamento; (5) verificare indipendentemente lo stato finale; (6) revocare eventuale consenso residuo; (7) conservare ricevuta e riconciliare.

**Rilevamento:** log bank/PISP/merchant e transfer reference forniscono forte attribuzione. **Capture-resilient OPSEC:** mantenere autenticazione e recovery bancari fuori da device operativi/field; il device dovrebbe contenere solo un service entitlement pagato. **Monitoring:** usare alert su transazioni/consensi bancari e investigare nuovi PISP grant, payee modificato o status callback fuori dalla session attesa.

## Platform wallet, app-store balance o in-app credit

**Meccanica:** una platform addebita l'utente o riscattata account credit, poi emette una signed receipt o entitlement per un'applicazione. Lo sviluppatore dell'app può non ricevere lo strumento di funding originale, mentre la platform collega account, device, funding, product e redemption.<sup>[[26]](#references)</sup>

**Vantaggi:** merchant/developer non ricevono il PAN primario; controlli antifrode/refund e family/business; un piccolo saldo prepaid limita l'esposizione; signed receipt semplifica la verifica dell'entitlement.

**Svantaggi:** l'account della platform è un forte hub di identità e comportamento; device e geografia dello store; traccia di acquisto/redemption del gift balance; cash-out limitato; i controlli antifrode possono congelare i fondi; non è denaro cross-platform.

**Procedura:** (1) usare un platform account gestito dall'organizzazione ove consentito; (2) verificare regole di funding, regione, refund e valore trasferibile; (3) aggiungere solo il budget approvato; (4) acquistare un prodotto benigno dallo store ufficiale; (5) verificare che l'app riceva solo i campi attesi della receipt; (6) disabilitare l'acquisto ricorrente; (7) riconciliare e rimuovere l'account dall'hardware operativo.

**Rilevamento:** receipt/notifica server della platform, login account/device e record di funding ricostruiscono l'acquisto. **Capture-resilient OPSEC:** non autenticare mai un field node con uno store account personale; fornire solo un'app entitlement limitato ove possibile. **Monitoring:** abilitare alert su nuovo device/acquisto e investigare receipt replay, cambi family/account o restore inattesi.

## Mutual credit, clearing o periodic net settlement

**Meccanica:** i partecipanti registrano obbligazioni in un private ledger e regolano periodicamente solo ciascuna posizione netta. I singoli eventi di servizio non devono creare pagamenti pubblici separati, ma ledger operator e controparti conservano l'attribuzione dettagliata.

**Vantaggi:** meno transazioni esterne e fee; gli osservatori pubblici vedono solo il settlement netto; utile tra organizzazioni ricorrenti; limiti di credito espliciti contengono l'esposizione.

**Svantaggi:** il ledger centralizzato è una prova completa e un target di frode; rischio counterparty/default; obblighi legali/accounting/tax; membership ridotta; net transfer insoliti possono rivelare relazioni.

**Procedura:** (1) usare solo organizzazioni identificate e consenzienti con approvazione legale/accounting; (2) definire unità, credit limit, settlement interval e regole di dispute; (3) registrare ogni obbligazione con approval immutabile; (4) far calcolare e approvare le posizioni nette a ruoli finance separati; (5) regolare tramite un rail lecito ordinario; (6) riconciliare le linee individuali al settlement; (7) chiudere l'accesso e conservare i record secondo policy.

**Rilevamento:** ledger, invoice, approval e settlement finale bank/chain forniscono il ground truth; gli analisti non devono inferire attività lorda mancante solo dal net transfer. **Capture-resilient OPSEC:** i device operativi possono inviare requisition limitate ma non modificare saldi o autorizzare settlement. **Monitoring:** segnalare violazioni del credit limit, entry retrodatate, cambi administrator, mismatch di riconciliazione e settlement verso un nuovo beneficiary.

## Matrice di esposizione a capture/compromise

Si applica un test di sequestro/perdita a ogni famiglia. L'obiettivo è limitare l'autorità di spesa e la divulgazione di identità non correlate mantenendo una contabilità lecita, non cancellare transazioni o ostacolare un'indagine.

| Famiglia tecnica | Cosa può rivelare un wallet/device/account catturato | Controllo autorizzato minimo |
|---|---|---|
| Contante, money order, COD, bearer value fisico | ricevute, seriali, note, valore residuo al portatore e contatti fisici | portare solo l'importo approvato; contabilità privata separata; segnalazione immediata della perdita; nessun record falso |
| Prepaid, gift, voucher, service credit | saldo, issuer, activation, redemption e account/session token | saldo ridotto; uno scopo; registrazione veritiera; freeze/revocation dell'issuer ove disponibile |
| Virtual/tokenized card, wallet token, payment app | account issuer, device token, transazioni, recovery e merchant history | device lock; transaction alert; merchant scope; sospensione remota issuer; nessun recovery account condiviso |
| Bank compartment, delegated procurement, red-team procurement | organization, approver, vendor, invoice e progetto | separazione dei ruoli; subaccount least-privilege; credenziali finance mai sui nodi operativi/field |
| Invoice, escrow, batch settlement | controparte, scopo, approval pending, coordinator o dispute trail | richiesta monouso; approver separato; session limitata; ledger autorevole centrale |
| Bitcoin, Silent Payments, PayJoin/CoinJoin | seed/key, label, address, transaction graph e configurazione network | firma hardware/offline; wallet cifrato; passphrase limitata; vista watch-only sul field; recovery documentato |
| Lightning/BOLT 12 | seed, channel, invoice, peer/LSP e payment database | hot balance minimo; backup cifrato; node identity separata; close/recovery secondo piano documentato |
| Monero, Zcash, MWEB, ZK application | spend/view key, cronologia locale wallet, RPC e boundary transaction | ruoli spend/view separati; supporto hardware ove disponibile; nessuna session exchange sul field node |
| Stablecoin, swap, bridge e DEX | grafo trasparente, approval, stato RPC/frontend e asset di destinazione | revocare allowance; contract verificati; test a basso valore; riconciliazione completa |
| Cashu, Fedimint, Taler, Privacy Pass | bearer token, mint/federation/exchange, cache di emissione/redemption | saldo ridotto; backup cifrato come supportato dal protocollo; redeem/reissue; non collocare la funding credential |
| Paymaster, multisig/threshold | session key, un signer, operation pending e policy sponsor | session key ristretta; quorum indipendente; rotazione signer; il field device non raggiunge il threshold |
| Mixer/peel/structuring, nominee/front, abuso refund/gambling | provider incriminante, comunicazioni, grafo e record dei partecipanti | nessun uso operativo; emulare solo con prove synthetic/testnet |
| Community/event currency | enrollment, saldo locale, controparti e redemption | valore limitato; freeze/reissue dell'issuer; ledger privato e auditabile con consenso |
| Reusable Bitcoin/EVM stealth address | payment/view/spend key, metadata della relazione, announcement e output derivati | ruolo network watch/view-only; spend role offline/hardware; nessuna personal funding session |
| Liquid confidential/state channel | seed, blinding data/latest state, peer, boundary e dispute | backup separato di spend/view/state; hot balance ridotto; dispute monitor indipendente |
| Carrier/open-banking/platform billing | account phone/bank/store, consenso, receipt, device e funding source | account organization; MFA esterno; limite ridotto; nessun account personale sull'hardware field |
| Mutual-credit clearing | membri, obbligazioni, limiti, approval e settlement ledger | solo requisition operative; ledger immutabile separato e dual approval finance |

## Monitoring di possibile discovery o compromise del pagamento

Un payment denial, una compliance review o un wallet offline non dimostrano che esista un'indagine. Monitorare solo account, ledger e infrastruttura che l'organizzazione è autorizzata a osservare; non sondare mai provider o controparti per verificare se collaborino con investigatori.

| Tecniche coperte | Segnali di monitoring sicuri | Condizione di freeze/stop |
|---|---|---|
| Contante, money order/COD, prepaid/gift/voucher, bearer value fisico | mismatch inventario/ricevuta, seriale duplicato, redemption/refund inatteso o report di perdita | strumento mancante, redemption fuori dall'ordine approvato, ricevuta alterata o rottura della custody |
| Virtual/tokenized card, payment app, bank/ACH/wire, open banking, carrier/platform billing | alert issuer/bank/platform, nuovo device/consenso/payee, token riutilizzato, SIM/account recovery | authorization sconosciuta, cambio payee, nuovo recovery factor, SIM swap o recurring charge |
| Account/merchant compartment, procurement controllato/delegato, service credit | cambi IdP/vendor project, role/token/budget, invoice e consumo | token cross-project, admin sconosciuto, superamento limite, invoice mismatch o destinazione non supportata |
| Invoice, escrow, pooled settlement, mutual credit | scadenza request, approval/release, integrità ledger, riconciliazione e cambio beneficiary | amount/payee alterato, ledger retrodatato, release unilaterale o batch non riconciliato |
| Bitcoin address/coin control, Silent Payments, BIP47/BIP351 | transazioni watch-only, notification/scan state, address reuse, label UTXO e consolidation | spend sconosciuto, recipient output riutilizzato, gap/recovery failure del wallet o merge non approvato |
| PayJoin/CoinJoin | input/output/fee della proposal, disponibilità coordinator, equality della transazione finale | output sostituito, fee eccessiva, input disclosure inatteso o cambio policy coordinator |
| Lightning/BOLT12/general channel | channel backup, uso invoice/offer, liquidità, peer/LSP e chain dispute | invoice payment sconosciuto, peer-key change, stale close o challenge deadline imminente |
| Monero/Zcash/MWEB/Liquid CT | eventi view/watch, tipo pool/domain/address, descriptor e boundary transaction | spend non approvato, downgrade transparent/unconfidential, key export o boundary sconosciuto |
| Ethereum ZK, stealth address, paymaster, stablecoin | contract/announcement, RPC/bundler, gas sponsor, allowance/session key e azioni issuer | contract/public field errato, approval/spend sconosciuto, cambio paymaster o freeze issuer |
| Cashu/Fedimint/Taler/Privacy Pass | health di mint/federation/exchange, double-spend/replay token, gateway e bearer balance | redemption sconosciuta, cambio mint key/terms, restore failure o saldo incoerente |
| Swap/bridge/DEX | contract verificato, allowance, conferme su entrambe le chain, rate e destinazione | contract/route mismatch, approval illimitata, destinazione mancante o incidente bridge |
| Multisig/threshold | cambio signer-set/policy, proposal pending, quorum e recovery audit | proposal/signer sconosciuto, riduzione threshold, recovery activation o policy bypass |
| Mixer/peel/structuring, nominee/front, NFT/gambling/refund abuse | solo ground truth del synthetic lab e output di detection | qualsiasi account, persona o valore reale che entri nell'emulazione: interrompere immediatamente |

## Workflow di selezione e verifica

1. Indicare quale parte non deve conoscere quale campo.
2. Identificare issuer/mint/custodian, ledger pubblico, network/RPC, merchant e osservatori fisici.
3. Verificare supporto attuale, legalità, limiti, custody, recovery e comportamento dei refund.
4. Usare un piccolo test end-to-end lecito.
5. Esaminare merchant receipt, provider statement, public chain e log wallet/node.
6. Testare backup/recovery e divulgazione deliberata per audit.
7. Mantenere accurati, ma access-controlled, i record richiesti di source, ownership, tax, sanzioni ed engagement.

## References

- [1] [EMVCo — Tokenizzazione dei pagamenti](https://www.emvco.com/emv-technologies/payment-tokenisation/)
- [2] [US CFPB — Osservazioni sulla raccolta dati da parte delle grandi payment platform](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf)
- [3] [Bitcoin.org — Proteggi la tua privacy](https://bitcoin.org/en/protect-your-privacy)
- [4] [BIP 352 — Silent Payments](https://bips.dev/352/)
- [5] [BIP 78 — Una semplice proposta PayJoin](https://bips.dev/78/)
- [6] [Lightning BOLT 4 — Protocollo di Onion Routing](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Lightning BOLT 12 — Offer](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
- [8] [Monero Documentation — Specifiche tecniche e privacy della network](https://docs.getmonero.org/technical-specs/)
- [9] [ZIP 224 — Protocollo Orchard Shielded](https://zips.z.cash/zip-0224)
- [10] [Litecoin — Mimblewimble Extension Blocks](https://litecoin.com/projects/mweb)
- [11] [Ethereum.org — Creazione di privacy application con zero-knowledge proof](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [12] [Cashu — Protocollo e limiti di privacy](https://docs.cashu.space/faq)
- [13] [Fedimint — Come funziona](https://fedimint.org/users/how-it-works)
- [14] [Documentazione GNU Taler](https://docs.taler.net/)
- [15] [FATF — Indicatori di red flag per Virtual Asset](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [16] [US FinCEN — Administrator, exchanger e utenti di virtual currency](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [17] [Regolamento UE 2023/1113 — informazioni sui trasferimenti e crypto-asset](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [18] [RFC 9576 — L'architettura Privacy Pass](https://www.rfc-editor.org/rfc/rfc9576.html) and [RFC 9577 — Privacy Pass HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html)
- [19] [ERC-4337 — Account Abstraction tramite un Mempool alternativo](https://eips.ethereum.org/EIPS/eip-4337) and [Ethereum.org — Privacy application architecture](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [20] [BIP 47 — Reusable Payment Code](https://bips.dev/47/) and [BIP 351 — Private Payments](https://bips.dev/351/)
- [21] [ERC-5564 — Stealth Address](https://eips.ethereum.org/EIPS/eip-5564)
- [22] [Liquid — Confidential Transaction](https://docs.liquid.net/docs/confidential-transactions)
- [23] [Ethereum.org — State e payment channel](https://ethereum.org/developers/docs/scaling/state-channels/)
- [24] [GSMA Open Gateway — Carrier Billing API](https://open-gateway.gsma.com/docs/carrier-billing/api-reference)
- [25] [Open Banking Standards — Payment Initiation Service](https://standards.openbanking.org.uk/customer-experience-guidelines/payment-initiation-services/v4-0/)
- [26] [Apple Developer — StoreKit](https://developer.apple.com/documentation/storekit/)
