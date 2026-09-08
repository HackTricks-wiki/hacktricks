# Protocolli di pagamento che preservano la privacy

{{#include ../banners/hacktricks-training.md}}

I sistemi di pagamento avanzati possono nascondere il pagatore al merchant, nascondere un destinatario o un importo da un ledger pubblico oppure impedire a una mint di collegare un prelievo a un riscatto. Si tratta di proprietà diverse. Nessuna elimina i record relativi ad acquisizione, dispositivo, rete, consegna, contabilità, sanzioni o endpoint.

Il [Catalogo delle tecniche di pagamento anonimo](anonymous-payment-techniques.md) fornisce una voce standardizzata `Pros`, `Cons`, `Procedure` passo-passo e `Detection` per ogni famiglia di pagamenti. Questa pagina approfondisce i protocolli avanzati.

{% hint style="danger" %}
Utilizza esclusivamente fondi e controparti leciti. Non utilizzare protocolli di privacy per eludere gli obblighi di identificazione, sanzioni, imposte, verifiche sull'origine dei fondi o segnalazione delle transazioni. Non gestire un exchange, una mint o un servizio di trasmissione senza comprendere gli obblighi relativi a licenze, custodia, AML e tutela dei consumatori.
{% endhint %}

## Confronto tra le opzioni avanzate

| Protocollo | Cosa nasconde al pubblico/merchant | Parte fidata o che osserva | Maturità/disponibilità |
|---|---|---|---|
| Bitcoin Silent Payments (BIP 352) | Gli osservatori esterni non possono collegare un payment code riutilizzabile ai relativi output monouso | Il grafo pubblico di Bitcoin rimane; il wallet/index server può vedere le scansioni | Specifica completa; il supporto dei wallet varia |
| Zcash completamente shielded Orchard | Mittente, destinatario e importo sono cifrati on-chain | Il backend/network del wallet e l'acquisizione/off-ramp rimangono visibili | Implementato; il supporto shielded varia tra wallet/exchange |
| GNU Taler | Il merchant non deve conoscere l'identità del pagatore; i ricavi del merchant rimangono rendicontabili | L'exchange/banca Taler vede il finanziamento; il merchant vede l'ordine | Le implementazioni sono geograficamente limitate |
| Federated Chaumian e-cash | La federation non dovrebbe collegare le note emesse ai trasferimenti/riscatti interni | Il quorum dei guardian custodisce le riserve; i gateway vedono l'attività ai confini | Implementazioni community emergenti |
| Lightning BOLT 12/route blinding | Riduce la divulgazione di destinatario/node e route | Endpoint, hop selezionati, funding chain e wallet services | Il supporto dipende dal wallet |
| Virtual card/token | Il merchant riceve una credenziale vincolata, non un PAN riutilizzabile | Issuer/network conservano pagatore e transazione | Maturo e ampiamente disponibile |

## Bitcoin Silent Payments (BIP 352)

Silent Payments consente a un destinatario di pubblicare un unico payment code statico, mentre ogni mittente deriva un output Taproot univoco. Un osservatore esterno della chain non può collegare direttamente tali output al code pubblicato e non è necessaria alcuna richiesta interattiva di indirizzo né un output di notifica on-chain. BIP 352 è contrassegnato come **Complete**, ma introduce un costo di scansione ed è incompatibile con i wallet che non lo hanno implementato.<sup>[[1]](#references)</sup>

### Workflow del destinatario

1. Seleziona un wallet mantenuto attivamente che supporti esplicitamente la ricezione BIP 352; verifica la funzionalità nella documentazione attuale del wallet, non in un'affermazione sui social media.
2. Esegui il backup del seed del wallet e del materiale relativo a descriptor/key di Silent Payment utilizzando il metodo di recovery documentato dal wallet. Testa la discovery con un piccolo importo su testnet/mainnet prima di pubblicare il code.
3. Genera **labels** separate per campagne, fatture o controparti quando il wallet supporta le labels BIP 352. Le labels aiutano la contabilità locale senza pubblicare indirizzi collegabili.
4. Pubblica il code statico di Silent Payment tramite un canale autenticato. È riutilizzabile, ma un impostore può sostituirlo con il proprio code.
5. Esegui la scansione tramite un full node locale quando possibile. Un server di indicizzazione/scansione di terze parti può apprendere i tempi delle richieste o i dati dei filtri, anche se non può effettuare spese.
6. Mantieni gli UTXO scoperti con le relative labels e applica le stesse regole di coin control del Bitcoin ordinario. Spenderli o consolidarli può rivelare relazioni di proprietà.
7. Verifica che il recovery individui i pagamenti senza dipendere da un indice esterno di cui non è stato eseguito il backup.

### Workflow del mittente

1. Verifica che il wallet supporti l'invio alla versione dell'indirizzo e autentica il code statico lungo del destinatario.
2. Lascia che sia il wallet a costruire l'output; non convertire né troncare manualmente il code.
3. Esamina attentamente gli input selezionati. Silent Payments migliora la privacy dell'indirizzo del destinatario, ma gli input del mittente rimangono nel grafo pubblico.
4. Utilizza il fee bumping/il comportamento PSBT supportato dal wallet. BIP 352 richiede una nuova derivazione dell'output se gli input cambiano e alcune modalità di signing non sono sicure.
5. Conserva una ricevuta o una prova cifrata necessaria per controversie o contabilità.

Silent Payments risolve il problema della pubblicazione ripetuta dell'indirizzo del destinatario. Non nasconde l'importo, i tempi della transazione, il cluster del mittente, la cronologia di acquisizione o la successiva co-spesa.

## Pagamenti Zcash completamente shielded

Zcash supporta pool di valore transparent e shielded. Le transazioni shielded Orchard utilizzano zero-knowledge proofs, consentendo ai nodi di verificare la validità mentre i dettagli della transazione sono cifrati; gli Unified Addresses possono contenere più tipi di destinatario.<sup>[[2]](#references)</sup> La privacy dipende dal percorso effettivamente selezionato dal wallet, non dal primo carattere dell'indirizzo visualizzato.

### Workflow shielded

1. Scegli un wallet mantenuto attivamente che identifichi chiaramente il comportamento **shielded-by-default** e il supporto Orchard attuale. Verifica il download ed esegui il backup/test del seed.
2. Ottieni ZEC legalmente e registra base/origine. Un exchange conosce comunque l'acquisizione e il withdrawal.
3. Ricevi verso un Unified Address supportato dal wallet, quindi verifica se la transazione è finita in un pool shielded. Non presumere lo shielding automatico senza confermare il comportamento del wallet.
4. Preferisci i trasferimenti **shielded-to-shielded**. I movimenti transparent-to-shielded e shielded-to-transparent ai confini espongono valori/tempi pubblici e possono consentire la correlazione degli importi; la specifica Orchard osserva che una spesa verso un indirizzo non-Orchard rivela il valore della transazione.<sup>[[3]](#references)</sup>
5. Evita round trip con importi esatti distintivi e attraversamenti immediati dei confini. Si tratta di igiene della privacy, non di un'autorizzazione a oscurare la proprietà o la rendicontazione.
6. Utilizza il percorso di network privacy supportato dal wallet. La crittografia shielded non nasconde IP/tempi ai wallet server o ai peer.
7. Conserva i record interni di compliance e utilizza le viewing key solo per audit/disclosure deliberati, dopo averne compreso l'ambito.
8. Conferma il supporto del wallet/exchange del destinatario prima dell'invio; un destinatario transparent imposto modifica la proprietà di privacy.

## GNU Taler: pagatore anonimo, merchant rendicontabile

GNU Taler è un protocollo open di pagamento elettronico che utilizza valute tradizionali, blind signatures e l'integrazione con exchange/banca regolamentati. Il suo design mira a mantenere anonimi i clienti nei confronti dei merchant, mentre i merchant rimangono identificabili e soggetti a imposte.<sup>[[4]](#references)</sup> Non è una cryptocurrency e la disponibilità dipende da un exchange regionale compatibile, una banca, un wallet e un merchant.

### Workflow dell'utente dove disponibile

1. Identifica un exchange Taler operativo e un merchant nella valuta/giurisdizione pertinente; leggi i termini attuali, le commissioni, le informazioni KYC e le informative sulla privacy.
2. Installa il wallet ufficiale e verifica la sua origine. Proteggi i dati di backup/recovery del wallet come denaro contante, perché il valore del wallet può essere un bearer asset.
3. Preleva il valore tramite il flusso banca/exchange supportato utilizzando informazioni veritiere. L'istituto di finanziamento/exchange può conoscere il withdrawal, anche se le blind signatures interrompono il collegamento diretto tra coin e withdrawal.
4. Esamina il merchant contract nel wallet: identità del merchant, articolo/riepilogo, importo, commissioni, rimborso e condizioni di consegna.
5. Paga e conserva i dati della ricevuta necessari per rimborso, garanzia, contabilità o imposte.
6. Non riutilizzare identificatori opzionali di sessione/account del merchant se è richiesta l'unlinkability nei confronti del merchant.
7. Mantieni nel threat model i metadati del wallet, della rete e della consegna; la crittografia di pagamento di Taler non nasconde un indirizzo di spedizione o un endpoint compromesso.

Il merchant e l'exchange rimangono responsabili e la gestione di uno dei due componenti può costituire un'attività regolamentata di servizi di pagamento.

## Federated Chaumian e-cash

Chaumian e-cash utilizza blind signatures affinché una mint firmi un token senza vedere il token non blinding speso successivamente. Fedimint distribuisce la custodia delle riserve e il signing tra una guardian federation; la sua documentazione afferma che i guardian vedono le riserve aggregate/le note in circolazione, ma non dovrebbero vedere il saldo individuale né chi ha pagato chi all'interno della federation.<sup>[[5]](#references)</sup>

Si tratta di **valore bearer custodial**. Un quorum sufficiente di guardian controlla le riserve; il malfunzionamento della federation, guardian disonesti, bug software o la perdita dello stato client possono causare una perdita. Depositi, withdrawal e gateway Lightning sono eventi di confine visibili e possono correlare tempi/importi.

### Workflow a rischio limitato

1. Utilizza solo un piccolo importo che puoi permetterti di perdere. Considera le federation pubbliche/sconosciute più rischiose rispetto a guardian con una responsabilità nel mondo reale.
2. Verifica l'invito alla federation tramite un canale autenticato e registra identità dei guardian, quorum, giurisdizione, commissioni, recovery e policy di chiusura.
3. Installa un wallet compatibile mantenuto attivamente, verificalo e comprendi il suo schema di backup prima di depositare.
4. Deposita Bitcoin acquisiti legalmente tramite il percorso documentato. Registra il peg-in per la contabilità e considera pubblici o noti al confine i relativi tempi/importi.
5. All'interno della federation, utilizza payment request fresche ed evita di aggiungere identificatori di account/chat/consegna che ricreino il collegamento rimosso dalla blind signature.
6. Per i pagamenti Lightning, considera il gateway un osservatore aggiuntivo delle invoice e dei tempi al confine.
7. Esegui il redeem/withdraw secondo la policy, aspettandoti che un importo distintivo e tempi immediati possano essere correlati a un deposito o a un pagamento esterno.
8. Conserva privatamente i record fiscali, di origine e di autorizzazione; non chiedere ai guardian o ai gateway di dichiarare erroneamente l'attività.

Non descrivere il federated e-cash come trustless, self-custodial o anonimo garantito.

## BOLT 12 offers e route blinding

Le BOLT 12 offers possono essere riutilizzabili senza pubblicare un indirizzo on-chain stabile e possono utilizzare blinded paths, in modo che il pagatore non debba conoscere l'identità o il percorso clear del node del destinatario. Questo integra, ma non sostituisce, l'onion routing già esistente di Lightning.

Prima dell'uso:

1. Conferma che i wallet del mittente e del destinatario supportino le stesse funzionalità BOLT 12 attuali; non dedurre il supporto dal generico branding “Lightning”.
2. Autentica l'offer out of band e controlla importo, issuer/descrizione e regole di ricorrenza.
3. Utilizza un contesto invoice/payment fresco generato dall'offer.
4. Mantieni al minimo gli alias dei node, le informazioni di contatto pubbliche e gli endpoint di rete stabili.
5. Presumi che mittente/destinatario, primo/ultimo hop, wallet service, grafo dei canali e funding/chiusura on-chain divulghino comunque parti della relazione.

## Auditabilità senza divulgazione pubblica

Privacy e audit possono coesistere:

- Conserva labels, invoice, autorizzazione, cost basis e mapping della proprietà in forma cifrata al di fuori del protocollo pubblico.
- Separa una **view/audit key** da una spending key quando il protocollo ne fornisce una; testa prima la sua divulgazione esatta su un wallet di esempio.
- Fornisci all'auditor la prova con il minimo ambito necessario, non un seed o una credenziale di spesa senza restrizioni.
- Registra versione del software, protocollo/pool, transaction ID o proof, finalità della controparte e fonte del tasso di cambio al momento della transazione.
- Definisci conservazione e cancellazione invece di accumulare un identity graph permanente non cifrato.

## Checklist di selezione

- [ ] Il campo nascosto e l'osservatore sono indicati con precisione.
- [ ] Il supporto di wallet/protocollo è stato verificato alla data della transazione.
- [ ] Sono documentati i collegamenti relativi ad acquisizione, rete, node/RPC, controparte, consegna e spesa successiva.
- [ ] Sono accettati i rischi relativi a custodia, recovery, liquidità, solvibilità di issuer/federation e rimborsi.
- [ ] I record obbligatori relativi a identità, imposte, sanzioni, origine e organizzazione rimangono accurati.
- [ ] Un piccolo test end-to-end, incluso recovery e audit proof, è andato a buon fine.

## References

- [1] [BIP 352 — Pagamenti silenziosi](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
- [2] [Zcash — Indirizzi unificati](https://z.cash/learn/what-are-zcash-unified-addresses/) and [The Orchard Book — Keys and addresses](https://zcash.github.io/orchard/design/keys.html)
- [3] [ZIP 224 — Protocollo shielded Orchard](https://zips.z.cash/zip-0224)
- [4] [Documentazione GNU Taler](https://docs.taler.net/) and [Merchant Manual — About GNU Taler](https://docs.taler.net/taler-merchant-manual.html)
- [5] [Fedimint — Come funziona](https://fedimint.org/users/how-it-works), [How federations work](https://fedimint.org/guardians/how-federations-work), and [Threshold blind signatures](https://docs.fedimint.org/crypto/index.html)
- [6] [BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
{{#include ../banners/hacktricks-training.md}}
