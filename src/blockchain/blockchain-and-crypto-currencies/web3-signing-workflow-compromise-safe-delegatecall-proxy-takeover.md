# Compromissione del workflow di signing Web3 e takeover del proxy Safe Delegatecall

## Panoramica

Una catena di furto da cold-wallet ha combinato una **compromissione supply-chain della web UI di Safe{Wallet}** con una **primitiva on-chain di delegatecall che sovrascriveva il puntatore all’implementazione di un proxy (slot 0)**. I punti chiave sono:

- Se una dApp può iniettare codice nel percorso di signing, può fare in modo che un signer produca una **firma EIP-712 valida su campi scelti dall’attaccante**, ripristinando al contempo i dati originali della UI affinché gli altri signer non si accorgano di nulla.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
- I proxy Safe memorizzano `masterCopy` (implementazione) nello **storage slot 0**. Una delegatecall a un contratto che scrive nello slot 0 effettua di fatto un “upgrade” del Safe alla logica dell’attaccante, ottenendo il pieno controllo del wallet.<sup>[[3]](#references)</sup>

## Off-chain: mutazione mirata del signing in Safe{Wallet}

Un bundle di Safe manomesso (`_app-*.js`) attaccava selettivamente specifici indirizzi Safe + signer. La logica iniettata veniva eseguita subito prima della chiamata di signing:<sup>[[1]](#references)[[3]](#references)</sup>
```javascript
// Pseudocode of the malicious flow
orig = structuredClone(tx.data);
if (isVictimSafe && isVictimSigner && tx.data.operation === 0) {
tx.data.to = attackerContract;
tx.data.data = "0xa9059cbb...";      // ERC-20 transfer selector
tx.data.operation = 1;                 // delegatecall
tx.data.value = 0;
tx.data.safeTxGas = 45746;
const sig = await sdk.signTransaction(tx, safeVersion);
sig.data = orig;                       // restore original before submission
tx.data = orig;
return sig;
}
```
### Proprietà dell'attacco
- **Context-gated**: le allowlist hard-coded per le Safe/firmatari vittima hanno impedito il noise e ridotto il rilevamento.<sup>[[1]](#references)[[3]](#references)</sup>
- **Last-moment mutation**: i campi (`to`, `data`, `operation`, gas) venivano sovrascritti immediatamente prima di `signTransaction`, per poi essere ripristinati, così i payload delle proposal nell'UI apparivano benigni mentre le firme corrispondevano al payload dell'attaccante.<sup>[[3]](#references)</sup>
- **EIP-712 opacity**: i wallet mostravano dati strutturati, ma non decodificavano il calldata annidato né evidenziavano `operation = delegatecall`, rendendo il messaggio mutato di fatto blind-signed.<sup>[[3]](#references)[[4]](#references)</sup>

### Rilevanza della validazione del Gateway
Le proposal Safe vengono inviate al **Safe Client Gateway**.<sup>[[5]](#references)</sup> Prima dell'introduzione di controlli più rigorosi, il gateway poteva accettare una proposal in cui `safeTxHash`/firma corrispondevano a campi diversi da quelli del JSON body se l'UI li riscriveva dopo la firma. Dopo l'incident, il gateway ora rifiuta le proposal il cui hash/firma non corrisponde alla transazione inviata.<sup>[[3]](#references)</sup> Una verifica server-side analoga dell'hash dovrebbe essere applicata a qualsiasi API di signing orchestration.

### Punti salienti dell'incident Bybit/Safe del 2025
- Il drain del cold-wallet di Bybit del 21 febbraio 2025 (~401k ETH) ha riutilizzato lo stesso pattern: un bundle S3 di Safe compromesso si attivava solo per i firmatari Bybit e cambiava `operation=0` → `1`, indirizzando `to` verso un contratto dell'attaccante pre-deployed che scrive nello slot 0.<sup>[[1]](#references)[[3]](#references)</sup>
- `_app-52c9031bfa03da47.js`, memorizzato nella cache di Wayback, mostra una logica basata sulla Safe di Bybit (`0x1db9…cf4`) e sugli indirizzi dei firmatari, quindi ripristinata immediatamente a un bundle pulito due minuti dopo l'esecuzione, replicando il trucco “mutate → sign → restore”.<sup>[[1]](#references)[[2]](#references)</sup>
- Il contratto malevolo (ad esempio `0x9622…c7242`) conteneva semplici funzioni `sweepETH/sweepERC20` e una `transfer(address,uint256)` che scrive nello slot dell'implementazione. L'esecuzione di `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` spostava l'implementazione della proxy e concedeva il controllo completo.<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain: takeover della proxy tramite Delegatecall e collisione degli slot

Le proxy Safe mantengono `masterCopy` nello **storage slot 0** e delegano tutta la logica a esso. Poiché Safe supporta **`operation = 1` (delegatecall)**, qualsiasi transazione firmata può puntare a un contratto arbitrario ed eseguire il suo codice nel contesto di storage della proxy.<sup>[[3]](#references)</sup>

Un contratto dell'attaccante imitava un `transfer(address,uint256)` ERC-20, ma scriveva invece `_to` nello slot 0:<sup>[[1]](#references)[[3]](#references)</sup>
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Percorso di esecuzione:<sup>[[1]](#references)[[3]](#references)</sup>
1. Le vittime firmano `execTransaction` con `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`.
2. Il masterCopy di Safe convalida le firme su questi parametri.
3. Il proxy esegue una delegatecall verso `attackerContract`; il corpo di `transfer` scrive nello slot 0.
4. Lo slot 0 (`masterCopy`) ora punta a una logica controllata dall'attaccante → **presa di controllo completa del wallet e drenaggio dei fondi**.

### Note su guard e versioni (hardening post-incidente)
- I transaction guard sono stati introdotti in Safe v1.3.0 e possono esaminare tutti i parametri di `execTransaction` prima dell'esecuzione; un guard può rifiutare `delegatecall` o applicare policy sulla destinazione e sul calldata. Bybit utilizzava la v1.1.1, che precede questo hook.<sup>[[2]](#references)[[6]](#references)</sup>

## Checklist di rilevamento e hardening

- **Integrità della UI**: bloccare gli asset JS / SRI; monitorare le differenze tra i bundle; considerare la signing UI parte del trust boundary.
- **Convalida al momento della firma**: hardware wallet con **clear-signing EIP-712**; visualizzare esplicitamente `operation` e decodificare il calldata annidato. Rifiutare la firma quando `operation = 1`, a meno che la policy non lo consenta.<sup>[[3]](#references)</sup>
- **Controlli degli hash lato server**: i gateway/servizi che inoltrano le proposte devono ricalcolare `safeTxHash` e verificare che le firme corrispondano ai campi inviati.<sup>[[3]](#references)</sup>
- **Policy/allowlist**: regole di preflight per `to`, selector e tipi di asset, vietando delegatecall eccetto nei flussi verificati. Richiedere un servizio di policy interno prima di trasmettere transazioni completamente firmate.
- **Progettazione dei contratti**: evitare di esporre delegatecall arbitrari nei wallet multisig/di tesoreria, salvo stretta necessità. Considerare qualsiasi puntatore all'implementazione una primitiva di upgrade: proteggerlo con controlli di accesso espliciti e applicare guard ai target/selector di delegatecall; spostare il puntatore in un altro slot, da solo, non costituisce una difesa completa.<sup>[[3]](#references)[[6]](#references)</sup>
- **Monitoraggio**: generare alert sulle esecuzioni di delegatecall provenienti da wallet che detengono fondi di tesoreria e sulle proposte che modificano `operation` rispetto ai pattern tipici di `call`.

## References

- [1] [Analisi forense di AnChain.AI dell'exploit di Bybit Safe](https://www.anchain.ai/blog/bybit)
- [2] [Analisi di Zero Hour Technology della compromissione del bundle Safe](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [Analisi tecnica approfondita dell'hack di Bybit (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)
- [6] [Changelog di Safe smart account v1.3.0 (GitHub)](https://github.com/safe-fndn/safe-smart-account/blob/main/CHANGELOG.md)
{{#include ../../banners/hacktricks-training.md}}
