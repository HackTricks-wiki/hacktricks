# Problemi di sicurezza degli Smart Account ERC-4337

{{#include ../../banners/hacktricks-training.md}}

L'account abstraction di ERC-4337 trasforma i wallet in sistemi programmabili. Il flusso principale segue il modello **validate-then-execute** per un intero bundle: `EntryPoint` valida ogni `UserOperation` prima di eseguirne una qualsiasi. Questo ordine crea una superficie di attacco non ovvia quando la validazione è permissiva, stateful o incoerente con le regole di simulazione dei bundler.

## 1) Bypass tramite chiamata diretta delle funzioni privilegiate
Qualsiasi funzione `execute` (o che trasferisce fondi) chiamabile esternamente e non limitata a `EntryPoint` (o a un modulo executor verificato) può essere chiamata direttamente per svuotare l'account.<sup>[[1]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Pattern sicuro: limita a `EntryPoint` e usa `msg.sender == address(this)` per i flussi di amministrazione/autogestione (installazione di moduli, modifiche dei validator, upgrade).
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Campi gas non firmati o non verificati -> drenaggio delle fee
Se la validazione della signature copre solo l'intento (`callData`), ma non i campi relativi al gas, un bundler o un frontrunner può gonfiare le fee e drenare ETH. Il payload firmato deve includere almeno:<sup>[[1]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Defensive pattern: usa lo `userOpHash` fornito da `EntryPoint` (che include i campi del gas) e/o imposta un limite rigido per ciascun campo.<sup>[[1]](#references)</sup>
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(_isApprovedCall(userOpHash, op.signature), "bad sig");
return 0;
}
```
## 3) Stateful validation clobbering (bundle semantics)
Poiché tutte le validazioni vengono eseguite prima di qualsiasi esecuzione, salvare i risultati della validazione nello stato del contratto non è sicuro. Un'altra op nello stesso bundle può sovrascriverli, facendo sì che l'esecuzione utilizzi uno stato influenzato dall'attacker.<sup>[[1]](#references)</sup>

Evita di scrivere nello storage in `validateUserOp`. Se è inevitabile, indicizza i dati temporanei per `userOpHash` ed eliminali in modo deterministico dopo l'uso (preferibilmente utilizzando una validazione stateless).<sup>[[1]](#references)</sup>

## 4) ERC-1271 replay across accounts/chains (missing domain separation)
`isValidSignature(bytes32 hash, bytes sig)` deve associare le signature a **questo contratto** e a **questa chain**. Eseguire il recupero su un hash raw consente il replay delle signature tra account o chain.<sup>[[1]](#references)</sup>

Utilizza dati tipizzati EIP-712 (il domain include `verifyingContract` e `chainId`) e restituisci l'exact magic value ERC-1271 `0x1626ba7e` in caso di successo.<sup>[[1]](#references)</sup>

## 5) Reverts do not refund after validation
Una volta che `validateUserOp` ha successo, le fee sono impegnate anche se l'esecuzione successivamente va in revert. Gli attacker possono inviare ripetutamente op che falliranno e riscuotere comunque le fee dall'account.<sup>[[1]](#references)</sup>

Per i paymaster, pagare da un pool condiviso in `validateUserOp` e addebitare gli utenti in `postOp` è fragile, perché `postOp` può andare in revert senza annullare il pagamento. Proteggi i fondi durante la validazione (escrow/deposit per utente), mantieni `postOp` minimale e non-reverting e prevedi un `paymasterPostOpGasLimit` sufficiente per il percorso di reimbursement nel caso peggiore.<sup>[[1]](#references)</sup>

## 6) Counterfactual deployment / factory assumptions
La prima `UserOperation` spesso contiene `initCode`, causando il deployment dell'account tramite una **factory** durante la validazione. Questo percorso è facile da sottoporre a un audit insufficiente perché viene eseguito solo al primo utilizzo.<sup>[[2]](#references)</sup>

Common failures:

- La factory/initializer si fida di `msg.sender == entryPoint`, ma il percorso di deployment ERC-4337 **non** chiama direttamente `initCode` da `EntryPoint`.
- Il salt, il owner, il validator o la configurazione del module non sono completamente associati all'intent firmato, quindi un frontrunner può anticipare il primo deployment e occupare l'indirizzo counterfactual con impostazioni controllate dall'attacker.
- La factory non è idempotent, quindi un flusso ripetuto al primo utilizzo blocca il wallet invece di restituire l'indirizzo già creato.

Safe pattern: ricalcola il sender atteso a partire dai parametri di deployment firmati, rendi il deployment deterministico (solitamente tramite `CREATE2`) e fai in modo che l'inizializzazione avvenga una sola volta.<sup>[[2]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Logica di validazione che i bundler rifiutano
Il codice di validazione può essere corretto nei test locali e risultare comunque inutilizzabile nei bundler reali. I bundler pubblici simulano `validateUserOp()` / `validatePaymasterUserOp()` off-chain e comunemente eseguono un `debug_traceCall(handleOps)` completo prima dell'inclusione.<sup>[[3]](#references)</sup>

Questo rende pericolosi questi pattern all'interno della validazione:

- Opcode dipendenti dal blocco come `TIMESTAMP`, `NUMBER` o `BLOCKHASH`
- Scritture nello state come `SSTORE`
- Iterazioni non limitate sullo storage
- Chiamate esterne arbitrarie o letture da oracle che possono cambiare tra la simulazione e l'inclusione

Esempio non valido:
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(block.timestamp < expiry, "expired");
seen[userOpHash] = true; // SSTORE in validation
require(oracle.isAllowed(op.sender), "oracle changed");
return 0;
}
```
Tratta la validazione come una funzione di preflight deterministica e vincolata. Se hai davvero bisogno di stato condiviso o di lookup esterni, sposta questa complessità in entità con stake e reputazione monitorata, quindi testa l'exact bundler simulation path, non solo gli unit test.

## 8) Frontrun dell'inizializzazione ERC-7702
ERC-7702 consente a un EOA di eseguire codice di smart account per una singola tx. Se l'inizializzazione è chiamabile esternamente, un frontrunner può impostare se stesso come owner.<sup>[[1]](#references)</sup>

Mitigazione: consenti l'inizializzazione solo tramite **self-call** e una sola volta.<sup>[[1]](#references)</sup>
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Controlli rapidi pre-merge
- Convalida le firme usando `userOpHash` di `EntryPoint` (associa i campi relativi al gas).
- Limita le funzioni privilegiate a `EntryPoint` e/o `address(this)`, secondo necessità.
- Mantieni `validateUserOp` stateless, deterministica e compatibile con le regole di simulazione del bundler.
- Applica la domain separation EIP-712 per ERC-1271 e restituisci `0x1626ba7e` in caso di successo.
- Mantieni `postOp` minimale, con limiti definiti e senza revert; proteggi le fee durante la validazione.
- Testa separatamente il primo percorso `initCode`: deployment deterministico, comportamento idempotente della factory e inizializzazione eseguibile una sola volta.
- Esegui una simulazione completa del bundler (`simulateValidation` più un `handleOps` tracciato) prima del rilascio.
- Per ERC-7702, consenti l'init solo durante una self-call e una sola volta.

## Riferimenti

- [1] [Sei errori negli smart account ERC-4337 (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [2] [ERC-4337: Account Abstraction Using Alt Mempool](https://eips.ethereum.org/EIPS/eip-4337)
- [3] [ERC-7562: Account Abstraction Validation Scope Rules](https://eips.ethereum.org/EIPS/eip-7562)

{{#include ../../banners/hacktricks-training.md}}
