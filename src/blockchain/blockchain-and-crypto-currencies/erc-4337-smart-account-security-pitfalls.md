# Problemi di sicurezza degli Smart Account ERC-4337

{{#include ../../banners/hacktricks-training.md}}

L'account abstraction di ERC-4337 trasforma i wallet in sistemi programmabili. Il flusso principale segue il modello **validate-then-execute** per l'intero bundle: `EntryPoint` valida ogni `UserOperation` prima di eseguirne una qualsiasi. Questo ordine crea una superficie d'attacco non ovvia quando la validazione è permissiva, stateful o incoerente con le regole di simulazione del bundler.

## 1) Bypass tramite chiamata diretta di funzioni privilegiate
Qualsiasi funzione `execute` chiamabile esternamente (o qualsiasi funzione che trasferisca fondi) non limitata a `EntryPoint` (o a un modulo executor verificato) può essere chiamata direttamente per svuotare l'account.<sup>[[1]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Pattern sicuro: limita a `EntryPoint` e usa `msg.sender == address(this)` per i flussi di amministrazione/auto-gestione (installazione di moduli, modifiche ai validator, upgrade).
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Campi gas non firmati o non verificati -> drenaggio delle fee
Se la validazione della firma copre solo l'intento (`callData`), ma non i campi relativi al gas, un bundler o un frontrunner può gonfiare le fee e drenare ETH. Il payload firmato deve includere almeno:<sup>[[1]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Pattern difensivo: usare lo `userOpHash` fornito da `EntryPoint` (che include i campi relativi al gas) e/o imporre un limite rigido a ciascun campo.<sup>[[1]](#references)</sup>
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(_isApprovedCall(userOpHash, op.signature), "bad sig");
return 0;
}
```
## 3) Stateful validation clobbering (semantica del bundle)
Poiché tutte le validation vengono eseguite prima di qualsiasi execution, memorizzare i risultati della validation nello state del contract non è sicuro. Un'altra op nello stesso bundle può sovrascriverli, facendo sì che la tua execution utilizzi uno state controllato dall'attacker.<sup>[[1]](#references)</sup>

Evita di scrivere nello storage in `validateUserOp`. Se è inevitabile, indicizza i dati temporanei tramite `userOpHash` ed eliminali deterministically dopo l'uso (preferibilmente usa una validation stateless).<sup>[[1]](#references)</sup>

## 4) Replay ERC-1271 tra account e chain (domain separation mancante)
`isValidSignature(bytes32 hash, bytes sig)` deve associare le signature a **questo contract** e a **questa chain**. Eseguire il recover su un raw hash consente il replay delle signature tra account o chain.<sup>[[1]](#references)</sup>

Usa typed data EIP-712 (il domain include `verifyingContract` e `chainId`) e restituisci l'esatto magic value ERC-1271 `0x1626ba7e` in caso di successo.<sup>[[1]](#references)</sup>

## 5) I revert non rimborsano dopo la validation
Una volta che `validateUserOp` ha successo, le fee sono impegnate anche se l'execution eseguita successivamente va in revert. Gli attacker possono inviare ripetutamente op che falliranno e continuare comunque a riscuotere le fee dall'account.<sup>[[1]](#references)</sup>

Per i paymaster, pagare da un pool condiviso in `validateUserOp` e addebitare gli utenti in `postOp` è fragile, perché `postOp` può andare in revert senza annullare il pagamento. Metti in sicurezza i fondi durante la validation (escrow/deposit per utente), mantieni `postOp` minimale e non-reverting, e prevedi un `paymasterPostOpGasLimit` sufficiente per il reimbursement path nel caso peggiore.<sup>[[1]](#references)</sup>

## 6) Deployment counterfactual / assunzioni sulla factory
La prima `UserOperation` spesso contiene `initCode`, che fa sì che l'account venga deployed tramite una **factory** durante la validation. Questo path è facile da sottoporre a un audit insufficiente, perché viene eseguito solo al primo utilizzo.<sup>[[2]](#references)</sup>

Failure comuni:

- La factory/initializer si basa su `msg.sender == entryPoint`, ma il deployment path di ERC-4337 **non** chiama `initCode` direttamente da `EntryPoint`.
- Il salt, l'owner, il validator o la configurazione del module non sono completamente associati all'intento firmato, quindi un frontrunner può competere per il primo deployment e occupare l'indirizzo counterfactual con impostazioni controllate dall'attacker.
- La factory non è idempotent, quindi un flow ripetuto al primo utilizzo blocca il wallet invece di restituire l'indirizzo già creato.

Pattern sicuro: ricalcola il sender previsto dai parametri di deployment firmati, rendi il deployment deterministico (in genere `CREATE2`) e fai in modo che l'initialization possa avvenire una sola volta.<sup>[[2]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Logica di validazione rifiutata dai bundler
Il codice di validazione può essere corretto nei test locali e risultare comunque inutilizzabile nei bundler reali. I bundler pubblici simulano `validateUserOp()` / `validatePaymasterUserOp()` off-chain ed eseguono comunemente un `debug_traceCall(handleOps)` completo prima dell'inclusione.

Questo rende pericolosi questi pattern durante la validazione:

- Opcode dipendenti dal blocco come `TIMESTAMP`, `NUMBER` o `BLOCKHASH`
- Scritture nello stato come `SSTORE`
- Iterazioni non vincolate sullo storage
- Chiamate esterne arbitrarie o letture da oracle che possono cambiare tra la simulazione e l'inclusione

Esempio errato:
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
Tratta la validazione come una funzione di preflight deterministica e con limiti definiti. Se hai davvero bisogno di stato condiviso o di lookup esterni, trasferisci questa complessità in entità con stake e tracciamento della reputazione e testa l'esatto percorso di simulazione del bundler, non solo gli unit tests.

## 8) ERC-7702 initialization frontrun
ERC-7702 consente a un EOA di eseguire smart-account code per una singola tx. Se l'inizializzazione è richiamabile esternamente, un frontrunner può impostare se stesso come owner.<sup>[[1]](#references)</sup>

Mitigazione: consenti l'inizializzazione solo tramite **self-call** e una sola volta.<sup>[[1]](#references)</sup>
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Controlli rapidi pre-merge
- Validate le firme usando `userOpHash` di `EntryPoint` (associa i campi del gas).
- Limita le funzioni privilegiate a `EntryPoint` e/o `address(this)` come appropriato.
- Mantieni `validateUserOp` stateless, deterministico e compatibile con le regole di simulazione del bundler.
- Applica la domain separation EIP-712 per ERC-1271 e restituisci `0x1626ba7e` in caso di successo.
- Mantieni `postOp` minimale, limitato e non-reverting; proteggi le fee durante la validazione.
- Testa separatamente il primo percorso `initCode`: deployment deterministico, comportamento idempotente della factory e inizializzazione one-shot.
- Esegui una simulazione completa del bundler (`simulateValidation` più un `handleOps` tracciato) prima del rilascio.
- Per ERC-7702, consenti l'init solo su self-call e una sola volta.



## Riferimenti

- [1] [Sei errori negli smart account ERC-4337 (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [2] [ERC-4337: Account Abstraction Using Alt Mempool](https://eips.ethereum.org/EIPS/eip-4337)

{{#include ../../banners/hacktricks-training.md}}
