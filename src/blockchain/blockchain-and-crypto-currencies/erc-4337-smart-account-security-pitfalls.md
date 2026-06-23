# ERC-4337 Smart Account Security Pitfalls

{{#include ../../banners/hacktricks-training.md}}

ERC-4337 account abstraction trasforma i wallet in sistemi programmabili. Il flusso principale è **validate-then-execute** su un intero bundle: `EntryPoint` valida ogni `UserOperation` prima di eseguire una qualsiasi di esse. Questo ordinamento crea una superficie d'attacco non ovvia quando la validation è permissiva, stateful, o inconsistente con le regole di simulazione del bundler.

## 1) Direct-call bypass of privileged functions
Any externally callable `execute` (or fund-moving) function that is not restricted to `EntryPoint` (or a vetted executor module) can be called directly to drain the account.
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Pattern sicuro: limita a `EntryPoint`, e usa `msg.sender == address(this)` per i flussi di admin/self-management (installazione module, modifiche validator, upgrade).
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Campi gas non firmati o non verificati -> fee drain
Se la validazione della signature copre solo l’intento (`callData`) ma non i campi legati al gas, un bundler o un frontrunner può gonfiare le fee e drenare ETH. Il payload firmato deve vincolare almeno:

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Pattern difensivo: usa il `userOpHash` fornito da `EntryPoint` (che include i campi gas) e/o limita in modo rigoroso ogni campo.
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
Poiché tutte le validazioni vengono eseguite prima di qualsiasi execution, memorizzare i risultati della validation nello state del contract non è sicuro. Un’altra op nello stesso bundle può sovrascriverli, causando l’uso, da parte della tua execution, di state influenzato dall’attaccante.

Evita di scrivere storage in `validateUserOp`. Se è inevitabile, indicizza i dati temporanei con `userOpHash` ed eliminali in modo deterministico dopo l’uso (preferisci validation stateless).

## 4) ERC-1271 replay across accounts/chains (missing domain separation)
`isValidSignature(bytes32 hash, bytes sig)` deve vincolare le signature a **questo contract** e a **questa chain**. Fare recovery su un raw hash permette alle signature di essere riutilizzate su account o chain diverse.

Usa EIP-712 typed data (il domain include `verifyingContract` e `chainId`) e restituisci il valore magic ERC-1271 esatto `0x1626ba7e` in caso di successo.

## 5) Reverts do not refund after validation
Una volta che `validateUserOp` ha avuto successo, le fee vengono impegnate anche se l'execution in seguito va in revert. Gli attaccanti possono inviare ripetutamente op che falliranno e continuare comunque a far addebitare fee all'account.

Per i paymaster, pagare da un pool condiviso in `validateUserOp` e addebitare gli utenti in `postOp` è fragile perché `postOp` può andare in revert senza annullare il pagamento. Metti in sicurezza i fondi durante la validation (escrow/deposit per utente), mantieni `postOp` minimale e non-reverting, e assegna `paymasterPostOpGasLimit` al worst-case reimbursement path.

## 6) Counterfactual deployment / factory assumptions
La prima `UserOperation` spesso include `initCode`, che fa sì che l'account venga deployed tramite una **factory** durante la validation. Questo path è facile da sottovalutare in audit perché viene eseguito solo al primo utilizzo.

Failure comuni:

- La factory/initializer si fida di `msg.sender == entryPoint`, ma il deployment path di ERC-4337 non chiama `initCode` direttamente da `EntryPoint`.
- Il salt, l'owner, il validator o la configurazione del module non sono completamente vincolati all'intento firmato, quindi un frontrunner può vincere la gara sul primo deployment e bruciare l'indirizzo counterfactual con impostazioni controllate dall'attaccante.
- La factory non è idempotent, quindi un flusso di first-use ripetuto bricka il wallet invece di restituire l'indirizzo già creato.

Safe pattern: ricalcola il sender atteso dai parametri di deployment firmati, rendi il deployment deterministic (tipicamente `CREATE2`), e rendi l'initialization one-shot.
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Logica di validazione che i bundlers rifiutano
Il codice di validazione può essere corretto nei test locali e comunque inutilizzabile nei bundlers reali. I bundlers pubblici simulano `validateUserOp()` / `validatePaymasterUserOp()` off-chain e comunemente eseguono un `debug_traceCall(handleOps)` completo prima dell'inclusione.

Questo rende pericolosi questi pattern dentro la validazione:

- Opcode dipendenti dal blocco come `TIMESTAMP`, `NUMBER`, o `BLOCKHASH`
- Scritture di stato come `SSTORE`
- Iterazione illimitata sullo storage
- Chiamate esterne arbitrarie o letture di oracle che possono cambiare tra simulazione e inclusione

Esempio sbagliato:
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
Tratta la validazione come una funzione di preflight deterministica e limitata. Se hai davvero bisogno di stato condiviso o di lookup esterni, sposta quella complessità in entità con stake/tracciamento della reputazione e testa il percorso esatto di simulazione del bundler, non solo i test unitari.

## 8) ERC-7702 initialization frontrun
ERC-7702 consente a un EOA di eseguire codice smart-account per una singola tx. Se l'inizializzazione è chiamabile esternamente, un frontrunner può impostarsi come owner.

Mitigazione: consenti l'inizializzazione solo su **self-call** e solo una volta.
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Quick pre-merge checks
- Valida le signature usando `userOpHash` di `EntryPoint` (lega i campi gas).
- Limita le funzioni privilegiate a `EntryPoint` e/o `address(this)` secondo necessità.
- Mantieni `validateUserOp` stateless, deterministic, e compatibile con le regole di simulazione del bundler.
- Impone la separazione del dominio EIP-712 per ERC-1271 e restituisci `0x1626ba7e` in caso di successo.
- Mantieni `postOp` minimale, bounded, e non-reverting; metti in sicurezza le fee durante la validation.
- Testa separatamente il primo percorso `initCode`: deployment deterministico, comportamento idempotente della factory, e inizializzazione one-shot.
- Esegui la simulazione completa del bundler (`simulateValidation` più un `handleOps` tracciato) prima del rilascio.
- Per ERC-7702, consenti init solo su self-call e solo una volta.



## References

- [https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [https://eips.ethereum.org/EIPS/eip-4337](https://eips.ethereum.org/EIPS/eip-4337)
{{#include ../../banners/hacktricks-training.md}}
