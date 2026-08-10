# Problemi di sicurezza degli Smart Account ERC-4337

L'account abstraction di ERC-4337 trasforma i wallet in sistemi programmabili. Il flusso principale è **validate-then-execute** attraverso un intero bundle: `EntryPoint` valida ogni `UserOperation` prima di eseguirne una qualsiasi.<sup>[[5]](#references)</sup> Questo ordinamento crea una attack surface non ovvia quando la validazione è permissiva, stateful o incoerente con le regole di simulazione dei bundler.

## 1) Bypass tramite chiamata diretta di funzioni privilegiate
Qualsiasi funzione `execute` (o che trasferisce fondi) richiamabile esternamente e non limitata a `EntryPoint` (o a un modulo executor verificato) può essere chiamata direttamente per svuotare l'account.<sup>[[2]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Pattern sicuro: limita a `EntryPoint` e usa `msg.sender == address(this)` per i flussi di amministrazione/autogestione (installazione di moduli, modifiche ai validator, upgrade).<sup>[[2]](#references)[[5]](#references)</sup>
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Campi gas non firmati o non verificati -> drenaggio delle commissioni
Se la validazione della firma copre solo l'intento (`callData`), ma non i campi relativi al gas, un bundler o un frontrunner può gonfiare le commissioni e drenare ETH. Il payload firmato deve associare almeno:<sup>[[2]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Pattern difensivo: usa lo `userOpHash` fornito da `EntryPoint` (che include i campi relativi al gas) e/o limita rigorosamente ogni campo.<sup>[[2]](#references)[[5]](#references)</sup>
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(_isApprovedCall(userOpHash, op.signature), "bad sig");
return 0;
}
```
## 3) Clobbering della validazione stateful (semantica del bundle)
Poiché tutte le validazioni vengono eseguite prima di qualsiasi esecuzione, memorizzare i risultati della validazione nello stato del contratto non è sicuro. Un'altra op nello stesso bundle può sovrascriverli, facendo sì che l'esecuzione utilizzi uno stato controllato dall'attaccante.<sup>[[2]](#references)</sup>

Evita di scrivere nello storage in `validateUserOp`. Se è inevitabile, indicizza i dati temporanei tramite `userOpHash` ed eliminali deterministicamente dopo l'uso (è preferibile una validazione stateless).<sup>[[2]](#references)</sup>

## 4) Replay di ERC-1271 tra account e chain (assenza di domain separation)
`isValidSignature(bytes32 hash, bytes sig)` deve associare le firme a **questo contratto** e a **questa chain**. Effettuare il recupero su un hash grezzo consente di riutilizzare le firme tra account o chain diversi.<sup>[[1]](#references)[[4]](#references)</sup>

Usa dati tipizzati EIP-712 (il domain include `verifyingContract` e `chainId`) e restituisci l'esatto magic value ERC-1271 `0x1626ba7e` in caso di successo.<sup>[[3]](#references)[[4]](#references)</sup>

## 5) I revert non rimborsano dopo la validazione
Una volta che `validateUserOp` ha esito positivo, le fee sono impegnate anche se l'esecuzione successiva va in revert. Gli attaccanti possono inviare ripetutamente op che falliranno e riscuotere comunque le fee dall'account.<sup>[[2]](#references)</sup>

Per i paymaster, pagare da un pool condiviso in `validateUserOp` e addebitare gli utenti in `postOp` è fragile, perché `postOp` può andare in revert senza annullare il pagamento. Metti al sicuro i fondi durante la validazione (escrow/deposito per utente), mantieni `postOp` minimale e senza revert, e assegna a `paymasterPostOpGasLimit` un budget sufficiente per il percorso di rimborso nel caso peggiore.<sup>[[2]](#references)[[5]](#references)</sup>

## 6) Deployment counterfactual / assunzioni sulla factory
La prima `UserOperation` spesso contiene `initCode`, che causa il deployment dell'account tramite una **factory** durante la validazione. Questo percorso è facile da sottoporre a un audit insufficiente perché viene eseguito solo al primo utilizzo.<sup>[[5]](#references)</sup>

I problemi comuni includono:<sup>[[5]](#references)</sup>

- La factory/initializer si fida di `msg.sender == entryPoint`, ma il percorso di deployment ERC-4337 **non** chiama direttamente `initCode` da `EntryPoint`.
- Il salt, il proprietario, il validator o la configurazione del modulo non sono completamente associati all'intento firmato; un frontrunner può quindi anticipare il primo deployment e occupare l'indirizzo counterfactual con impostazioni controllate dall'attaccante.
- La factory non è idempotente; di conseguenza, un flusso ripetuto al primo utilizzo blocca il wallet invece di restituire l'indirizzo già creato.

Pattern sicuro: ricalcola il sender previsto a partire dai parametri di deployment firmati, rendi il deployment deterministico (in genere tramite `CREATE2`) e fai in modo che l'inizializzazione avvenga una sola volta.<sup>[[5]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Logica di validazione che i bundler rifiutano
Il codice di validazione può essere corretto nei test locali e tuttavia risultare inutilizzabile nei bundler reali. I bundler eseguono la validazione più volte e dovrebbero effettuare una validazione tracciata dell'intero bundle prima dell'invio.<sup>[[6]](#references)</sup>

In base a queste regole sull'ambito della validazione, i seguenti pattern sono pericolosi:<sup>[[6]](#references)</sup>

- Opcode dipendenti dal blocco come `TIMESTAMP`, `NUMBER` o `BLOCKHASH`
- Accesso allo storage al di fuori dell'ambito consentito dell'account/entity o iterazione non limitata sullo storage
- Chiamate esterne o letture da oracle che dipendono da uno stato mutabile al di fuori dell'ambito di validazione consentito

Esempio errato:
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(block.timestamp < expiry, "expired");
seen[userOpHash] = true; // stateful validation can be clobbered by another op
require(oracle.isAllowed(op.sender), "oracle changed");
return 0;
}
```
Tratta la validazione come una funzione di preflight deterministica e vincolata. Se sono necessari uno stato condiviso o lookup esterni, segui le regole delle entità in staking e testa lo stesso percorso di simulazione multi-pass del bundler, non solo gli unit test.<sup>[[6]](#references)</sup>

## 8) ERC-7702 front-run dell'inizializzazione
ERC-7702 assegna a un EOA una delega persistente al codice di uno smart account; la delega non esegue l'inizializzazione in modo atomico. Se l'inizializzazione è richiamabile esternamente, un osservatore può eseguire il front-run e impostare sé stesso come proprietario.<sup>[[7]](#references)</sup>

Mitigazione: richiedi che i calldata di inizializzazione siano autorizzati dall'EOA e consenti l'inizializzazione una sola volta. In un flusso ERC-4337 EIP-7702, limita inoltre il chiamante a `EntryPoint.senderCreator()`.<sup>[[5]](#references)[[7]](#references)</sup>
```solidity
function initialize(address newOwner, bytes calldata initSig) external {
require(owner == address(0), "already inited");
// Verify the EOA's signature over the complete initialization calldata.
require(_isAuthorizedByEOA(newOwner, initSig), "bad init auth");
owner = newOwner;
}
```
## Controlli rapidi pre-merge
- Validate le signatures usando `userOpHash` di `EntryPoint` (associa i campi del gas).
- Limita le funzioni privilegiate a `EntryPoint` e/o `address(this)`, come appropriato.
- Mantieni `validateUserOp` stateless, deterministica e compatibile con le regole di simulazione del bundler.
- Applica la domain separation di EIP-712 per ERC-1271 e restituisci `0x1626ba7e` in caso di successo.
- Mantieni `postOp` minimale, limitata e senza revert; proteggi le fee durante la validation.
- Testa separatamente il primo percorso `initCode`: deployment deterministico, comportamento idempotente della factory e inizializzazione one-shot.
- Esegui la validation multi-pass del bundler e un controllo tracciato del bundle completo prima del rilascio.
- Per ERC-7702, associa l'init all'autorizzazione dell'EOA e consentila una sola volta; nei flussi ERC-4337, limita il caller a `EntryPoint.senderCreator()`.

## References

- [1] [Replay di ERC1271 - Oltre 15 team interessati (curiousapple)](https://paragraph.com/@curiousapple/fwlBuaAuGsWwLRPTLKxB)
- [2] [Sei errori negli smart account ERC-4337 (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [3] [ERC-1271: Metodo standard di validation delle signatures per i contratti](https://eips.ethereum.org/EIPS/eip-1271)
- [4] [EIP-712: Hashing e signing di dati strutturati tipizzati](https://eips.ethereum.org/EIPS/eip-712)
- [5] [ERC-4337: Account Abstraction usando Alt Mempool](https://eips.ethereum.org/EIPS/eip-4337)
- [6] [ERC-7562: Regole sull'ambito della validation di Account Abstraction](https://eips.ethereum.org/EIPS/eip-7562)
- [7] [EIP-7702: Impostazione del codice per gli EOA](https://eips.ethereum.org/EIPS/eip-7702)
{{#include ../../banners/hacktricks-training.md}}
