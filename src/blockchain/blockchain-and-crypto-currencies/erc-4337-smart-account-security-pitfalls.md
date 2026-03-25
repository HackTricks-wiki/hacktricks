# ERC-4337 Insidie di sicurezza degli Smart Account

{{#include ../../banners/hacktricks-training.md}}

L'astrazione dell'account ERC-4337 trasforma i wallet in sistemi programmabili. Il flusso principale è **validate-then-execute** su un intero bundle: il `EntryPoint` valida ogni `UserOperation` prima di eseguire qualunque di esse. Questo ordine crea una superficie di attacco non ovvia quando la validazione è permissiva o con stato.

## 1) Bypass tramite chiamata diretta di funzioni privilegiate
Qualsiasi funzione esternamente richiamabile `execute` (o che sposta fondi) che non sia limitata a `EntryPoint` (o a un modulo executor verificato) può essere chiamata direttamente per svuotare l'account.
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Pattern per Safe: limitare a `EntryPoint` e usare `msg.sender == address(this)` per i flussi di amministrazione/autogestione (installazione del modulo, modifiche al validator, aggiornamenti).
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Campi gas non firmati o non verificati -> drenaggio di ETH per fee
Se la validazione della firma copre solo l'intento (`callData`) ma non i campi relativi al gas, un bundler o frontrunner può gonfiare le fee e prosciugare ETH. Il payload firmato deve vincolare almeno:

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Pattern difensivo: utilizzare il `userOpHash` fornito da `EntryPoint` (che include i campi gas) e/o imporre un limite rigoroso su ciascun campo.
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(_isApprovedCall(userOpHash, op.signature), "bad sig");
return 0;
}
```
## 3) Sovrascrittura di validazioni con stato (semantica del bundle)
Poiché tutte le validazioni vengono eseguite prima di qualsiasi esecuzione, memorizzare i risultati di validazione nello stato del contratto non è sicuro. Un'altra op nello stesso bundle può sovrascriverli, facendo sì che la tua esecuzione utilizzi uno stato influenzato dall'attaccante.

Evita di scrivere su storage in `validateUserOp`. Se inevitabile, indicizza i dati temporanei tramite `userOpHash` e cancellali in modo deterministico dopo l'uso (preferisci validazione stateless).

## 4) ERC-1271 replay tra account/catene (mancata separazione del dominio)
`isValidSignature(bytes32 hash, bytes sig)` deve vincolare le firme a **questo contratto** e **questa chain**. Recuperare la firma su un hash grezzo permette il replay delle firme tra account o catene.

Usa EIP-712 typed data (il dominio include `verifyingContract` e `chainId`) e restituisci l'esatto valore magic ERC-1271 `0x1626ba7e` in caso di successo.

## 5) I revert non rimborsano dopo la validazione
Una volta che `validateUserOp` ha successo, le fee vengono impegnate anche se l'esecuzione in seguito revertisce. Gli attaccanti possono inviare ripetutamente ops che falliranno e comunque incassare le fee dall'account.

Per i paymasters, pagare da un pool condiviso in `validateUserOp` e addebitare gli utenti in `postOp` è fragile perché `postOp` può eseguire un revert senza annullare il pagamento. Metti in sicurezza i fondi durante la validazione (escrow/deposito per utente) e mantieni `postOp` minimale e non revertente.

## 6) ERC-7702 initialization frontrun
ERC-7702 permette a un EOA di eseguire codice di smart-account per una singola tx. Se l'inizializzazione è chiamabile dall'esterno, un frontrunner può impostarsi come owner.

Mitigazione: permettere l'inizializzazione solo su **self-call** e solo una volta.
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Controlli rapidi prima del merge
- Validare le firme usando il `userOpHash` di `EntryPoint` (associa i campi gas).
- Limitare le funzioni privilegiate a `EntryPoint` e/o `address(this)` come appropriato.
- Mantenere `validateUserOp` senza stato.
- Garantire la separazione del dominio EIP-712 per ERC-1271 e restituire `0x1626ba7e` in caso di successo.
- Mantenere `postOp` minimo, limitato e non-reverting; assicurare le commissioni durante la validazione.
- Per ERC-7702, permettere l'init solo su self-call e solo una volta.

## Riferimenti

- [https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)

{{#include ../../banners/hacktricks-training.md}}
