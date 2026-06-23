# ERC-4337 Smart Account Security Pitfalls

{{#include ../../banners/hacktricks-training.md}}

ERC-4337 account abstraction convierte wallets en sistemas programables. El flujo principal es **validate-then-execute** en un bundle completo: el `EntryPoint` valida cada `UserOperation` antes de ejecutar cualquiera de ellas. Este orden crea una superficie de ataque no obvia cuando la validación es permisiva, stateful, o inconsistente con las reglas de simulación del bundler.

## 1) Direct-call bypass de funciones privilegiadas
Cualquier función `execute` de acceso externo (o de movimiento de fondos) que no esté restringida a `EntryPoint` (o a un módulo executor verificado) puede ser llamada directamente para vaciar la cuenta.
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Patrón seguro: restringir a `EntryPoint`, y usar `msg.sender == address(this)` para flujos de administración/autogestión (instalación de módulos, cambios de validador, upgrades).
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Campos de gas no firmados o no verificados -> drenaje de fees
Si la validación de la signature solo cubre la intención (`callData`) pero no los campos relacionados con gas, un bundler o frontrunner puede inflar los fees y drenar ETH. El payload firmado debe vincular al menos:

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Patrón defensivo: usa el `userOpHash` proporcionado por `EntryPoint` (que incluye los campos de gas) y/o limita estrictamente cada campo.
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(_isApprovedCall(userOpHash, op.signature), "bad sig");
return 0;
}
```
## 3) Clobbering de validación con estado (semántica de bundle)
Como todas las validaciones se ejecutan antes de cualquier ejecución, almacenar los resultados de validación en el estado del contrato es inseguro. Otra op en el mismo bundle puede sobrescribirlo, haciendo que tu ejecución use estado influenciado por el atacante.

Evita escribir storage en `validateUserOp`. Si es inevitable, indexa los datos temporales por `userOpHash` y elimínalos de forma determinista después de usarlos (mejor validación sin estado).

## 4) Reutilización de ERC-1271 entre cuentas/chains (falta de separación de dominio)
`isValidSignature(bytes32 hash, bytes sig)` debe vincular las firmas a **este contract** y a **esta chain**. Recuperar sobre un hash bruto permite que las firmas se repliquen entre cuentas o chains.

Usa EIP-712 typed data (el domain incluye `verifyingContract` y `chainId`) y devuelve el valor mágico exacto de ERC-1271 `0x1626ba7e` en caso de éxito.

## 5) Los reverts no reembolsan después de la validación
Una vez que `validateUserOp` tiene éxito, las fees quedan comprometidas incluso si la ejecución falla después. Los atacantes pueden enviar repetidamente ops que fallarán y aun así cobrar fees de la cuenta.

Para paymasters, pagar desde un pool compartido en `validateUserOp` y cobrar a los users en `postOp` es frágil porque `postOp` puede revertir sin deshacer el pago. Asegura los fondos durante la validación (escrow/deposit por user), mantén `postOp` mínimo y no revirtiendo, y reserva `paymasterPostOpGasLimit` para el peor caso de reembolso.

## 6) Suposiciones de despliegue contrafactual / factory
La primera `UserOperation` a menudo lleva `initCode`, lo que hace que la account se despliegue a través de una **factory** durante la validación. Esta ruta es fácil de subauditar porque solo se ejecuta en el primer uso.

Fallos comunes:

- La factory/initializer confía en `msg.sender == entryPoint`, pero la ruta de despliegue de ERC-4337 no llama `initCode` directamente desde `EntryPoint`.
- El salt, owner, validator o la configuración del module no están completamente ligados a la intención firmada, así que un frontrunner puede competir por el primer despliegue y quemar la dirección contrafactual con settings controlados por el atacante.
- La factory no es idempotente, así que un flujo repetido de primer uso rompe la wallet en vez de devolver la dirección ya creada.

Patrón seguro: recalcula el sender esperado a partir de los parámetros de despliegue firmados, haz que el despliegue sea determinista (normalmente `CREATE2`) y haz que la inicialización sea de una sola vez.
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Lógica de validación que los bundlers rechazan
El código de validación puede ser correcto en pruebas locales y aun así no ser utilizable en bundlers reales. Los bundlers públicos simulan `validateUserOp()` / `validatePaymasterUserOp()` off-chain y comúnmente ejecutan un `debug_traceCall(handleOps)` completo antes de la inclusión.

Eso hace que estos patrones sean peligrosos dentro de la validación:

- Opcodes dependientes del bloque como `TIMESTAMP`, `NUMBER`, o `BLOCKHASH`
- Escrituras de estado como `SSTORE`
- Iteración no acotada sobre storage
- Llamadas externas arbitrarias o lecturas de oracle que pueden cambiar entre la simulación y la inclusión

Bad example:
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
Trata la validación como una función de preflight determinista y acotada. Si realmente necesitas estado compartido o búsquedas externas, empuja esa complejidad a entidades con stake/seguimiento de reputación y prueba la ruta exacta de simulación del bundler, no solo unit tests.

## 8) ERC-7702 initialization frontrun
ERC-7702 permite que un EOA ejecute código de smart-account para una sola tx. Si la inicialización es externamente callable, un frontrunner puede establecerse como owner.

Mitigation: permite la inicialización solo en **self-call** y solo una vez.
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Comprobaciones rápidas antes del merge
- Valida las firmas usando `userOpHash` de `EntryPoint` (vincula los campos de gas).
- Restringe las funciones privilegiadas a `EntryPoint` y/o `address(this)` según corresponda.
- Mantén `validateUserOp` stateless, deterministic y compatible con las reglas de simulación de bundler.
- Aplica separación de dominio EIP-712 para ERC-1271 y devuelve `0x1626ba7e` en caso de éxito.
- Mantén `postOp` minimal, bounded y no-reverting; asegura las fees durante la validación.
- Prueba la primera ruta de `initCode` por separado: deterministic deployment, comportamiento idempotent del factory y initialización de un solo uso.
- Ejecuta la simulación completa de bundler (`simulateValidation` más un `handleOps` con trazas) antes de desplegar.
- Para ERC-7702, permite la init solo en self-call y solo una vez.



## Referencias

- [https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [https://eips.ethereum.org/EIPS/eip-4337](https://eips.ethereum.org/EIPS/eip-4337)
{{#include ../../banners/hacktricks-training.md}}
