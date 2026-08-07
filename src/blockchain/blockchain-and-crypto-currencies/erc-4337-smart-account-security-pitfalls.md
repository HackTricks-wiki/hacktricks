# Errores de seguridad de las Smart Accounts ERC-4337

{{#include ../../banners/hacktricks-training.md}}

La account abstraction de ERC-4337 convierte las wallets en sistemas programables. El flujo principal es **validate-then-execute** en todo el bundle: el `EntryPoint` valida cada `UserOperation` antes de ejecutar cualquiera de ellas. Este orden crea una attack surface no evidente cuando la validación es permisiva, stateful o incoherente con las reglas de simulación del bundler.

## 1) Bypass mediante llamadas directas a funciones privilegiadas
Cualquier función `execute` (o que mueva fondos) invocable externamente que no esté restringida a `EntryPoint` (o a un módulo executor verificado) puede llamarse directamente para vaciar la cuenta.<sup>[[1]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Patrón seguro: restringir a `EntryPoint` y usar `msg.sender == address(this)` para los flujos de administración/autogestión (instalación de módulos, cambios de validadores y actualizaciones).
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Campos de gas sin firmar o sin comprobar -> drenaje de fees
Si la validación de la firma solo cubre la intención (`callData`), pero no los campos relacionados con el gas, un bundler o frontrunner puede inflar las fees y drenar ETH. El payload firmado debe vincular como mínimo:<sup>[[1]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Patrón defensivo: usar el `userOpHash` proporcionado por `EntryPoint` (que incluye los campos de gas) y/o establecer límites estrictos para cada campo.<sup>[[1]](#references)</sup>
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(_isApprovedCall(userOpHash, op.signature), "bad sig");
return 0;
}
```
## 3) Clobbering de la validación con estado (semántica del bundle)
Dado que todas las validaciones se ejecutan antes de cualquier ejecución, almacenar los resultados de validación en el estado del contrato no es seguro. Otra op del mismo bundle puede sobrescribirlos, haciendo que tu ejecución use un estado controlado por el atacante.<sup>[[1]](#references)</sup>

Evita escribir en storage dentro de `validateUserOp`. Si es inevitable, identifica los datos temporales mediante `userOpHash` y elimínalos de forma determinista después de usarlos (preferiblemente, usa validación stateless).<sup>[[1]](#references)</sup>

## 4) Replay de ERC-1271 entre cuentas y chains (falta de separación de dominio)
`isValidSignature(bytes32 hash, bytes sig)` debe vincular las firmas a **este contrato** y a **esta chain**. Recuperar la firma sobre un hash sin más permite hacer replay de las firmas entre cuentas o chains.<sup>[[1]](#references)</sup>

Usa typed data de EIP-712 (el dominio incluye `verifyingContract` y `chainId`) y devuelve el valor mágico exacto de ERC-1271 `0x1626ba7e` cuando la validación tenga éxito.<sup>[[1]](#references)</sup>

## 5) Los reverts no reembolsan después de la validación
Una vez que `validateUserOp` tiene éxito, las fees quedan comprometidas incluso si la ejecución revierte posteriormente. Los atacantes pueden enviar repetidamente ops que fallarán y aun así cobrar las fees de la cuenta.<sup>[[1]](#references)</sup>

En el caso de los paymasters, pagar desde un pool compartido en `validateUserOp` y cobrar a los usuarios en `postOp` es frágil porque `postOp` puede revertir sin deshacer el pago. Asegura los fondos durante la validación (escrow o depósito por usuario), mantén `postOp` mínimo y sin posibilidad de revertir, y reserva presupuesto en `paymasterPostOpGasLimit` para la ruta de reembolso del peor caso.<sup>[[1]](#references)</sup>

## 6) Deployment contrafactual / suposiciones sobre la factory
La primera `UserOperation` suele incluir `initCode`, lo que provoca que la cuenta se despliegue mediante una **factory** durante la validación. Esta ruta es fácil de auditar de forma insuficiente porque solo se ejecuta durante el primer uso.<sup>[[2]](#references)</sup>

Fallos comunes:

- La factory o el inicializador confía en `msg.sender == entryPoint`, pero la ruta de deployment de ERC-4337 **no** llama directamente a `initCode` desde `EntryPoint`.
- El salt, owner, validator o la configuración del módulo no están vinculados por completo a la intención firmada, por lo que un frontrunner puede competir por el primer deployment y quemar la dirección contrafactual con configuraciones controladas por el atacante.
- La factory no es idempotente, por lo que un flujo repetido del primer uso bloquea la wallet en lugar de devolver la dirección ya creada.

Patrón seguro: vuelve a calcular el sender esperado a partir de los parámetros de deployment firmados, haz que el deployment sea determinista (normalmente mediante `CREATE2`) y realiza la inicialización una sola vez.<sup>[[2]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Lógica de validación que los bundlers rechazan
El código de validación puede ser correcto en las pruebas locales y aun así ser inutilizable en bundlers reales. Los bundlers públicos simulan `validateUserOp()` / `validatePaymasterUserOp()` off-chain y normalmente ejecutan un `debug_traceCall(handleOps)` completo antes de la inclusión.<sup>[[3]](#references)</sup>

Esto hace que estos patrones sean peligrosos dentro de la validación:

- Opcodes dependientes del bloque, como `TIMESTAMP`, `NUMBER` o `BLOCKHASH`
- Escrituras de estado, como `SSTORE`
- Iteración sin límites sobre el almacenamiento
- Llamadas externas arbitrarias o lecturas de oráculos que pueden cambiar entre la simulación y la inclusión

Mal ejemplo:
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
Trata la validación como una función de preflight determinista y acotada. Si realmente necesitas estado compartido o consultas externas, traslada esa complejidad a entidades con stake y seguimiento de reputación, y prueba la ruta exacta de simulación del bundler, no solo las pruebas unitarias.

## 8) Frontrun de inicialización de ERC-7702
ERC-7702 permite que una EOA ejecute código de smart-account durante una sola tx. Si la inicialización se puede invocar externamente, un frontrunner puede establecerse como owner.<sup>[[1]](#references)</sup>

Mitigación: permite la inicialización únicamente mediante **self-call** y solo una vez.<sup>[[1]](#references)</sup>
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Comprobaciones rápidas previas al merge
- Valida las firmas usando `userOpHash` de `EntryPoint` (vincula los campos de gas).
- Restringe las funciones privilegiadas a `EntryPoint` y/o `address(this)` según corresponda.
- Mantén `validateUserOp` sin estado, determinista y compatible con las reglas de simulación del bundler.
- Aplica la separación de dominios de EIP-712 para ERC-1271 y devuelve `0x1626ba7e` en caso de éxito.
- Mantén `postOp` mínima, acotada y sin reverts; protege las comisiones durante la validación.
- Prueba la primera ruta de `initCode` por separado: despliegue determinista, comportamiento idempotente de la factory e inicialización de un solo uso.
- Ejecuta la simulación completa del bundler (`simulateValidation` más un `handleOps` trazado) antes de publicar.
- Para ERC-7702, permite la inicialización solo en una self-call y solo una vez.

## Referencias

- [1] [Seis errores en las smart accounts de ERC-4337 (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [2] [ERC-4337: Abstracción de cuentas usando Alt Mempool](https://eips.ethereum.org/EIPS/eip-4337)
- [3] [ERC-7562: Reglas del ámbito de validación de la abstracción de cuentas](https://eips.ethereum.org/EIPS/eip-7562)

{{#include ../../banners/hacktricks-training.md}}
