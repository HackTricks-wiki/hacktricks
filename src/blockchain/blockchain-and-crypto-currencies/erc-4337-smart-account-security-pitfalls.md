# Errores de seguridad de las Smart Accounts de ERC-4337

La account abstraction de ERC-4337 convierte las wallets en sistemas programables. El flujo principal es **validate-then-execute** en todo un paquete: `EntryPoint` valida cada `UserOperation` antes de ejecutar cualquiera de ellas.<sup>[[5]](#references)</sup> Este orden crea una attack surface no obvia cuando la validación es permisiva, stateful o incoherente con las reglas de simulación del bundler.

## 1) Bypass mediante llamada directa de funciones privilegiadas
Cualquier función `execute` (o que mueva fondos) accesible externamente y que no esté restringida a `EntryPoint` (o a un módulo executor verificado) puede llamarse directamente para drenar la cuenta.<sup>[[2]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Patrón seguro: restringir a `EntryPoint` y usar `msg.sender == address(this)` para los flujos de administración/autogestión (instalación de módulos, cambios de validadores, actualizaciones).<sup>[[2]](#references)[[5]](#references)</sup>
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Campos de gas sin firmar o sin verificar -> agotamiento de fondos por tarifas
Si la validación de la firma solo cubre la intención (`callData`), pero no los campos relacionados con el gas, un bundler o frontrunner puede inflar las tarifas y drenar ETH. El payload firmado debe vincular como mínimo:<sup>[[2]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Patrón defensivo: usar el `userOpHash` proporcionado por `EntryPoint` (que incluye los campos de gas) y/o limitar estrictamente cada campo.<sup>[[2]](#references)[[5]](#references)</sup>
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(_isApprovedCall(userOpHash, op.signature), "bad sig");
return 0;
}
```
## 3) Sobrescritura de la validación con estado (semántica del bundle)
Como todas las validaciones se ejecutan antes de cualquier ejecución, almacenar los resultados de validación en el estado del contrato no es seguro. Otra op del mismo bundle puede sobrescribirlos, haciendo que tu ejecución use un estado influido por el atacante.<sup>[[2]](#references)</sup>

Evita escribir en el storage dentro de `validateUserOp`. Si es inevitable, identifica los datos temporales mediante `userOpHash` y elimínalos determinísticamente después de usarlos (preferiblemente, usa una validación stateless).<sup>[[2]](#references)</sup>

## 4) Replay de ERC-1271 entre cuentas/cadenas (falta de separación de dominio)
`isValidSignature(bytes32 hash, bytes sig)` debe vincular las firmas a **este contrato** y a **esta cadena**. Recuperar sobre un hash sin modificar permite hacer replay de las firmas entre cuentas o cadenas.<sup>[[1]](#references)[[4]](#references)</sup>

Usa typed data de EIP-712 (el dominio incluye `verifyingContract` y `chainId`) y devuelve el valor mágico exacto de ERC-1271 `0x1626ba7e` cuando la operación tenga éxito.<sup>[[3]](#references)[[4]](#references)</sup>

## 5) Los reverts no reembolsan después de la validación
Una vez que `validateUserOp` tiene éxito, las fees quedan comprometidas aunque la ejecución revierta posteriormente. Los atacantes pueden enviar repetidamente ops que fallarán y aun así cobrar fees de la cuenta.<sup>[[2]](#references)</sup>

En el caso de los paymasters, pagar desde un pool compartido en `validateUserOp` y cobrar a los usuarios en `postOp` es frágil, porque `postOp` puede revertir sin deshacer el pago. Asegura los fondos durante la validación (mediante un escrow/deposit por usuario), mantén `postOp` minimalista y sin reverts, y reserva un `paymasterPostOpGasLimit` suficiente para la ruta de reembolso del peor caso.<sup>[[2]](#references)[[5]](#references)</sup>

## 6) Despliegue contrafactual / suposiciones sobre la factory
La primera `UserOperation` suele incluir `initCode`, lo que provoca que la cuenta se despliegue mediante una **factory** durante la validación. Esta ruta es fácil de auditar de forma insuficiente porque solo se ejecuta durante el primer uso.<sup>[[5]](#references)</sup>

Entre los fallos comunes se incluyen:<sup>[[5]](#references)</sup>

- La factory/initializer confía en `msg.sender == entryPoint`, pero la ruta de despliegue de ERC-4337 **no** llama a `initCode` directamente desde `EntryPoint`.
- El salt, el owner, el validator o la configuración del module no están completamente vinculados a la intención firmada, por lo que un frontrunner puede competir por el primer despliegue y ocupar la dirección contrafactual con configuraciones controladas por el atacante.
- La factory no es idempotente, por lo que un flujo repetido de primer uso bloquea la wallet en lugar de devolver la dirección ya creada.

Patrón seguro: vuelve a calcular el sender esperado a partir de los parámetros de despliegue firmados, haz que el despliegue sea determinista (normalmente mediante `CREATE2`) y realiza la inicialización una sola vez.<sup>[[5]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Lógica de validación que los bundlers rechazan
El código de validación puede ser correcto en las pruebas locales y aun así resultar inutilizable en bundlers reales. Los bundlers ejecutan la validación varias veces y deberían realizar una validación trazada del bundle completo antes del envío.<sup>[[6]](#references)</sup>

Según esas reglas de alcance de validación, estos patrones son peligrosos:<sup>[[6]](#references)</sup>

- Opcodes dependientes del bloque, como `TIMESTAMP`, `NUMBER` o `BLOCKHASH`
- Acceso al almacenamiento fuera del alcance permitido de la cuenta/entidad, o iteración no acotada sobre el almacenamiento
- Llamadas externas o lecturas de oráculos que dependan de un estado mutable fuera del alcance de validación permitido

Mal ejemplo:
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
Trata la validación como una función determinista de preflight con límites definidos. Si son necesarios shared state o external lookups, sigue las reglas de staked-entity y prueba la misma ruta de simulación multi-pass del bundler, no solo unit tests.<sup>[[6]](#references)</sup>

## 8) ERC-7702 initialization frontrun
ERC-7702 proporciona a una EOA una delegación persistente al código de smart-account; la delegación no ejecuta la inicialización de forma atómica. Si la inicialización se puede invocar externamente, un observador puede hacer frontrun y establecerse como owner.<sup>[[7]](#references)</sup>

Mitigación: exige que el calldata de inicialización esté autorizado por la EOA y permite la inicialización solo una vez. En un flujo ERC-4337 EIP-7702, restringe también el caller a `EntryPoint.senderCreator()`.<sup>[[5]](#references)[[7]](#references)</sup>
```solidity
function initialize(address newOwner, bytes calldata initSig) external {
require(owner == address(0), "already inited");
// Verify the EOA's signature over the complete initialization calldata.
require(_isAuthorizedByEOA(newOwner, initSig), "bad init auth");
owner = newOwner;
}
```
## Comprobaciones rápidas antes del merge
- Valida las firmas usando `userOpHash` de `EntryPoint` (vincula los campos de gas).
- Restringe las funciones privilegiadas a `EntryPoint` y/o `address(this)` según corresponda.
- Mantén `validateUserOp` sin estado, determinista y compatible con las reglas de simulación del bundler.
- Aplica la separación de dominios de EIP-712 para ERC-1271 y devuelve `0x1626ba7e` en caso de éxito.
- Mantén `postOp` mínima, acotada y sin revertir; asegura las fees durante la validación.
- Prueba por separado la primera ruta de `initCode`: deployment determinista, comportamiento idempotente de la factory e inicialización de un solo uso.
- Ejecuta la validación multipase del bundler y una comprobación trazada del bundle completo antes del lanzamiento.
- Para ERC-7702, vincula la inicialización a la autorización de la EOA y permítela solo una vez; en los flujos de ERC-4337, restringe el caller a `EntryPoint.senderCreator()`.

## References

- [1] [Replay de ERC1271 - Más de 15 equipos afectados (curiousapple)](https://paragraph.com/@curiousapple/fwlBuaAuGsWwLRPTLKxB)
- [2] [Seis errores en las smart accounts de ERC-4337 (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [3] [ERC-1271: Método estándar de validación de firmas para contratos](https://eips.ethereum.org/EIPS/eip-1271)
- [4] [EIP-712: Hashing y firma de datos estructurados tipados](https://eips.ethereum.org/EIPS/eip-712)
- [5] [ERC-4337: Abstracción de cuentas mediante Alt Mempool](https://eips.ethereum.org/EIPS/eip-4337)
- [6] [ERC-7562: Reglas del ámbito de validación de la abstracción de cuentas](https://eips.ethereum.org/EIPS/eip-7562)
- [7] [EIP-7702: Establecer código para EOAs](https://eips.ethereum.org/EIPS/eip-7702)
{{#include ../../banners/hacktricks-training.md}}
