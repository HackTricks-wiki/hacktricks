# ERC-4337 Smart Account Security Pitfalls

{{#include ../../banners/hacktricks-training.md}}

La abstracción de cuentas de ERC-4337 convierte las wallets en sistemas programables. El flujo principal es **validate-then-execute** en todo un bundle: el `EntryPoint` valida cada `UserOperation` antes de ejecutar cualquiera de ellas.<sup>[[5]](#references)</sup> Este orden crea una superficie de ataque no evidente cuando la validación es permisiva, stateful o incoherente con las reglas de simulación del bundler.

## 1) Direct-call bypass de funciones privilegiadas
Cualquier función `execute` (o que mueva fondos) accesible externamente que no esté restringida al `EntryPoint` (o a un módulo executor validado) puede ser llamada directamente para drenar la cuenta.<sup>[[2]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Patrón seguro: restringir a `EntryPoint` y usar `msg.sender == address(this)` para los flujos de administración/autogestión (instalación de módulos, cambios de validadores y actualizaciones).<sup>[[2]](#references)[[5]](#references)</sup>
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Campos de gas sin firmar o sin verificar -> drenaje de comisiones
Si la validación de la firma solo cubre la intención (`callData`), pero no los campos relacionados con el gas, un bundler o frontrunner puede inflar las comisiones y drenar ETH. El payload firmado debe vincular como mínimo:<sup>[[2]](#references)</sup>

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
## 3) Anulación de la validación con estado (semántica del bundle)
Dado que todas las validaciones se ejecutan antes de cualquier ejecución, almacenar los resultados de la validación en el estado del contrato es inseguro. Otra op en el mismo bundle puede sobrescribirlos, haciendo que tu ejecución use un estado influenciado por el atacante.<sup>[[2]](#references)</sup>

Evita escribir en storage desde `validateUserOp`. Si es inevitable, identifica los datos temporales mediante `userOpHash` y elimínalos determinísticamente después de usarlos (se prefiere una validación sin estado).<sup>[[2]](#references)</sup>

## 4) Replay de ERC-1271 entre cuentas y chains (falta de separación de dominio)
`isValidSignature(bytes32 hash, bytes sig)` debe vincular las firmas a **este contrato** y a **esta chain**. Recuperar sobre un hash sin más permite hacer replay de las firmas entre cuentas o chains.<sup>[[1]](#references)[[4]](#references)</sup>

Usa datos tipados de EIP-712 (el dominio incluye `verifyingContract` y `chainId`) y devuelve el valor mágico exacto de ERC-1271 `0x1626ba7e` cuando la operación tenga éxito.<sup>[[3]](#references)[[4]](#references)</sup>

## 5) Los reverts no reembolsan después de la validación
Una vez que `validateUserOp` tiene éxito, las fees quedan comprometidas aunque la ejecución revierta posteriormente. Los atacantes pueden enviar repetidamente ops que fallarán y aun así cobrar fees de la cuenta.<sup>[[2]](#references)</sup>

En el caso de los paymasters, pagar desde un pool compartido en `validateUserOp` y cobrar a los usuarios en `postOp` es frágil, porque `postOp` puede revertir sin deshacer el pago. Asegura los fondos durante la validación (escrow o depósito por usuario), mantén `postOp` al mínimo y evita que revierta, y reserva un `paymasterPostOpGasLimit` suficiente para la ruta de reembolso en el peor caso.<sup>[[2]](#references)[[5]](#references)</sup>

## 6) Despliegue contrafactual / suposiciones sobre la factory
La primera `UserOperation` suele incluir `initCode`, lo que provoca que la cuenta se despliegue mediante una **factory** durante la validación. Esta ruta es fácil de auditar de forma insuficiente porque solo se ejecuta durante el primer uso.<sup>[[5]](#references)</sup>

Entre los fallos comunes se incluyen:<sup>[[5]](#references)</sup>

- La factory o el inicializador confía en `msg.sender == entryPoint`, pero la ruta de despliegue de ERC-4337 **no** llama a `initCode` directamente desde `EntryPoint`.
- El salt, el owner, el validator o la configuración del módulo no están vinculados por completo a la intención firmada, por lo que un frontrunner puede competir por el primer despliegue y ocupar la dirección contrafactual con configuraciones controladas por el atacante.
- La factory no es idempotente, por lo que un flujo repetido de primer uso inutiliza la wallet en lugar de devolver la dirección ya creada.

Patrón seguro: vuelve a calcular el sender esperado a partir de los parámetros de despliegue firmados, haz que el despliegue sea determinista (normalmente mediante `CREATE2`) y haz que la inicialización solo pueda ejecutarse una vez.<sup>[[5]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Lógica de validación que los bundlers rechazan
El código de validación puede ser correcto en las pruebas locales y aun así ser inutilizable en bundlers reales. Los bundlers ejecutan la validación varias veces y deberían realizar una validación completa del bundle mediante tracing antes del envío.<sup>[[6]](#references)</sup>

Bajo esas reglas de alcance de validación, estos patrones son peligrosos:<sup>[[6]](#references)</sup>

- Opcodes dependientes del bloque, como `TIMESTAMP`, `NUMBER` o `BLOCKHASH`
- Acceso al storage fuera del alcance permitido de la cuenta/entidad, o iteración no acotada sobre el storage
- Llamadas externas o lecturas de oráculos que dependen de un estado mutable fuera del alcance de validación permitido

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
Trata la validación como una función determinista y acotada de preflight. Si se necesita estado compartido o consultas externas, sigue las reglas de las entidades con stake y prueba la misma ruta de simulación multipase del bundler, no solo las pruebas unitarias.<sup>[[6]](#references)</sup>

## 8) Front-run de inicialización de ERC-7702
ERC-7702 proporciona a una EOA una delegación persistente al código de una cuenta inteligente; la delegación no ejecuta la inicialización de forma atómica. Si la inicialización se puede llamar externamente, un observador puede hacer front-run y establecerse como propietario.<sup>[[7]](#references)</sup>

Mitigación: exige que los datos de llamada de inicialización estén autorizados por la EOA y permite la inicialización solo una vez. En un flujo ERC-4337 EIP-7702, restringe también el caller a `EntryPoint.senderCreator()`.<sup>[[5]](#references)[[7]](#references)</sup>
```solidity
function initialize(address newOwner, bytes calldata initSig) external {
require(owner == address(0), "already inited");
// Verify the EOA's signature over the complete initialization calldata.
require(_isAuthorizedByEOA(newOwner, initSig), "bad init auth");
owner = newOwner;
}
```
## Comprobaciones rápidas antes de la integración
- Validar las firmas usando `userOpHash` de `EntryPoint` (vincula los campos de gas).
- Restringir las funciones privilegiadas a `EntryPoint` y/o `address(this)` según corresponda.
- Mantener `validateUserOp` sin estado, determinista y compatible con las reglas de simulación del bundler.
- Aplicar la separación de dominios de EIP-712 para ERC-1271 y devolver `0x1626ba7e` en caso de éxito.
- Mantener `postOp` minimalista, acotado y sin posibilidad de revertir; asegurar las fees durante la validación.
- Probar por separado la primera ruta de `initCode`: despliegue determinista, comportamiento idempotente de la factory e inicialización de un solo uso.
- Ejecutar la validación multipaso del bundler y una comprobación trazada del bundle completo antes del lanzamiento.
- Para ERC-7702, vincular la inicialización a la autorización de la EOA y permitirla solo una vez; en los flujos de ERC-4337, restringir el caller a `EntryPoint.senderCreator()`.

## References

- [1] [Replay de ERC1271: más de 15 equipos afectados (curiousapple)](https://paragraph.com/@curiousapple/fwlBuaAuGsWwLRPTLKxB)
- [2] [Seis errores en las smart accounts de ERC-4337 (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [3] [ERC-1271: método estándar de validación de firmas para contratos](https://eips.ethereum.org/EIPS/eip-1271)
- [4] [EIP-712: hashing y firma de datos estructurados tipados](https://eips.ethereum.org/EIPS/eip-712)
- [5] [ERC-4337: abstracción de cuentas usando Alt Mempool](https://eips.ethereum.org/EIPS/eip-4337)
- [6] [ERC-7562: reglas del alcance de validación de la abstracción de cuentas](https://eips.ethereum.org/EIPS/eip-7562)
- [7] [EIP-7702: establecer código para EOAs](https://eips.ethereum.org/EIPS/eip-7702)
{{#include ../../banners/hacktricks-training.md}}
