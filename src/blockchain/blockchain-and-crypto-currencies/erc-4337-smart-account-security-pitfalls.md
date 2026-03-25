# ERC-4337 Riesgos de seguridad de cuentas inteligentes

{{#include ../../banners/hacktricks-training.md}}

La abstracción de cuentas ERC-4337 convierte wallets en sistemas programables. El flujo central es **validar-antes-de-ejecutar** a lo largo de todo un lote: el `EntryPoint` valida cada `UserOperation` antes de ejecutar cualquiera de ellas. Este orden crea una superficie de ataque no obvia cuando la validación es permisiva o con estado.

## 1) Evasión por llamada directa a funciones privilegiadas
Cualquier función `execute` invocable externamente (o que mueva fondos) que no esté restringida a `EntryPoint` (o a un módulo ejecutor verificado) puede ser llamada directamente para vaciar la cuenta.
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Patrón seguro: restringir a `EntryPoint` y usar `msg.sender == address(this)` para flujos de administración/autogestión (instalación de módulos, cambios de validadores, actualizaciones).
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Campos de gas no firmados o no verificados -> drenaje de tarifas
Si la validación de la firma solo cubre la intención (`callData`) pero no los campos relacionados con gas, un bundler o frontrunner puede inflar las tarifas y drenar ETH. La carga firmada debe vincular al menos:

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Patrón defensivo: usa el `EntryPoint`-proporcionado `userOpHash` (que incluye los campos de gas) y/o limita estrictamente cada campo.
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
Debido a que todas las validaciones se ejecutan antes de cualquier ejecución, almacenar resultados de validación en el estado del contrato es inseguro. Otra op en el mismo bundle puede sobrescribirlo, provocando que tu ejecución use un estado influenciado por el atacante.

Evita escribir en storage dentro de `validateUserOp`. Si es inevitable, indexa los datos temporales por `userOpHash` y elimínalos de forma determinista después de usarlos (preferir validación sin estado).

## 4) ERC-1271 replay across accounts/chains (missing domain separation)
`isValidSignature(bytes32 hash, bytes sig)` debe vincular las firmas a **este contrato** y **esta cadena**. Recuperar sobre un hash crudo permite que las firmas se repliquen entre cuentas o cadenas.

Usa EIP-712 typed data (el dominio incluye `verifyingContract` y `chainId`) y devuelve el valor mágico exacto de ERC-1271 `0x1626ba7e` en caso de éxito.

## 5) Reverts do not refund after validation
Una vez que `validateUserOp` tiene éxito, las tarifas quedan comprometidas incluso si la ejecución revierte después. Los atacantes pueden enviar repetidamente ops que fallarán y aun así cobrar las tarifas de la cuenta.

Para paymasters, pagar desde un pool compartido en `validateUserOp` y cobrar a los usuarios en `postOp` es frágil porque `postOp` puede revertir sin deshacer el pago. Asegura los fondos durante la validación (depósito en custodia por usuario), y mantén `postOp` mínimo y sin reversiones.

## 6) ERC-7702 initialization frontrun
ERC-7702 permite que una EOA ejecute código de smart-account para una sola tx. Si la inicialización es callable externamente, un frontrunner puede establecerse como owner.

Mitigación: permitir la inicialización solo en **self-call** y solo una vez.
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Chequeos rápidos antes del merge
- Validar firmas usando `userOpHash` de `EntryPoint` (vincula los campos de gas).
- Restringir las funciones privilegiadas a `EntryPoint` y/o `address(this)` según corresponda.
- Mantener `validateUserOp` sin estado.
- Aplicar la separación de dominio EIP-712 para ERC-1271 y devolver `0x1626ba7e` en caso de éxito.
- Mantener `postOp` mínimo, acotado y que no revierta; asegurar las tarifas durante la validación.
- Para ERC-7702, permitir init solo en self-call y solo una vez.

## Referencias

- [https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)

{{#include ../../banners/hacktricks-training.md}}
