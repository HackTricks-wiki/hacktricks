# Compromiso del flujo de firma de Web3 y takeover de un proxy Safe mediante Delegatecall

{{#include ../../banners/hacktricks-training.md}}

## Descripción general

Una cadena de theft de una cold-wallet combinó un **compromiso de la cadena de suministro de la web UI de Safe{Wallet}** con una **primitive on-chain de delegatecall que sobrescribió el puntero de implementación de un proxy (slot 0)**. Las conclusiones clave son:

- Si una dApp puede inyectar código en el signing path, puede hacer que un signer produzca una **firma EIP-712 válida sobre campos elegidos por el atacante**, mientras restaura los datos originales de la UI para que los demás signers no se den cuenta.
- Los proxies de Safe almacenan `masterCopy` (implementación) en el **storage slot 0**. Un delegatecall a un contrato que escribe en el slot 0 efectivamente “actualiza” el Safe a la lógica del atacante, otorgando control total de la wallet.

## Off-chain: mutación de signing dirigida en Safe{Wallet}

Un bundle de Safe manipulado (`_app-*.js`) atacaba selectivamente direcciones específicas de Safe + signer. La lógica inyectada se ejecutaba justo antes de la llamada de firma:<sup>[[1]](#references)[[3]](#references)</sup>
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
### Propiedades del ataque
- **Context-gated**: las allowlists codificadas de Safes/firmantes víctimas evitaron ruido y redujeron la detección.<sup>[[1]](#references)[[3]](#references)</sup>
- **Last-moment mutation**: los campos (`to`, `data`, `operation`, gas) se sobrescribían inmediatamente antes de `signTransaction` y después se revertían, por lo que los payloads de la propuesta en la UI parecían benignos mientras que las firmas coincidían con el payload del atacante.
- **EIP-712 opacity**: las wallets mostraban datos estructurados, pero no decodificaban calldata anidado ni destacaban `operation = delegatecall`, lo que hacía que el mensaje mutado se firmara a ciegas.

### Relevancia de la validación del Gateway
Las propuestas de Safe se envían al **Safe Client Gateway**. Antes de que se implementaran checks reforzados, el gateway podía aceptar una propuesta cuyo `safeTxHash`/firma correspondiera a campos diferentes de los del cuerpo JSON si la UI los reescribía después de la firma. Tras el incidente, el gateway ahora rechaza las propuestas cuyo hash/firma no coincida con la transacción enviada. Debe aplicarse una verificación del hash similar en el servidor para cualquier API de orquestación de firmas.

### Aspectos destacados del incidente de Bybit/Safe de 2025
- El vaciado de la cold-wallet de Bybit del 21 de febrero de 2025 (~401k ETH) reutilizó el mismo patrón: un bundle S3 comprometido solo se activaba para los firmantes de Bybit y cambiaba `operation=0` → `1`, apuntando `to` a un contrato del atacante predesplegado que escribía en el slot 0.<sup>[[1]](#references)[[3]](#references)</sup>
- `_app-52c9031bfa03da47.js`, almacenado en la caché de Wayback, muestra la lógica vinculada al Safe de Bybit (`0x1db9…cf4`) y a las direcciones de los firmantes; después se revirtió inmediatamente a un bundle limpio dos minutos después de la ejecución, reproduciendo el truco de “mutate → sign → restore”.<sup>[[1]](#references)[[2]](#references)</sup>
- El contrato malicioso (por ejemplo, `0x9622…c7242`) contenía funciones simples `sweepETH/sweepERC20` y un `transfer(address,uint256)` que escribe en el implementation slot. La ejecución de `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` cambió la implementación del proxy y otorgó control total.<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain: Delegatecall proxy takeover mediante colisión de slots

Los proxies de Safe mantienen `masterCopy` en el **storage slot 0** y delegan toda la lógica en él. Como Safe admite **`operation = 1` (delegatecall)**, cualquier transacción firmada puede apuntar a un contrato arbitrario y ejecutar su código en el contexto de almacenamiento del proxy.<sup>[[3]](#references)</sup>

Un contrato del atacante imitaba un `transfer(address,uint256)` de ERC-20, pero en su lugar escribía `_to` en el slot 0:<sup>[[1]](#references)[[3]](#references)</sup>
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Execution path:<sup>[[1]](#references)[[3]](#references)</sup>
1. Las víctimas firman `execTransaction` con `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`.
2. Safe masterCopy valida las firmas sobre estos parámetros.
3. El proxy ejecuta un delegatecall en `attackerContract`; el cuerpo de `transfer` escribe en el slot 0.
4. El slot 0 (`masterCopy`) ahora apunta a lógica controlada por el atacante → **full wallet takeover y fund drain**.

### Notas sobre Guard y versiones (hardening posterior al incidente)
- Los Safes >= v1.3.0 pueden instalar un **Guard** para vetar `delegatecall` o aplicar ACLs sobre `to`/selectores; Bybit utilizaba v1.1.1, por lo que no existía ningún hook de Guard. Es necesario actualizar los contratos (y volver a añadir los owners) para obtener este control plane.

## Checklist de detección y hardening

- **Integridad de la UI**: fijar los assets JS / SRI; monitorizar las diferencias entre bundles; tratar la signing UI como parte del trust boundary.
- **Validación en el momento de firmar**: hardware wallets con **EIP-712 clear-signing**; mostrar explícitamente `operation` y decodificar el calldata anidado. Rechazar la firma cuando `operation = 1`, salvo que la policy lo permita.
- **Comprobaciones de hashes en el servidor**: los gateways/services que retransmiten proposals deben recalcular `safeTxHash` y validar que las firmas coincidan con los campos enviados.
- **Policies/allowlists**: reglas de preflight para `to`, selectores y tipos de assets, y prohibir delegatecall salvo en flows verificados. Exigir un servicio interno de policy antes de broadcast de transacciones completamente firmadas.
- **Diseño de contratos**: evitar exponer delegatecall arbitrario en wallets multisig/treasury, salvo que sea estrictamente necesario. Colocar los punteros de upgrade lejos del slot 0 o protegerlos con lógica de upgrade explícita y access control.
- **Monitoring**: generar alertas sobre ejecuciones de delegatecall desde wallets que contienen fondos de treasury y sobre proposals que cambien `operation` respecto a los patrones habituales de `call`.

## Referencias

- [1] [AnChain.AI forensic breakdown of the Bybit Safe exploit](https://www.anchain.ai/blog/bybit)
- [2] [Zero Hour Technology analysis of the Safe bundle compromise](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [In-depth technical analysis of the Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
