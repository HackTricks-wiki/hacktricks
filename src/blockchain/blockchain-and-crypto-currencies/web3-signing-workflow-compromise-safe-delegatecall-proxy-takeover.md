# Compromiso del flujo de firma de Web3 y takeover de proxy Safe Delegatecall

{{#include ../../banners/hacktricks-training.md}}

## Descripción general

Una cadena de robo de una cold-wallet combinó un **supply-chain compromise de la interfaz web de Safe{Wallet}** con una **primitiva on-chain de delegatecall que sobrescribía el puntero de implementación de un proxy (slot 0)**. Las conclusiones clave son:

- Si una dApp puede inyectar código en el flujo de firma, puede hacer que un signer produzca una **firma EIP-712 válida sobre campos elegidos por el atacante** mientras restaura los datos originales de la UI para que los demás signers no se den cuenta.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
- Los proxies de Safe almacenan `masterCopy` (implementación) en el **storage slot 0**. Un delegatecall a un contrato que escribe en el slot 0 efectivamente “actualiza” el Safe a la lógica del atacante, otorgándole control total de la wallet.<sup>[[3]](#references)</sup>

## Off-chain: Mutación de firma dirigida en Safe{Wallet}

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
- **Context-gated**: las allowlists codificadas de forma rígida para las Safes/firmantes víctimas evitaron el ruido y redujeron la detección.<sup>[[1]](#references)[[3]](#references)</sup>
- **Last-moment mutation**: los campos (`to`, `data`, `operation`, gas) se sobrescribían inmediatamente antes de `signTransaction` y luego se revertían, por lo que los payloads de las propuestas en la UI parecían benignos mientras las firmas coincidían con el payload del atacante.<sup>[[3]](#references)</sup>
- **EIP-712 opacity**: las wallets mostraban datos estructurados, pero no decodificaban el calldata anidado ni resaltaban `operation = delegatecall`, lo que hacía que el mensaje mutado se firmara a ciegas.<sup>[[3]](#references)[[4]](#references)</sup>

### Relevancia de la validación del Gateway
Las propuestas de Safe se envían al **Safe Client Gateway**.<sup>[[5]](#references)</sup> Antes de implementar comprobaciones reforzadas, el gateway podía aceptar una propuesta en la que `safeTxHash`/la firma correspondieran a campos distintos de los del cuerpo JSON si la UI los reescribía después de la firma. Tras el incidente, el gateway ahora rechaza las propuestas cuyo hash o firma no coinciden con la transacción enviada.<sup>[[3]](#references)</sup> Debe aplicarse una verificación del hash similar en el servidor para cualquier API de orquestación de firmas.

### Aspectos destacados del incidente de Bybit/Safe de 2025
- El vaciado de la cold wallet de Bybit del 21 de febrero de 2025 (~401k ETH) reutilizó el mismo patrón: un bundle S3 comprometido solo se activaba para los firmantes de Bybit y cambiaba `operation=0` → `1`, apuntando `to` a un contrato del atacante previamente desplegado que escribía en el slot 0.<sup>[[1]](#references)[[3]](#references)</sup>
- `_app-52c9031bfa03da47.js`, almacenado en la caché de Wayback, muestra la lógica vinculada a la Safe de Bybit (`0x1db9…cf4`) y a las direcciones de los firmantes; después se revirtió inmediatamente a un bundle limpio dos minutos después de la ejecución, reproduciendo el truco de «mutar → firmar → restaurar».<sup>[[1]](#references)[[2]](#references)</sup>
- El contrato malicioso (por ejemplo, `0x9622…c7242`) contenía funciones simples `sweepETH/sweepERC20` y un `transfer(address,uint256)` que escribía en el slot de implementación. La ejecución de `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` modificó la implementación del proxy y otorgó control total.<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain: toma de control de un proxy mediante delegatecall y colisión de slots

Los proxies de Safe mantienen `masterCopy` en el **storage slot 0** y delegan toda la lógica en él. Debido a que Safe admite **`operation = 1` (delegatecall)**, cualquier transacción firmada puede apuntar a un contrato arbitrario y ejecutar su código en el contexto de almacenamiento del proxy.<sup>[[3]](#references)</sup>

Un contrato del atacante imitaba un `transfer(address,uint256)` de ERC-20, pero en su lugar escribía `_to` en el slot 0:<sup>[[1]](#references)[[3]](#references)</sup>
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Ruta de ejecución:<sup>[[1]](#references)[[3]](#references)</sup>
1. Las víctimas firman `execTransaction` con `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`.
2. Safe masterCopy valida las firmas sobre estos parámetros.
3. El proxy ejecuta un delegatecall en `attackerContract`; el cuerpo de `transfer` escribe en el slot 0.
4. El slot 0 (`masterCopy`) ahora apunta a una lógica controlada por el atacante → **toma de control total de la wallet y drenaje de fondos**.

### Notas sobre guards y versiones (hardening posterior al incidente)
- Los transaction guards se introdujeron en Safe v1.3.0 y pueden inspeccionar todos los parámetros de `execTransaction` antes de la ejecución; un guard puede rechazar `delegatecall` o aplicar políticas sobre el destino y el calldata. Bybit ejecutaba v1.1.1, que es anterior a este hook.<sup>[[2]](#references)[[6]](#references)</sup>

## Lista de comprobación de detección y hardening

- **Integridad de la UI**: fijar los assets JS / SRI; monitorizar las diferencias entre bundles; tratar la UI de firma como parte del límite de confianza.
- **Validación en el momento de la firma**: hardware wallets con **EIP-712 clear-signing**; mostrar explícitamente `operation` y decodificar el calldata anidado. Rechazar la firma cuando `operation = 1`, salvo que la política lo permita.<sup>[[3]](#references)</sup>
- **Comprobaciones de hashes en el servidor**: los gateways/services que retransmiten propuestas deben volver a calcular `safeTxHash` y validar que las firmas coincidan con los campos enviados.<sup>[[3]](#references)</sup>
- **Políticas/allowlists**: reglas de preflight para `to`, selectors y tipos de assets, y prohibir delegatecall salvo en flows verificados. Requerir un servicio interno de políticas antes de broadcast de transacciones completamente firmadas.
- **Diseño de contratos**: evitar exponer delegatecall arbitrario en wallets multisig/treasury, salvo que sea estrictamente necesario. Tratar cualquier puntero de implementación como un primitivo de upgrade: protegerlo con un control de acceso explícito y aplicar guard a los destinos/selectors de delegatecall; mover el puntero a otro slot por sí solo no constituye una defensa completa.<sup>[[3]](#references)[[6]](#references)</sup>
- **Monitorización**: generar alertas ante ejecuciones de delegatecall desde wallets que contienen fondos de treasury y ante propuestas que cambien `operation` desde los patrones habituales de `call`.

## References

- [1] [Análisis forense de AnChain.AI sobre el exploit de Bybit Safe](https://www.anchain.ai/blog/bybit)
- [2] [Análisis de Zero Hour Technology sobre el compromiso del bundle de Safe](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [Análisis técnico detallado del hack de Bybit (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)
- [6] [Registro de cambios de Safe smart account v1.3.0 (GitHub)](https://github.com/safe-fndn/safe-smart-account/blob/main/CHANGELOG.md)
{{#include ../../banners/hacktricks-training.md}}
