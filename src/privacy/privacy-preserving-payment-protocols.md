# Protocolos de pago que preservan la privacidad

Los sistemas de pago avanzados pueden ocultar al pagador frente al merchant, ocultar un receptor o un importe en un ledger público, o impedir que un mint vincule un withdrawal con un redemption. Estas son propiedades diferentes. Ninguna elimina los registros de adquisición, dispositivo, red, entrega, contabilidad, sanciones o endpoint.

El [Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) proporciona una entrada estandarizada de `Pros`, `Cons`, `Procedure` paso a paso y `Detection` para cada familia de pagos. Esta página amplía los protocolos avanzados.

{% hint style="danger" %}
Usa únicamente fondos y counterparties legales. No utilices privacy protocols para eludir requisitos de identificación, sanciones, impuestos, comprobaciones de source-of-funds o notificación de transacciones. No operes un exchange, mint o servicio de transmisión sin comprender las obligaciones de licensing, custody, AML y protección del consumidor.
{% endhint %}

## Comparación de las opciones avanzadas

| Protocol | Oculta frente a public/merchant | Parte de confianza u observadora | Madurez/disponibilidad |
|---|---|---|---|
| Bitcoin Silent Payments (BIP 352) | Los terceros no pueden vincular un payment code reutilizable con sus outputs de un solo uso | El grafo público de Bitcoin permanece; el wallet/index server puede ver los scans | Especificación completa; el soporte de los wallets varía |
| Zcash fully shielded Orchard | El sender, receiver y amount están cifrados on-chain | El wallet backend/network y la acquisition/off-ramp permanecen | Desplegado; el soporte shielded varía según el wallet/exchange |
| GNU Taler | El merchant no necesita conocer la identidad del payer; los ingresos del merchant siguen siendo auditables | El Taler exchange/bank ve el funding; el merchant ve el pedido | Los deployments están limitados geográficamente |
| Federated Chaumian e-cash | La federation no debería vincular los notes emitidos con las transferencias/redemptions internas | El guardian quorum custodia las reservas; los gateways ven la actividad de los límites | Deployments comunitarios emergentes |
| Lightning BOLT 12/route blinding | Reduce la divulgación del receiver/node y de la ruta | Los endpoints, hops seleccionados, funding chain y wallet services | El soporte depende del wallet |
| Virtual card/token | El merchant recibe una credencial limitada, no un PAN reutilizable | El issuer/network conserva el payer y la transacción | Maduro y ampliamente disponible |

## Bitcoin Silent Payments (BIP 352)

Silent Payments permite que un receiver publique un único payment code estático mientras cada sender deriva un output Taproot único. Un observador externo de la chain no puede vincular directamente esos outputs con el code publicado, y no se requiere una solicitud interactiva de address ni un output de notificación on-chain. BIP 352 está marcado como **Complete**, pero introduce un coste de scanning y es incompatible con los wallets que no lo han implementado.<sup>[[1]](#references)</sup>

### Flujo de trabajo del receiver

1. Selecciona un wallet mantenido que admita explícitamente la recepción mediante BIP 352; verifica la función en la documentación actual del wallet, no en una afirmación de redes sociales.
2. Haz backup del seed del wallet y del material del descriptor/key de Silent Payment usando el método de recuperación documentado por el wallet. Prueba el discovery con un importe pequeño de testnet/mainnet antes de publicar el code.
3. Genera **labels** separadas para campañas, invoices o counterparties cuando el wallet admita labels de BIP 352. Las labels ayudan a la contabilidad local sin publicar addresses vinculables.
4. Publica el code estático de Silent Payment mediante un canal autenticado. Es reutilizable, pero un impostor puede sustituirlo por su propio code.
5. Realiza el scan mediante un full node local cuando sea práctico. Un servidor de index/scanning de terceros puede conocer los tiempos de las solicitudes o los datos de los filtros aunque no pueda gastar.
6. Mantén los UTXOs descubiertos etiquetados y aplica las mismas reglas de coin-control que con Bitcoin ordinario. Gastarlos o consolidarlos puede revelar relaciones de ownership.
7. Confirma que la recovery descubre los pagos sin depender de un index externo no respaldado.

### Flujo de trabajo del sender

1. Confirma que el wallet admite el envío a la versión de address y autentica el code estático del receiver.
2. Deja que el wallet construya el output; nunca conviertas ni trunques el code manualmente.
3. Revisa cuidadosamente los inputs seleccionados. Silent Payments mejora la privacidad de la address del receiver, pero los inputs del sender siguen en el grafo público.
4. Utiliza el comportamiento de fee bumping/PSBT compatible con el wallet. BIP 352 requiere volver a derivar el output si cambian los inputs, y algunos modos de signing no son seguros.
5. Conserva un receipt o proof cifrado necesario para disputas/contabilidad.

Silent Payments resuelve la publicación repetida de la address del receiver. No oculta el amount, el momento de la transacción, el cluster del sender, el historial de adquisición ni el co-spending posterior.

## Pagos Zcash fully shielded

Zcash admite pools de valor transparent y shielded. Las transacciones shielded de Orchard utilizan zero-knowledge proofs para que los nodos puedan verificar la validez mientras los detalles de la transacción están cifrados; las Unified Addresses pueden contener varios tipos de receiver.<sup>[[2]](#references)</sup> La privacidad depende de la ruta real seleccionada por el wallet, no del primer carácter de una address mostrada.

### Flujo de trabajo shielded

1. Elige un wallet mantenido que identifique claramente el comportamiento **shielded-by-default** y el soporte actual de Orchard. Verifica el download y haz backup/test del seed.
2. Obtén ZEC legalmente y registra la base/fuente. Un exchange seguirá conociendo la adquisición y el withdrawal.
3. Recibe en una Unified Address compatible con el wallet y comprueba si la transacción llegó a un pool shielded. No asumas shielding automático sin confirmar el comportamiento del wallet.
4. Prefiere las transferencias **shielded-to-shielded**. Los movimientos de transparent-to-shielded y shielded-to-transparent exponen valores/tiempos públicos y pueden permitir la correlación de amounts; la especificación de Orchard indica que gastar hacia una address no-Orchard revela el valor de la transacción.<sup>[[3]](#references)</sup>
5. Evita round trips con importes exactos distintivos y boundary crossings inmediatos. Esto es higiene de privacidad, no un permiso para ocultar ownership o reporting.
6. Utiliza la ruta de network-privacy compatible con el wallet. La criptografía shielded no oculta la IP/temporalidad frente a los wallet servers o peers.
7. Conserva los registros internos de compliance y utiliza viewing keys únicamente para auditorías/divulgaciones deliberadas después de comprender su alcance.
8. Confirma el soporte del wallet/exchange del receiver antes de enviar; un receiver transparent obligado cambia la propiedad de privacidad.

## GNU Taler: payer anónimo, merchant responsable

GNU Taler es un protocolo abierto de electronic-payment que utiliza monedas tradicionales, blind signatures e integración con exchange/bank regulados. Su diseño pretende mantener anónimos a los customers frente a los merchants, mientras los merchants siguen siendo identificables y sujetos a impuestos.<sup>[[4]](#references)</sup> No es una cryptocurrency y su disponibilidad depende de un exchange, bank, wallet y merchant regionales compatibles.

### Flujo de trabajo del usuario cuando está disponible

1. Identifica un exchange Taler y un merchant operativos en la moneda/jurisdicción relevante; lee sus términos, fees, KYC y avisos de privacidad actuales.
2. Instala el wallet oficial y verifica su origen. Protege los datos de backup/recovery del wallet como si fueran efectivo, porque el valor del wallet puede ser un bearer asset.
3. Realiza el withdrawal mediante el flujo compatible de bank/exchange usando información veraz. La institución de funding/exchange puede conocer el withdrawal aunque las blind signatures rompan el vínculo directo entre coin y withdrawal.
4. Revisa el contrato del merchant en el wallet: identidad del merchant, artículo/resumen, amount, fees, refund y condiciones de entrega.
5. Paga y conserva los datos del receipt necesarios para refund, garantía, contabilidad o impuestos.
6. No reutilices identificadores opcionales de sesión/cuenta del merchant si necesitas unlinkability frente al merchant.
7. Incluye en el threat model los metadatos del wallet, la red y la entrega; la criptografía de pago de Taler no oculta una shipping address ni un endpoint comprometido.

El merchant y el exchange siguen siendo responsables, y operar cualquiera de esos componentes puede constituir una actividad regulada de servicios de pago.

## Federated Chaumian e-cash

Chaumian e-cash utiliza blind signatures para que un mint firme un token sin ver posteriormente el token sin blinding que se gasta. Fedimint distribuye la custodia de reservas y el signing entre una guardian federation; su documentación indica que los guardians ven las reservas agregadas/notes pendientes, pero no deberían ver el balance individual ni quién pagó a quién dentro de la federation.<sup>[[5]](#references)</sup>

Se trata de **custodial bearer value**. Un quorum suficiente de guardians controla las reservas; el fallo de la federation, guardians deshonestos, bugs de software o la pérdida del estado del cliente pueden causar pérdidas. Los depósitos, withdrawals y Lightning gateways son boundary events visibles y pueden correlacionar tiempos/amounts.

### Flujo de trabajo de riesgo limitado

1. Utiliza únicamente un importe pequeño que puedas permitirte perder. Trata las federations públicas/desconocidas como de mayor riesgo que los guardians con responsabilidad en el mundo real.
2. Verifica la invitación de la federation mediante un canal autenticado y registra las identidades de los guardians, el quorum, la jurisdicción, los fees, la recovery y la política de shutdown.
3. Instala un wallet compatible y mantenido, verifícalo y comprende su esquema de backup antes de depositar.
4. Deposita Bitcoin adquirido legalmente mediante la ruta documentada. Registra el peg-in para la contabilidad y asume que su momento/amount es público o conocido en el límite.
5. Dentro de la federation, utiliza payment requests nuevos y evita añadir identificadores de cuenta/chat/entrega que reconstruyan el vínculo eliminado por la blind signature.
6. Para pagos Lightning, trata el gateway como un observador adicional de los invoices y del momento del boundary.
7. Realiza el redeem/withdraw según la política, esperando que un amount distintivo y un momento inmediato puedan correlacionarse con un depósito o pago externo.
8. Conserva de forma privada los registros fiscales, de origen y autorización; no pidas a guardians o gateways que falseen la actividad.

No describas el e-cash federado como trustless, self-custodial o anónimo garantizado.

## BOLT 12 offers y route blinding

Las BOLT 12 offers pueden ser reutilizables sin publicar una address on-chain estable y pueden utilizar blinded paths para que el payer no necesite conocer la identidad/path clear del node del receiver. Esto complementa, pero no sustituye, el onion routing existente de Lightning.

Antes de usarlo:

1. Confirma que los wallets del sender y del receiver admiten las mismas funciones actuales de BOLT 12; no deduzcas el soporte a partir de una marca genérica de “Lightning”.
2. Autentica la offer out of band y comprueba el amount, el issuer/description y las reglas de recurrencia.
3. Utiliza un contexto nuevo de invoice/payment generado a partir de la offer.
4. Mantén al mínimo los aliases de los nodes, la información de contacto pública y los endpoints de red estables.
5. Asume que el sender/receiver, el first/last hop, el wallet service, el channel graph y el funding/closure on-chain siguen revelando partes de la relación.

## Auditabilidad sin divulgación pública

La privacidad y la auditoría pueden coexistir:

- Conserva cifrados fuera del protocolo público las labels, invoices, autorizaciones, el cost basis y el mapping de ownership.
- Separa una **view/audit key** de una spending key cuando el protocolo proporcione una; prueba primero su divulgación exacta en un wallet de muestra.
- Proporciona al auditor el proof mínimo y limitado, en lugar de un seed o una credencial de spending sin restricciones.
- Registra en el momento de la transacción la versión del software, el protocolo/pool, el ID o proof de la transacción, el propósito del counterparty y la fuente del tipo de cambio.
- Define la retención y eliminación en lugar de acumular un identity graph permanente sin cifrar.

## Checklist de selección

- [ ] El campo oculto y el observer están definidos con precisión.
- [ ] El soporte del wallet/protocolo se verificó en la fecha de la transacción.
- [ ] Están documentados los vínculos de adquisición, red, node/RPC, counterparty, entrega y gasto posterior.
- [ ] Se aceptan los riesgos de custody, recovery, liquidity, solvency del issuer/federation y refunds.
- [ ] Los registros obligatorios de identidad, impuestos, sanciones, origen y organización siguen siendo exactos.
- [ ] Una prueba end-to-end pequeña, incluida la recovery y el audit proof, tuvo éxito.

## References

- [1] [BIP 352 — Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
- [2] [Zcash — Unified Addresses](https://z.cash/learn/what-are-zcash-unified-addresses/) and [The Orchard Book — Keys and addresses](https://zcash.github.io/orchard/design/keys.html)
- [3] [ZIP 224 — Orchard Shielded Protocol](https://zips.z.cash/zip-0224)
- [4] [Documentación de GNU Taler](https://docs.taler.net/) and [Merchant Manual — About GNU Taler](https://docs.taler.net/taler-merchant-manual.html)
- [5] [Fedimint — Cómo funciona](https://fedimint.org/users/how-it-works), [How federations work](https://fedimint.org/guardians/how-federations-work), and [Threshold blind signatures](https://docs.fedimint.org/crypto/index.html)
- [6] [BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
