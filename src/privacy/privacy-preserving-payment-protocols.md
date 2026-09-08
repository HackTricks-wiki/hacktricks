# Protocolos de pago que preservan la privacidad

{{#include ../banners/hacktricks-training.md}}

Los sistemas de pago avanzados pueden ocultar al pagador frente al comerciante, ocultar un destinatario o importe en un registro público, o impedir que un mint vincule un retiro con un canje. Estas son propiedades diferentes. Ninguna elimina los registros de adquisición, dispositivo, red, entrega, contabilidad, sanciones o endpoints.

El [Catálogo de técnicas de Anonymous Payment](anonymous-payment-techniques.md) proporciona entradas estandarizadas de `Pros`, `Cons`, `Procedure` paso a paso y `Detection` para cada familia de pagos. Esta página amplía los protocolos avanzados.

{% hint style="danger" %}
Usa únicamente fondos y contrapartes legales. No utilices protocolos de privacidad para evadir la identificación obligatoria, las sanciones, los impuestos, las comprobaciones de origen de fondos o los informes de transacciones. No operes un exchange, mint o servicio de transmisión sin comprender las obligaciones de licensing, custodia, AML y protección al consumidor.
{% endhint %}

## Comparación de las opciones avanzadas

| Protocolo | Qué oculta frente al público/comerciante | Parte de confianza u observadora | Madurez/disponibilidad |
|---|---|---|---|
| Bitcoin Silent Payments (BIP 352) | Los externos no pueden vincular un código de pago reutilizable con sus outputs de un solo uso | El grafo público de Bitcoin permanece; el servidor de wallet/index puede ver los escaneos | Especificación completa; el soporte de wallets varía |
| Zcash fully shielded Orchard | El remitente, receptor e importe están cifrados on-chain | El backend/red de la wallet y la adquisición/off-ramp permanecen visibles | Desplegado; el soporte shielded varía según la wallet/exchange |
| GNU Taler | El comerciante no necesita conocer la identidad del pagador; los ingresos del comerciante siguen siendo trazables | El exchange/banco de Taler ve la financiación; el comerciante ve el pedido | Los despliegues están geográficamente limitados |
| Federated Chaumian e-cash | La federación no debería vincular las notas emitidas con las transferencias/canjes internos | El quórum de guardians custodia las reservas; los gateways ven la actividad de los límites | Despliegues comunitarios emergentes |
| Lightning BOLT 12/route blinding | Reduce la divulgación del receptor/nodo y de la ruta | Los endpoints, saltos seleccionados, cadena de financiación y servicios de wallet | El soporte depende de la wallet |
| Virtual card/token | El comerciante recibe una credencial limitada, no un PAN reutilizable | El emisor/red conserva el pagador y la transacción | Maduro y ampliamente disponible |

## Bitcoin Silent Payments (BIP 352)

Silent Payments permite que un receptor publique un único código de pago estático mientras cada remitente deriva un output Taproot único. Un observador externo de la cadena no puede vincular directamente esos outputs con el código publicado, y no se requiere una solicitud interactiva de dirección ni un output de notificación on-chain. BIP 352 está marcado como **Complete**, pero introduce un coste de escaneo y es incompatible con las wallets que no lo han implementado.<sup>[[1]](#references)</sup>

### Flujo de trabajo del receptor

1. Selecciona una wallet mantenida que admita explícitamente la recepción mediante BIP 352; verifica la función en la documentación actual de la wallet, no en una afirmación de redes sociales.
2. Realiza un backup del seed de la wallet y del material del descriptor/clave de Silent Payment usando el método de recuperación documentado por la wallet. Prueba el descubrimiento con un importe pequeño en testnet/mainnet antes de publicar el código.
3. Genera **labels** separadas para campañas, facturas o contrapartes cuando la wallet admita labels de BIP 352. Las labels ayudan a la contabilidad local sin publicar direcciones vinculables.
4. Publica el código estático de Silent Payment mediante un canal autenticado. Es reutilizable, pero un impostor puede sustituirlo por su propio código.
5. Escanea mediante un full node local cuando sea práctico. Un servidor externo de indexación/escaneo puede conocer el momento de las solicitudes o los datos de los filtros aunque no pueda gastar los fondos.
6. Mantén los UTXOs descubiertos etiquetados y aplica las mismas reglas de coin-control que con Bitcoin ordinario. Gastarlos o consolidarlos puede revelar relaciones de propiedad.
7. Confirma que la recuperación descubre los pagos sin depender de un índice externo no respaldado.

### Flujo de trabajo del remitente

1. Confirma que la wallet admite el envío a la versión de dirección y autentica el código estático largo del receptor.
2. Permite que la wallet construya el output; nunca conviertas ni trunques el código manualmente.
3. Revisa cuidadosamente los inputs seleccionados. Silent Payments mejora la privacidad de la dirección del receptor, pero los inputs del remitente siguen estando en el grafo público.
4. Usa el comportamiento de fee bumping/PSBT compatible con la wallet. BIP 352 requiere volver a derivar los outputs si cambian los inputs, y algunos modos de firma no son seguros.
5. Conserva un recibo o prueba cifrada necesaria para disputas/contabilidad.

Silent Payments resuelve la publicación repetida de la dirección del receptor. No oculta el importe, el momento de la transacción, el cluster del remitente, el historial de adquisición ni el co-gasto posterior.

## Pagos de Zcash fully shielded

Zcash admite pools de valor transparentes y shielded. Las transacciones shielded de Orchard utilizan zero-knowledge proofs para que los nodos puedan verificar la validez mientras los detalles de la transacción están cifrados; las Unified Addresses pueden contener varios tipos de receptores.<sup>[[2]](#references)</sup> La privacidad depende de la ruta real seleccionada por la wallet, no del primer carácter de una dirección mostrada.

### Flujo de trabajo shielded

1. Elige una wallet mantenida que identifique claramente el comportamiento **shielded-by-default** y el soporte actual de Orchard. Verifica la descarga y realiza un backup/prueba del seed.
2. Obtén ZEC legalmente y registra la base/el origen. Un exchange sigue conociendo la adquisición y el retiro.
3. Recibe en una Unified Address compatible con la wallet y comprueba si la transacción llegó a un pool shielded. No asumas el shielding automático sin confirmar el comportamiento de la wallet.
4. Prefiere las transferencias **shielded-to-shielded**. Los movimientos transparent-to-shielded y shielded-to-transparent en los límites exponen valores/momentos públicos y pueden permitir la correlación de importes; la especificación de Orchard señala que gastar en una dirección no-Orchard revela el valor de la transacción.<sup>[[3]](#references)</sup>
5. Evita los round trips con importes exactos distintivos y los cruces inmediatos de límites. Esto es higiene de privacidad, no un permiso para ocultar la propiedad o los informes.
6. Utiliza la ruta de privacidad de red compatible con la wallet. La criptografía shielded no oculta la IP/el momento frente a los servidores de la wallet o los peers.
7. Conserva registros internos de compliance y utiliza viewing keys únicamente para auditorías/divulgaciones deliberadas después de comprender su alcance.
8. Confirma el soporte de la wallet/exchange del receptor antes de enviar; un receptor transparente forzado cambia la propiedad de privacidad.

## GNU Taler: pagador anónimo, comerciante responsable

GNU Taler es un protocolo abierto de pagos electrónicos que utiliza monedas tradicionales, blind signatures e integración con exchanges/bancos regulados. Su diseño pretende mantener anónimos a los clientes frente a los comerciantes, mientras los comerciantes siguen siendo identificables y sujetos a impuestos.<sup>[[4]](#references)</sup> No es una criptomoneda y su disponibilidad depende de un exchange regional compatible, un banco, una wallet y un comerciante.

### Flujo de trabajo del usuario cuando está disponible

1. Identifica un exchange y un comerciante de Taler operativos en la moneda/jurisdicción correspondiente; lee sus términos, tarifas, KYC y avisos de privacidad actuales.
2. Instala la wallet oficial y verifica su origen. Protege los datos de backup/recuperación de la wallet como si fueran efectivo, porque el valor de la wallet puede ser un bearer asset.
3. Retira valor mediante el flujo compatible de banco/exchange usando información veraz. La institución de financiación/exchange puede conocer el retiro aunque las blind signatures rompan el vínculo directo entre la moneda y el retiro.
4. Revisa el contrato del comerciante en la wallet: identidad del comerciante, artículo/resumen, importe, tarifas, reembolso y condiciones de entrega.
5. Paga y conserva los datos del recibo necesarios para el reembolso, la garantía, la contabilidad o los impuestos.
6. No reutilices identificadores opcionales de sesión/cuenta del comerciante si se requiere unlinkability frente al comerciante.
7. Incluye los metadatos de la wallet, la red y la entrega en el threat model; la criptografía de pago de Taler no oculta una dirección de envío ni un endpoint comprometido.

El comerciante y el exchange siguen siendo responsables, y operar cualquiera de esos componentes puede constituir una actividad regulada de servicios de pago.

## Federated Chaumian e-cash

Chaumian e-cash utiliza blind signatures para que un mint firme un token sin ver posteriormente el token sin cegar que se gasta. Fedimint distribuye la custodia de reservas y la firma entre una federación de guardians; su documentación indica que los guardians ven las reservas agregadas/notas pendientes, pero no deberían ver el saldo individual ni quién pagó a quién dentro de la federación.<sup>[[5]](#references)</sup>

Esto es **valor bearer con custodia**. Un quórum suficiente de guardians controla las reservas; un fallo de la federación, guardians deshonestos, errores de software o la pérdida del estado del cliente pueden causar pérdidas. Los depósitos, retiros y gateways de Lightning son eventos de límite visibles y pueden correlacionar el momento/importe.

### Flujo de trabajo de riesgo limitado

1. Utiliza únicamente un importe pequeño que puedas permitirte perder. Trata las federaciones públicas/desconocidas como de mayor riesgo que los guardians con responsabilidad en el mundo real.
2. Verifica la invitación de la federación mediante un canal autenticado y registra las identidades de los guardians, el quórum, la jurisdicción, las tarifas, la recuperación y la política de cierre.
3. Instala una wallet compatible y mantenida, verifícala y comprende su esquema de backup antes de depositar.
4. Deposita Bitcoin adquirido legalmente mediante la ruta documentada. Registra el peg-in para la contabilidad y asume que su momento/importe es público o conocido en el límite.
5. Dentro de la federación, utiliza solicitudes de pago nuevas y evita añadir identificadores de cuenta/chat/entrega que reconstruyan el vínculo eliminado por la blind signature.
6. Para pagos de Lightning, trata el gateway como un observador adicional de las facturas y del momento del límite.
7. Canjea/retira según la política, esperando que un importe distintivo y un momento inmediato puedan correlacionarse con un depósito o pago externo.
8. Conserva de forma privada los registros de impuestos/origen/autorización; no pidas a los guardians o gateways que falseen la actividad.

No describas el e-cash federado como trustless, self-custodial o anónimo garantizado.

## BOLT 12 offers y route blinding

Las BOLT 12 offers pueden reutilizarse sin publicar una dirección on-chain estable y pueden utilizar blinded paths para que el pagador no necesite conocer la identidad/ruta clara del nodo receptor. Esto complementa, pero no sustituye, el onion routing existente de Lightning.

Antes de usarlo:

1. Confirma que las wallets del remitente y del receptor admiten las mismas funciones actuales de BOLT 12; no deduzcas el soporte a partir de una marca genérica de “Lightning”.
2. Autentica la offer out of band y comprueba el importe, el emisor/la descripción y las reglas de recurrencia.
3. Utiliza un contexto nuevo de factura/pago generado a partir de la offer.
4. Mantén al mínimo los aliases de nodo, la información de contacto pública y los endpoints de red estables.
5. Asume que el remitente/receptor, el primer/último salto, el servicio de wallet, el grafo de canales y la financiación/cierre on-chain siguen revelando partes de la relación.

## Auditabilidad sin divulgación pública

La privacidad y la auditoría pueden coexistir:

- Conserva cifrados fuera del protocolo público las labels, facturas, autorizaciones, el coste de adquisición y el mapeo de propiedad.
- Separa una **view/audit key** de una spending key cuando el protocolo proporcione una; prueba primero su divulgación exacta en una wallet de muestra.
- Proporciona al auditor la prueba mínima y limitada, no un seed ni una credencial de gasto sin restricciones.
- Registra la versión del software, el protocolo/pool, el ID o la prueba de la transacción, el propósito de la contraparte y la fuente del tipo de cambio en el momento de la transacción.
- Define la retención y eliminación en lugar de acumular un grafo de identidades permanente y sin cifrar.

## Lista de comprobación de selección

- [ ] El campo oculto y el observador están definidos con precisión.
- [ ] El soporte de la wallet/protocolo se verificó en la fecha de la transacción.
- [ ] Los vínculos de adquisición, red, nodo/RPC, contraparte, entrega y gasto posterior están documentados.
- [ ] Se aceptan los riesgos de custodia, recuperación, liquidez, solvencia del emisor/federación y reembolsos.
- [ ] Los registros obligatorios de identidad, impuestos, sanciones, origen y organización siguen siendo precisos.
- [ ] Una prueba end-to-end pequeña, incluida la recuperación y la prueba de auditoría, tuvo éxito.

## References

- [1] [BIP 352 — Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
- [2] [Zcash — Direcciones unificadas](https://z.cash/learn/what-are-zcash-unified-addresses/) and [The Orchard Book — Keys and addresses](https://zcash.github.io/orchard/design/keys.html)
- [3] [ZIP 224 — Protocolo Shielded de Orchard](https://zips.z.cash/zip-0224)
- [4] [Documentación de GNU Taler](https://docs.taler.net/) and [Merchant Manual — About GNU Taler](https://docs.taler.net/taler-merchant-manual.html)
- [5] [Fedimint — Cómo funciona](https://fedimint.org/users/how-it-works), [How federations work](https://fedimint.org/guardians/how-federations-work), and [Threshold blind signatures](https://docs.fedimint.org/crypto/index.html)
- [6] [BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
{{#include ../banners/hacktricks-training.md}}
