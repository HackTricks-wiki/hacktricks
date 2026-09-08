# Catálogo de técnicas de pago anónimo

{{#include ../banners/hacktricks-training.md}}

Este catálogo abarca **familias** de pago, desde el efectivo ordinario hasta el e-cash con blind signatures y la ofuscación en cadenas públicas. “Anónimo” siempre significa anónimo frente a un observador concreto. Un comerciante, emisor, mint, exchange, analista de blockchain, proveedor de red, empleador y observador físico ven hechos diferentes.

Los procedimientos siguientes son para fondos lícitos, cuentas veraces y procurement autorizado. Las técnicas cuyo propósito en los casos citados fue el blanqueo, la evasión de sanciones o el fraude de identidad se explican y detectan, pero su procedimiento es un ejercicio forense sintético, no instrucciones para cometer el delito.

## Matriz de cobertura

| Familia | Propiedad principal de privacidad | Observador/confianza principal | Tratamiento |
|---|---|---|---|
| Efectivo y equivalentes | no existe un registro remoto de la red de pagos | receptor y entorno físico | flujo lícito |
| Valor prepago/regalo/vale | separa el canje de la tarjeta principal | vendedor, emisor y servicio de canje | flujo lícito, varía según jurisdicción |
| Tarjeta virtual/tokenizada | oculta el PAN reutilizable o separa a los comerciantes | emisor/red/wallet aún identifica al pagador | flujo lícito |
| App de pago/intermediario | el comerciante puede ver un alias/intermediario | la app recopila identidad/dispositivo/transacción | referencia comparativa |
| Higiene de Bitcoin/Silent Payments | seudónimos y unlinkability del receptor | grafo público y límite wallet/red | desplegable |
| PayJoin/CoinJoin | debilita las heurísticas de propiedad común/enlace | participantes/coordinator/red/grafo público | desplegable cuando sea compatible; revisión legal |
| Lightning/BOLT 12 | routing off-chain y reducción de la ruta del receptor | extremos, hops, servicios y grafo de canales | desplegable cuando sea compatible |
| Monero/Zcash/MWEB | confidencialidad on-chain a nivel de protocolo | adquisición, extremo, red y límites siguen expuestos | desplegable cuando sea lícito/compatible |
| Aplicación ZK de Ethereum | oculta un vínculo específico entre declaración/acción | entradas públicas, RPC, relayer y app | específico de la aplicación |
| Cashu/Fedimint/Taler | privacidad del pagador mediante blind signatures | custodia del mint/federation/exchange y límites | emergente/específico del despliegue |
| Stablecoins | liquidación digital conveniente | cadena transparente más control/congelación del emisor | no es una referencia de anonimato |
| Swaps/bridges/DEX | mueve valor entre activos/cadenas | ambos grafos, contratos y proveedores | mecánica forense; solo swaps lícitos ordinarios |
| Mixers/peel/structuring | aumenta la ambigüedad y el trabajo del grafo | grafo de entrada/salida y registros del servicio | solo ejercicio sintético de detección |
| Nominees/mules/OTC/fronts | inserta intermediarios humanos/empresariales | facilitadores, bancos, comunicaciones | solo análisis de abuso delictivo |
| Direcciones de pago reutilizables/stealth | dirección nueva del receptor por pago | anuncio/notificación públicos y límites del wallet | desplegable cuando sea compatible |
| Sidechain/State channel confidencial | oculta importe/activo o actualizaciones intermedias | pares, bridge/federation y liquidación del ciclo de vida | específico del protocolo |
| Carrier/open-banking/facturación de plataforma | oculta la tarjeta principal al comerciante | carrier, banco/PISP o plataforma identifica al cliente | pago ordinario identificado |
| Crédito mutuo/liquidación neta | menos registros externos de liquidación | el operador del ledger privado tiene el mapeo completo | solo participantes identificados |

## Efectivo

**Mecánica:** el valor físico al portador cambia de manos sin autorización online del emisor ni ledger público.

**Ventajas:** el comerciante no necesita conocer la identidad bancaria/de tarjeta; no existe grafo remoto de transacciones; es ampliamente comprensible y final.

**Desventajas:** solo cara a cara; robo/pérdida; controles de cambio/recibos/series o reporting; las retiradas, cámaras, testigos y ubicación aún pueden vincular al pagador.

**Procedimiento:** (1) confirmar que el efectivo es legal/aceptado y cualquier regla de importe/reporting; (2) retirarlo o recibirlo legalmente y conservar registros privados de contabilidad; (3) pagar a un comerciante ordinario sin identificadores innecesarios de loyalty/account; (4) solicitar solo el recibo necesario; (5) evitar datos de envío/cuenta si la compra no los necesita; (6) registrar internamente el propósito empresarial legítimo.

**Detección:** conciliar caja/recibo/inventario, cámaras y logs de acceso según la política aplicable; investigar reembolsos inusuales en efectivo o importes repetidos justo por debajo de controles sin tratar el uso ordinario de efectivo como sospechoso por sí mismo.

## Money order, giro postal, instrumento de caja y pago contra entrega

**Mecánica:** un emisor regulado convierte efectivo/fondos de cuenta en un instrumento numerado pagadero a un receptor identificado; COD retrasa el cobro hasta la entrega.

**Ventajas:** el receptor puede no recibir el número de la cuenta bancaria/tarjeta principal del pagador; útil donde el efectivo no puede viajar remotamente; recibo claro.

**Desventajas:** el emisor/comerciante conserva datos de compra/identidad según sea necesario; seguimiento por serie; dirección del receptor/entrega; pérdida/fraude y restricciones regionales; generalmente no es anónimo.

**Procedimiento:** (1) comprobar reglas, límites, identificación y aceptación del receptor; (2) comprar con información veraz y fondos lícitos; (3) completar inmediatamente beneficiario/importe; (4) conservar serie/recibo; (5) usar entrega con seguimiento adecuada al valor; (6) conciliar canje/reembolso.

**Detección:** registro de compra/canje del emisor, serie del instrumento, comerciante/cámara, envío y cuenta del receptor; marcar alteraciones, series duplicadas y canjes rápidos geográficamente incompatibles.

## Open-loop prepaid card

**Mecánica:** una credencial con marca de red autoriza contra un saldo prepago en lugar de una cuenta de crédito principal.

**Ventajas:** limita la exposición y la pérdida del comerciante; separa al comerciante del PAN principal; puede usarse online donde se acepte.

**Desventajas:** registros de compra/activación/recarga/registro y dispositivo; KYC y límites variables; fallos de dirección de facturación; restricciones de cash-out/reembolso; “sin nombre” no significa ausencia de registro del emisor.

**Procedimiento:** (1) verificar la identidad actual del emisor, comisiones, KYC, geografía y compatibilidad online/recurrente; (2) adquirirla mediante un vendedor autorizado con fondos lícitos; (3) registrar los datos veraces requeridos; (4) usarla para un único contexto/propósito; (5) no estructurar cargas ni falsificar residencia; (6) conservar pruebas de compra/gasto y cerrarla/desecharla según los términos del emisor.

**Detección:** unir vendedor/activación, financiación, dispositivo/IP, autorización del comerciante, comprobaciones de saldo y canje/reembolso. Los patrones importan más que la etiqueta prepago.

## Closed-loop gift card, voucher y crédito de servicio transferible

**Mecánica:** el valor numerado solo puede canjearse con un comerciante/servicio o ecosistema. Los créditos de airtime/game/store son variantes.

**Ventajas:** el comerciante receptor puede ver solo el código/saldo; alcance limitado; fácil de regalar y separar presupuestos.

**Desventajas:** el vendedor y el servicio registran compra/activación/canje; cuenta/dispositivo/entrega aún vinculan; estafas, descuentos de reventa y límites de caducidad/región; derechos de reembolso débiles.

**Procedimiento:** (1) comprar solo por canales autorizados; (2) registrar el valor del código sin exponer el secreto; (3) evitar asociar una cuenta de loyalty identificativa si no es necesario; (4) canjear mediante una cuenta/contexto legítimo separado del comerciante; (5) conservar el recibo hasta la aceptación; (6) nunca comprar códigos ante una demanda no solicitada de “impuestos/soporte/rescate”.

**Detección:** hora de emisión/canje del código, convergencia de dispositivo/cuenta, compras masivas o por umbrales, un dispositivo comprobando muchos saldos y canjes rápidos a distancia.

## Cryptocurrency-funded card o broker de gift codes

**Mecánica:** un intermediario acepta cryptocurrency y emite una tarjeta, voucher o código de comerciante. Es una conversión cross-rail: el comerciante ve valor ordinario de tarjeta/regalo, mientras el broker vincula el depósito on-chain con la emisión y entrega.

**Ventajas:** el comerciante no recibe el wallet de financiación; útil para comerciantes legítimos que no aceptan crypto; valor almacenado acotado.

**Desventajas:** no es anónimo frente al broker/emisor; KYC, sanciones, exchange y reglas del programa de tarjetas; grafo público del depósito; cuenta/dispositivo/email y canje del código reconectan ambos lados; riesgo de estafa/insolvencia.

**Procedimiento:** (1) verificar la entidad legal, emisor de tarjeta, jurisdicción compatible, KYC, comisiones y política de reembolso; (2) usar únicamente fondos lícitos documentados; (3) probar la denominación mínima; (4) verificar restricciones de red/comerciante antes de comprar; (5) conservar tanto la transacción blockchain como el recibo del broker para contabilidad; (6) nunca usar un broker que prometa fraude de identidad, evasión de sanciones o cash-out “inrastreable”.

**Detección:** correlacionar direcciones de depósito del broker, importe/hora únicos, cuenta/dispositivo y autorización de tarjeta emitida o canje de gift code; los registros del emisor y del broker conectan la cadena pública con el comerciante.

## Virtual o merchant-locked card

**Mecánica:** el emisor asigna un PAN/token generado a la cuenta real, normalmente restringiendo comerciante, importe o caducidad.

**Ventajas:** evita revelar un PAN reutilizable; compartimentación por comerciante; límites de gasto y revocación sencilla; control antifraude maduro.

**Desventajas:** el emisor sigue conociendo pagador, financiación, comerciante, dispositivo/IP y hora; el comerciante ve cuenta/entrega; algunos reembolsos/cargos recurrentes fallan; no es anónimo.

**Procedimiento:** (1) usar la función oficial del emisor regulado; (2) crear una tarjeta para un solo comerciante/engagement; (3) establecer el límite y caducidad mínimos útiles; (4) usar facturación exacta cuando sea necesario; (5) verificar el comportamiento del descriptor del extracto/reembolso; (6) congelar/eliminar después de la liquidación final conservando la evidencia de auditoría.

**Detección:** mapeo token-cuenta del emisor, autorización del comerciante, dispositivo y entrega. Los defensores usan señales de reutilización específica por comerciante, velocidad y account takeover.

## Mobile-wallet network token

**Mecánica:** la tokenización de pagos EMV sustituye el PAN por una credencial restringida, normalmente vinculada a un dispositivo, comerciante o escenario de pago.<sup>[[1]](#references)</sup>

**Ventajas:** el comerciante no recibe el PAN reutilizable; la criptografía del dispositivo y los datos dinámicos reducen la clonación; puede revocarse sin sustituir la tarjeta.

**Desventajas:** el emisor, token service, plataforma wallet y red conservan mapeos/transacciones; la cuenta de plataforma/dispositivo y la ubicación pueden identificar al pagador.

**Procedimiento:** (1) registrar una tarjeta legítima en el wallet oficial; (2) proteger la cuenta de plataforma/dispositivo con autenticación fuerte; (3) verificar el token del dispositivo/últimos dígitos en la compra; (4) desactivar ubicación/analytics innecesarios cuando sea compatible; (5) eliminar inmediatamente tokens/dispositivos perdidos; (6) revisar los registros del emisor y wallet.

**Detección:** requestor del token/cryptogram del dispositivo y mapeo del emisor, telemetría del wallet/cuenta, terminal del comerciante y evidencia física.

## Payment app, marketplace wallet e intermediario centralizado

**Mecánica:** el servicio mantiene cuentas y transferencias internas o usa rails bancarios/de tarjeta; el comerciante puede ver un alias mientras el servicio ve a ambas partes.

**Ventajas:** comodidad, mecanismos de disputa/reembolso; el receptor no necesariamente ve los datos bancarios/de tarjeta.

**Desventajas:** grafo centralizado de identidad/social/transacciones/dispositivo; bloqueos y procesos legales; las contrapartes pueden exponer el perfil; el uso de datos puede superar la necesidad del pago.<sup>[[2]](#references)</sup>

**Procedimiento:** (1) leer los términos de identidad, privacidad, conservación y protección del comprador; (2) minimizar la sincronización opcional de perfil/contactos; (3) usar una cuenta separada y veraz solo cuando los términos lo permitan; (4) activar MFA/alertas; (5) verificar el receptor y la privacidad de memo/profile; (6) exportar registros y cerrar enlaces no utilizados.

**Detección:** cuenta del proveedor, dispositivo/IP, grafo de contactos, financiación/retiro, memo y registros del comerciante. Un alias es seudonimato frente a una contraparte, no anonimato frente a la plataforma.

## Transferencia bancaria, ACH, wire e instant-account payment

**Mecánica:** las instituciones reguladas mueven valor entre cuentas identificadas e intercambian los datos de pago exigidos.

**Ventajas:** rápida, responsable, reversible en casos limitados, con registros sólidos; los números de cuenta virtuales pueden reducir la divulgación al comerciante.

**Desventajas:** los bancos/procesadores conocen a ambas partes; extractos y referencias; no es anónima; datos transfronterizos y de Travel Rule/AML.

**Procedimiento:** usarla solo cuando la responsabilidad sea aceptable: verificar independientemente al beneficiario, minimizar datos opcionales del memo, usar una cuenta/referencia virtual proporcionada por el banco cuando exista, activar alertas, conservar factura y conciliar.

**Detección:** registros bancarios/de pago deterministas, titularidad del beneficiario/cuenta, dispositivo/sesión y controles antifraude. Es una referencia básica, no una técnica de anonimato.

## Compartimentación de cuentas y comerciantes

**Mecánica:** identidades/cuentas, aliases de email, tarjetas y contextos de entrega separados evitan que comerciantes no relacionados unan trivialmente la actividad mientras un emisor/controlador conserva el mapeo.

**Ventajas:** reduce filtraciones y enlaces entre comerciantes; fácil de auditar; compatible con pagos regulados.

**Desventajas:** el proveedor sigue mapeando los compartimentos; teléfono de recuperación/dispositivo/IP y envío pueden reconectarlos; la política puede prohibir múltiples cuentas.

**Procedimiento:** (1) definir un propósito; (2) crear solo aliases/subcuentas conformes con los términos; (3) usar un token/tarjeta específico del comerciante; (4) desactivar contactos/personalización publicitaria entre cuentas; (5) conservar un ledger controlador cifrado; (6) retirar identificadores después de terminar las necesidades de reembolso/conservación.

**Detección:** los proveedores unen recuperación, dispositivo, financiación e IP; los comerciantes unen entrega, navegador y comportamiento de cuenta. Los defensores deben distinguir la compartimentación legítima del fraude de identidad sintética.

## Procurement controlado de red team

**Mecánica:** el SOC desconoce una compra mientras un controlador del ejercicio conserva el mapeo de entidad legal, operador e infraestructura.

**Ventajas:** ejercicio realista de detección; ninguna exposición personal; desambiguación y auditoría inmediatas.

**Desventajas:** no es anónimo frente a la organización/proveedor; carga de governance; filtraciones si el ledger controlador se gestiona mal.

**Procedimiento:** (1) asignar una tarjeta/wallet/presupuesto de la organización específico del engagement; (2) separar las funciones de comprador/operador; (3) registrar activo, importe, servicio, propósito y fecha de finalización; (4) guardar el mapeo de atribución con acceso limitado al controlador; (5) nunca usar identidad falsa/mule/fondos robados; (6) revelar y conciliar indicadores y reembolsos al cerrar.

**Detección:** el controlador relaciona factura del proveedor y activo; el SOC prueba el descubrimiento independiente mediante dominio, certificado, hosting y tráfico, no mediante datos del titular de la tarjeta.

## Higiene de direcciones Bitcoin y coin control

**Mecánica:** las direcciones nuevas de recepción, el etiquetado local y el gasto selectivo de UTXO reducen la reutilización de direcciones y la unión accidental de compartimentos en un ledger público.

**Ventajas:** ampliamente compatible; self-custodial; evita el enlace público más sencillo.

**Desventajas:** todas las transacciones/importes siguen siendo públicos; heurísticas de common-input/change/timing y consolidaciones posteriores vinculan actividad; permanecen los registros de adquisición/RPC/red.

**Procedimiento:** (1) instalar/verificar un wallet mantenido; (2) hacer backup y probar la recuperación del seed; (3) usar una dirección nueva por invoice; (4) etiquetar localmente origen/propósito; (5) usar coin control para evitar unir contextos; (6) preferir un nodo local o conexión consciente de la privacidad; (7) previsualizar change/comisiones y conservar la contabilidad lícita.<sup>[[3]](#references)</sup>

**Detección:** grafo de direcciones, heurísticas de common-input/change con incertidumbre, importe/hora exactos, consolidación, depósitos en servicios, tiempo de broadcast del nodo/RPC y registros off-chain.

## Bitcoin Silent Payments

**Mecánica:** BIP 352 permite que un receptor publique un código estático mientras los emisores derivan outputs Taproot únicos mediante ECDH; los observadores externos no pueden vincular directamente los outputs con el código.<sup>[[4]](#references)</sup>

**Ventajas:** identificador público reutilizable sin reutilizar direcciones; no requiere solicitud interactiva de dirección ni output de notificación; se integra con outputs Taproot.

**Desventajas:** coste de escaneo del receptor; compatibilidad variable del wallet; grafo de importe/emisor y gasto siguen siendo públicos; el index server puede observar los escaneos.

**Procedimiento:** (1) seleccionar un wallet BIP 352 actual; (2) hacer backup/probar descriptor y recuperación del escaneo; (3) generar un código etiquetado cuando sea compatible; (4) autenticar el código publicado; (5) el emisor revisa las entradas y envía una prueba pequeña; (6) el receptor escanea preferiblemente mediante su propio nodo; (7) mantener separados los UTXO recibidos.

**Detección:** por diseño, no es identificable de forma fiable solo a partir del output; los analistas usan entradas del emisor, importe/hora, gasto posterior, wallet/red/index y registros de contrapartes.

## PayJoin

**Mecánica:** el pagador y el receptor aportan inputs a una misma transacción de pago, rompiendo la suposición de que todos los inputs tienen un único propietario.<sup>[[5]](#references)</sup>

**Ventajas:** pago ordinario con mayor privacidad; beneficia al grafo general al debilitar una heurística común; no requiere un conjunto de outputs iguales.

**Desventajas:** requiere interacción/compatibilidad; disponibilidad del endpoint del receptor; importe y transacción final públicos; metadata de implementación y fallback.

**Procedimiento:** (1) confirmar que ambos wallets mantenidos son compatibles con la misma versión de PayJoin; (2) autenticar invoice/endpoint; (3) comenzar desde el payment URI compatible con PayJoin del wallet; (4) inspeccionar importe/comisión finales y firmar solo los inputs esperados; (5) evitar manipulación manual de la transacción; (6) verificar broadcast y recepción; (7) registrar el fallback si falla la negociación.

**Detección:** los analistas de blockchain no deben imponer clustering de common-input; el endpoint/proveedor puede registrar la negociación; usar evidencia del wallet/red y del gasto posterior, no solo la forma de la transacción.

## CoinJoin

**Mecánica:** varios participantes crean colaborativamente una transacción con muchos inputs/outputs, normalmente de denominaciones iguales, aumentando la ambigüedad sobre la correspondencia input-output.

**Ventajas:** mayor conjunto de ambigüedad on-chain; existen diseños self-custodial; estructura de ronda medible.

**Desventajas:** metadata del coordinator/peer/red; comisiones/liquidez; forma identificable de la transacción; change tóxico y consolidaciones posteriores destruyen las mejoras; disponibilidad legal/proveedor variable.

**Procedimiento:** (1) verificar la disponibilidad y legalidad actuales del wallet/coordinator; (2) instalar el wallet oficial y hacer backup; (3) usar solo UTXO lícitos; (4) comprender denominación, comisión y modelo del coordinator; (5) etiquetar/separar change y outputs mezclados; (6) nunca consolidarlos juntos; (7) encaminar el tráfico de red según soporte oficial y conservar la contabilidad.

**Detección:** identificar estructura colaborativa sin asumir delito; calcular mapeos posibles/conjunto de anonimato y observar después change/consolidación, límites de servicios y registros de red/coordinator.

## Lightning Network

**Mecánica:** los pagos HTLC atraviesan canales con onion routing; la mayoría de los detalles no se publica on-chain, mientras que la financiación/cierre y la información pública de canales sí.

**Ventajas:** rápida y barata; los intermediarios normalmente ven hops adyacentes; los detalles rutinarios permanecen off-chain.

**Desventajas:** emisor/receptor y primer/último hop saben más; probing, timing, grafo de canales, liquidez y registros de wallet/LSP; los custodial wallets identifican a los usuarios.

**Procedimiento:** (1) elegir conscientemente entre self-custodial y custodial; (2) verificar recuperación de wallet/seed/canales; (3) usar un invoice por el importe exacto; (4) preferir canales privados/funciones LSP solo después de leer sus compromisos; (5) proteger la IP del nodo con Tor compatible cuando sea necesario; (6) evitar reutilizar invoices identificativas; (7) mantener la contabilidad de canales y pagos.<sup>[[6]](#references)</sup>

**Detección:** logs del nodo/LSP/custodian, grafo/probes de canales, fallos/timing de pagos y financiación/cierre on-chain; que no exista una transacción pública no significa que no haya registros.

## BOLT 12 offers y route blinding

**Mecánica:** una offer reutilizable produce invoices nuevos y puede anunciar paths blinded para que el pagador no necesite conocer el nodo/path claro del receptor.

**Ventajas:** privacidad del receptor; endpoint de donación/pago reutilizable sin invoice estático; integración con onion routing de Lightning.

**Desventajas:** compatibilidad variable del wallet; endpoints, hops elegidos y financiación permanecen; el contacto público o endpoint de red puede volver a identificar al receptor.

**Procedimiento:** (1) confirmar compatibilidad BOLT 12 en ambos extremos; (2) autenticar la offer; (3) solicitar un invoice nuevo; (4) revisar importe/emisor/recurrencia; (5) pagar mediante el wallet; (6) verificar recepción/comportamiento del reembolso; (7) minimizar alias/contacto del nodo y conservar la contabilidad.<sup>[[7]](#references)</sup>

**Detección:** telemetría del wallet/LSP y del primer/último hop, cuenta de distribución de la offer, timing/valor y grafo de financiación; route blinding limita intencionadamente la visibilidad del pagador.

## Monero

**Mecánica:** las stealth addresses de un solo uso ocultan el vínculo del receptor, RingCT oculta los importes y las ring signatures proporcionan ambigüedad del emisor.

**Ventajas:** privacidad predeterminada on-chain; confidencialidad de emisor/receptor/importe; ecosistema maduro de wallet/node dedicado.

**Desventajas:** registros de adquisición/off-ramp y de extremo/red/contraparte; el remote node ve consultas/IP; el soporte del exchange y el tratamiento legal varían; pequeños errores operativos aún pueden unir contextos.

**Procedimiento:** (1) adquirir legalmente y conservar base/origen; (2) instalar/verificar el wallet oficial mantenido; (3) hacer backup/probar el seed; (4) usar un nodo local o una ruta documentada de remote node mediante Tor/I2P; (5) usar una subaddress nueva por pagador/invoice; (6) etiquetar localmente los contextos; (7) divulgar pruebas de transacción/acceso de view deliberadamente.<sup>[[8]](#references)</sup>

**Detección:** centrarse en evidencia de exchange/comerciante/dispositivo/red y wallet incautado; el uso del protocolo por sí solo no es sospechoso y la cadena pública expone deliberadamente menos información.

## Zcash fully shielded Orchard

**Mecánica:** las zero-knowledge proofs validan transferencias shielded mientras emisor, receptor e importe están cifrados; los pools transparentes y las transiciones de pool permanecen públicos.

**Ventajas:** fuerte confidencialidad on-chain en shielded; viewing keys para auditorías acotadas; validez impuesta por el protocolo.

**Desventajas:** el soporte del wallet/exchange y la elección real de pool varían; correlación de timing/valor en límites transparentes; red/RPC y extremos permanecen expuestos.

**Procedimiento:** (1) seleccionar un wallet Orchard mantenido y shielded por defecto; (2) verificar/hacer backup; (3) obtener ZEC legalmente; (4) recibir en una Unified Address compatible y confirmar el pool; (5) preferir shielded-to-shielded; (6) usar privacidad de red compatible; (7) probar la divulgación de viewing key con un wallet pequeño antes de auditar.<sup>[[9]](#references)</sup>

**Detección:** registros de límites transparentes y servicios, metadata de wallet/red y viewing keys cuando se proporcionen legalmente; no asumir que todos los pagos a Unified Address fueron shielded.

## Mimblewimble y Litecoin MWEB

**Mecánica:** las confidential transactions ocultan importes y la agregación estilo Mimblewimble elimina el historial convencional rico en direcciones; Litecoin implementa un extension block opcional junto a su cadena transparente.

**Ventajas:** importes confidenciales y fungibilidad mejorada en el dominio privado; pruning/agregación eficiente.

**Desventajas:** el límite opt-in de peg-in/out es público y correlacionable; soporte de wallet/exchange; diferencias de modelo interactivo/direcciones; registros de red y adquisición.

**Procedimiento:** (1) elegir un wallet mantenido con soporte MWEB explícito; (2) verificar/hacer backup y probar con un importe pequeño; (3) adquirir legalmente; (4) hacer peg a MWEB y verificar el dominio del saldo; (5) operar solo con un receptor compatible; (6) evitar un peg-out inmediato y distintivo; (7) conservar registros privados de auditoría.<sup>[[10]](#references)</sup>

**Detección:** timing/valor públicos de peg-in/out, datos de exchange/wallet/node y gastos transparentes posteriores; los detalles de transferencias confidenciales internas se reducen intencionadamente.

## Aplicaciones de privacidad zero-knowledge de Ethereum

**Mecánica:** un circuit demuestra una declaración —membership, propiedad válida de una note o autorización— sin revelar el secreto; un contrato verifier la comprueba. Los depósitos, retiros, inputs públicos, events y gas aún pueden exponer vínculos.

**Ventajas:** divulgación selectiva programable; aplicaciones con anonymous set; reglas verificables sin revelar todos los datos.

**Desventajas:** bugs de contrato/circuito; anonymous set pequeño; límites públicos; RPC/IP/sesión/analytics/financiación de gas; riesgo legal y de la aplicación/sanciones.

**Procedimiento:** (1) definir exactamente qué oculta la proof; (2) usar una aplicación auditada y mantenida cuando sea lícito; (3) inspeccionar inputs/events públicos y reglas de depósito/retiro; (4) separar el action wallet y el gas sponsorship según el protocolo; (5) usar una ruta RPC/red consciente de la privacidad; (6) probar con poco valor; (7) conservar registros de compliance.<sup>[[11]](#references)</sup>

**Detección:** events del contrato, timing/valor de depósito/retiro, relayer/paymaster, RPC/sesión, almacenamiento/analytics del frontend y límite final de exchange/comerciante. No afirmar que la proof ZK oculta campos declarados públicos.

## Stablecoins

**Mecánica:** los tokens se transfieren en una cadena pública; los emisores centralizados pueden congelar/blacklistear o canjear frente a cuentas identificadas.

**Ventajas:** estabilidad de precio, liquidez y soporte de comerciantes; liquidación rápida; contabilidad sencilla.

**Desventajas:** grafo transparente de direcciones/importes/contratos; financiación del gas; identidad/control del emisor y exchange; screening de sanciones; anonimato generalmente deficiente.

**Procedimiento:** tratarla como pago identificado: usar una dirección empresarial nueva solo para compartimentación, verificar contrato del token/red, probar con poco importe, proteger el wallet, usar RPC de confianza/nodo local, conservar origen/base y examinar las partes requeridas.

**Detección:** grafo completo de eventos de tokens, listas/acciones de freeze del emisor y relaciones de exchange/RPC/dispositivo/financiación del gas.

## Cashu Chaumian e-cash

**Mecánica:** un mint firma ciegamente secretos bearer generados por el cliente, respaldados por reservas Bitcoin/Lightning; puede impedir el double-spend sin vincular directamente la emisión con el canje posterior.

**Ventajas:** bearer tokens sin cuenta; transferencia peer instantánea; el mint no puede vincular directamente el retiro blinded con el gasto; los tokens pueden moverse como datos/QR.

**Desventajas:** custodia/solvencia/censura del mint; pérdida/robo de datos bearer; denominación/timing y límites Lightning; metadata de red; ecosistema de software temprano.<sup>[[12]](#references)</sup>

**Procedimiento:** (1) usar primero un test mint oficial o un valor desechable pequeño; (2) instalar un wallet mantenido y probar las limitaciones de backup/restore; (3) autenticar el mint y revisar custodia/comisiones; (4) acuñar una cantidad pequeña; (5) enviar el token mediante canal privado/QR autenticado; (6) el receptor canjea el token antes de tratarlo como final; (7) canjear y conciliar. Nunca almacenar valor significativo en un mint no confiable.

**Detección:** el mint ve red, límites de emisión/canje/Lightning y el conjunto de tokens gastados, pero blinding elimina el enlace directo del token; extremos/mensajes y un importe/timing distintivo pueden restaurar vínculos.

## Fedimint federated e-cash

**Mecánica:** un threshold de guardians mantiene reservas y firma e-cash ciegamente; las transferencias bearer internas son privadas frente a los guardians, mientras los gateways Lightning conectan pagos externos.

**Ventajas:** distribuye la custodia; transferencia interna privada; governance comunitaria; ningún guardian controla la reserva por debajo del threshold.

**Desventajas:** riesgo de quorum/custodia/software de guardians; el gateway observa invoices/timing; límites de depósito/retiro; complejidad de recuperación del estado del cliente.

**Procedimiento:** (1) verificar invite, guardians, quorum y jurisdicción de la federation; (2) instalar un cliente mantenido y probar recovery; (3) depositar un importe lícito pequeño; (4) usar payment requests internos nuevos; (5) tratar el gateway como observador de Lightning; (6) probar el canje; (7) conservar registros de origen/impuestos fuera de los datos públicos de pago.<sup>[[13]](#references)</sup>

**Detección:** la federation ve emisión/canje agregado, los gateways ven invoices externos, Bitcoin/Lightning muestran los límites y la evidencia de extremos/comunicaciones puede vincular transferencias internas.

## GNU Taler

**Mecánica:** el e-cash con blind signatures integrado con bancos pretende mantener anónimo al pagador frente a los comerciantes mientras los comerciantes y los ingresos siguen siendo responsables.

**Ventajas:** privacidad del pagador por diseño; moneda ordinaria; responsabilidad/reembolsos del comerciante; no requiere un token especulativo.

**Desventajas:** despliegues limitados; exchange/banco ve la financiación; el comerciante ve pedido/entrega; riesgo de bearer/recovery del wallet; operadores regulados.

**Procedimiento:** (1) localizar un exchange/comerciante actual para la jurisdicción/moneda; (2) leer KYC/comisiones/privacidad; (3) instalar el wallet oficial; (4) retirar legalmente desde el banco/exchange compatible; (5) revisar el contrato del comerciante; (6) pagar y conservar datos de recibo/reembolso; (7) evitar identificadores de sesión innecesarios del comerciante.<sup>[[14]](#references)</sup>

**Detección:** la retirada del banco/exchange y el depósito del comerciante son límites responsables; el pedido/dispositivo/entrega y timing del comerciante pueden correlacionarse aunque las coins estén blinded.

## Cross-chain bridge, atomic swap y decentralized exchange

**Mecánica:** un contrato/servicio bloquea/quema un activo y libera/emite otro, o las contrapartes intercambian atómicamente. Rompe la visión de un solo ledger, no la continuidad económica.

**Ventajas:** interoperabilidad de activos/redes; puede evitar un custodio centralizado; uso ordinario de portfolio/liquidez.

**Desventajas:** ambas cadenas son públicas; tiempo/valor/comisiones/liquidez y contratos se correlacionan; registros de bridge/relayer/frontend/RPC; riesgo de smart contract/contraparte y regulatorio.

**Procedimiento para swaps lícitos:** (1) verificar el contrato/servicio oficial y disponibilidad legal; (2) inspeccionar custodia/auditoría/comisiones/slippage; (3) hacer una prueba pequeña; (4) registrar ambos IDs de transacción y el tipo de cambio; (5) proteger approvals; (6) conciliar el activo de destino y revocar approvals innecesarios. No usar swaps para disfrazar el origen de fondos.

**Detección:** events de depósito/retiro del bridge, importe único menos comisiones, orden temporal, liquidez, relayer/RPC/frontend y depósitos posteriores en servicios.

## Centralized mixer o tumbler

**Mecánica:** un servicio recibe depósitos en un pool y devuelve unidades diferentes posteriormente, intentando ocultar el mapeo directo input-output.

**Ventajas:** en teoría puede ampliar la ambigüedad de las transacciones.

**Desventajas:** el operador puede robar/registrar; análisis de timing/valor de entrada/salida; exposición a sanciones, money transmission y delitos; incautaciones que expongan mapeos; riesgo de taint/rechazo.

**Procedimiento:** no se proporciona una guía operativa de mixing. Reproducir el grafo de forma segura ampliando [Lab 6](authorized-adversary-emulation-labs.md#lab-6-synthetic-peel-chain-and-bridge-graph): crear depósitos sintéticos, outputs agrupados, comisiones y retrasos; proporcionar a los analistas mapeos incompletos; medir qué heurísticas funcionan; después revelar la ground truth.

**Detección:** identificar wallet/contrato del servicio, conjuntos candidatos de entrada/salida, importe/comisión/timing, reutilización de direcciones de depósito, logs incautados/del proveedor y consolidación posterior. Etiquetar la atribución probabilística.

## Peel chains, fan-out/fan-in y structuring

**Mecánica:** transacciones repetidas extraen pagos pequeños del change, dividen el valor entre muchas direcciones, reconvergen collectors o dividen importes para evitar revisiones.

**Ventajas:** aumenta la carga de trabajo del analista ingenuo y el número de direcciones.

**Desventajas:** continuidad reconocible de valor/cadencia/transacciones; consolidación y endpoints de servicios; el structuring puede ser ilegal por sí mismo; comisiones y errores operativos.

**Procedimiento:** usar únicamente datos CSV/testnet sintéticos: generar una fuente grande, edges repetidos de pago/change, ramas paralelas y un collector; añadir ejemplos benignos parecidos a exchanges; ajustar la detección y documentar falsos positivos.

**Detección:** continuidad del grafo, patrón repetido de change, cadencia, importes justo por debajo de controles, endpoint común de servicio y registros off-chain. Los hot wallets de exchanges pueden parecerse a estos patrones, por lo que el contexto es obligatorio.<sup>[[15]](#references)</sup>

## Nominee, money mule, broker OTC y front company

**Mecánica:** otra persona/cuenta/empresa recibe, convierte o gasta fondos, insertando capas legales y operativas entre el controlador y la transacción.

**Ventajas para un adversario:** la cuenta nominal no identifica inmediatamente al controlador; puede conectar efectivo, crypto, bienes y jurisdicciones.

**Desventajas:** exposición a fraude de identidad/blanqueo; cada participante añade comunicaciones, registros bancarios/empresariales/fiscales/de envío, comisiones, incoherencias y testigos; la reutilización del facilitador crea hubs.

**Procedimiento:** no emular con personas/cuentas reales. Crear un grafo sintético con controller, recruiter, mule, OTC, shell merchant y beneficiary; sembrar edges de dispositivo/IP/mensajes/banco; pedir a los investigadores que distingan titular de cuenta y controlador y registren la confianza de la evidencia.

**Detección:** dispositivo/IP/recuperación compartidos, beneficiario/velocidad inusuales, muchos emisores no relacionados, movimiento inmediato posterior, incoherencia de empresa/director/factura, comunicaciones y entrega de efectivo/mercancía.

## NFTs, gambling, bienes de comerciantes y refund loops

**Mecánica:** el valor se convierte en un activo de precio propio, saldo de apuestas, bienes revendibles o reembolsos para crear una narrativa de transacción diferente.

**Ventajas para un adversario:** cambia la forma del activo e introduce intermediarios de marketplace/comerciantes.

**Desventajas:** grafo de marketplace/cuenta/dispositivo y wash trade; registros de probabilidades/juego y reembolsos; evidencia de entrega/reventa; comisiones/pérdidas; responsabilidad por fraude/blanqueo.

**Procedimiento:** no proporcionar un flujo de ocultación. Usar datos sintéticos de marketplace con self-trades de wallets relacionadas, precios inverosímiles, juego mínimo, instrumento de reembolso no coincidente y envío común; validar la detección frente a collectors/clientes legítimos.

**Detección:** operaciones circulares/autofinanciadas, propiedad/financiación común, valores atípicos de precio, reventa/reembolso inmediato, actividad económica mínima, dispositivo/entrega compartidos y reconvergencia de fondos.

## Physical bearer wallet o transferencia de token offline

**Mecánica:** un dispositivo, papel/QR, instrumento hardware bearer o token e-cash transfiere el control de un secreto en lugar de emitir un pago durante la entrega.

**Ventajas:** ningún evento de red en directo durante el intercambio; útil offline; custodia física similar al efectivo.

**Desventajas:** copia/robo/pérdida y exclusividad incierta; el canje/broadcast posterior vincula; reunión/envío físico; riesgo de falsificación/manipulación.

**Procedimiento:** (1) usar solo un instrumento/protocolo revisado; (2) inicializar/verificar autenticidad de forma privada; (3) cargar solo un valor lícito pequeño; (4) transferirlo en un contexto autorizado documentado; (5) el receptor verifica o hace sweep rápidamente según requiera el protocolo; (6) nunca asumir que el emisor no conservó una copia; (7) registrar en privado evidencia de propiedad/impuestos.

**Detección:** financiación/compra y sweep/canje final, serie del dispositivo/evidencia de manipulación, entrega/reunión y registros de los extremos.

## Merchant-scoped invoice o one-time payment request

**Mecánica:** el comerciante crea una solicitud de un solo uso con importe, caducidad y referencia del pedido. El pagador la liquida mediante un rail compatible sin exponer directamente una credencial reutilizable al comerciante; el emisor o procesador puede identificar igualmente a ambas partes.

**Ventajas:** limita la reutilización de credenciales y los identificadores cruzados accidentales entre comerciantes; importe/caducidad exactos reducen errores; compatible con contabilidad y reembolsos ordinarios.

**Desventajas:** invoice, entrega, navegador, procesador y emisor siguen vinculando el pedido; un importe/hora únicos pueden reforzar la correlación; los payment links maliciosos son habituales.

**Procedimiento:** (1) autenticar independientemente al comerciante; (2) solicitar un invoice nuevo con importe, activo/red y caducidad exactos; (3) inspeccionar destino y reglas de reembolso; (4) pagar desde el compartimento de engagement aprobado; (5) verificar que el comerciante reconoce el mismo invoice; (6) conservar recibo y referencia de transacción; (7) dejar caducar la solicitud en lugar de reutilizarla.

**Detección:** comerciante y procesador unen invoice, sesión y liquidación; importes/horas únicos y entrega identifican al pagador. **Wallet/dispositivo capturado:** el historial de invoices expone contrapartes y propósito; minimizar datos innecesarios del memo, cifrar el dispositivo y mantener la contabilidad autorizada en el sistema financiero controlado.

## Prepaid service credit y capability token

**Mecánica:** un servicio convierte un pago convencional en créditos internos acotados o una capability bearer. El uso posterior de API/recurso puede evitar presentar la tarjeta original en cada solicitud, pero el servicio normalmente puede mapear emisión y canje.

**Ventajas:** limita gasto y pérdidas por compromiso; separa a los operadores cotidianos de la credencial de financiación; permite presupuestos por proyecto y revocación.

**Desventajas:** normalmente es seudónimo, no anónimo; la base de datos del servicio, la IP de canje y el patrón de uso único vinculan actividad; los tokens bearer pueden robarse; los reembolsos pueden requerir al pagador original.

**Procedimiento:** (1) comprar créditos mediante una cuenta de organización; (2) crear un proyecto y presupuesto; (3) emitir un token limitado con restricciones de servicio, importe y caducidad; (4) almacenarlo solo en el secret manager aprobado o mediante workload identity; (5) probar el rechazo fuera del ámbito y tras la caducidad; (6) monitorizar el consumo; (7) revocar y conciliar el valor no usado.

**Detección:** el proveedor une cuenta de financiación, proyecto, emisión del token y uso; los defensores alertan ante cambios geográficos/de proceso y consumo anómalo. **Node capturado:** asumir que su capability restante puede gastarse; usar caducidad corta, saldo bajo, binding de audiencia y revocación inmediata server-side.

## Privacy Pass o token de autorización blinded

**Mecánica:** un emisor produce un token de autorización con preservación de privacidad que un origin puede validar sin vincular el canje con la emisión. Puede representar entitlement pagado o acceso limitado por tasa, pero no es una moneda general. La arquitectura separa los roles de client, attester, issuer y origin y advierte que IP/timing o la colusión pueden deshacer la unlinkability.<sup>[[18]](#references)</sup>

**Ventajas:** canje unlinkable para servicios compatibles; no existe una cookie de cuenta reutilizable en el origin; los tokens almacenados pueden separar emisión y uso temporalmente.

**Desventajas:** específico de la aplicación; confianza en issuer/attester y particionado del anonymity set; permanecen IP y metadata del navegador; el robo del token o un timing distintivo de emisión puede correlacionar el uso.

**Procedimiento:** (1) usar una implementación conforme con el tipo de token Privacy Pass relevante; (2) definir exactamente qué entitlement demuestra el token; (3) separar la administración del issuer y origin cuando lo requiera el threat model; (4) minimizar metadata del challenge; (5) emitir varios tokens de prueba y canjear cada uno una vez en origins propios; (6) comparar logs para detectar identificadores estables prohibidos; (7) probar replay, caducidad y controles de revocación/abuso.

**Detección:** los origins ven IP/hora de canje y validez del token; issuers/attesters ven el contexto de emisión; los analistas prueban particiones temporales y de metadata sin asumir una ruptura criptográfica. **Client capturado:** los bearer tokens no gastados pueden utilizarse; limitar su valor, duración y audiencia, y nunca almacenar junto a ellos la credencial de financiación.

## Delegated organization procurement o fiscal sponsor

**Mecánica:** un equipo de procurement autorizado, reseller o fiscal sponsor contrata y paga mientras el equipo operativo recibe un servicio acotado. Es separación de roles con registros veraces, no un nominee ni una identidad falsa.

**Ventajas:** los proveedores no necesitan recibir la identidad ni los datos personales de pago de cada operador; compliance, impuestos y reembolsos centralizados; presupuesto y offboarding claros.

**Desventajas:** el sponsor conoce al beneficiario y el propósito; permanecen contratos, aprobaciones, entrega y cuentas; demora/comisiones adicionales; separación débil si la misma persona administra todas las capas.

**Procedimiento:** (1) documentar propósito empresarial, beneficiario y autoridad aprobadora; (2) seleccionar un intermediario aprobado por la organización; (3) contratar con datos veraces; (4) provisionar una subcuenta limitada al proyecto sin credencial personal de facturación; (5) separar administradores financieros de operadores; (6) conciliar facturas y acceso; (7) terminar servicio y acceso delegado al cerrar.

**Detección:** los registros de procurement, identity provider, proveedor y entrega unen la cadena. **Dispositivo operativo capturado:** debe revelar el proyecto de servicio, pero no las credenciales financieras; mantener facturas e identidades de pagadores en el sistema financiero, no en field nodes.

## Escrow o liquidación condicional

**Mecánica:** un escrow agent de confianza o smart contract mantiene el valor hasta cumplir condiciones documentadas. Puede reducir la divulgación directa entre pagador y receptor, mientras escrow y los rails subyacentes conservan la relación.

**Ventajas:** protección frente a disputas y entrega; pagador y comerciante pueden exponerse mutuamente menos credenciales reutilizables; condiciones de liberación auditables.

**Desventajas:** riesgo de custodia/contrato del escrow, comisiones y obligaciones de identidad; los contratos on-chain son públicos; permanecen datos de pedido, envío y disputa; no es anónimo frente al intermediario.

**Procedimiento:** (1) verificar entidad legal, custodia, comisiones, foro de disputas y activos compatibles; (2) crear un hito escrito exacto y una ruta de reembolso; (3) financiar desde una cuenta de organización aprobada; (4) verificar independientemente recepción y autorización de liberación; (5) liberar solo después de la evidencia; (6) conservar el registro completo de auditoría; (7) cerrar permisos o contract approvals no usados.

**Detección:** events de cuenta/contrato escrow, financiación y hora de liberación, beneficiario y registros de disputa revelan la transacción. **Dispositivo capturado:** session tokens o contract approvals pueden permitir la liberación; exigir approver/MFA separado y revocar sesiones activas tras una pérdida.

## Liquidación agrupada o pooled de una organización

**Mecánica:** muchas obligaciones aprobadas se agregan y liquidan en menos transacciones bancarias o blockchain, con un ledger interno privado que asigna cada parte. El batching puede reducir detalles públicos por compra, pero el coordinator conserva la atribución completa.

**Ventajas:** menores comisiones; menos edges en el grafo público; oculta líneas individuales a un observador público cuando se agregan importes; contabilidad interna sencilla.

**Desventajas:** el coordinator es un observador completo y un objetivo de alto valor; totales/timing distintivos pueden correlacionarse; riesgo de custodia y conciliación; puede parecer structuring si se abusa.

**Procedimiento:** (1) definir participantes y obligaciones lícitas en el sistema contable; (2) establecer una ventana regular justificada por negocio, no umbrales diseñados para evitar controles; (3) exigir aprobación dual del agregado; (4) liquidar a receptores autenticados; (5) conciliar cada línea interna con el batch; (6) tratar reembolsos como correcciones vinculadas; (7) proteger el acceso al ledger y conservarlo según la política.

**Detección:** el ledger, aprobaciones y beneficiarios del coordinator proporcionan ground truth; los analistas públicos usan con cautela el clustering de inputs/outputs/valor/tiempo. **Dispositivo del pagador capturado:** solo debe contener su requisición, no la signing key del pool ni el ledger de participantes.

## Account-abstraction paymaster o sponsored gas

**Mecánica:** un relayer/bundler envía una operación de smart account y un paymaster paga las comisiones de transacción, evitando un edge directo de financiación de native gas desde el wallet del usuario. Mejora una propiedad del grafo; la operación, el contrato y la telemetría del servicio siguen siendo públicos u observables.<sup>[[19]](#references)</sup>

**Ventajas:** elimina un vínculo común de financiación de gas; permite sponsorship acotado y rate limits; mejora el onboarding de aplicaciones legítimas de privacidad.

**Desventajas:** paymaster/bundler/RPC/frontend pueden correlacionar solicitudes; events del contrato e inputs públicos permanecen; la política de sponsorship identifica a un grupo; contratos o approvals maliciosos pueden robar activos.

**Procedimiento:** (1) usar una smart account y paymaster auditados y mantenidos en la red correcta; (2) inspeccionar qué campos son públicos y qué registra el sponsor; (3) limitar sponsorship por contrato, función, importe, nonce y caducidad; (4) probar con poco valor; (5) enviar mediante la ruta de privacidad prevista por la aplicación; (6) verificar on-chain la operación y el pagador de la comisión; (7) revocar allowances/session keys y conservar registros de compliance.

**Detección:** unir logs de UserOperation, EntryPoint, paymaster, bundler/RPC y aplicación; agrupar con cautela políticas de sponsorship idénticas. **Wallet capturado:** session keys y approvals pendientes pueden usarse incluso sin gas; limitar su alcance y revocarlos mediante la recovery policy de la cuenta.

## Threshold o autorización de pago multisignature

**Mecánica:** el gasto requiere un threshold de signers independientes. No oculta la transacción, pero separa la autoridad de pago de cualquier laptop, field node u operador capturado.

**Ventajas:** fuerte resistencia al compromiso y a insiders; aprobación responsable; ningún dispositivo de campo contiene autoridad completa; permite recovery.

**Desventajas:** coordinación y disponibilidad; metadata de signer/dispositivo/cuenta puede correlacionar participantes; un mal diseño de backups provoca pérdidas; los patrones públicos multisig pueden ser identificables.

**Procedimiento:** (1) definir signers, threshold, límites y recovery antes de financiar; (2) inicializar en hardware/cuentas compatibles separadas; (3) verificar independientemente direcciones y backups; (4) dar a las cargas de campo solo capacidad de requisición sin firma; (5) exigir revisión out-of-band de receptor, importe y propósito; (6) probar recovery y pérdida de un signer con poco valor; (7) rotar un signer tras el compromiso.

**Detección:** el sistema de aprobación, los dispositivos de signers y el script/contrato público proporcionan evidencia; alertar ante cambios de política o del conjunto de signers. **Node capturado:** como máximo debe exponer una session key de baja autoridad o una solicitud sin firmar; nunca guardar material de quorum junto.

## Moneda comunitaria o de evento closed-loop

**Mecánica:** una cooperativa, conferencia o entorno de pruebas privado emite créditos canjeables solo entre participantes inscritos. La transferencia interna puede exponer menos a las redes globales de pago, mientras el operador controla emisión y canje.

**Ventajas:** dominio económico acotado; permite probar UX de pagos offline o con privacidad; limita la exposición de tarjetas externas; controles experimentales claros.

**Desventajas:** anonymous set pequeño; operador y comerciantes observan la actividad; aceptación y canje limitados; pueden aplicar reglas de licencias, protección al consumidor e impuestos incluso al valor local.

**Procedimiento:** (1) obtener revisión legal/compliance y publicar términos del emisor; (2) inscribir participantes que consientan; (3) limitar la emisión y prohibir el uso indebido como efectivo; (4) usar payment requests nuevos y minimizar identificadores públicos de participantes; (5) registrar reservas agregadas y recibos individuales privados; (6) probar pérdida/reembolso/canje; (7) cerrar el ledger y devolver el valor residual según lo prometido.

**Detección:** el ledger del emisor, inscripción, comerciante y canje reconstruyen los flujos; transferencias circulares inusuales o cash-out rápido requieren revisión. **Wallet capturado:** pueden exponerse saldo local y contrapartes; limitar valor, cifrar estado y permitir freeze/reissue por el emisor con registro auditable.

## Bitcoin reusable payment codes e instrucciones privadas de pago

**Mecánica:** los payment codes BIP 47 usan un identificador público reutilizable más direcciones de depósito de un solo uso derivadas mediante ECDH; BIP 351 especifica un diseño más reciente de instrucciones de pago privadas. Reducen la reutilización pública de direcciones y permiten que un receptor publique instrucciones estables. La notificación, soporte del wallet, financiación y selección posterior de coins siguen afectando la privacidad.<sup>[[20]](#references)</sup>

**Ventajas:** una instrucción pública puede producir direcciones distintas; el receptor no necesita publicar cada dirección de invoice; wallets compatibles pueden monitorizar pagos derivados; útil para donantes/clientes lícitos recurrentes.

**Desventajas:** interoperabilidad variable; las transacciones de notificación o el payment code publicado vinculan un contexto relacional; emisor, receptor y grafo público siguen viendo transacciones; consolidación o gestión de change descuidadas anulan la ventaja.

**Procedimiento:** (1) confirmar que ambos wallets mantenidos admiten exactamente la misma especificación/versión; (2) hacer backup y probar recovery en un wallet de bajo valor; (3) autenticar out-of-band el payment code del receptor; (4) enviar una prueba lícita pequeña; (5) verificar que se usó una dirección derivada nueva; (6) etiquetar localmente la relación y aplicar coin control; (7) probar recovery y reembolsos antes de depender de ella.

**Detección:** los analistas examinan patrones de notificación, financiación/change, consolidación posterior y límites de servicios; la publicación del código público identifica el contexto del receptor aunque las direcciones de depósito difieran. **OPSEC resistente a captura:** mantener spend keys fuera de field devices y exponer como máximo una vista watch-only de la relación. **Monitoring:** alertar ante transacciones de notificación inesperadas, direcciones derivadas reutilizadas, errores de gap-limit/recovery del wallet y consolidaciones no planificadas.

## EVM stealth addresses (ERC-5564)

**Mecánica:** un emisor deriva una stealth account de un stealth meta-address del receptor y publica un anuncio que contiene una ephemeral public key y view tag. El receptor escanea los anuncios con una viewing key y deriva la spend key correspondiente. Mejora el vínculo del receptor, pero emisor, importe/token, gas, anuncio y gasto posterior siguen visibles.<sup>[[21]](#references)</sup>

**Ventajas:** dirección fresca del receptor sin interacción; meta-address reutilizable; separación de funciones de viewing y spending; funciona entre activos/aplicaciones EVM compatibles.

**Desventajas:** escaneo de anuncios y spam; financiar el gas de la nueva dirección puede volver a vincularla; el emisor conoce al receptor; token/importe públicos y consolidación final permanecen; soporte de implementación/wallet variable.

**Procedimiento:** (1) usar primero una implementación auditada y mantenida en una testnet; (2) generar y proteger por separado el material de viewing y spending; (3) autenticar el meta-address; (4) enviar una prueba de bajo valor y anuncio; (5) escanear y derivar la stealth account; (6) probar el gas sponsorship compatible sin edge de financiación personal; (7) registrar los campos públicos y conservar la contabilidad lícita.

**Detección:** seguir caller del anuncio, token/importe, timing, gas sponsor, gasto y consolidación; una view key puede demostrar recepción sin conceder gasto. **OPSEC resistente a captura:** un scanner conectado a red solo debe tener el rol de viewing cuando sea compatible; mantener spend y recovery keys en otro lugar. **Monitoring:** alertar ante anuncios malformados/spam, acceso a view keys, derivación de gasto inesperada y stealth outputs movidos sin autorización.

## Liquid Confidential Transactions

**Mecánica:** Liquid oculta por defecto importes y tipos de activo de los outputs mediante commitments y proofs, mientras deja visibles el grafo de transacciones, número de inputs/outputs, comisión y hora del bloque. Peg-in/peg-out y límites de servicio siguen siendo vinculables, y los usuarios pueden divulgar selectivamente datos de blinding.<sup>[[22]](#references)</sup>

**Ventajas:** importe y tipo de activo confidenciales por defecto; liquidación rápida en sidechain; auditoría selectiva mediante blinding keys/descriptors; oculta valores comercialmente sensibles a observadores públicos.

**Desventajas:** estructura del grafo y timing permanecen; confianza en federation/bridge y exchange; límites peg y outputs no confidenciales; registros de wallet/node/red; emisor y receptor conocen su transacción.

**Procedimiento:** (1) seleccionar un wallet Liquid mantenido y verificar su modelo de backup; (2) usar testnet o un importe lícito pequeño; (3) recibir en una dirección confidencial y verificar que el wallet marca el output como blinded; (4) enviar una transacción confidencial de prueba; (5) inspeccionar qué campos del explorer siguen siendo públicos; (6) exportar solo la proof de blinding necesaria para la auditoría; (7) documentar límites peg/exchange y conciliar fondos.

**Detección:** analizar grafo/fee/time visibles, registros de peg y exchange, metadata de red y evidencia posterior de unblinding; no inferir el importe o activo oculto. **OPSEC resistente a captura:** separar spend seed, datos de blinding/view y operaciones watch-only. **Monitoring:** alertar ante direcciones accidentalmente no confidenciales, solicitudes peg desconocidas, cambios de descriptor y exportación no autorizada de claves de unblinding.

## General payment o state channel

**Mecánica:** los participantes bloquean fondos, intercambian actualizaciones de estado off-chain firmadas y publican en la cadena solo la apertura, cierre o estado disputado. Los pagos intermedios no se transmiten globalmente, pero los pares y servicios de routing/intermediarios observan su parte y los extremos deben conservar el último estado ejecutable.<sup>[[23]](#references)</sup>

**Ventajas:** muchas interacciones rápidas y baratas entre ledger privado y público; menos detalles de transacción globales; saldo de canal acotado; útil para servicios medidos y contrapartes recurrentes.

**Desventajas:** los pares conocen al otro y pueden conservar actualizaciones; apertura/cierre/valor/timing se correlacionan; puede requerirse monitorización online durante ventanas de challenge; riesgo de implementación/liquidez; por sí solo no crea un anonymous set grande.

**Procedimiento:** (1) elegir una implementación auditada y mantenida y comprender su dispute window; (2) abrir un canal de prueba de bajo valor entre partes propias; (3) intercambiar state updates firmadas con nonces únicos; (4) hacer backup del último estado ejecutable; (5) cerrar cooperativamente; (6) ensayar el rechazo de estados antiguos en testnet; (7) conservar contabilidad y registros de pares del canal.

**Detección:** la cadena pública expone ciclo de vida/disputas; pares, watch services y transporte de la aplicación exponen timing y partes off-chain. **OPSEC resistente a captura:** limitar el saldo hot y guardar el último estado firmado en un almacén cifrado y recuperable separado de field nodes. **Monitoring:** vigilar continuamente publicación de estados antiguos, fallos de backup, cambios de peer key y proximidad de la fecha límite del challenge.

## Mobile carrier billing

**Mecánica:** un servicio online carga una compra a una suscripción móvil o saldo prepago mediante el sistema de carrier billing. El comerciante puede recibir autorización del carrier en lugar de datos de tarjeta/banco, mientras el carrier conoce suscriptor/línea, contexto de dispositivo/red, comerciante, importe y hora.<sup>[[24]](#references)</sup>

**Ventajas:** no hay número de tarjeta en el comerciante; amplia disponibilidad telefónica; útil para bienes digitales de bajo valor; el carrier puede limitar y revertir cargos.

**Desventajas:** fuertemente identificado por SIM/cuenta y a menudo dispositivo; límites pequeños y comisiones altas; restricciones de categoría; riesgo de account takeover/SIM-swap; carrier y aggregator crean un registro completo.

**Procedimiento:** (1) confirmar disponibilidad, límite, comisión y reembolso con la cuenta de carrier de la organización; (2) activarlo solo en una línea empresarial dedicada si está justificado; (3) establecer el límite de gasto útil más bajo; (4) comprar un artículo de prueba benigno; (5) verificar recibos del comerciante y carrier; (6) desactivar la autorización recurrente; (7) conciliar y desactivar la función tras la evaluación.

**Detección:** los registros de carrier, aggregator y comerciante unen línea, suscriptor, IP/dispositivo y cargo; las facturas de telecomunicaciones empresariales lo exponen. **OPSEC resistente a captura:** no usar un número personal y exigir MFA de la cuenta del carrier fuera del field device. **Monitoring:** activar alertas inmediatas de cargos/cambios de SIM y detenerse ante inscripción inesperada en servicios premium, forwarding o recuperación de cuenta.

## Open-banking payment initiation

**Mecánica:** con consentimiento explícito del usuario, un regulated payment-initiation service provider (PISP) pide al banco que mantiene la cuenta iniciar una transferencia. El comerciante puede no recibir credenciales de tarjeta, pero el PISP y los bancos conservan registros regulados del pagador, beneficiario, consentimiento, dispositivo y transacción.<sup>[[25]](#references)</sup>

**Ventajas:** no hay número de tarjeta reutilizable en checkout; autenticación bancaria sólida; liquidación exacta account-to-account; APIs de consentimiento/estado; conciliación clara.

**Desventajas:** no es anónimo frente a bancos/PISP; el beneficiario suele ver datos de cuenta legal o referencia; riesgo de phishing/redirect; jurisdicción y protección de reembolsos variables; la metadata del consentimiento añade otro observador.

**Procedimiento:** (1) verificar que el PISP está regulado actualmente y que el callback domain del comerciante es auténtico; (2) comenzar desde la solicitud del comerciante; (3) revisar beneficiario, importe, referencia y consentimiento solicitado en el banco; (4) autorizar solo el pago individual; (5) verificar independientemente el estado final; (6) revocar cualquier consentimiento residual; (7) conservar recibo y conciliar.

**Detección:** logs del banco/PISP/comerciante y referencias de transferencia proporcionan una atribución sólida. **OPSEC resistente a captura:** mantener autenticación y recuperación bancaria fuera de dispositivos operativos/de campo; el dispositivo solo debe contener el entitlement del servicio pagado. **Monitoring:** usar alertas de transacciones/consentimiento bancarias e investigar nuevos grants PISP, cambios de beneficiario o callbacks de estado fuera de la sesión esperada.

## Platform wallet, saldo de app store o crédito in-app

**Mecánica:** una plataforma factura al usuario o canjea crédito de cuenta y después emite un recibo firmado o entitlement a una aplicación. El desarrollador puede no recibir el instrumento de financiación original, mientras la plataforma mapea cuenta, dispositivo, financiación, producto y canje.<sup>[[26]](#references)</sup>

**Ventajas:** el merchant/developer no recibe el PAN principal; controles antifraude/reembolso y familiares/empresariales; un saldo prepago pequeño limita exposición; los recibos firmados simplifican la verificación del entitlement.

**Desventajas:** la cuenta de plataforma es un fuerte hub de identidad y comportamiento; dispositivo y geografía de storefront; rastro de compra/canje del saldo regalo; cash-out limitado; controles de fraude pueden congelar fondos; no es dinero multiplataforma.

**Procedimiento:** (1) usar una cuenta de plataforma gestionada por la organización cuando la política lo permita; (2) revisar reglas de financiación, región, reembolso y valor transferible; (3) añadir solo el presupuesto aprobado; (4) comprar un producto benigno mediante la store oficial; (5) verificar que la aplicación recibe solo los campos esperados del recibo; (6) desactivar compras recurrentes; (7) conciliar y eliminar la cuenta del hardware operativo.

**Detección:** receipts/notificaciones server-side de la plataforma, login de cuenta/dispositivo y registros de financiación reconstruyen la compra. **OPSEC resistente a captura:** nunca iniciar sesión en una cuenta personal de store desde un field node; proporcionar solo un app entitlement acotado cuando sea posible. **Monitoring:** activar alertas de nuevos dispositivos/compras e investigar replay de recibos, cambios de familia/cuenta o restores inesperados.

## Mutual credit, clearing o liquidación neta periódica

**Mecánica:** los participantes registran obligaciones en un ledger privado y liquidan periódicamente solo cada posición neta. Los eventos de servicio individuales no necesitan crear pagos públicos separados, pero el operador del ledger y las contrapartes conservan una atribución detallada.

**Ventajas:** menos transacciones y comisiones externas; los observadores públicos solo ven la liquidación neta; funciona para organizaciones recurrentes; límites de crédito explícitos contienen la exposición.

**Desventajas:** el ledger centralizado es evidencia completa y objetivo de fraude; riesgo de contraparte/default; obligaciones legales/contables/fiscales; membership pequeño; transferencias netas inusuales aún pueden revelar relaciones.

**Procedimiento:** (1) usar solo organizaciones identificadas que consientan y tengan aprobación legal/contable; (2) definir unidad, límite de crédito, intervalo de liquidación y reglas de disputa; (3) registrar cada obligación con aprobación inmutable; (4) permitir que roles financieros separados calculen y aprueben posiciones netas; (5) liquidar mediante un rail ordinario y lícito; (6) conciliar cada línea con la liquidación; (7) cerrar el acceso y conservar registros según la política.

**Detección:** ledger, facturas, aprobaciones y liquidación bancaria/blockchain final proporcionan ground truth; los analistas no deben inferir actividad bruta ausente únicamente a partir de la transferencia neta. **OPSEC resistente a captura:** los dispositivos operativos pueden enviar requisiciones acotadas, pero no editar saldos ni autorizar liquidaciones. **Monitoring:** alertar ante incumplimiento de límite de crédito, entradas retrofechadas, cambios de administrador, discrepancias de conciliación y liquidaciones a un beneficiario nuevo.

## Matriz de exposición ante captura/compromiso

Se aplica una prueba de incautación/pérdida a cada familia. El objetivo es limitar la autoridad de gasto y la divulgación de identidades no relacionadas mientras se conserva la contabilidad lícita, no borrar transacciones ni impedir una investigación.

| Familia técnica | Lo que puede revelar un wallet/dispositivo/cuenta capturado | Control autorizado mínimo |
|---|---|---|
| Efectivo, money order, COD, valor físico al portador | recibos, series, notas, valor bearer restante y contactos físicos | llevar solo el importe aprobado; contabilidad privada separada; reportar pronto la pérdida; ningún registro falso |
| Prepaid, gift, voucher, service credits | saldo, emisor, activación, canje y tokens de cuenta/sesión | saldo bajo; un propósito; registro veraz; freeze/revocación del emisor cuando exista |
| Tarjeta virtual/tokenizada, wallet token, payment app | cuenta del emisor, token de dispositivo, transacciones, recuperación e historial del comerciante | bloqueo del dispositivo; alertas de transacción; alcance por comerciante; suspensión remota del emisor; ninguna cuenta de recuperación compartida |
| Bank compartment, procurement delegado, red-team procurement | organización, aprobadores, proveedor, facturas y proyecto | separación de roles; subcuenta de mínimo privilegio; credenciales financieras nunca en nodos operativos/de campo |
| Invoice, escrow, batch settlement | contraparte, propósito, aprobación pendiente, coordinator o rastro de disputa | solicitud de un solo uso; approver separado; sesión limitada; ledger central autorizado |
| Bitcoin, Silent Payments, PayJoin/CoinJoin | seeds/keys, etiquetas, direcciones, grafo de transacciones y configuración de red | firma hardware/offline; wallet cifrado; límites de passphrase; vista watch-only en campo; recovery documentado |
| Lightning/BOLT 12 | seed, canales, invoices, pares/LSP y base de datos de pagos | saldo hot mínimo; backup cifrado; identidad de nodo separada; cierre/recovery según plan documentado |
| Monero, Zcash, MWEB, aplicaciones ZK | spend/view keys, historial local, RPC y transacciones límite | roles spend/view separados; soporte hardware cuando exista; ninguna sesión de exchange en el field node |
| Stablecoins, swaps, bridges y DEX | grafo transparente, approvals, estado RPC/frontend y activos de destino | revocar allowances; contratos verificados; prueba de bajo valor; conciliación completa |
| Cashu, Fedimint, Taler, Privacy Pass | tokens bearer, mint/federation/exchange y caché de emisión/canje | saldo pequeño; backup cifrado según el protocolo; canjear/reemitir; nunca compartir credencial de financiación |
| Paymaster, multisig/threshold | session key, un signer, operaciones pendientes y política del sponsor | session key limitada; quorum independiente; rotación de signer; field device sin acceso al threshold |
| Mixer/peel/structuring, nominees/fronts, abuso de reembolsos/gambling | proveedor incriminatorio, comunicaciones, grafo y registros de participantes | ningún uso operativo; emulación solo con evidencia sintética/testnet |
| Moneda comunitaria/evento | inscripción, saldo local, contrapartes y canje | valor limitado; freeze/reissue del emisor; ledger privado auditable y consentimiento |
| Bitcoin/EVM stealth address reutilizable | payment/view/spend keys, metadata relacional, anuncios y outputs derivados | rol de red watch/view-only; rol spend offline/hardware; ninguna sesión de financiación personal |
| Liquid confidential/state channels | seed, datos de blinding/último estado, pares, límites y disputas | backup spend/view/state separado; saldo hot bajo; dispute monitor independiente |
| Carrier/open-banking/platform billing | cuenta telefónica/bancaria/store, consentimiento, recibo, dispositivo y fuente de financiación | cuenta empresarial; MFA externo; límite bajo; ninguna cuenta personal en hardware de campo |
| Mutual-credit clearing | miembros, obligaciones, límites, aprobaciones y ledger de liquidación | solo requisición operativa; ledger inmutable separado y aprobación financiera dual |

## Monitorización de posibles descubrimientos o compromisos de pago

La denegación de un pago, una revisión de compliance o la desconexión de un wallet no demuestra que exista una investigación. Monitorizar únicamente cuentas, ledgers e infraestructura que la organización tenga derecho a observar; nunca sondear proveedores o contrapartes para comprobar si cooperan con investigadores.

| Técnicas cubiertas | Señales de monitorización seguras | Condición de freeze/stop |
|---|---|---|
| Efectivo, money order/COD, prepaid/gift/voucher, valor físico bearer | discrepancia de inventario/recibo, serie duplicada, canje/reembolso inesperado o reporte de pérdida | instrumento perdido, canje fuera del pedido aprobado, recibo alterado o ruptura de custodia |
| Virtual/tokenized card, payment app, bank/ACH/wire, open banking, carrier/platform billing | alertas del emisor/banco/plataforma, nuevo dispositivo/consentimiento/beneficiario, reutilización de token, recovery de SIM/cuenta | autorización desconocida, cambio de beneficiario, factor de recuperación nuevo, SIM swap o cargo recurrente |
| Account/merchant compartment, procurement controlado/delegado, service credits | cambios de IdP/proveedor/proyecto, rol/token/presupuesto, factura y consumo | token entre proyectos, admin desconocido, límite excedido, factura incorrecta o destino no compatible |
| Invoice, escrow, pooled settlement, mutual credit | caducidad de solicitudes, aprobación/liberación, integridad del ledger, conciliación y cambio de beneficiario | importe/beneficiario alterado, ledger retrofechado, liberación unilateral o batch no conciliado |
| Bitcoin address/coin control, Silent Payments, BIP47/BIP351 | transacciones watch-only, estado de notificación/escaneo, reutilización de direcciones, etiquetas UTXO y consolidación | gasto desconocido, output de receptor reutilizado, fallo de gap/recovery del wallet o merge no aprobado |
| PayJoin/CoinJoin | inputs/outputs/comisiones de propuesta, disponibilidad del coordinator, transacción final | output sustituido, comisión excesiva, divulgación inesperada de inputs o cambio de política del coordinator |
| Lightning/BOLT12/general channels | backup de canal, uso de invoice/offer, liquidez, peer/LSP y disputa on-chain | pago de invoice desconocido, cambio de peer key, cierre antiguo o disputa próxima |
| Monero/Zcash/MWEB/Liquid CT | eventos view/watch, tipo de pool/dominio/dirección, descriptor y transacción límite | gasto no aprobado, downgrade transparente/no confidencial, exportación de clave o límite desconocido |
| Ethereum ZK, stealth addresses, paymaster, stablecoin | contrato/anuncio, RPC/bundler, gas sponsor, allowance/session key y acción del emisor | contrato/campo público incorrecto, approval/spend desconocido, cambio de paymaster o freeze del emisor |
| Cashu/Fedimint/Taler/Privacy Pass | salud mint/federation/exchange, double-spend/replay de token, gateway y saldo bearer | canje desconocido, cambio de clave/términos del mint, fallo de restore o inconsistencia de saldo |
| Swaps/bridges/DEX | contrato verificado, allowance, confirmaciones en ambas cadenas, tipo y destino | discrepancia de contrato/ruta, approval ilimitado, destino ausente o incidente del bridge |
| Multisig/threshold | cambio de signers/política, propuesta pendiente, quorum y auditoría de recovery | signer/propuesta desconocido, reducción del threshold, activación de recovery o bypass de política |
| Mixer/peel/structuring, nominees/fronts, NFT/gambling/refund abuse | únicamente ground truth y resultados de detección del laboratorio sintético | cualquier cuenta, persona o valor real entrando en la emulación: detener inmediatamente |

## Flujo de selección y verificación

1. Nombrar qué parte no debe conocer qué campo.
2. Identificar emisor/mint/custodian, ledger público, red/RPC, comerciante y observadores físicos.
3. Verificar soporte actual, legalidad, límites, custodia, recovery y comportamiento del reembolso.
4. Usar una prueba end-to-end pequeña y lícita.
5. Inspeccionar el recibo del comerciante, extracto del proveedor, cadena pública y logs del wallet/node.
6. Probar backup/recovery y divulgación de auditoría deliberada.
7. Mantener exactos, pero con acceso controlado, los registros requeridos de origen, propiedad, impuestos, sanciones y engagement.

## References

- [1] [EMVCo — Tokenización de pagos](https://www.emvco.com/emv-technologies/payment-tokenisation/)
- [2] [US CFPB — Observaciones sobre la recopilación de datos por grandes plataformas de pago](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf)
- [3] [Bitcoin.org — Protege tu privacidad](https://bitcoin.org/en/protect-your-privacy)
- [4] [BIP 352 — Silent Payments](https://bips.dev/352/)
- [5] [BIP 78 — Una propuesta sencilla de Payjoin](https://bips.dev/78/)
- [6] [Lightning BOLT 4 — Protocolo de Onion Routing](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Lightning BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
- [8] [Documentación de Monero — Especificaciones técnicas y privacidad de red](https://docs.getmonero.org/technical-specs/)
- [9] [ZIP 224 — Protocolo Shielded de Orchard](https://zips.z.cash/zip-0224)
- [10] [Litecoin — Mimblewimble Extension Blocks](https://litecoin.com/projects/mweb)
- [11] [Ethereum.org — Creación de aplicaciones de privacidad con zero-knowledge proofs](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [12] [Cashu — Protocolo y limitaciones de privacidad](https://docs.cashu.space/faq)
- [13] [Fedimint — Cómo funciona](https://fedimint.org/users/how-it-works)
- [14] [Documentación de GNU Taler](https://docs.taler.net/)
- [15] [FATF — Indicadores de alerta roja para Virtual Assets](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [16] [US FinCEN — Administradores, exchangers y usuarios de moneda virtual](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [17] [Reglamento de la UE 2023/1113 — información de transferencias y crypto-assets](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [18] [RFC 9576 — La arquitectura de Privacy Pass](https://www.rfc-editor.org/rfc/rfc9576.html) and [RFC 9577 — Privacy Pass HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html)
- [19] [ERC-4337 — Account Abstraction Using an Alternative Mempool](https://eips.ethereum.org/EIPS/eip-4337) and [Ethereum.org — Privacy application architecture](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [20] [BIP 47 — Reusable Payment Codes](https://bips.dev/47/) and [BIP 351 — Private Payments](https://bips.dev/351/)
- [21] [ERC-5564 — Stealth Addresses](https://eips.ethereum.org/EIPS/eip-5564)
- [22] [Liquid — Confidential Transactions](https://docs.liquid.net/docs/confidential-transactions)
- [23] [Ethereum.org — State y payment channels](https://ethereum.org/developers/docs/scaling/state-channels/)
- [24] [GSMA Open Gateway — API de Carrier Billing](https://open-gateway.gsma.com/docs/carrier-billing/api-reference)
- [25] [Open Banking Standards — Servicios de iniciación de pagos](https://standards.openbanking.org.uk/customer-experience-guidelines/payment-initiation-services/v4-0/)
- [26] [Apple Developer — StoreKit](https://developer.apple.com/documentation/storekit/)
{{#include ../banners/hacktricks-training.md}}
