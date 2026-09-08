# Catálogo de técnicas de pago anónimo

Este catálogo abarca **familias** de pago, desde el efectivo ordinario hasta el e-cash con blind signatures y la ofuscación en cadenas públicas. “Anónimo” siempre significa anónimo frente a un observador identificado. Un merchant, issuer, mint, exchange, blockchain analyst, network provider, employer y observador físico ven hechos diferentes.

Los procedimientos siguientes son para fondos lícitos, cuentas veraces y procurement autorizado. Las técnicas cuyo propósito en los casos citados fue el blanqueo de capitales, la evasión de sanciones o el fraude de identidad se explican y detectan, pero su procedimiento es un ejercicio forense sintético, no instrucciones para cometer el delito.

## Matriz de cobertura

| Familia | Propiedad principal de privacidad | Observador/confianza principal | Tratamiento |
|---|---|---|---|
| Efectivo y equivalentes | sin registro remoto de la red de pagos | receptor y entorno físico | flujo lícito |
| Valor prepagado/regalo/vale | separa el canje de la tarjeta principal | seller, issuer y servicio de canje | flujo lícito, varía según jurisdicción |
| Tarjeta virtual/tokenizada | oculta el PAN reutilizable o separa merchants | issuer/network/wallet aún identifica al pagador | flujo lícito |
| Payment app/intermediario | el merchant puede ver un alias/intermediario | la app recopila identidad/dispositivo/transacción | referencia comparativa |
| Higiene de Bitcoin/Silent Payments | seudónimos y unlinkability del receptor | grafo público y límite wallet/network | deployable |
| PayJoin/CoinJoin | debilita heurísticas de propiedad común/enlace | participantes/coordinator/network/grafo público | deployable donde sea compatible; revisión legal |
| Lightning/BOLT 12 | routing off-chain y reducción de la ruta del receptor | endpoints, hops, servicios y grafo de canales | deployable donde sea compatible |
| Monero/Zcash/MWEB | confidencialidad on-chain a nivel de protocolo | adquisición, endpoint, red y límites siguen expuestos | deployable donde sea lícito/compatible |
| Aplicación ZK de Ethereum | oculta una declaración/acción específica | entradas públicas, RPC, relayer y app | específico de la aplicación |
| Cashu/Fedimint/Taler | privacidad del pagador mediante blind signatures | mint/federation/exchange y custodia/límites | emergente/específico del despliegue |
| Stablecoins | liquidación digital conveniente | cadena transparente más control/congelación del issuer | no es una referencia de anonimato |
| Swaps/bridges/DEX | mueve valor entre activos/cadenas | ambos grafos, contratos y proveedores | mecánica forense; solo swaps lícitos ordinarios |
| Mixers/peel/structuring | aumenta la ambigüedad/trabajo del grafo | grafo de entrada/salida y registros del servicio | solo ejercicio sintético de detección |
| Nominees/mules/OTC/fronts | inserta intermediarios humanos/empresariales | facilitadores, bancos, comunicaciones | solo análisis de abuso criminal |
| Direcciones de pago reutilizables/stealth | dirección nueva del receptor por pago | anuncio/notificación pública y límites del wallet | deployable donde sea compatible |
| Sidechain/State channel confidencial | oculta importe/activo o actualizaciones intermedias | peers, bridge/federation y liquidación del ciclo de vida | específico del protocolo |
| Carrier/open-banking/platform billing | oculta la tarjeta principal al merchant | carrier, banco/PISP o plataforma identifica al cliente | pago ordinario identificado |
| Mutual credit/net settlement | menos registros externos de liquidación | el operador del ledger privado conserva todo el mapeo | solo participantes identificados |

## Efectivo

**Mecánica:** el valor físico al portador cambia de manos sin autorización online del issuer ni ledger público.

**Ventajas:** el merchant no necesita conocer la identidad bancaria/de tarjeta; no hay grafo remoto de transacciones; es ampliamente comprensible y final.

**Desventajas:** solo presencial; robo/pérdida; controles de cambio/recibo/serial o reporting; retiros, cámaras, testigos y ubicación aún vinculan al pagador.

**Procedimiento:** (1) confirmar que el efectivo es lícito/aceptado y cualquier regla de importe/reporting; (2) retirarlo o recibirlo lícitamente y mantener registros contables privados; (3) pagar a un merchant ordinario sin identificadores innecesarios de loyalty/account; (4) solicitar solo el recibo requerido; (5) evitar datos de envío/cuenta si la compra no los necesita; (6) registrar internamente el propósito empresarial legítimo.

**Detección:** conciliar caja/recibo/inventario, cámaras y logs de acceso conforme a la política aplicable; investigar reembolsos en efectivo inusuales o importes repetidos justo por debajo de los controles sin tratar por sí solo el uso ordinario de efectivo como sospechoso.

## Money order, giro postal, instrumento bancario y pago contra entrega

**Mecánica:** un issuer regulado convierte efectivo/fondos de cuenta en un instrumento numerado pagadero a un receptor identificado; el COD aplaza el cobro hasta la entrega.

**Ventajas:** el receptor puede no recibir el número de banco/tarjeta principal del pagador; sirve cuando el efectivo no puede enviarse a distancia; recibo claro.

**Desventajas:** issuer/retailer conserva los datos de compra/identidad exigidos; seguimiento por serial; dirección del receptor/entrega; pérdida/fraude y restricciones regionales; generalmente no es anónimo.

**Procedimiento:** (1) comprobar reglas, límites, identificación y aceptación del receptor; (2) comprar con información veraz y fondos lícitos; (3) completar inmediatamente beneficiario/importe; (4) conservar serial/recibo; (5) usar entrega con tracking adecuada al valor; (6) conciliar canje/reembolso.

**Detección:** registro de compra/canje del issuer, serial, retailer/cámara, envío y cuenta del receptor; marcar alteraciones, seriales duplicados y canjes rápidos geográficamente incompatibles.

## Open-loop prepaid card

**Mecánica:** una credencial con marca de una red autoriza contra un saldo prepagado en lugar de una cuenta de crédito principal.

**Ventajas:** limita la exposición del merchant y la pérdida; separa al merchant del PAN principal; utilizable online donde se acepte.

**Desventajas:** registros de compra/activación/recarga y dispositivo; KYC y límites variables; fallos de dirección de facturación; restricciones de cash-out/reembolso; “sin nombre” no significa sin registro del issuer.

**Procedimiento:** (1) verificar identidad actual del issuer, tarifas, KYC, geografía y soporte online/recurrente; (2) adquirir mediante seller autorizado con fondos lícitos; (3) registrar los datos veraces requeridos; (4) usarla para un único contexto/propósito; (5) no estructurar cargas ni falsificar residencia; (6) conservar pruebas de compra/gasto y cerrarla/eliminarla según los términos del issuer.

**Detección:** unir seller/activación, financiación, dispositivo/IP, autorización del merchant, comprobaciones de saldo y canje/reembolso. Importan más los patrones que la etiqueta prepaid.

## Closed-loop gift card, voucher y crédito de servicio transferible

**Mecánica:** el valor numerado solo puede canjearse con un merchant/servicio o ecosistema. Los créditos de airtime/game/store son variantes.

**Ventajas:** el merchant receptor puede ver solo código/saldo; impacto limitado; fácil de regalar y separar presupuestos.

**Desventajas:** seller y servicio registran compra/activación/canje; cuenta/dispositivo/entrega aún vinculan; estafas, descuentos de reventa y límites de caducidad/región; derechos de reembolso débiles.

**Procedimiento:** (1) comprar solo en canales autorizados; (2) registrar el valor del código sin exponer el secreto; (3) evitar asociar una cuenta de loyalty identificativa si no es necesario; (4) canjear mediante una cuenta/contexto legítimo separado; (5) conservar el recibo hasta su aceptación; (6) nunca comprar códigos por una solicitud no solicitada de “impuestos/soporte/rescate”.

**Detección:** hora de emisión/canje, convergencia de dispositivo/cuenta, compras masivas o por umbral, un dispositivo comprobando muchos saldos y canje rápido a distancia.

## Cryptocurrency-funded card o broker de gift codes

**Mecánica:** un intermediario acepta cryptocurrency y emite una tarjeta, voucher o código de merchant. Es una conversión entre rails: el merchant ve valor ordinario de tarjeta/regalo, mientras el broker vincula el depósito on-chain con la emisión y entrega.

**Ventajas:** el merchant no recibe el funding wallet; útil para merchants legítimos que no aceptan crypto; valor almacenado limitado.

**Desventajas:** no es anónimo frente al broker/issuer; reglas de KYC, sanciones, exchange y card-program; grafo público del depósito; cuenta/dispositivo/email y canje del código vuelven a conectar ambos lados; riesgo de estafa/insolvencia.

**Procedimiento:** (1) verificar entidad legal, issuer de la tarjeta, jurisdicción admitida, KYC, tarifas y política de reembolso; (2) usar únicamente fondos lícitos documentados; (3) probar la denominación mínima; (4) verificar restricciones de red/merchant antes de comprar; (5) conservar la transacción blockchain y el recibo del broker para contabilidad; (6) nunca usar un broker que prometa fraude de identidad, evasión de sanciones o cash-out “imposible de rastrear”.

**Detección:** correlacionar direcciones de depósito del broker, importe/hora únicos, cuenta/dispositivo y autorización de la tarjeta emitida o canje del código; los registros del issuer y broker conectan la cadena pública con el merchant.

## Tarjeta virtual o limitada a un merchant

**Mecánica:** el issuer asigna un PAN/token generado a la cuenta real, a menudo restringiendo merchant, importe o caducidad.

**Ventajas:** evita revelar el PAN reutilizable; compartimentación por merchant; límites de gasto y revocación sencilla; control antifraude maduro.

**Desventajas:** el issuer sigue conociendo pagador, financiación, merchant, dispositivo/IP y hora; el merchant ve cuenta/entrega; algunos reembolsos/cargos recurrentes fallan; no es anónima.

**Procedimiento:** (1) usar la función oficial del issuer regulado; (2) crear una tarjeta para un merchant/engagement; (3) establecer el límite y caducidad mínimos útiles; (4) usar billing exacto cuando sea necesario; (5) verificar descriptor del extracto/comportamiento del reembolso; (6) congelar/eliminar tras la liquidación final conservando las pruebas de auditoría.

**Detección:** mapeo token-to-account del issuer, autorización del merchant, dispositivo y entrega. Los defensores utilizan señales de reutilización por merchant, velocity y account takeover.

## Mobile-wallet network token

**Mecánica:** la tokenización de pagos EMV sustituye el PAN por una credencial limitada, normalmente vinculada a dispositivo, merchant o escenario de pago.<sup>[[1]](#references)</sup>

**Ventajas:** el merchant no recibe el PAN reutilizable; la criptografía del dispositivo y los datos dinámicos reducen la clonación; revocable sin sustituir la tarjeta.

**Desventajas:** issuer, token service, wallet platform y network conservan mapeos/transacciones; la cuenta de plataforma/dispositivo y ubicación pueden identificar al pagador.

**Procedimiento:** (1) inscribir una tarjeta legítima en el wallet oficial; (2) proteger cuenta de plataforma/dispositivo con autenticación fuerte; (3) verificar token del dispositivo/últimos dígitos durante la compra; (4) desactivar ubicación/analytics innecesarios cuando sea compatible; (5) desactivar inmediatamente dispositivos/tokens perdidos; (6) revisar los registros del issuer y wallet.

**Detección:** requestor del token/cryptogram del dispositivo y mapeo del issuer, telemetría de wallet/cuenta, terminal del merchant y pruebas físicas.

## Payment app, marketplace wallet e intermediario centralizado

**Mecánica:** el servicio mantiene cuentas y transfiere internamente o mediante rails bancarios/de tarjeta; el merchant puede ver un alias mientras el servicio ve a ambas partes.

**Ventajas:** comodidad, mecanismos de disputa/reembolso; el receptor no necesariamente ve datos bancarios/de tarjeta.

**Desventajas:** grafo centralizado de identidad/social/transacciones/dispositivo; bloqueos y procesos legales; las contrapartes pueden exponer el perfil; el uso de datos puede superar la necesidad de pago.<sup>[[2]](#references)</sup>

**Procedimiento:** (1) leer términos de identidad, privacidad, retención y protección del comprador; (2) minimizar sincronización opcional de perfil/contactos; (3) usar una cuenta separada y veraz solo cuando los términos lo permitan; (4) activar MFA/alertas; (5) verificar receptor y privacidad de memo/perfil; (6) exportar registros y cerrar enlaces no utilizados.

**Detección:** cuenta del provider, dispositivo/IP, grafo de contactos, financiación/retiro, memo y registros del merchant. Un alias es seudonimato frente a una contraparte, no anonimato frente a la plataforma.

## Bank transfer, ACH, wire e instant-account payment

**Mecánica:** instituciones reguladas mueven valor entre cuentas identificadas e intercambian los datos de pago exigidos.

**Ventajas:** rápido, responsable, reversible en casos limitados, con registros sólidos; los números de cuenta virtuales pueden reducir la revelación al merchant.

**Desventajas:** bancos/processors conocen a ambas partes; extractos y referencias; no es anónimo; datos cross-border y Travel Rule/AML.

**Procedimiento:** usarlo solo cuando la responsabilidad sea aceptable: verificar independientemente al beneficiario, minimizar datos opcionales del memo, usar una cuenta/referencia virtual proporcionada por el banco cuando exista, activar alertas, conservar factura y conciliar.

**Detección:** registros bancarios/payment deterministas, titularidad de beneficiario/cuenta, dispositivo/sesión y controles antifraude. Es una referencia básica, no una técnica de anonimato.

## Compartimentación de cuentas y merchants

**Mecánica:** identidades/cuentas, aliases de email, tarjetas y contextos de entrega separados evitan que merchants no relacionados unan trivialmente la actividad, mientras un issuer/controller conserva el mapeo.

**Ventajas:** reduce filtraciones y enlaces entre merchants; fácil de auditar; compatible con pagos regulados.

**Desventajas:** el provider aún mapea los compartimentos; teléfono de recuperación/dispositivo/IP y envío pueden reconectarlos; la política puede prohibir múltiples cuentas.

**Procedimiento:** (1) definir un propósito; (2) crear únicamente aliases/subcuentas conformes con los términos; (3) usar un token/tarjeta específico del merchant; (4) desactivar personalización cruzada de contactos/anuncios; (5) mantener un ledger de control cifrado; (6) retirar identificadores después de terminar las necesidades de reembolso/retención.

**Detección:** los providers unen recuperación, dispositivo, financiación e IP; los merchants unen entrega, navegador y comportamiento de cuenta. Los defensores deben distinguir la compartimentación legítima del fraude de identidad sintética.

## Controlled red-team procurement

**Mecánica:** el SOC desconoce una compra mientras un controller del ejercicio conserva el mapeo de entidad legal, operador e infraestructura.

**Ventajas:** ejercicio realista de detección; sin exposición personal; desconflicción y auditoría inmediatas.

**Desventajas:** no es anónimo frente a la organización/provider; carga de governance; filtraciones si se maneja mal el ledger del controller.

**Procedimiento:** (1) asignar una tarjeta/wallet/presupuesto de la organización específico del engagement; (2) separar roles de purchaser/operator; (3) registrar asset, importe, servicio, propósito y kill date; (4) almacenar el mapeo de atribución con acceso limitado al controller; (5) nunca usar identidad falsa, mule ni fondos robados; (6) revelar/conciliar indicadores y reembolsos al cerrar.

**Detección:** el controller mapea factura del provider y asset; el SOC prueba descubrimiento independiente mediante dominio, certificado, hosting y tráfico, no mediante datos del titular de la tarjeta.

## Bitcoin address hygiene y coin control

**Mecánica:** direcciones nuevas de recepción, labels locales y gasto selectivo de UTXO reducen la reutilización de direcciones y la combinación accidental de compartimentos en un ledger público.

**Ventajas:** ampliamente compatible; self-custodial; evita el enlace público más simple.

**Desventajas:** todas las transacciones/importes siguen siendo públicos; heurísticas de common-input/change, timing y consolidación posterior enlazan actividad; permanecen registros de adquisición/RPC/red.

**Procedimiento:** (1) instalar/verificar un wallet mantenido; (2) hacer backup y probar recuperación del seed; (3) usar una dirección nueva por invoice; (4) etiquetar localmente origen/propósito; (5) usar coin control para no mezclar contextos; (6) preferir un nodo local o conexión privacy-aware; (7) revisar change/fees y conservar la contabilidad lícita.<sup>[[3]](#references)</sup>

**Detección:** grafo de direcciones, heurísticas de common-input/change con incertidumbre, importe/hora exactos, consolidación, depósitos en servicios, timing de broadcast del nodo/RPC y registros off-chain.

## Bitcoin Silent Payments

**Mecánica:** BIP 352 permite que un receptor publique un código estático mientras los senders derivan outputs Taproot únicos mediante ECDH; los observadores externos no pueden enlazar directamente los outputs con el código.<sup>[[4]](#references)</sup>

**Ventajas:** identificador público reutilizable sin reutilizar direcciones; no requiere solicitud interactiva de dirección ni output de notificación; se integra en outputs Taproot.

**Desventajas:** coste de scanning para el receptor; soporte variable de wallets; grafo de importe/sender y gasto siguen siendo públicos; el index server puede observar scans.

**Procedimiento:** (1) seleccionar un wallet BIP 352 actual; (2) hacer backup/probar descriptor y recuperación del scanning; (3) generar un código etiquetado donde sea compatible; (4) autenticar el código publicado; (5) el sender revisa inputs y envía una prueba pequeña; (6) el receptor escanea preferiblemente mediante su propio nodo; (7) mantener separados los UTXO recibidos.

**Detección:** por diseño no es identificable de forma fiable solo por el output; los analysts usan inputs del sender, importe/hora, gasto posterior, wallet/red/index y registros de contrapartes.

## PayJoin

**Mecánica:** payer y payee aportan inputs a una misma transacción, rompiendo la suposición de que todos los inputs pertenecen al mismo propietario.<sup>[[5]](#references)</sup>

**Ventajas:** pago ordinario con mayor privacidad; beneficia al grafo general debilitando una heurística común; no requiere un conjunto de outputs iguales.

**Desventajas:** requisito interactivo/de soporte; disponibilidad del endpoint del receptor; importe y transacción final públicos; metadata de implementación y fallback.

**Procedimiento:** (1) confirmar que ambos wallets mantenidos admiten la misma versión de PayJoin; (2) autenticar invoice/endpoint; (3) iniciar desde el URI de pago con PayJoin del wallet; (4) inspeccionar importe/fee final y firmar solo los inputs esperados; (5) evitar manipulación manual de transacciones; (6) verificar broadcast y recepción; (7) registrar fallback si falla la negociación.

**Detección:** los analysts de blockchain no deben forzar clustering de common-input; el endpoint/provider puede registrar la negociación; usar evidencia de wallet/red y gasto posterior, no solo la forma de la transacción.

## CoinJoin

**Mecánica:** varios participantes crean colaborativamente una transacción con muchos inputs/outputs, normalmente de denominaciones iguales, aumentando la ambigüedad sobre la correspondencia input-output.

**Ventajas:** conjunto de ambigüedad on-chain mayor; existen diseños self-custodial; estructura de rondas medible.

**Desventajas:** metadata de coordinator/peer/red; fees/liquidez; forma identificable de la transacción; change tóxico y consolidación posterior destruyen las ventajas; disponibilidad legal/provider variable.

**Procedimiento:** (1) verificar disponibilidad y legalidad actual del wallet/coordinator; (2) instalar el wallet oficial y hacer backup; (3) usar solo UTXO lícitos; (4) comprender denominación, fee y modelo del coordinator; (5) mantener change y outputs mixed etiquetados/separados; (6) nunca consolidarlos entre sí; (7) enrutar el tráfico según el soporte oficial y conservar la contabilidad.

**Detección:** identificar estructura colaborativa sin asumir delito; calcular mappings posibles/anonymity set y observar después change/consolidación, límites de servicios y registros de red/coordinator.

## Lightning Network

**Mecánica:** los pagos HTLC atraviesan canales con onion routing; la mayoría de detalles no se publica on-chain, aunque sí la apertura/cierre y la información pública de canales.

**Ventajas:** rápido y barato; los intermediarios normalmente ven hops adyacentes; los detalles rutinarios permanecen off-chain.

**Desventajas:** sender/receiver y primer/último hop saben más; probing, timing, grafo de canales, liquidez y registros de wallet/LSP; los custodial wallets identifican usuarios.

**Procedimiento:** (1) elegir conscientemente entre self-custodial y custodial; (2) verificar recuperación de wallet/seed/channel; (3) usar una invoice por el importe exacto; (4) preferir canales privados/funciones LSP solo tras leer sus tradeoffs; (5) proteger la IP del nodo con Tor compatible cuando sea necesario; (6) evitar reutilizar invoices identificativas; (7) conservar la contabilidad de canales y pagos.<sup>[[6]](#references)</sup>

**Detección:** logs de node/LSP/custodian, grafo/probes de canales, fallos/timing de pagos y funding/closure on-chain; que no exista una transacción pública no significa que no haya registros.

## BOLT 12 offers y route blinding

**Mecánica:** un offer reutilizable produce invoices nuevas y puede anunciar paths blinded para que el payer no tenga que conocer el nodo/path claro del receptor.

**Ventajas:** privacidad del receptor; endpoint reutilizable de donación/pago sin invoice estática; integra onion routing de Lightning.

**Desventajas:** soporte variable de wallets; endpoints, hops elegidos y financiación permanecen; el contacto público o endpoint de red puede volver a identificar al receptor.

**Procedimiento:** (1) confirmar soporte BOLT 12 compatible; (2) autenticar el offer; (3) solicitar una invoice nueva; (4) revisar importe/issuer/recurrencia; (5) pagar mediante el wallet; (6) verificar recepción/comportamiento del reembolso; (7) minimizar alias/contacto del nodo y conservar contabilidad.<sup>[[7]](#references)</sup>

**Detección:** telemetría de wallet/LSP y primer/último hop, cuenta de distribución del offer, timing/valor y grafo de financiación; route blinding limita intencionadamente la visibilidad del payer.

## Monero

**Mecánica:** las stealth addresses de un solo uso ocultan el vínculo del receptor, RingCT oculta importes y las ring signatures proporcionan ambigüedad del sender.

**Ventajas:** privacidad predeterminada on-chain; confidencialidad de sender/receiver/importe; ecosistema maduro de wallets/nodes dedicados.

**Desventajas:** registros de adquisición/off-ramp y de endpoint/red/contraparte; el remote node ve queries/IP; soporte de exchanges y tratamiento legal variables; pequeños errores operativos aún enlazan contextos.

**Procedimiento:** (1) adquirir lícitamente y conservar base/origen; (2) instalar/verificar un wallet oficial mantenido; (3) hacer backup/probar seed; (4) usar nodo local o ruta documentada Tor/I2P hacia remote node; (5) usar una subaddress nueva por payer/invoice; (6) etiquetar contextos localmente; (7) revelar transaction proof/view access solo deliberadamente.<sup>[[8]](#references)</sup>

**Detección:** centrarse en evidencia de exchange/merchant/dispositivo/red y wallets incautados; el uso del protocolo por sí solo no es sospechoso y la cadena pública expone deliberadamente menos.

## Zcash fully shielded Orchard

**Mecánica:** las zero-knowledge proofs validan transferencias shielded mientras sender, receiver e importe están cifrados; los pools transparentes y las transiciones de pool siguen siendo públicas.

**Ventajas:** fuerte confidencialidad on-chain shielded; viewing keys permiten auditoría limitada; validez impuesta por el protocolo.

**Desventajas:** soporte de wallets/exchanges y elección real de pool variables; correlación de tiempo/valor en límites transparentes; red/RPC y endpoint permanecen expuestos.

**Procedimiento:** (1) seleccionar un wallet Orchard mantenido y shielded por defecto; (2) verificar/hacer backup; (3) obtener ZEC lícitamente; (4) recibir en una Unified Address compatible y confirmar el pool; (5) preferir shielded-to-shielded; (6) usar privacidad de red compatible; (7) probar la revelación de viewing key con un wallet pequeño antes de auditar.<sup>[[9]](#references)</sup>

**Detección:** límites transparentes y registros de servicios, metadata de wallet/red y viewing keys cuando se proporcionen lícitamente; no asumir que todos los pagos a Unified Address fueron shielded.

## Mimblewimble y Litecoin MWEB

**Mecánica:** las confidential transactions ocultan importes y la agregación estilo Mimblewimble elimina el historial convencional rico en direcciones; Litecoin implementa un extension block opcional junto a su cadena transparente.

**Ventajas:** importes confidenciales y mayor fungibilidad en el dominio privado; pruning/agregación eficiente.

**Desventajas:** el límite opt-in de peg-in/out es público y correlacionable; soporte de wallet/exchange; diferencias interactivas y de modelo de dirección; registros de red y adquisición.

**Procedimiento:** (1) elegir un wallet mantenido con soporte explícito de MWEB; (2) verificar/hacer backup y probar un importe pequeño; (3) adquirir lícitamente; (4) hacer peg a MWEB y verificar el dominio del saldo; (5) operar solo con un receptor compatible; (6) evitar un peg-out inmediato y distintivo; (7) conservar registros privados de auditoría.<sup>[[10]](#references)</sup>

**Detección:** timing/valor públicos de peg-in/out, datos de exchange/wallet/node y gastos transparentes posteriores; los detalles de transferencias confidenciales internas se reducen intencionadamente.

## Aplicaciones de privacidad zero-knowledge de Ethereum

**Mecánica:** un circuit demuestra una declaración —membership, propiedad válida de una note o autorización— sin revelar el secreto; un verifier contract la comprueba. Deposits, withdrawals, public inputs, events y gas aún pueden exponer enlaces.

**Ventajas:** selective disclosure programable; aplicaciones con anonymity set; reglas verificables sin revelar todos los datos.

**Desventajas:** bugs de contrato/circuit; anonymity set pequeño; límites públicos; RPC/IP/session/analytics/gas funding; riesgos legales y de la aplicación/sanciones.

**Procedimiento:** (1) definir exactamente qué oculta la proof; (2) usar una aplicación auditada y mantenida cuando sea lícito; (3) inspeccionar public inputs/events y reglas de deposit/withdraw; (4) separar action wallet y gas sponsorship como indique el protocolo; (5) usar una ruta RPC/red privacy-aware; (6) probar con poco valor; (7) conservar registros de compliance.<sup>[[11]](#references)</sup>

**Detección:** events del contrato, timing/valor de deposit/withdraw, relayer/paymaster, RPC/session, storage/analytics del frontend y límite posterior de exchange/merchant. No afirmar que la ZK proof oculta campos declarados públicos.

## Stablecoins

**Mecánica:** los tokens se transfieren en una cadena pública; los issuers centralizados pueden congelar/incluir en blacklist o canjear frente a cuentas identificadas.

**Ventajas:** estabilidad de precio, liquidez y soporte de merchants; liquidación rápida; contabilidad sencilla.

**Desventajas:** grafo transparente de dirección/importe/contrato; gas funding; identidad/control del issuer y exchange; screening de sanciones; anonimato generalmente deficiente.

**Procedimiento:** tratarlo como pago identificado: usar una dirección empresarial nueva solo para compartimentación, verificar contrato/network del token, probar un importe pequeño, proteger el wallet, usar RPC fiable/nodo local, conservar origen/base y verificar las partes exigidas.

**Detección:** grafo completo de eventos de token, freeze list/acciones del issuer, exchange/RPC/dispositivo y relaciones de gas funding.

## Cashu Chaumian e-cash

**Mecánica:** un mint firma ciegamente secretos bearer generados por el cliente, respaldados por reservas Bitcoin/Lightning del mint; puede impedir el double-spend sin vincular directamente la emisión con el canje posterior.

**Ventajas:** bearer tokens sin cuenta; transferencia peer-to-peer instantánea; el mint no puede vincular directamente withdrawal blinded con spend; los tokens pueden moverse como datos/QR.

**Desventajas:** custodia/solvencia/censura del mint; pérdida/robo de datos bearer; límites de denominación/timing y Lightning; metadata de red; ecosistema de software temprano.<sup>[[12]](#references)</sup>

**Procedimiento:** (1) usar primero un test mint oficial o valor desechable mínimo; (2) instalar un wallet mantenido y probar limitaciones de backup/restore; (3) autenticar el mint y revisar custodia/fees; (4) acuñar un importe pequeño; (5) enviar el token mediante canal privado/QR autenticado; (6) el receptor canjea el token antes de tratarlo como final; (7) redimir y conciliar. Nunca almacenar valor significativo en un mint no confiable.

**Detección:** el mint ve red, límites de issue/redeem/Lightning y el conjunto de tokens gastados, pero blinding elimina el vínculo directo del token; endpoints/mensajes e importe/timing distintivos pueden restaurar enlaces.

## Fedimint federated e-cash

**Mecánica:** un threshold de guardians mantiene reservas y firma e-cash ciegamente; las transferencias bearer internas son privadas frente a guardians, mientras gateways Lightning conectan pagos externos.

**Ventajas:** custodia distribuida; transferencia interna privada; governance comunitaria; ningún guardian controla la reserva por debajo del threshold.

**Desventajas:** riesgo de quorum/custodia/software de guardians; el gateway observa invoices/timing; límites de depósito/retiro; complejidad de recuperación del estado del cliente.

**Procedimiento:** (1) verificar invite, guardians, quorum, jurisdicción de la federation; (2) instalar un cliente mantenido y probar recuperación; (3) depositar un importe lícito pequeño; (4) usar payment requests internos nuevos; (5) tratar el gateway como observador de Lightning; (6) probar redemption; (7) conservar registros de origen/impuestos fuera de los datos públicos de pago.<sup>[[13]](#references)</sup>

**Detección:** la federation ve emisión/redención agregadas, los gateways ven invoices externas, Bitcoin/Lightning muestran límites, y la evidencia de endpoint/comunicaciones puede vincular transferencias internas.

## GNU Taler

**Mecánica:** el e-cash con blind signatures integrado con bancos busca mantener anónimo al pagador frente a los merchants, mientras merchants e ingresos siguen siendo responsables.

**Ventajas:** privacidad del pagador por diseño; moneda ordinaria; responsabilidad/reembolsos del merchant; no requiere token especulativo.

**Desventajas:** despliegues limitados; exchange/banco ve financiación; merchant ve pedido/entrega; riesgo de bearer/recovery del wallet; operadores regulados.

**Procedimiento:** (1) localizar un exchange/merchant actual para jurisdicción/moneda; (2) leer KYC/fees/privacy; (3) instalar el wallet oficial; (4) retirar lícitamente desde banco/exchange compatible; (5) revisar contrato del merchant; (6) pagar y conservar datos de recibo/reembolso; (7) evitar identificadores innecesarios de sesión del merchant.<sup>[[14]](#references)</sup>

**Detección:** withdrawal del banco/exchange y depósito del merchant son límites responsables; pedido/dispositivo/entrega y timing del merchant pueden correlacionar aunque las coins estén blinded.

## Cross-chain bridge, atomic swap y decentralized exchange

**Mecánica:** un contrato/servicio bloquea/quema un activo y libera/emite otro, o las contrapartes intercambian atómicamente. Rompe la visión de un único ledger, no la continuidad económica.

**Ventajas:** interoperabilidad de activos/redes; puede evitar un custodio centralizado; uso ordinario de portfolio/liquidity.

**Desventajas:** ambas cadenas son públicas; tiempo/valor/fees/liquidity y contratos correlacionan; registros de bridge/relayer/frontend/RPC; riesgo de smart contract/contraparte y regulatorio.

**Procedimiento para swaps lícitos:** (1) verificar contrato/servicio oficial y disponibilidad legal; (2) inspeccionar custodia/auditoría/fees/slippage; (3) usar una prueba pequeña; (4) registrar ambos transaction IDs y la tasa; (5) proteger approvals; (6) conciliar el activo de destino y revocar approvals innecesarios. No usar swaps para disfrazar el origen de fondos.

**Detección:** events de deposit/withdraw del bridge, importe único menos fees, orden temporal, liquidity, relayer/RPC/frontend y depósitos posteriores en servicios.

## Centralized mixer o tumbler

**Mecánica:** un servicio recibe depósitos en un pool y devuelve unidades diferentes posteriormente, intentando ocultar el mapeo directo input-output.

**Ventajas:** en teoría puede ampliar la ambigüedad de la transacción.

**Desventajas:** el operador puede robar/registrar; análisis de timing/valor de entrada/salida; exposición a sanciones, money transmission y delitos; incautaciones exponen mappings; riesgo de taint/rechazo.

**Procedimiento:** no se proporciona una guía operativa de mixing. Reproducir el grafo de forma segura ampliando [Lab 6](authorized-adversary-emulation-labs.md#lab-6-synthetic-peel-chain-and-bridge-graph): crear depósitos sintéticos, outputs pooled, fees y retrasos; proporcionar mappings incompletos a los analysts; medir qué heurísticas funcionan; después revelar la ground truth.

**Detección:** identificación de wallet/contrato del servicio, conjuntos candidatos de entrada/salida, importe/fee/timing, reutilización de direcciones de depósito, logs incautados/del provider y consolidación posterior. Etiquetar la atribución probabilística.

## Peel chains, fan-out/fan-in y structuring

**Mecánica:** transacciones repetidas extraen pagos pequeños del change, dividen valor entre muchas direcciones, reconvergen collectors o separan importes para evitar revisión.

**Ventajas:** aumenta la carga de trabajo del analyst ingenuo y el número de direcciones.

**Desventajas:** continuidad reconocible de valor/cadencia/transacción; consolidación y endpoints de servicio; structuring puede ser ilegal; fees y errores operativos.

**Procedimiento:** usar únicamente datos CSV/testnet sintéticos: generar una fuente grande, edges repetidos de pago/change, ramas paralelas y un collector; añadir ejemplos parecidos a exchanges legítimos; ajustar la detección y documentar falsos positivos.

**Detección:** continuidad del grafo, patrón repetido de change, cadencia, importes justo por debajo del control, endpoint común de servicio y registros off-chain. Los hot wallets de exchanges pueden parecerse a estos patrones, por lo que el contexto es obligatorio.<sup>[[15]](#references)</sup>

## Nominee, money mule, broker OTC y front company

**Mecánica:** otra persona/cuenta/empresa recibe, convierte o gasta fondos, insertando capas legales y operativas entre controller y transacción.

**Ventajas para un adversario:** la cuenta identificada no revela inmediatamente al controller; puede conectar efectivo, crypto, bienes y jurisdicciones.

**Desventajas:** exposición a fraude de identidad/blanqueo; cada participante añade comunicaciones, registros bancarios/empresariales/fiscales/de envío, fees, inconsistencias y testigos; la reutilización de facilitadores crea hubs.

**Procedimiento:** no emular con personas/cuentas reales. Construir un grafo sintético con controller, recruiter, mule, OTC, shell merchant y beneficiary; sembrar edges de dispositivo/IP/mensaje/banco; pedir a los investigators distinguir titular de cuenta y controller y registrar la confianza de la evidencia.

**Detección:** dispositivo/IP/recovery compartidos, beneficiario/velocity inusuales, muchos senders no relacionados, movimiento inmediato posterior, inconsistencias de empresa/director/factura, comunicaciones y entrega de efectivo/commodities.

## NFTs, gambling, bienes de merchant y refund loops

**Mecánica:** el valor se convierte en un activo de precio propio, saldo de apuestas, bienes revendibles o reembolsos para crear una narrativa transaccional diferente.

**Ventajas para un adversario:** cambia la forma del activo e introduce intermediarios de marketplace/merchant.

**Desventajas:** grafo de marketplace/cuenta/dispositivo y wash trading; registros de odds/play y reembolsos; evidencia de entrega/reventa; fees/pérdidas; responsabilidad por fraude/blanqueo.

**Procedimiento:** no se proporciona flujo de ocultación. Usar datos sintéticos de marketplace con self-trades de wallets relacionadas, precios inverosímiles, juego mínimo, instrumento de reembolso discordante y envío común; validar la detección frente a collectors/customers legítimos.

**Detección:** operaciones circulares/autofinanciadas, propiedad/financiación comunes, outliers de precio, reventa/reembolso inmediato, actividad económica mínima, dispositivo/entrega compartidos y reconvergencia de proceeds.

## Physical bearer wallet o transferencia de token offline

**Mecánica:** un dispositivo, papel/QR, instrumento hardware bearer o token e-cash transfiere el control de un secreto en lugar de transmitir un pago durante la entrega.

**Ventajas:** ningún evento de red en directo durante el intercambio; útil offline; custodia física similar al efectivo.

**Desventajas:** copia/robo/pérdida y exclusividad incierta; redemption/broadcast posterior enlaza; encuentro/envío físico; riesgo de falsificación/manipulación.

**Procedimiento:** (1) usar solo un instrumento/protocolo revisado; (2) inicializar/verificar autenticidad en privado; (3) cargar solo valor lícito pequeño; (4) transferir en un contexto autorizado documentado; (5) el receptor verifica o hace sweep pronto según requiera el protocolo; (6) nunca asumir que el sender no conservó una copia; (7) registrar privadamente evidencia de propiedad/impuestos.

**Detección:** financiación/compra y sweep/redención posterior, serial/manipulación del dispositivo, entrega/encuentro y registros de endpoint.

## Merchant-scoped invoice o solicitud de pago de un solo uso

**Mecánica:** el merchant crea una solicitud de un solo uso con importe, caducidad y referencia del pedido. El payer la liquida mediante un rail compatible sin exponer directamente una credencial reutilizable al merchant; el issuer o payment processor aún puede identificar a ambas partes.

**Ventajas:** limita la reutilización de credenciales e identificadores cruzados accidentales; importe/caducidad exactos reducen errores; compatible con contabilidad y reembolsos ordinarios.

**Desventajas:** invoice, entrega, navegador, processor e issuer aún vinculan el pedido; un importe/hora únicos pueden reforzar la correlación; los payment links maliciosos son comunes.

**Procedimiento:** (1) autenticar independientemente al merchant; (2) solicitar una invoice nueva con importe, asset/network y caducidad exactos; (3) inspeccionar destino y reglas de reembolso; (4) pagar desde el compartimento de engagement aprobado; (5) verificar que el merchant reconoce la misma invoice; (6) conservar recibo y referencia de transacción; (7) dejar caducar la solicitud en vez de reutilizarla.

**Detección:** merchant y processor unen invoice, sesión y liquidación; importes/tiempos únicos y entrega identifican al payer. **Captured wallet/device:** el historial de invoices expone contrapartes y propósito; minimizar datos de memo innecesarios, cifrar el dispositivo y mantener la contabilidad autorizada en el finance system controlado.

## Prepaid service credit y capability token

**Mecánica:** un servicio convierte un pago convencional en créditos internos limitados o una capability bearer. El uso posterior de API/recursos puede evitar presentar la tarjeta original en cada request, pero el servicio normalmente puede mapear emisión y canje.

**Ventajas:** limita gasto y pérdida por compromiso; separa a workers diarios de la credencial de financiación; permite presupuestos por proyecto y revocación.

**Desventajas:** normalmente seudónimo, no anónimo; base de datos del servicio, IP de redemption y patrón de uso único vinculan la actividad; los bearer tokens pueden robarse; los reembolsos pueden requerir al payer original.

**Procedimiento:** (1) comprar créditos mediante una cuenta de organización; (2) crear un proyecto y presupuesto; (3) emitir un token limitado por servicio, importe y caducidad; (4) almacenarlo solo en el secret manager aprobado o ruta de workload identity; (5) probar el rechazo fuera de alcance y tras expirar; (6) monitorizar consumo; (7) revocar y conciliar el valor no usado.

**Detección:** el provider une cuenta de financiación, proyecto, emisión del token y uso; los defensores alertan sobre cambios geográficos/de proceso y consumo anómalo. **Captured node:** asumir que su capability restante puede gastarse; usar caducidad corta, saldo bajo, audience binding y revocación inmediata server-side.

## Privacy Pass o blinded authorization token

**Mecánica:** un issuer produce un token de autorización privacy-preserving que un origin puede validar sin vincular redemption con issuance. Puede representar entitlement pagado o acceso limitado por tasa, pero no es moneda general. La arquitectura separa roles de client, attester, issuer y origin y advierte que IP/timing o colusión pueden deshacer la unlinkability.<sup>[[18]](#references)</sup>

**Ventajas:** redemption unlinkable para servicios compatibles; no hay cookie de cuenta reutilizable en el origin; los tokens en caché pueden separar temporalmente emisión y uso.

**Desventajas:** específico de la aplicación; confianza en issuer/attester y partición del anonymity set; metadata de IP/navegador permanece; robo del token o timing distintivo de emisión puede correlacionar usos.

**Procedimiento:** (1) usar una implementación conforme al tipo de token Privacy Pass relevante; (2) definir exactamente qué entitlement demuestra el token; (3) separar la administración de issuer y origin cuando lo requiera el threat model; (4) minimizar metadata del challenge; (5) emitir varios tokens de prueba y canjear cada uno una vez en origins propios; (6) comparar logs en busca de identificadores estables prohibidos; (7) probar replay, expiración y controles de revocación/abuso.

**Detección:** los origins ven IP/hora de redemption y validez del token; issuers/attesters ven contexto de emisión; los analysts prueban timing y particiones de metadata sin asumir un cryptographic break. **Captured client:** los bearer tokens no gastados pueden utilizarse; limitar su valor, duración y audience, y nunca almacenar junto a ellos la credencial de financiación.

## Delegated organization procurement o fiscal sponsor

**Mecánica:** un equipo de procurement autorizado, reseller o fiscal sponsor contrata y paga mientras el equipo operativo recibe un servicio limitado. Es separación de roles con registros veraces, no nominee ni identidad falsa.

**Ventajas:** los vendors no necesitan recibir la identidad de cada operador ni sus datos personales de pago; compliance, impuestos y reembolsos centralizados; presupuesto y offboarding claros.

**Desventajas:** el sponsor conoce beneficiario y propósito; contratos, aprobaciones, entrega y cuentas permanecen; retrasos/fees adicionales; separación débil si la misma persona administra todas las capas.

**Procedimiento:** (1) documentar propósito empresarial, beneficiario y autoridad aprobadora; (2) seleccionar un intermediario aprobado por la organización; (3) contratar con datos veraces; (4) provisionar una subcuenta limitada al proyecto sin credencial personal de billing; (5) separar administradores de finanzas de operadores; (6) conciliar facturas y accesos; (7) terminar servicio y acceso delegado al cerrar.

**Detección:** registros de procurement, identity-provider, vendor y entrega unen la cadena. **Captured operational device:** debe revelar el proyecto de servicio, pero no credenciales financieras; conservar invoices e identidades del payer en el finance system, no en field nodes.

## Escrow o liquidación condicional

**Mecánica:** un escrow agent de confianza o smart contract mantiene el valor hasta que se cumplan condiciones documentadas. Puede reducir la revelación directa entre payer y payee, mientras escrow y rails subyacentes conservan la relación.

**Ventajas:** protección de disputa y entrega; payer y merchant pueden exponer menos credenciales reutilizables entre sí; condiciones de release auditables.

**Desventajas:** riesgo de custodia/contrato, fees y obligaciones de identidad; contratos on-chain públicos; datos de pedido, envío y disputa permanecen; no es anónimo frente al intermediario.

**Procedimiento:** (1) verificar entidad legal, custodia, fees, foro de disputa y activos compatibles; (2) crear un milestone y ruta de reembolso escritos y exactos; (3) financiar desde una cuenta de organización aprobada; (4) verificar independientemente recepción y autorización de release; (5) liberar solo tras la evidencia; (6) conservar el registro completo de auditoría; (7) cerrar permisos o approvals no usados.

**Detección:** events de cuenta/contrato de escrow, hora de financiación/release, beneficiario y registros de disputa revelan la transacción. **Captured device:** session tokens o contract approvals pueden permitir release; exigir approver/MFA separado y revocar sesiones activas si se pierde.

## Liquidación de organización agrupada o pooled

**Mecánica:** muchas obligaciones aprobadas se agregan y liquidan en menos transacciones bancarias o blockchain, con un ledger interno privado que asigna cada parte. El batching puede reducir el detalle público por compra, pero el coordinator conserva toda la atribución.

**Ventajas:** fees menores; menos edges públicos del grafo; oculta line items individuales a un observador público cuando los importes se agregan; contabilidad interna sencilla.

**Desventajas:** el coordinator es observador completo y objetivo de alto valor; totales/timing distintivos pueden correlacionar; riesgo de custodia/conciliación; puede parecer structuring si se abusa.

**Procedimiento:** (1) definir participantes y obligaciones lícitas en el sistema contable; (2) establecer una ventana regular justificada por negocio, no umbrales diseñados para evitar controles; (3) exigir aprobación dual del agregado; (4) liquidar a receptores autenticados; (5) conciliar cada línea interna con el batch; (6) tratar reembolsos como correcciones vinculadas; (7) proteger el acceso al ledger y conservarlo según la política.

**Detección:** ledger, aprobaciones y registros de beneficiarios del coordinator proporcionan ground truth; los analysts públicos usan clustering de input/output/valor/tiempo con cautela. **Captured payer device:** solo debe contener su requisición, no la signing key del pool ni el ledger de participantes.

## Account-abstraction paymaster o sponsored gas

**Mecánica:** un relayer/bundler envía una operación de smart account y un paymaster paga las fees de transacción, evitando un edge directo de native-gas funding desde el wallet del usuario. Mejora una propiedad del grafo; la operación, el contrato y la telemetría del servicio siguen siendo públicos u observables.<sup>[[19]](#references)</sup>

**Ventajas:** elimina un enlace común de gas funding; permite sponsorship limitado y rate limits; mejora el onboarding de aplicaciones legítimas de privacidad.

**Desventajas:** paymaster/bundler/RPC/frontend pueden correlacionar requests; events del contrato y public inputs permanecen; la política de sponsorship identifica una cohorte; contratos o approvals maliciosos pueden robar activos.

**Procedimiento:** (1) usar una smart account y paymaster auditados y mantenidos en la red correcta; (2) inspeccionar qué campos son públicos y qué registra el sponsor; (3) limitar sponsorship por contrato, función, importe, nonce y caducidad; (4) probar con poco valor; (5) enviar por la ruta privacy-aware prevista por la aplicación; (6) verificar on-chain la operación y el fee payer; (7) revocar allowances/session keys y conservar registros de compliance.

**Detección:** unir logs de UserOperation, EntryPoint, paymaster, bundler/RPC y aplicación; agrupar con cautela políticas de sponsorship idénticas. **Captured wallet:** session keys y approvals pendientes pueden usarse incluso sin gas; limitarlas estrictamente y revocarlas mediante la recovery policy de la cuenta.

## Threshold o autorización multisig de pagos

**Mecánica:** el gasto requiere un threshold de signers independientes. No oculta la transacción, pero separa la autoridad de pago de un laptop, field node u operador capturado.

**Ventajas:** resistencia fuerte a compromise e insider; aprobación responsable; ningún field device contiene autoridad completa; permite recovery.

**Desventajas:** coordinación/disponibilidad; metadata de signer/dispositivo/cuenta puede correlacionar participantes; un backup defectuoso causa pérdida; patrones multisig públicos pueden ser identificables.

**Procedimiento:** (1) definir signers, threshold, límites y recovery antes de financiar; (2) inicializar en hardware/cuentas compatibles separadas; (3) verificar direcciones y backups independientemente; (4) dar a workloads de campo solo capacidad de requisición sin firma; (5) exigir revisión out-of-band de receptor, importe y propósito; (6) probar recovery y pérdida de un signer con poco valor; (7) rotar un signer tras un compromise.

**Detección:** sistema de aprobación, dispositivo de signer y script/contrato público proporcionan evidencia; alertar sobre cambios de policy o signer-set. **Captured node:** como máximo debe exponer una session key de baja autoridad o request sin firmar; nunca almacenar material de quorum junto.

## Closed-loop community o event currency

**Mecánica:** una cooperativa, conferencia o entorno privado de pruebas emite créditos canjeables solo entre participantes inscritos. La transferencia interna puede exponer menos a las redes globales de pago, mientras el operator controla emisión y canje.

**Ventajas:** dominio económico limitado; permite probar UX de pagos offline o privacy-preserving; limita exposición de tarjetas externas; controles experimentales claros.

**Desventajas:** anonymity set pequeño; operator y merchants observan actividad; aceptación/canje limitados; pueden aplicarse licencias, consumer protection e impuestos incluso a valor local.

**Procedimiento:** (1) obtener revisión legal/compliance y publicar términos del issuer; (2) inscribir participantes que consientan; (3) limitar emisión y prohibir uso similar a efectivo; (4) usar payment requests nuevas y minimizar identificadores públicos de participantes; (5) registrar reservas agregadas y recibos individuales privados; (6) probar pérdida/reembolso/canje; (7) cerrar el ledger y devolver el valor residual según lo prometido.

**Detección:** ledger del issuer, inscripción, merchant y redemption reconstruyen flujos; transferencias circulares inusuales o cash-out rápido justifican revisión. **Captured wallet:** pueden exponerse saldo local y contrapartes; limitar valor, cifrar estado y soportar freeze/reissue del issuer con registro auditable.

## Bitcoin reusable payment codes e instrucciones privadas de pago

**Mecánica:** los payment codes BIP 47 usan un identificador público reutilizable más direcciones de depósito de un solo uso derivadas mediante ECDH; BIP 351 especifica un diseño más reciente de instrucciones de pago privadas. Reducen la reutilización pública de direcciones permitiendo que un receptor publique instrucciones estables. Notification, soporte del wallet, funding y selección posterior de coins siguen afectando la privacidad.<sup>[[20]](#references)</sup>

**Ventajas:** una instrucción pública puede producir direcciones distintas; el receptor no necesita publicar cada dirección de invoice; wallets compatibles pueden monitorizar pagos derivados; útil para donantes/clientes lícitos recurrentes.

**Desventajas:** interoperabilidad variable; las notification transactions o el payment code publicado vinculan un contexto de relación; sender, receiver y grafo público aún ven transacciones; consolidación o change descuidados anulan la ventaja.

**Procedimiento:** (1) confirmar que ambos wallets mantenidos soportan exactamente la misma especificación/versión; (2) hacer backup y probar recovery en un wallet de poco valor; (3) autenticar out-of-band el payment code del receptor; (4) enviar una prueba lícita pequeña; (5) verificar que se usó una dirección derivada nueva; (6) etiquetar localmente la relación y aplicar coin control; (7) probar recovery y reembolso antes de depender del sistema.

**Detección:** los analysts examinan patrones de notification, funding/change, consolidación posterior y límites de servicios; publicar el código identifica el contexto del receptor aunque las direcciones de depósito difieran. **Capture-resilient OPSEC:** mantener spend keys fuera de field devices y exponer como máximo una vista watch-only de la relación. **Monitoring:** alertar sobre notification transactions inesperadas, direcciones derivadas reutilizadas, errores de gap-limit/recovery y consolidación no planificada.

## EVM stealth addresses (ERC-5564)

**Mecánica:** un sender deriva una stealth account de un stealth meta-address del receptor y publica un announcement con una ephemeral public key y view tag. El receptor escanea announcements con una viewing key y deriva la spend key correspondiente. Mejora el vínculo del receptor, pero sender, importe/token, gas, announcement y gasto posterior siguen visibles.<sup>[[21]](#references)</sup>

**Ventajas:** dirección nueva del receptor sin interacción; meta-address reutilizable; separación de roles de viewing y spending; funciona con assets/aplicaciones EVM compatibles.

**Desventajas:** scanning y spam de announcements; financiar gas de la nueva dirección puede volver a enlazarla; el sender conoce al receptor; token/importe públicos y consolidación posterior permanecen; soporte de implementación/wallet variable.

**Procedimiento:** (1) usar primero una implementación auditada y mantenida en una testnet; (2) generar y hacer backup de material separado de viewing y spending; (3) autenticar el meta-address; (4) enviar una prueba de poco valor y announcement; (5) escanear y derivar la stealth account; (6) probar gas sponsorship compatible sin edge de financiación personal; (7) registrar campos públicos y conservar contabilidad lícita.

**Detección:** seguir caller del announcement, token/importe, timing, gas sponsor, gasto y consolidación; una view key puede probar la recepción sin conceder gasto. **Capture-resilient OPSEC:** un scanner conectado a la red solo debe tener el rol de viewing cuando sea compatible; mantener spend y recovery keys en otro lugar. **Monitoring:** alertar sobre announcements malformados/spam, acceso a view key, derivación de gasto inesperada y stealth outputs movidos sin aprobación.

## Liquid Confidential Transactions

**Mecánica:** Liquid oculta por defecto importes y tipos de activo mediante commitments y proofs, dejando visibles el grafo de transacción, número de inputs/outputs, fee y block time. Peg-in/peg-out y límites de servicio siguen siendo enlazables, y los usuarios pueden revelar selectivamente datos de blinding.<sup>[[22]](#references)</sup>

**Ventajas:** importe y tipo de activo confidenciales por defecto; liquidación sidechain rápida; auditoría selectiva mediante blinding keys/descriptors; oculta valores comerciales sensibles a observadores públicos.

**Desventajas:** estructura del grafo y timing permanecen; confianza en federation/bridge/exchange; límites de peg y outputs no confidenciales; registros de wallet/node/red; sender y receiver conocen su transacción.

**Procedimiento:** (1) seleccionar un wallet Liquid mantenido y verificar su modelo de backup; (2) usar testnet o un importe lícito pequeño; (3) recibir en una dirección confidencial y verificar que el wallet marca el output como blinded; (4) enviar una transacción confidencial de prueba; (5) inspeccionar qué campos del explorer siguen públicos; (6) exportar solo la blinding proof limitada necesaria para la auditoría; (7) documentar límites peg/exchange y conciliar fondos.

**Detección:** analizar grafo/fee/time visibles, registros de peg y exchange, metadata de red y evidencia posterior de unblinding; no inferir importe o activo ocultos. **Capture-resilient OPSEC:** separar spend seed, datos de blinding/view y operaciones watch-only. **Monitoring:** alertar sobre direcciones accidentalmente no confidenciales, solicitudes de peg desconocidas, cambios de descriptor y exportación no aprobada de unblinding key.

## General payment o state channel

**Mecánica:** los participantes bloquean fondos, intercambian actualizaciones de estado firmadas off-chain y publican on-chain solo la apertura, cierre o estado disputado. Los pagos intermedios no se transmiten globalmente, pero peers y servicios de routing/intermediarios observan su parte y los endpoints deben conservar el último estado ejecutable.<sup>[[23]](#references)</sup>

**Ventajas:** muchas interacciones rápidas y baratas entre ledger privado y público; menos detalle global; saldo de canal limitado; útil para servicios medidos y contrapartes recurrentes.

**Desventajas:** los channel peers se conocen y pueden conservar updates; apertura/cierre/valor/timing correlacionan; puede requerirse monitorización online durante ventanas de challenge; riesgo de implementación/liquidez; no crea por sí solo un anonymity set grande.

**Procedimiento:** (1) elegir una implementación auditada y mantenida y comprender su dispute window; (2) abrir un canal de prueba de poco valor entre partes propias; (3) intercambiar state updates firmadas con nonces únicos; (4) hacer backup del último estado ejecutable; (5) cerrar cooperativamente; (6) ensayar rechazo de stale-state en testnet; (7) conservar registros de contabilidad y channel peer.

**Detección:** la cadena pública expone lifecycle/disputes; peers, watch services y application transport exponen timing y partes off-chain. **Capture-resilient OPSEC:** limitar hot balance y mantener el último estado firmado en un store cifrado y recuperable separado de field nodes. **Monitoring:** vigilar publicación de stale-state, backup perdido, cambio de peer-key y proximidad de challenge deadline.

## Mobile carrier billing

**Mecánica:** un servicio online carga una compra a una suscripción móvil o saldo prepaid mediante el sistema de carrier billing. El merchant puede recibir autorización del carrier en lugar de datos de tarjeta/banco, mientras el carrier conoce subscriber/line, contexto de dispositivo/red, merchant, importe y hora.<sup>[[24]](#references)</sup>

**Ventajas:** no hay número de tarjeta en el merchant; amplia disponibilidad telefónica; útil para bienes digitales de poco valor; el carrier puede limitar y revertir cargos.

**Desventajas:** fuertemente identificado por SIM/cuenta y a menudo dispositivo; límites pequeños y fees altos; restricciones de categoría del merchant; riesgo de account takeover/SIM-swap; carrier y aggregator crean un rastro completo.

**Procedimiento:** (1) confirmar disponibilidad, límite, fee y términos de reembolso con la cuenta del carrier de la organización; (2) activarlo solo en una línea dedicada de la organización si está justificado; (3) establecer el límite mínimo útil; (4) comprar un artículo de prueba benigno; (5) verificar recibos del merchant y carrier; (6) desactivar autorización recurrente; (7) conciliar y desactivar la función tras la evaluación.

**Detección:** los registros de carrier, aggregator y merchant unen línea, subscriber, IP/dispositivo y cargo; las facturas de telecomunicaciones empresariales lo exponen. **Capture-resilient OPSEC:** no usar un número personal y exigir MFA de la cuenta del carrier fuera del field device. **Monitoring:** activar alertas instantáneas de cargo/cambio de SIM y detenerse ante inscripción inesperada en servicios premium, forwarding o recovery de cuenta.

## Open-banking payment initiation

**Mecánica:** con consentimiento explícito del usuario, un PISP regulado solicita al banco que mantiene la cuenta iniciar una transferencia. El merchant puede no recibir credenciales de tarjeta, pero PISP y bancos conservan registros regulados de payer, payee, consentimiento, dispositivo y transacción.<sup>[[25]](#references)</sup>

**Ventajas:** no hay número de tarjeta reutilizable en checkout; autenticación bancaria fuerte; liquidación exacta account-to-account; APIs de consentimiento/estado; conciliación clara.

**Desventajas:** no es anónimo frente a bancos/PISP; el payee suele ver datos legales de cuenta o referencia; riesgo de phishing/redirect; jurisdicción y protecciones de reembolso variables; metadata de consentimiento añade otro observador.

**Procedimiento:** (1) verificar que el PISP sigue regulado y que el callback domain del merchant es auténtico; (2) comenzar desde la solicitud del merchant; (3) revisar en el banco payee, importe, referencia y consentimiento solicitado; (4) autorizar solo el pago único; (5) verificar el estado final independientemente; (6) revocar cualquier consentimiento residual; (7) conservar recibo y conciliar.

**Detección:** logs de banco/PISP/merchant y referencias de transferencia proporcionan atribución sólida. **Capture-resilient OPSEC:** mantener autenticación y recovery bancarios fuera de operational/field devices; el dispositivo solo debe contener un entitlement del servicio pagado. **Monitoring:** usar alertas bancarias de transacciones/consentimientos e investigar nuevos grants de PISP, payees modificados o callbacks de estado fuera de la sesión esperada.

## Platform wallet, saldo de app store o crédito in-app

**Mecánica:** una plataforma factura al usuario o canjea crédito de cuenta y emite un recibo firmado o entitlement a una aplicación. El developer de la app puede no recibir el instrumento de financiación original, mientras la plataforma mapea cuenta, dispositivo, financiación, producto y redemption.<sup>[[26]](#references)</sup>

**Ventajas:** merchant/developer no recibe el PAN principal; controles de fraude/reembolso y familiares/empresariales; un saldo prepaid pequeño limita exposición; recibos firmados simplifican la verificación del entitlement.

**Desventajas:** la cuenta de plataforma es un hub fuerte de identidad y comportamiento; dispositivo y geografía de storefront; rastro de compra/canje de gift balance; cash-out limitado; controles antifraude pueden congelar fondos; no es dinero cross-platform.

**Procedimiento:** (1) usar una cuenta de plataforma gestionada por la organización cuando la policy lo permita; (2) revisar reglas de funding, región, reembolso y valor transferible; (3) añadir solo el presupuesto aprobado; (4) comprar un producto benigno mediante la store oficial; (5) verificar que la aplicación recibe solo los campos esperados del recibo; (6) desactivar compras recurrentes; (7) conciliar y eliminar la cuenta del hardware operativo.

**Detección:** receipts/notificaciones del servidor de la plataforma, login de cuenta/dispositivo y registros de funding reconstruyen la compra. **Capture-resilient OPSEC:** nunca iniciar sesión en una store personal desde un field node; proporcionar solo un app entitlement limitado cuando sea posible. **Monitoring:** activar alertas de nuevo dispositivo/compra e investigar replay de receipts, cambios de family/account o restores inesperados.

## Mutual credit, clearing o periodic net settlement

**Mecánica:** los participantes registran obligaciones en un ledger privado y liquidan periódicamente solo cada posición neta. Los eventos individuales de servicio no necesitan crear pagos públicos separados, pero el operador del ledger y las contrapartes conservan atribución detallada.

**Ventajas:** menos transacciones externas y fees; los observadores públicos ven solo la liquidación neta; funciona con organizaciones recurrentes; límites de crédito explícitos contienen la exposición.

**Desventajas:** el ledger centralizado es evidencia completa y objetivo de fraude; riesgo de contraparte/default; obligaciones legales/contables/fiscales; membresía pequeña; transferencias netas inusuales aún pueden revelar relaciones.

**Procedimiento:** (1) usar solo organizaciones identificadas y consintientes con aprobación legal/contable; (2) definir unidad, límite de crédito, intervalo de liquidación y reglas de disputa; (3) registrar cada obligación con aprobación inmutable; (4) dejar que roles financieros separados calculen y aprueben posiciones netas; (5) liquidar mediante un rail lícito ordinario; (6) conciliar líneas individuales con la liquidación; (7) cerrar accesos y conservar registros según la policy.

**Detección:** ledger, invoices, aprobaciones y liquidación bancaria/on-chain final proporcionan ground truth; los analysts no deben inferir actividad bruta faltante solo a partir de la transferencia neta. **Capture-resilient OPSEC:** los dispositivos operativos pueden enviar requisiciones limitadas, pero no editar saldos ni autorizar liquidaciones. **Monitoring:** alertar sobre incumplimiento del límite de crédito, entradas retrodatadas, cambios de administrator, errores de conciliación y liquidaciones a un nuevo beneficiario.

## Matriz de exposición a captura/compromise

Esto aplica una prueba de seizure/loss a cada familia. El objetivo es limitar la autoridad de gasto y la revelación de identidades no relacionadas conservando una contabilidad lícita, no borrar transacciones ni frustrar una investigación.

| Familia técnica | Lo que puede revelar un wallet/dispositivo/cuenta capturado | Control autorizado mínimo |
|---|---|---|
| Efectivo, money order/COD, valor bearer físico | recibos, seriales, notas, valor bearer restante y contactos físicos | llevar solo el importe aprobado; contabilidad privada separada; reportar pronto la pérdida; no registros falsos |
| Prepaid, gift, voucher, service credits | saldo, issuer, activación, redemption y session tokens de cuenta | saldo bajo; un propósito; registro veraz; freeze/revocación del issuer cuando exista |
| Tarjeta virtual/tokenizada, wallet token, payment app | cuenta del issuer, token de dispositivo, transacciones, recovery e historial del merchant | bloqueo de dispositivo; alertas; alcance por merchant; suspensión remota del issuer; sin cuenta de recovery compartida |
| Bank compartment, delegated procurement, red-team procurement | organización, aprobadores, vendor, invoices y proyecto | separación de roles; subcuenta con mínimo privilegio; credenciales financieras nunca en operational/field nodes |
| Invoice, escrow, batch settlement | contraparte, propósito, aprobación pendiente, coordinator o disputa | solicitud de un solo uso; approver separado; sesión limitada; ledger central autorizado |
| Bitcoin, Silent Payments, PayJoin/CoinJoin | seed/keys, labels, direcciones, grafo de transacciones y configuración de red | firma hardware/offline; wallet cifrado; límites de passphrase; vista watch-only en campo; recovery documentado |
| Lightning/BOLT 12 | seed, canales, invoices, peers/LSP y base de datos de pagos | hot balance mínimo; backup cifrado; identidad de nodo separada; cierre/recovery según plan documentado |
| Monero, Zcash, MWEB, aplicaciones ZK | spend/view keys, historial local, RPC y transacciones de límites | roles spend/view separados; hardware cuando exista; sin sesión de exchange en field node |
| Stablecoins, swaps, bridges y DEX | grafo transparente, approvals, estado RPC/frontend y activos de destino | revocar allowances; contratos verificados; prueba de poco valor; conciliación completa |
| Cashu, Fedimint, Taler, Privacy Pass | bearer tokens, mint/federation/exchange, caché de emisión/redemption | saldo pequeño; backup cifrado según protocolo; redeem/reissue; nunca junto a la credencial de financiación |
| Paymaster, multisig/threshold | session key, un signer, operaciones pendientes y policy del sponsor | session key limitada; quorum independiente; rotación de signer; field device sin acceso al threshold |
| Mixer/peel/structuring, nominees/fronts, abuso de refunds/gambling | provider incriminatorio, comunicaciones, grafo y registros de participantes | sin uso operativo; emular solo con evidencia sintética/testnet |
| Community/event currency | inscripción, saldo local, contrapartes y redemption | valor limitado; freeze/reissue del issuer; ledger privado auditable y con consentimiento |
| Bitcoin/EVM stealth address reutilizable | payment/view/spend keys, metadata de relación, announcements y outputs derivados | rol de red watch/view-only; rol de gasto offline/hardware; sin sesión de financiación personal |
| Liquid confidential/state channels | seed, datos de blinding/último estado, peers, límites y disputas | backup separado de spend/view/state; hot balance bajo; monitor de disputas independiente |
| Carrier/open-banking/platform billing | cuenta de teléfono/banco/store, consentimiento, recibo, dispositivo y origen de fondos | cuenta de organización; MFA externo; límite bajo; sin cuenta personal en field hardware |
| Mutual-credit clearing | miembros, obligaciones, límites, aprobaciones y ledger de liquidación | solo requisición operativa; ledger inmutable separado y aprobación financiera dual |

## Monitorización de posible descubrimiento o compromise de pagos

La denegación de un pago, una revisión de compliance o un wallet offline no demuestra que exista una investigación. Monitorizar solo cuentas, ledgers e infraestructura que la organización tenga derecho a observar; nunca sondear providers o contrapartes para comprobar si cooperan con investigators.

| Técnicas cubiertas | Señales seguras de monitorización | Condición de freeze/stop |
|---|---|---|
| Efectivo, money order/COD, prepaid/gift/voucher, valor bearer físico | discrepancia de inventario/recibo, serial duplicado, redemption/refund inesperado o reporte de pérdida | instrumento perdido, redemption fuera del pedido aprobado, recibo alterado o ruptura de custodia |
| Tarjeta virtual/tokenizada, payment app, banco/ACH/wire, open banking, carrier/platform billing | alertas de issuer/banco/plataforma, nuevo dispositivo/consent/payee, reutilización de token, recovery de SIM/cuenta | autorización desconocida, cambio de payee, nuevo factor de recovery, SIM swap o cargo recurrente |
| Compartment de cuenta/merchant, procurement controlado/delegado, service credits | cambio de IdP/vendor project, role/token/budget, invoice y consumo | token entre proyectos, admin desconocido, límite superado, invoice discordante o destino no admitido |
| Invoice, escrow, pooled settlement, mutual credit | caducidad de solicitud, approval/release, integridad del ledger, conciliación y cambio de beneficiario | importe/payee alterado, ledger retrodatado, release unilateral o batch no conciliado |
| Bitcoin address/coin control, Silent Payments, BIP47/BIP351 | transacciones watch-only, estado de notification/scan, reutilización de direcciones, labels de UTXO y consolidación | gasto desconocido, output de receptor reutilizado, fallo de gap/recovery o merge no aprobado |
| PayJoin/CoinJoin | inputs/outputs/fees de propuesta, disponibilidad del coordinator, transacción final | output sustituido, fee excesiva, revelación inesperada de input o cambio de policy del coordinator |
| Lightning/BOLT12/general channels | backup de canal, uso de invoice/offer, liquidez, peer/LSP y disputa on-chain | pago de invoice desconocido, cambio de peer-key, cierre stale o challenge deadline próximo |
| Monero/Zcash/MWEB/Liquid CT | eventos view/watch, pool/domain/address type, descriptor y transacción límite | gasto no aprobado, downgrade transparente/no confidencial, exportación de key o límite desconocido |
| Ethereum ZK, stealth addresses, paymaster, stablecoin | contrato/announcement, RPC/bundler, gas sponsor, allowance/session key y acción del issuer | contrato/campo público incorrecto, approval/spend desconocido, cambio de paymaster o freeze del issuer |
| Cashu/Fedimint/Taler/Privacy Pass | salud de mint/federation/exchange, double-spend/replay de tokens, gateway y saldo bearer | redemption desconocido, cambio de mint key/términos, fallo de restore o inconsistencia de saldo |
| Swaps/bridges/DEX | contrato verificado, allowance, confirmaciones en ambas cadenas, tasa y destino | mismatch de contrato/ruta, approval ilimitada, destino ausente o incidente del bridge |
| Multisig/threshold | cambio de signer-set/policy, propuesta pendiente, quorum y auditoría de recovery | proposal/signer desconocido, reducción de threshold, activación de recovery o bypass de policy |
| Mixer/peel/structuring, nominees/fronts, NFT/gambling/refund abuse | únicamente ground truth del laboratorio sintético y resultado de detección | cualquier cuenta, persona o valor real entrando en la emulación: detener inmediatamente |

## Flujo de selección y verificación

1. Nombrar qué parte no debe conocer qué campo.
2. Identificar issuer/mint/custodian, ledger público, red/RPC, merchant y observadores físicos.
3. Verificar soporte actual, legalidad, límites, custodia, recovery y comportamiento de reembolso.
4. Usar una prueba end-to-end lícita y pequeña.
5. Inspeccionar recibo del merchant, extracto del provider, cadena pública y logs de wallet/node.
6. Probar backup/recovery y la revelación deliberada para auditoría.
7. Mantener exactos, pero con acceso controlado, los registros requeridos de origen, propiedad, impuestos, sanciones y engagement.

## References

- [1] [EMVCo — Tokenización de pagos](https://www.emvco.com/emv-technologies/payment-tokenisation/)
- [2] [US CFPB — Observaciones sobre la recopilación de datos por grandes plataformas de pago](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf)
- [3] [Bitcoin.org — Protege tu privacidad](https://bitcoin.org/en/protect-your-privacy)
- [4] [BIP 352 — Silent Payments](https://bips.dev/352/)
- [5] [BIP 78 — Una propuesta sencilla de PayJoin](https://bips.dev/78/)
- [6] [Lightning BOLT 4 — Protocolo de Onion Routing](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Lightning BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
- [8] [Monero Documentation — Especificaciones técnicas y privacidad de red](https://docs.getmonero.org/technical-specs/)
- [9] [ZIP 224 — Protocolo shielded de Orchard](https://zips.z.cash/zip-0224)
- [10] [Litecoin — Mimblewimble Extension Blocks](https://litecoin.com/projects/mweb)
- [11] [Ethereum.org — Creación de aplicaciones de privacidad con zero-knowledge proofs](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [12] [Cashu — Limitaciones del protocolo y la privacidad](https://docs.cashu.space/faq)
- [13] [Fedimint — Cómo funciona](https://fedimint.org/users/how-it-works)
- [14] [GNU Taler documentation](https://docs.taler.net/)
- [15] [FATF — Indicadores de alerta de Virtual Assets](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [16] [US FinCEN — Administradores, exchanges y usuarios de moneda virtual](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [17] [Reglamento UE 2023/1113 — información de transferencias y crypto-assets](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [18] [RFC 9576 — La arquitectura de Privacy Pass](https://www.rfc-editor.org/rfc/rfc9576.html) and [RFC 9577 — Privacy Pass HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html)
- [19] [ERC-4337 — Account Abstraction Using an Alternative Mempool](https://eips.ethereum.org/EIPS/eip-4337) and [Ethereum.org — Privacy application architecture](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [20] [BIP 47 — Reusable Payment Codes](https://bips.dev/47/) and [BIP 351 — Private Payments](https://bips.dev/351/)
- [21] [ERC-5564 — Stealth Addresses](https://eips.ethereum.org/EIPS/eip-5564)
- [22] [Liquid — Confidential Transactions](https://docs.liquid.net/docs/confidential-transactions)
- [23] [Ethereum.org — State y payment channels](https://ethereum.org/developers/docs/scaling/state-channels/)
- [24] [GSMA Open Gateway — Carrier Billing API](https://open-gateway.gsma.com/docs/carrier-billing/api-reference)
- [25] [Open Banking Standards — Servicios de iniciación de pagos](https://standards.openbanking.org.uk/customer-experience-guidelines/payment-initiation-services/v4-0/)
- [26] [Apple Developer — StoreKit](https://developer.apple.com/documentation/storekit/)
