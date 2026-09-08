# Técnicas de ofuscación financiera

La privacidad de los pagos es un problema de atribución, no de la marca de pago. Una operación deja evidencia cuando el valor se adquiere, mueve, convierte, gasta y entrega. Una dirección de una cadena pública puede ser seudónima, mientras que un exchange, un emisor de tarjetas, un comerciante, un dispositivo móvil o una cámara de envíos identifica a la persona que está detrás.

Esta página explica los patrones de ofuscación financiera utilizados en el ciberdelito y en operaciones vinculadas a Estados para que los defensores puedan reconocerlos. **No** proporciona un procedimiento de blanqueo de capitales, evasión de sanciones, identidad falsa o elusión de KYC.

## El grafo de valor de extremo a extremo
```text
funding source -> acquisition -> transfer/layering -> conversion -> merchant/host -> delivery/use
|              |                |                 |             |
bank/account     KYC/P2P          blockchain         VASP/OTC    service + device
```
Un actor intenta impedir que cualquier observador vea ambos extremos. Los investigadores hacen lo contrario: conservan registros en cada límite, normalizan el tiempo/valor/comisiones e identifican el **punto de reconvergencia** donde distintas identidades reutilizan un mismo facilitador, dispositivo, cuenta, comerciante o destino.

## Instrumentos y sus observadores reales

| Instrumento | Oculto al comerciante/público | Aún visible para |
|---|---|---|
| Tarjeta virtual/token del emisor | número de tarjeta subyacente | emisor, red/proveedor de tokens, wallet, cuenta del comerciante y sistemas de entrega |
| Valor prepago/regalo | a veces el nombre legal en una compra ordinaria | minorista/carril de pagos, servicio de activación/canje, cámaras, dispositivo y entrega |
| Efectivo | registro público y emisor remoto | contrapartes, cámaras, controles de retiro/número de serie cuando corresponda, registro físico |
| Bitcoin/nueva dirección | nombre legal directo | todos los observadores de la blockchain; pares de wallet/red; servicios de adquisición/off-ramp |
| CoinJoin/PayJoin | heurísticas simples de entradas comunes/pago | transacción pública, metadatos del coordinador/par/red y comportamiento de gasto posterior |
| Privacy coin | remitente/receptor/cantidad públicos, según el protocolo | adquisición/off-ramp, endpoint de wallet, observador de red y contraparte |
| Mixer centralizado | vínculo directo entre depósito y retiro | operador/registros del mixer, conjuntos de entrada/salida de la blockchain y contrapartes |
| Puente/intercambio cross-chain | continuidad en una cadena | ambas cadenas, servicio de puente/intercambio, restricciones de tiempo/valor y liquidez |
| Bróker OTC/P2P | cuenta de intercambio directa en algunos casos | bróker, comunicaciones, movimientos bancarios/de efectivo, contrapartes y dispositivos |

## Tarjetas, valor prepago, testaferros y mulas

### Tarjetas virtuales y enmascaradas

Un emisor puede crear un número de tarjeta limitado a un comerciante o desechable. Esto reduce la exposición del comerciante y la reutilización del número entre comerciantes. El emisor aún lo vincula con el cliente, la cuenta de financiación, el dispositivo, la IP y la transacción. Los descriptores de facturación, la cuenta del comerciante, la dirección de envío y los datos del navegador siguen siendo vinculables.

El marketing de tarjetas “sin nombre” no implica una liquidación anónima. Los emisores y distribuidores regulados pueden realizar verificaciones de identidad, conservar registros, imponer límites geográficos/de importe y responder a requerimientos legales. Una tarjeta obtenida mediante una identidad robada añade robo de identidad; no elimina la telemetría del emisor/dispositivo/comerciante.

### Valor prepago y de regalo

Las tarjetas prepagadas y los códigos de regalo separan un canje posterior del instrumento de pago original, pero crean un objeto numerado con eventos de compra, activación, consulta de saldo y canje. Los patrones relevantes incluyen compras al por mayor, repetición de importes justo por debajo de los controles, canje rápido a distancia, un dispositivo consultando muchos saldos o muchas tarjetas convergiendo en un mismo comerciante/cuenta.

### Testaferros, mulas financieras y fachadas comerciales

Un testaferro o una mula proporciona una cuenta y una identidad legal que se sitúan entre el operador y un servicio. Las redes pueden incorporar reclutadores, titulares de cuentas, procesadores de pagos, comerciantes pantalla y brókeres de retirada de efectivo. Esto crea distancia, pero cada participante añade comunicaciones, comisiones, inconsistencias conductuales y un posible testigo colaborador. Las empresas fachada añaden registros de constitución, fiscales, bancarios, de directores, facturas, hosting y envíos.

Los defensores deben investigar dispositivos/IPs compartidos, reutilización de beneficiarios, contradicciones de geolocalización, velocidad incompatible con el historial de la cuenta, transferencias circulares, múltiples remitentes no relacionados que convergen y movimiento inmediato posterior. No se debe asumir que el titular de la cuenta nombrado es el actor que la controla; debe tratarse como un nodo cuyo rol requiere determinación.

## Patrones de ofuscación de transacciones en cadenas públicas

### Rotación de direcciones y control de monedas

Crear una nueva dirección para cada recepción evita la reutilización trivial de direcciones, pero las transacciones aún pueden vincularse mediante entradas comunes, detección del cambio, valor/tiempo exactos y consolidación posterior. El **Coin control** permite que una wallet elija qué outputs gastar y evite unir compartimentos. Mejora la higiene; no puede eliminar un vínculo ya público.

### Peel chains

Una peel chain gasta repetidamente un saldo grande, enviando un importe menor hacia el exterior y devolviendo el resto a una nueva dirección:
```text
100 -> payment 3 + change 97
97 -> payment 4 + change 93
93 -> payment 2 + change 91 -> ...
```
La dirección cambia en cada paso, pero la continuidad del valor, la cadencia y la estructura de las transacciones suelen formar una cadena reconocible. Las hot wallets legítimas de exchanges pueden comportarse de forma similar, por lo que la atribución requiere evidencias del servicio y del contexto. DOJ ha utilizado el análisis de peel-chain en casos de decomiso vinculados a DPRK.<sup>[[1]](#references)</sup>

### Structuring y fan-out/fan-in

- **Fan-out:** una fuente se divide en muchas direcciones para aumentar la carga de trabajo investigativa o preparar una conversión paralela.
- **Fan-in:** muchas fuentes se consolidan en un único collector, lo que revela un control común o un servicio.
- **Structuring:** transferencias pequeñas y repetidas intentan evitar los umbrales de revisión o mezclarse con el volumen ordinario.
- **Commingling:** fondos ilícitos y no relacionados comparten wallets, pools o servicios, lo que hace inseguras las afirmaciones proporcionales simplistas.

La forma del grafo es una pista, no una prueba. Los analistas deben tener en cuenta las comisiones, el modelo UTXO/account, el comportamiento del servicio y las convenciones de cambio.

### CoinJoin y PayJoin

En un CoinJoin típico, varios participantes aportan inputs y reciben outputs en una única transacción colaborativa, a menudo con denominaciones de output iguales. Esto rompe la suposición de que cada input y output de una transacción tiene un único propietario. El anonymity set está limitado por el número de participantes y el comportamiento posterior: change desigual, toxic change, consolidación o el cruce con un servicio conocido pueden reintroducir vínculos.

PayJoin modifica un pago ordinario para que tanto el pagador como el beneficiario aporten inputs, invalidando directamente la heurística de propiedad basada en inputs comunes para esa transacción. Es principalmente un protocolo de privacidad para pagos, no un servicio de laundering a gran escala. La detección debe evitar declarar que todos los inputs son propiedad conjunta y debe expresar la incertidumbre en lugar de imponer un cluster falso.

### Centralized mixers y tumblers

Un centralized mixer acepta depósitos y posteriormente paga monedas diferentes desde una reserva común, a menudo después de aplicar comisiones y demoras. Su privacidad depende del tamaño del pool, la política de retiros, los logs, la honestidad del operador y la resistencia al decomiso. El análisis del momento y valor de entrada y salida, las direcciones de depósito, el clustering de wallets del servicio y los registros pueden reducir el conjunto. Los operadores pueden robar los fondos o conservar un mapeo completo.

La exposición legal es considerable y depende de la jurisdicción. Los casos de DOJ contra ChipMixer, Samourai Wallet y los desarrolladores u operadores de Tornado Cash, así como la evolución de los litigios sobre sanciones, muestran que los hechos relativos al protocolo, la custodia, el control y la transmisión de dinero son relevantes; una etiqueta como “descentralizado” no constituye una conclusión jurídica.<sup>[[2]](#references)</sup>

### Cross-chain hopping, swaps y bridges

Chain hopping convierte un activo o lo mueve a través de un bridge, interrumpiendo una consulta en un único ledger, pero no la continuidad económica:
```text
chain A deposit -> bridge/swap event -> chain B issuance/withdrawal
t0, amount A                    t1, amount B - fees
```
Los analistas correlacionan los contratos de bridge/direcciones de depósito de servicios, el orden de las transacciones, la ventana temporal, el tipo de cambio, las comisiones, la liquidez y los importes únicos. Los swaps repetidos pueden ampliar la ambigüedad, a la vez que añaden telemetría del proveedor/API/wallet. FATF identifica específicamente el chain hopping, los mixers, los servicios peer-to-peer y las monedas con privacidad mejorada como indicadores de riesgo cuando se combinan con un contexto sospechoso.<sup>[[3]](#references)</sup>

### NFTs, gambling y compras a comerciantes

Las operaciones de NFT consigo mismo o colusorias pueden dar a los fondos una narrativa aparente de venta; el gambling puede intercambiar depósitos por retiros; los bienes pueden convertir valor digital en inventario revendible. Estas rutas dejan cuentas de marketplace, vínculos con creadores/royalties, grafos de wash-trading, probabilidades/historial de juego, logs de dispositivos y pruebas de entrega y reventa. Una pérdida o comisión no demuestra que el origen haya desaparecido.

## Cryptocurrencies que preservan la privacidad

Los protocolos de privacidad difieren técnicamente:

- **Monero** utiliza direcciones de un solo uso, ring signatures e importes confidenciales, reduciendo la visibilidad pública del remitente/receptor/importe. La observación de la red, el compromiso de la wallet, la adquisición/off-ramp y los registros de las contrapartes permanecen fuera de esas protecciones on-chain.
- **Zcash shielded pools** pueden ocultar el remitente, el receptor y el importe cuando se utilizan transacciones shielded; las direcciones transparentes y las transiciones entre pools permanecen públicas, y los patrones de uso afectan al anonymity set efectivo.
- **Bitcoin** es transparente por defecto. Las nuevas direcciones, CoinJoin, PayJoin y Lightning modifican determinadas suposiciones de vinculación, pero no hacen privadas todas las capas.

La tecnología de privacidad tiene usos legítimos de seguridad y comerciales. Desde una perspectiva investigativa, cuando el ledger proporciona menos información, las pruebas de endpoint, servicio, red y humanas adquieren mayor importancia. Nunca se debe inferir criminalidad únicamente por la elección de un protocolo que preserve la privacidad.

## Modelo de caso multicapa de DPRK

Las acusaciones públicas del DOJ y las acciones de forfeiture describen un proceso compuesto, no un único truco:<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

1. trabajadores utilizaron material de identidad ficticio/robado y VPNs para obtener empleo remoto;
2. los empleadores pagaron en cryptocurrency, incluidas stablecoins;
3. los fondos se movieron en importes menores, atravesaron distintas chains o tokens, compraron NFTs o se mezclaron con otros fondos;
4. otros fondos robados entraron en mixers;
5. traders OTC y empresas pantalla convirtieron el valor en pagos fiat o bienes;
6. los facilitadores, cuentas y rutas de blockchain repetidos permitieron a los investigadores volver a conectar las capas.

Treasury declaró que Lazarus utilizó Blender.io para procesar parte del robo de Axie Infinity/Ronin, mientras que el FBI ha publicado direcciones y ha instado a bridges, exchanges, operadores de RPC y empresas de analytics a bloquear los fondos vinculados a robos posteriores de TraderTraitor.<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

La lección es bidireccional: los actores estatales utilizan servicios comerciales/delictivos ordinarios, y las blockchains públicas permiten a los defensores seguir el valor incluso cuando inicialmente se desconocen los nombres.

## Flujo de trabajo de detección

1. **Conservar los identificadores y registros sin procesar de las transacciones.** Las capturas de pantalla y los valores fiat redondeados son insuficientes.
2. **Normalizar los activos y el tiempo.** Registrar la chain, el contrato del token, las unidades, la hora del bloque, la zona horaria del servicio, las comisiones y la fuente del tipo de cambio.
3. **Etiquetar la confianza de las pruebas.** Distinguir entre una dirección publicada por un servicio, un evento determinista de un contrato, una heurística de clustering y threat intelligence externa.
4. **Rastrear ambas direcciones.** Encontrar el origen de la financiación, la dispersión inmediata, la reconvergencia, las salidas de bridges, los depósitos en servicios y el gasto/la entrega.
5. **Unir las pruebas off-chain.** Los registros de KYC de cuentas, dispositivos, IPs, tickets de soporte, API keys, bancos/pagos, envíos y comunicaciones suelen resolver la ambigüedad.
6. **Probar explicaciones alternativas.** Los exchanges, custodios, sistemas de payroll y protocolos de privacidad pueden producir fan-in/out o co-spends sin una titularidad efectiva común.
7. **Monitorizar en lugar de cerrar prematuramente.** Un output inactivo puede volverse atribuible cuando posteriormente llegue a un servicio.
8. **Aplicar las obligaciones vigentes de sanciones/AML con asesoramiento legal.** Las normas y designaciones cambian; una asociación histórica no sustituye al análisis jurídico actual.

## Modelo seguro de procurement para red teams

Un equipo autorizado puede necesitar que el SOC objetivo no reconozca su pago de hosting, mientras el responsable del engagement mantiene la rendición de cuentas:

- utilizar una tarjeta de organización específica para el engagement o una wallet corporativa documentada;
- mantener exactos los registros de facturación, impuestos y proveedores;
- separar al operador de las funciones de procurement y limitar el acceso al mapa de atribución;
- no utilizar un mule, una identidad falsa, una tarjeta robada, una evasión de sanciones ni un exchanger sin licencia;
- registrar el activo, el importe, el propietario, el servicio, la fecha, la ruta de reembolso y las pruebas de teardown;
- comunicar al responsable del engagement los indicadores relevantes de pago/proveedor después del ejercicio.

Esto crea **ceguera frente al participante del ejercicio**, no ceguera frente a la ley, el proveedor o la gobernanza.

## References

- [1] [US DOJ — Marco de aplicación de la ley sobre cryptocurrency (ejemplo de peel-chain e investigaciones sobre DPRK)](https://www.justice.gov/archives/ag/page/file/1326061/dl?inline=)
- [2] [US DOJ — Desmantelamiento de ChipMixer](https://www.justice.gov/archives/opa/pr/justice-department-investigation-leads-takedown-darknet-cryptocurrency-mixer-processed-over-3)
- [3] [FATF — Indicadores de alerta de Virtual Assets](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [4] [US DOJ — Representante del Foreign Trade Bank de DPRK acusado de conspiraciones de blanqueo de cryptocurrency](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [5] [US DOJ — Demanda de forfeiture relativa a 7,74 millones de dólares presuntamente blanqueados para DPRK](https://www.justice.gov/usao-dc/pr/department-files-civil-forfeiture-complaint-against-more-774-million-laundered-behalf-0)
- [6] [US Treasury — Sanciones contra Blender.io y fondos de Lazarus](https://home.treasury.gov/news/press-releases/jy0768)
- [7] [FBI — Corea del Norte es responsable del robo de Bybit de 2025](https://www.fbi.gov/investigate/cyber/alerts/2025/north-korea-responsible-for-1-5-billion-bybit-hack)
- [8] [FinCEN — Aplicación de las regulaciones a usuarios, administradores y exchangers de virtual currency](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
