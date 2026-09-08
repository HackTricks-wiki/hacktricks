# Privacidad de las criptomonedas

La privacidad de las criptomonedas es una cuestión de protocolo y operaciones, no un sinónimo de secreto o inmunidad. Los registros públicos, exchanges, servidores de wallets, peers de red, comercios y transacciones posteriores exponen distintas partes del grafo.

Comienza con el [Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) para consultar el formato de pros/contras/procedimiento/detección de cada técnica. Esta página amplía los mecanismos específicos de las criptomonedas y sus límites operativos.

{% hint style="danger" %}
Este capítulo está destinado a la autocustodia lícita y a la minimización de datos. No lo utilices para blanquear ganancias, evadir sanciones, impuestos u obligaciones de reporte, realizar transacciones con partes prohibidas, engañar a un proveedor regulado ni operar un servicio de transmisión sin licencia. La tecnología de privacidad no cambia el origen legal ni la propiedad de los fondos.
{% endhint %}

## Modelo de amenazas por capa

| Capa | Observador | Divulgación habitual |
|---|---|---|
| Adquisición/salida | Exchange, banco, broker, contraparte P2P | Identidad, cuenta de financiación, destino, dispositivo, IP, hora |
| Ledger | Cualquiera que ejecute analytics | Direcciones/outputs, cantidades y hora en chains transparentes; metadatos específicos del protocolo en otros casos |
| Backend de la wallet | Proveedor RPC, explorer, nodo remoto | Consultas de direcciones, saldos, IP, emisión de transacciones |
| Red | ISP, peers, entrada a una red de anonimato | IP, tiempos, volumen y uso del protocolo |
| Contraparte | Pagador/receptor | Invoice/dirección, entrega, conversación, cuenta y hora |
| Endpoint | Malware, backup en la nube, incautación física | Seed, claves, etiquetas, historial, capturas y portapapeles |

La autocustodia puede eliminar a un custodio de la ruta de control, pero no borra el ledger, el registro de adquisición, los metadatos de red ni las evidencias del endpoint.

## Comparación de protocolos

| Método | Propiedad de privacidad útil | Limitaciones importantes |
|---|---|---|
| Bitcoin on-chain | Autocustodia; las direcciones nuevas evitan la reutilización simple de direcciones | Grafo público y permanente de transacciones; heurísticas de cantidades, tiempos y gastos |
| Bitcoin PayJoin | El input del receptor puede romper la heurística de propiedad común de los inputs | Ambas wallets necesitan compatibilidad; la transacción sigue siendo pública; la compatibilidad es desigual |
| Bitcoin CoinJoin | Crea ambigüedad entre participantes coordinados | Patrones reconocibles, vínculos previos/posteriores, consolidación, riesgo de políticas/legislación/proveedores |
| Lightning | Los pagos onion-routed no se publican globalmente como transferencias ordinarias | Los canales se abren/cierran on-chain; los endpoints, peers, probes o custodios pueden inferir datos |
| Monero | Mayor confidencialidad on-chain predeterminada para receptor, cantidad y conjunto de remitentes | Persisten los vínculos con exchange, nodo, hora, endpoint y contraparte |
| Ethereum/stablecoins | Amplia disponibilidad e interoperabilidad con smart contracts | Estado/acciones públicos; metadatos RPC; los emisores centralizados pueden bloquear/congelar/reportar |

## Bitcoin: base de preservación de la privacidad

Bitcoin es pseudónimo, no anónimo. Las transacciones confirmadas son públicas y duraderas; la reutilización de direcciones, la propiedad común de inputs, la detección del cambio y las direcciones identificadas públicamente pueden crear clusters.<sup>[[1]](#references)</sup>

### Flujo de trabajo

1. **Elige una wallet de autocustodia mantenida.** Descárgala del proyecto oficial, verifica las firmas/hashes cuando se ofrezcan y aplica las actualizaciones de seguridad.
2. **Crea la wallet en un endpoint de confianza.** Registra la seed de recuperación offline; nunca la coloques en email, chat, capturas de pantalla o notas normales en la nube. Prueba la recuperación antes de manejar cantidades importantes.
3. **Mantén hot únicamente el valor operativo.** Utiliza custodia offline/hardware adecuada para el valor a largo plazo, con un plan de recuperación que no exponga la seed a una única ubicación frágil.
4. **Genera una dirección/invoice de recepción nueva para cada transacción.** No publiques una dirección estática cuando sea posible utilizar un servidor de invoices o una entrega privada autenticada.
5. **Utiliza tu propio full node cuando sea viable.** Un explorer/servidor electrum de terceros puede conocer las direcciones consultadas y los metadatos de IP. Configura únicamente el comportamiento de Tor/proxy compatible con la wallet; Tor oculta un extremo de red, no el grafo de la blockchain.
6. **Etiqueta cada UTXO de forma privada** con su origen, propietario, propósito y estado de compliance. Activa coin control para evitar gastar conjuntamente contextos de identidad no relacionados.
7. **Previsualiza la transacción:** inputs seleccionados, destino del cambio, cantidad, fee, contraparte y si el gasto mezcla compartimentos. Evita consolidaciones innecesarias.
8. **Conserva por separado y cifrados los registros lícitos.** Preserva la base de adquisición, invoices, autorizaciones y datos fiscales/de reporte sin publicar la correspondencia.
9. **Considera el gasto posterior como parte de la misma decisión de privacidad.** Una recepción bien separada puede volver a vincularse cuando su output se gasta conjuntamente con fondos identificados.

La documentación de privacidad de Bitcoin Core explica que un full node evita revelar las consultas de la wallet a servidores de terceros, pero que la emisión de transacciones y el historial público siguen requiriendo análisis.<sup>[[2]](#references)</sup>

## PayJoin

PayJoin es un pago colaborativo en el que el receptor añade un input. Esto derrota la suposición simplista de que todos los inputs pertenecen al remitente. BIP 78 describe el protocolo interactivo original; el borrador BIP 77 define un diseño asíncrono v2 que utiliza un buzón cifrado/OHTTP.<sup>[[3]](#references)</sup>

Uso seguro:

1. Confirma que ambas wallets mantenidas son compatibles con la misma versión de PayJoin.
2. Obtén el invoice compatible con PayJoin mediante un canal autenticado; protégelo como cualquier solicitud de pago.
3. Comprueba la cantidad y el destino originales, y permite que la wallet valide la propuesta/PSBT, la contribución al fee y las sustituciones prohibidas.
4. Confirma el resumen final de la wallet. No apruebes manualmente un output, cantidad o fee excesivo inesperado.
5. Si la negociación falla, entiende si la wallet vuelve de forma segura a un pago ordinario o requiere un invoice nuevo.
6. Conserva los recibos/registros privados necesarios para la propiedad, la contabilidad y las disputas.

PayJoin mejora una heurística de chain analysis; no oculta el pago a las partes, la plataforma de adquisición, los endpoints ni el ledger público.

## CoinJoin: beneficios y limitaciones

CoinJoin coordina a varios usuarios en una misma transacción para que el mapeo entre inputs y outputs sea menos certero. La investigación sobre diseños históricos específicos de Wasabi y Samourai encontró transacciones altamente reconocibles y mostró que el comportamiento antes/después del mix puede reducir considerablemente el anonimato.<sup>[[4]](#references)</sup> Este resultado no debe generalizarse a todas las implementaciones o versiones futuras, pero demuestra por qué una cifra del “anonymity-set” no es una garantía.

Antes de cualquier uso lícito:

- comprueba la legislación local vigente, el estado de las sanciones, la política del exchange/custodio y las obligaciones fiscales/de reporte;
- utiliza software mantenido y non-custodial obtenido del proyecto oficial;
- comprende el modelo del coordinator, los fees, los controles contra denial-of-service y si el servicio actual sigue operativo—zkSNACKs terminó su coordinator en 2024, aunque pueden existir otros coordinators de Wasabi;
- conserva de forma privada los registros del origen de fondos y de las transacciones;
- nunca aceptes fondos desconocidos en nombre de otra persona ni utilices un “mixer” custodial que prometa retiros imposibles de rastrear;
- mantén los outputs separados por origen/contexto y evita consolidaciones posteriores que destruyan la ambigüedad buscada.

Los resultados legales dependen de los hechos y la jurisdicción. Las declaraciones de culpabilidad de Samourai de 2025 se referían a operar conscientemente un transmisor de dinero sin licencia que movía ganancias criminales; no establecen que toda transacción colaborativa o todo usuario que busque privacidad sea criminal.<sup>[[5]](#references)</sup>

## Lightning Network

El onion routing Sphinx de Lightning está diseñado para que un salto intermedio conozca a su predecesor y sucesor, en lugar de toda la ruta.<sup>[[6]](#references)</sup> No proporciona anonimato absoluto: la financiación/cierre de canales es pública, los nodos anuncian la topología, las contrapartes conocen los endpoints, el routing/probing puede inferir saldos o partes, y una wallet custodial ve la actividad de la cuenta de su usuario.

Para mejorar la privacidad:

1. Prefiere una wallet mantenida y non-custodial si importa la privacidad frente al intermediario; planifica primero el backup/recuperación de los canales.
2. Utiliza un invoice u offer nuevo para cada pago. Verifica si la wallet exacta es compatible con BOLT 12/route blinding, en lugar de asumirlo.
3. Evita publicar aliases de nodo, datos de contacto y endpoints de red estables innecesarios.
4. Conéctate mediante una red de privacidad compatible cuando corresponda, entendiendo que los patrones de disponibilidad y tiempos aún pueden correlacionarse.
5. No supongas que un pago off-chain no deja registros: el remitente, receptor, peers, watchtowers, proveedores de liquidez y servicios de wallet pueden conservar observaciones.

La investigación publicada ha demostrado la inferencia del remitente/receptor y del saldo de los canales a partir de datos públicos y probing activo, aunque los ataques y las mitigaciones evolucionan.<sup>[[7]](#references)</sup>

## Monero

Monero utiliza stealth addresses de un solo uso para los outputs, RingCT para ocultar las cantidades y ring signatures para proporcionar ambigüedad probabilística del remitente; sus especificaciones técnicas actuales documentan un ring size de 16 (15 decoys).<sup>[[8]](#references)</sup> Estos son valores predeterminados más sólidos para la confidencialidad on-chain que los ledgers transparentes, no una protección mágica frente a errores del endpoint o de las operaciones.

### Flujo de trabajo lícito

1. **Adquiere de forma lícita.** Un exchange regulado puede conocer la compra y el retiro aunque los detalles on-chain posteriores sean confidenciales. Conserva los registros de origen, base y reporte.
2. **Instala la wallet oficial mantenida** y verifica su descarga según las instrucciones del proyecto. Haz backup de la seed offline y prueba la restauración con una cantidad pequeña.
3. **Prefiere un nodo local** para maximizar la privacidad de las consultas de la wallet. Si no es práctico, elige un nodo remoto de confianza accesible mediante una configuración onion/I2P admitida oficialmente. Un nodo remoto puede registrar la IP, las solicitudes, los tiempos y los IDs de transacción; algunos diseños ligeros revelan una view key.
4. **Utiliza una subaddress nueva por pagador, campaña o invoice.** Un pagador puede correlacionar el uso repetido de la misma subaddress.<sup>[[9]](#references)</sup>
5. **Etiqueta localmente los contextos entrantes.** Evita fusionar operativamente receipts separados cuando un pagador informado pudiera reconocer el comportamiento posterior.
6. **Protege los metadatos de red.** Sigue la configuración oficial de la red de anonimato; reconoce los leaks documentados derivados de timestamps, sincronización intermitente, patrón de ancho de banda y reutilización de streams.<sup>[[10]](#references)</sup>
7. **Mantén privados los datos de compliance/auditoría.** Divulga una view key o una prueba de transacción solo de forma deliberada, al auditor/parte previsto, y comprende exactamente qué revela.

Los estudios históricos de trazabilidad incluyen bugs y épocas de selección de decoys que han cambiado desde entonces; no apliques porcentajes antiguos de éxito a las transacciones actuales. Del mismo modo, FCMP++ sigue siendo trabajo de roadmap a fecha de corte de investigación de este capítulo, septiembre de 2026, y no una protección desplegada.<sup>[[11]](#references)</sup>

## Ethereum y stablecoins

El material de privacidad de Ethereum señala que las acciones on-chain son visibles y que la infraestructura de wallet/RPC añade exposición de IP y metadatos.<sup>[[12]](#references)</sup> Las transferencias de tokens, approvals, interacciones con smart contracts, name services y la financiación de gas pueden conectar identidades.

Las stablecoins centralizadas añaden control del emisor. Los términos actuales de USDC y Tether se reservan facultades para bloquear/congelar direcciones o activos y cumplir obligaciones legales/procesales.<sup>[[13]](#references)</sup> Pueden ser instrumentos de pago útiles, pero son malas opciones cuando el requisito es resistencia a la censura o anonimato on-chain.

## Límites de compliance

- Las recomendaciones del FATF se implementan mediante la legislación nacional y cambian con el tiempo; su actualización de 2026 enfatiza la licencia/registro de VASPs y la implementación de la Travel Rule.<sup>[[14]](#references)</sup>
- En Estados Unidos, FinCEN distingue a una persona que utiliza convertible virtual currency para sus propios bienes/servicios de un negocio que la acepta y transmite o intercambia; los hechos y las normas posteriores son relevantes.<sup>[[15]](#references)</sup>
- El Reglamento de la UE sobre Transferencias de Fondos exige información del originador/beneficiario cuando interviene un proveedor de servicios de criptoactivos y añade reglas de verificación para ciertas transferencias hacia/desde direcciones self-hosted.<sup>[[16]](#references)</sup>
- Las sanciones y obligaciones fiscales siguen aplicándose. Realiza screening cuando sea necesario, rechaza a las partes prohibidas y conserva registros; las listas y el estado legal pueden cambiar rápidamente.<sup>[[17]](#references)</sup>

Antes de manejar cantidades importantes, realizar actividad transfronteriza, coordinar actividades de mejora de privacidad o realizar exchange/transmisión con carácter empresarial, obtén asesoramiento profesional actualizado para las jurisdicciones relevantes.

Para Bitcoin Silent Payments, Zcash fully shielded, GNU Taler, federated Chaumian e-cash y BOLT 12, continúa en [Privacy-Preserving Payment Protocols](privacy-preserving-payment-protocols.md).

## References

- [1] [Bitcoin.org — Protege tu privacidad](https://bitcoin.org/en/protect-your-privacy) and [Bitcoin Developer Guide — Transactions](https://developer.bitcoin.org/devguide/transactions.html)
- [2] [Bitcoin Core — Funciones de privacidad](https://bitcoin.org/en/bitcoin-core/features/privacy) and [Bitcoin.org — Secure your wallet](https://bitcoin.org/en/secure-your-wallet)
- [3] [BIP 78 — Una propuesta sencilla de PayJoin](https://bips.dev/78/) and [Draft BIP 77 — Async Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0077.md)
- [4] [Stütz et al. — Adopción y privacidad real de las implementaciones descentralizadas de CoinJoin en Bitcoin (AFT 2022)](https://arxiv.org/abs/2109.10229) and [Wasabi Wallet — Coin consolidation warning](https://docs.wasabiwallet.io/FAQ/FAQ-UseWasabi.html)
- [5] [US DOJ — Los fundadores de Samourai Wallet se declaran culpables (2025)](https://www.justice.gov/usao-sdny/pr/founders-samourai-wallet-cryptocurrency-mixing-service-plead-guilty) and [Wasabi — coordinator status](https://docs.wasabiwallet.io/FAQ/FAQ-Introduction.html)
- [6] [Lightning BOLT 4 — Protocolo de Onion Routing](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Kappos et al. — Un análisis empírico de la privacidad en Lightning Network](https://arxiv.org/abs/2003.12470)
- [8] Monero Project — [Stealth addresses](https://www.getmonero.org/resources/moneropedia/stealthaddress.html), [RingCT](https://www.getmonero.org/resources/moneropedia/ringCT.html), [Ring signatures](https://www.getmonero.org/resources/moneropedia/ringsignatures.html) y [Especificaciones técnicas](https://docs.getmonero.org/technical-specs/)
- [9] [Monero Docs — Subaddress](https://docs.getmonero.org/public-address/subaddress/)
- [10] [Monero Docs — Redes](https://docs.getmonero.org/infrastructure/networks/), [Running a node with Tor/I2P](https://docs.getmonero.org/running-node/monerod-tori2p/), and [Monero Project — Anonymity networks](https://github.com/monero-project/monero/blob/master/docs/ANONYMITY_NETWORKS.md)
- [11] [Hammad y Victor — Exploración de la evolución de la privacidad de Monero (2024)](https://arxiv.org/abs/2408.05332) and [Monero Roadmap](https://beta.getmonero.org/resources/roadmap/)
- [12] [Ethereum.org — Privacidad en Ethereum](https://ethereum.org/privacy/ethereum)
- [13] [Circle — Términos de USDC](https://www.circle.com/legal/usdc-terms) and [Tether — Legal](https://tether.to/en/legal/)
- [14] [FATF — Actualización específica de 2026 sobre activos virtuales y VASPs](https://www.fatf-gafi.org/en/publications/Fatfrecommendations/targeted-updated-virtualassets-vasps-2026.html)
- [15] [FinCEN — Aplicación de las regulaciones de FinCEN a las personas que administran, intercambian o utilizan monedas virtuales](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [16] [Reglamento (UE) 2023/1113](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [17] [US OFAC — Guía de compliance de sanciones para la industria de las monedas virtuales](https://ofac.treasury.gov/system/files/126/virtual_currency_guidance_brochure.pdf) and [US IRS — Digital asset transaction FAQs](https://www.irs.gov/individuals/international-taxpayers/frequently-asked-questions-on-digital-asset-transactions)
