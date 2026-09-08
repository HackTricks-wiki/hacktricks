# Privacidad de las criptomonedas

{{#include ../banners/hacktricks-training.md}}

La privacidad de las criptomonedas es una cuestión de protocolo y operaciones, no un sinónimo de secreto o inmunidad. Los registros públicos, exchanges, wallets servers, peers de red, comerciantes y transacciones posteriores exponen diferentes partes del grafo.

Comienza con el [Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) para consultar el formato de pros/contras/procedimiento/detección de cada técnica. Esta página amplía los mecanismos específicos de las criptomonedas y sus límites operativos.

{% hint style="danger" %}
Este capítulo está destinado a la self-custody legal y a la minimización de datos. No lo uses para blanquear ganancias, evadir sanciones/impuestos/obligaciones de reporte, realizar transacciones con partes prohibidas, engañar a un proveedor regulado ni operar un servicio de transmisión sin licencia. La tecnología de privacidad no cambia el origen legal ni la propiedad de los fondos.
{% endhint %}

## Modelo de amenazas por capa

| Capa | Observador | Divulgación habitual |
|---|---|---|
| Adquisición/off-ramp | Exchange, banco, broker, contraparte P2P | Identidad, cuenta de financiación, destino, dispositivo, IP, hora |
| Ledger | Cualquiera que ejecute analytics | Direcciones/outputs, cantidades y hora en chains transparentes; metadatos específicos del protocolo en otros casos |
| Backend de la wallet | Proveedor RPC, explorer, remote node | Consultas de direcciones, balances, IP, broadcast de transacciones |
| Red | ISP, peers, entrada de anonymity-network | IP, tiempos, volumen y uso del protocolo |
| Contraparte | Pagador/receptor | Invoice/dirección, entrega, conversación, cuenta y tiempos |
| Endpoint | Malware, cloud backup, incautación física | Seed, keys, etiquetas, historial, capturas de pantalla y portapapeles |

La self-custody puede eliminar a un custodio de la ruta de control, pero no borra el ledger, el registro de adquisición, los metadatos de red ni las evidencias del endpoint.

## Comparación de protocolos

| Método | Propiedad de privacidad útil | Limitaciones importantes |
|---|---|---|
| Bitcoin on-chain | Self-custody; las direcciones nuevas evitan la reutilización simple de direcciones | Grafo público y permanente de transacciones; heurísticas de cantidades/tiempos y gastos |
| Bitcoin PayJoin | El input del receptor puede romper la heurística de propiedad común de inputs | Ambas wallets necesitan soporte; la transacción sigue siendo pública; el soporte es desigual |
| Bitcoin CoinJoin | Crea ambigüedad entre participantes coordinados | Patrones reconocibles, vínculos pre/post, consolidación, riesgo de políticas/legales/proveedores |
| Lightning | Los pagos onion-routed no se publican globalmente como transferencias ordinarias | Los canales se abren/cierran on-chain; endpoints, peers, probes o un custodio pueden inferir datos |
| Monero | Mayor confidencialidad on-chain predeterminada para receptor, cantidad y conjunto de emisores | Los vínculos con exchange, node, tiempos, endpoint y contraparte permanecen |
| Ethereum/stablecoins | Amplia disponibilidad e interoperabilidad con smart contracts | Estado/acciones públicos; metadatos RPC; los emisores centralizados pueden bloquear/congelar/reportar |

## Bitcoin: baseline de preservación de la privacidad

Bitcoin es pseudónimo, no anónimo. Las transacciones confirmadas son públicas y duraderas; la reutilización de direcciones, la propiedad común de inputs, la detección del change y las direcciones identificadas públicamente pueden crear clusters.<sup>[[1]](#references)</sup>

### Flujo de trabajo

1. **Elige una wallet de self-custody mantenida.** Descárgala del proyecto oficial, verifica las firmas/hashes cuando se ofrezcan y aplica las actualizaciones de seguridad.
2. **Crea la wallet en un endpoint de confianza.** Registra el seed de recuperación offline; nunca lo guardes en email, chat, capturas de pantalla o notas normales en la cloud. Prueba la recuperación antes de manejar un valor significativo.
3. **Mantén hot solo el valor operativo.** Usa una custodia offline/hardware adecuada para el valor a largo plazo, con un plan de recuperación que no exponga el seed a una única ubicación frágil.
4. **Genera una dirección de recepción/invoice nueva para cada transacción.** No publiques una dirección estática cuando sea posible usar un invoice server o una entrega privada autenticada.
5. **Usa tu propio full node cuando sea viable.** Un explorer/electrum server de terceros puede conocer las direcciones consultadas y los metadatos de IP. Configura únicamente el comportamiento de Tor/proxy compatible con la wallet; Tor oculta un extremo de red, no el grafo de la blockchain.
6. **Etiqueta cada UTXO de forma privada** con origen, propietario, finalidad y estado de compliance. Activa coin control para que contextos de identidad no relacionados no se gasten conjuntamente.
7. **Previsualiza la transacción:** inputs seleccionados, destino del change, cantidad, fee, contraparte y si el gasto mezcla compartimentos. Evita consolidaciones innecesarias.
8. **Conserva por separado y cifrados los registros legales.** Preserva la base de adquisición, invoices, autorizaciones y datos fiscales/de reporte sin publicar la relación.
9. **Considera el gasto posterior como parte de la misma decisión de privacidad.** Una recepción bien separada puede volver a vincularse cuando su output se gasta conjuntamente con fondos identificados.

La documentación de privacidad de Bitcoin Core explica que un full node evita revelar las consultas de la wallet a servidores de terceros, pero que el broadcast de transacciones y el historial público todavía requieren análisis.<sup>[[2]](#references)</sup>

## PayJoin

PayJoin es un pago colaborativo en el que el receptor añade un input. Esto derrota la suposición simplista de que todos los inputs pertenecen al emisor. BIP 78 describe el protocolo interactivo original; el draft BIP 77 define un diseño asíncrono v2 que utiliza un mailbox cifrado/OHTTP.<sup>[[3]](#references)</sup>

Uso seguro:

1. Confirma que ambas wallets mantenidas sean compatibles con la misma versión de PayJoin.
2. Obtén el invoice compatible con PayJoin a través de un canal autenticado; protégelo como cualquier solicitud de pago.
3. Comprueba la cantidad y el destino originales, y deja que la wallet valide la propuesta/PSBT, la contribución a la fee y las sustituciones prohibidas.
4. Confirma el resumen final de la wallet. No apruebes manualmente un output, cantidad o fee excesiva inesperados.
5. Si la negociación falla, entiende si la wallet vuelve de forma segura a un pago ordinario o requiere un invoice nuevo.
6. Conserva los recibos/registros privados necesarios para la propiedad, la contabilidad y las disputas.

PayJoin mejora una heurística de chain analysis; no oculta el pago a las partes, la plataforma de adquisición, los endpoints ni el ledger público.

## CoinJoin: beneficios y limitaciones

CoinJoin coordina a varios usuarios en una única transacción para hacer menos certero el mapeo entre inputs y outputs. La investigación sobre diseños históricos específicos de Wasabi y Samourai encontró transacciones altamente reconocibles y mostró que el comportamiento pre/post-mix puede reducir sustancialmente el anonimato.<sup>[[4]](#references)</sup> Este resultado no debe generalizarse a cada implementación o versión futura, pero demuestra por qué un número de “conjunto de anonimato” no es una garantía.

Antes de cualquier uso legal:

- comprueba la legislación local vigente, el estado de las sanciones, la política del exchange/custodio y las obligaciones fiscales/de reporte;
- usa software mantenido y no custodial obtenido del proyecto oficial;
- comprende el modelo del coordinator, las fees, los controles contra la denegación de servicio y si el servicio actual sigue operativo —zkSNACKs terminó su coordinator en 2024, aunque pueden existir otros coordinators de Wasabi—;
- conserva de forma privada los registros del origen de los fondos y de las transacciones;
- nunca aceptes fondos desconocidos en nombre de otra persona ni uses un “mixer” custodial que prometa retiradas imposibles de rastrear;
- mantén los outputs separados por origen/contexto y evita consolidaciones posteriores que destruyan la ambigüedad buscada.

Los resultados legales dependen de los hechos y de la jurisdicción. Las declaraciones de culpabilidad de Samourai de 2025 se referían a operar conscientemente un transmisor de dinero sin licencia que movía ganancias criminales; no establecen que toda transacción colaborativa o todo usuario que busque privacidad sea criminal.<sup>[[5]](#references)</sup>

## Lightning Network

El onion routing Sphinx de Lightning está diseñado para que un salto intermedio conozca a su predecesor y sucesor, en lugar de toda la ruta.<sup>[[6]](#references)</sup> No proporciona anonimato absoluto: la financiación/cierre de canales es público, los nodos anuncian la topología, las contrapartes conocen los endpoints, el routing/probing puede inferir balances o partes, y una wallet custodial ve la actividad de la cuenta de su usuario.

Para mejorar la privacidad:

1. Prefiere una wallet mantenida y no custodial si importa la privacidad frente al intermediario; planifica primero el backup/recuperación de los canales.
2. Usa un invoice u offer nuevo para cada pago. Verifica si la wallet exacta admite BOLT 12/route blinding en lugar de asumir que lo hace.
3. Evita publicar aliases de nodo, datos de contacto y endpoints de red estables innecesarios.
4. Conéctate a través de una red de privacidad compatible cuando sea apropiado, entendiendo que los patrones de disponibilidad/tiempo todavía pueden correlacionarse.
5. No deduzcas que un pago off-chain no deja registros: el emisor, el receptor, los peers, los watchtowers, los proveedores de liquidez y los servicios de wallet pueden conservar observaciones.

La investigación publicada ha demostrado la inferencia del emisor/receptor y del balance de los canales a partir de datos públicos y probing activo, aunque los ataques y las mitigaciones evolucionan.<sup>[[7]](#references)</sup>

## Monero

Monero utiliza stealth addresses de un solo uso para los outputs, RingCT para ocultar las cantidades y ring signatures para proporcionar ambigüedad probabilística sobre el emisor; sus especificaciones técnicas actuales documentan un ring size de 16 (15 decoys).<sup>[[8]](#references)</sup> Estos son valores predeterminados más sólidos para la confidencialidad on-chain que los ledgers transparentes, no una protección mágica frente a errores de endpoint u operativos.

### Flujo de trabajo legal

1. **Adquiere de forma legal.** Un exchange regulado puede conocer la compra y la retirada aunque los detalles on-chain posteriores sean confidenciales. Conserva los registros de origen, base y reporte.
2. **Instala la wallet oficial mantenida** y verifica su descarga según las instrucciones del proyecto. Haz backup del seed offline y prueba la restauración con una cantidad pequeña.
3. **Prefiere un node local** para obtener la máxima privacidad en las consultas de la wallet. Si no es viable, elige un remote node de confianza accesible mediante una configuración onion/I2P oficialmente compatible. Un remote node puede registrar IP, solicitudes, tiempos e IDs de transacción; algunos diseños ligeros revelan una view key.
4. **Usa un subaddress nuevo por pagador, campaña o invoice.** Un pagador puede correlacionar el uso repetido del mismo subaddress.<sup>[[9]](#references)</sup>
5. **Etiqueta localmente los contextos entrantes.** Evita fusionar operativamente recibos separados cuando un pagador informado pudiera reconocer el comportamiento posterior.
6. **Protege los metadatos de red.** Sigue la configuración oficial de anonymity-network; reconoce los leaks documentados derivados de timestamps, sincronización intermitente, forma del ancho de banda y reutilización de streams.<sup>[[10]](#references)</sup>
7. **Mantén privados los datos de compliance/auditoría.** Revela una view key o una prueba de transacción solo deliberadamente, a la parte/auditor previsto, y comprende exactamente qué revela.

Los estudios históricos de traceability incluyen bugs y épocas de selección de decoys que han cambiado desde entonces; no apliques porcentajes antiguos de éxito a las transacciones actuales. Del mismo modo, FCMP++ sigue siendo trabajo de roadmap a fecha del corte de investigación de septiembre de 2026 de este capítulo, no una protección desplegada.<sup>[[11]](#references)</sup>

## Ethereum y stablecoins

El material de privacidad de Ethereum señala que las acciones on-chain son visibles y que la infraestructura de wallet/RPC añade exposición de IP y metadatos.<sup>[[12]](#references)</sup> Las transferencias de tokens, approvals, interacciones con smart contracts, name services y la financiación de gas pueden conectar identidades.

Las stablecoins centralizadas añaden control del emisor. Los términos actuales de USDC y Tether reservan facultades para bloquear/congelar direcciones o activos y cumplir obligaciones legales/de procedimiento.<sup>[[13]](#references)</sup> Pueden ser instrumentos de pago útiles, pero son malas opciones cuando el requisito es resistencia a la censura o anonimato on-chain.

## Límites de compliance

- Las recomendaciones del FATF se implementan mediante la legislación nacional y cambian con el tiempo; su actualización de 2026 enfatiza la concesión de licencias/registro de VASPs y la implementación de la Travel Rule.<sup>[[14]](#references)</sup>
- En EE. UU., FinCEN distingue entre una persona que utiliza moneda virtual convertible para sus propios bienes/servicios y una empresa que la acepta y transmite o intercambia; los hechos y las normas posteriores son relevantes.<sup>[[15]](#references)</sup>
- El Reglamento de Transferencia de Fondos de la UE exige información del originador/beneficiario cuando interviene un proveedor de servicios de criptoactivos y añade reglas de verificación para determinadas transferencias hacia/desde direcciones self-hosted.<sup>[[16]](#references)</sup>
- Las sanciones y obligaciones fiscales siguen siendo aplicables. Realiza screening cuando sea necesario, rechaza a las partes prohibidas y conserva registros; las listas y el estado legal pueden cambiar rápidamente.<sup>[[17]](#references)</sup>

Antes de manejar un valor significativo, realizar actividad transfronteriza, coordinar actividades privacy-enhancing o llevar a cabo exchange/transmission con carácter empresarial, obtén asesoramiento profesional actualizado para las jurisdicciones relevantes.

Para Bitcoin Silent Payments, Zcash totalmente shielded, GNU Taler, federated Chaumian e-cash y BOLT 12, continúa en [Privacy-Preserving Payment Protocols](privacy-preserving-payment-protocols.md).

## References

- [1] [Bitcoin.org — Protege tu privacidad](https://bitcoin.org/en/protect-your-privacy) and [Bitcoin Developer Guide — Transactions](https://developer.bitcoin.org/devguide/transactions.html)
- [2] [Bitcoin Core — Funciones de privacidad](https://bitcoin.org/en/bitcoin-core/features/privacy) and [Bitcoin.org — Secure your wallet](https://bitcoin.org/en/secure-your-wallet)
- [3] [BIP 78 — Una propuesta simple de PayJoin](https://bips.dev/78/) and [Draft BIP 77 — Async Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0077.md)
- [4] [Stütz et al. — Adopción y privacidad real de implementaciones descentralizadas de CoinJoin en Bitcoin (AFT 2022)](https://arxiv.org/abs/2109.10229) and [Wasabi Wallet — Coin consolidation warning](https://docs.wasabiwallet.io/FAQ/FAQ-UseWasabi.html)
- [5] [US DOJ — Los fundadores de Samourai Wallet se declaran culpables (2025)](https://www.justice.gov/usao-sdny/pr/founders-samourai-wallet-cryptocurrency-mixing-service-plead-guilty) and [Wasabi — coordinator status](https://docs.wasabiwallet.io/FAQ/FAQ-Introduction.html)
- [6] [Lightning BOLT 4 — Protocolo de Onion Routing](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Kappos et al. — Un análisis empírico de la privacidad en Lightning Network](https://arxiv.org/abs/2003.12470)
- [8] Monero Project — [Stealth addresses](https://www.getmonero.org/resources/moneropedia/stealthaddress.html), [RingCT](https://www.getmonero.org/resources/moneropedia/ringCT.html), [Ring signatures](https://www.getmonero.org/resources/moneropedia/ringsignatures.html) y [Especificaciones técnicas](https://docs.getmonero.org/technical-specs/)
- [9] [Monero Docs — Subaddress](https://docs.getmonero.org/public-address/subaddress/)
- [10] [Monero Docs — Redes](https://docs.getmonero.org/infrastructure/networks/), [Running a node with Tor/I2P](https://docs.getmonero.org/running-node/monerod-tori2p/), and [Monero Project — Anonymity networks](https://github.com/monero-project/monero/blob/master/docs/ANONYMITY_NETWORKS.md)
- [11] [Hammad and Victor — Explorando la evolución de la privacidad de Monero (2024)](https://arxiv.org/abs/2408.05332) and [Monero Roadmap](https://beta.getmonero.org/resources/roadmap/)
- [12] [Ethereum.org — Privacidad en Ethereum](https://ethereum.org/privacy/ethereum)
- [13] [Circle — Términos de USDC](https://www.circle.com/legal/usdc-terms) and [Tether — Legal](https://tether.to/en/legal/)
- [14] [FATF — Actualización específica de 2026 sobre activos virtuales y VASPs](https://www.fatf-gafi.org/en/publications/Fatfrecommendations/targeted-updated-virtualassets-vasps-2026.html)
- [15] [FinCEN — Aplicación de las regulaciones de FinCEN a las personas que administran, intercambian o utilizan monedas virtuales](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [16] [Reglamento (UE) 2023/1113](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [17] [US OFAC — Guía de cumplimiento de sanciones para la industria de la moneda virtual](https://ofac.treasury.gov/system/files/126/virtual_currency_guidance_brochure.pdf) and [US IRS — Digital asset transaction FAQs](https://www.irs.gov/individuals/international-taxpayers/frequently-asked-questions-on-digital-asset-transactions)
{{#include ../banners/hacktricks-training.md}}
