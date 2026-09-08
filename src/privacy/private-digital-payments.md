# Pagos digitales privados

{{#include ../banners/hacktricks-training.md}}

La privacidad de los pagos es la divulgación controlada de los datos de una transacción. No es una forma de legitimar fondos ilegales, evadir impuestos o sanciones, eludir el KYC, utilizar identidades falsas ni ocultar una actividad no autorizada. Un pago puede ser privado frente a un comerciante y, al mismo tiempo, permanecer completamente visible para un emisor, una red, un empleador, una autoridad fiscal o un investigador.

El [Catálogo de técnicas de pago anónimo](anonymous-payment-techniques.md) es el inventario normalizado con `Pros`, `Cons`, `Procedure` paso a paso y legal, y `Detection` para cada familia. Esta página amplía los métodos de pago convencionales.

{% hint style="danger" %}
Nunca utilices cuentas robadas, identidades sintéticas, mulas de dinero, residencias ficticias o declaraciones falsas sobre el origen de los fondos, fraccionamiento de transacciones (“structuring”) ni brokers opacos de “tarjetas sin KYC”. Comprueba la legislación vigente y las condiciones del proveedor en cada jurisdicción relevante.
{% endhint %}

## Define la propiedad de privacidad

Identifica al observador antes de elegir un rail:

| Observador | Datos habituales | Control útil | Lo que permanece |
|---|---|---|---|
| Comerciante | Nombre, correo electrónico, dirección, token de tarjeta, IP/dispositivo, cesta | Checkout como invitado, mínimo de datos opcionales, tarjeta virtual específica para el comerciante | Entrega, cuenta y telemetría antifraude |
| Emisor/procesador de pagos | Identidad legal, fuente de fondos, comerciante, importe, hora, dispositivo | Elegir un proveedor regulado con buenas condiciones de privacidad/seguridad | El proveedor sigue procesando los registros y puede conservarlos o divulgarlos |
| Empleador/propietario de la actividad | Gasto, operador y finalidad | Presupuesto separado para la actividad y libro mayor con acceso controlado | La gobernanza legítima requiere atribución interna |
| Observador de una blockchain pública | Direcciones, flujos, importes y hora, según la chain | Protocolo adecuado y disciplina con la wallet | La adquisición, los endpoints y los gastos posteriores pueden volver a vincular la actividad |
| Operador de red/RPC/node | IP, consultas de la wallet, difusión de transacciones | Node local o red de privacidad adecuada | El comportamiento temporal y de los endpoints aún puede correlacionarse |
| Observador físico | Rostro, ubicación, vehículo, CCTV, recibo | Privacidad situacional ordinaria | El efectivo no hace físicamente invisible a una persona |

La CFPB describe las aplicaciones de pago como capaces de recopilar datos de identidad, dispositivo, ubicación, contactos, transacciones y comportamiento; las normas estatales de privacidad no necesariamente impiden la monetización ni todos los usos secundarios.<sup>[[1]](#references)</sup> Lee el aviso real del proveedor en lugar de inferir la privacidad a partir del nombre de un producto.

## Comparar métodos de pago

| Método | Beneficio de privacidad | Principales observadores/enlaces | Uso adecuado |
|---|---|---|---|
| Efectivo | No existe un libro mayor de la red de pagos | Receptor, cámaras, testigos, normas de declaración de efectivo | Compras locales legales donde se acepte |
| Tarjeta prepago/de regalo open-loop | Separa el número de tarjeta de la tarjeta principal | Vendedor, proveedor de activación/registro, fuente de fondos, comerciante | Presupuestación o compartimentación limitada por comerciante |
| Número de tarjeta virtual/de un solo uso | Oculta el PAN reutilizable al comerciante; revocación sencilla | El emisor sigue conociendo la identidad y la transacción | Compartimentación de comerciantes online |
| Token de mobile wallet | El dispositivo/comerciante recibe un token en lugar del PAN subyacente | Proveedor de la wallet, emisor, red de pagos y comerciante | Seguridad de credenciales, no anonimato |
| Transferencia bancaria/app | Registro de auditoría práctico | Banco/app, contraparte e identidad vinculada | Pagos organizativos sujetos a rendición de cuentas |
| Cryptocurrency | Varía según el protocolo; la self-custody puede reducir la exposición al custodio | Libro mayor público o protocolo de privacidad, exchange, endpoint, contraparte | Transferencias legales tras un análisis específico del protocolo |

## Efectivo

El efectivo aún se considera importante para la privacidad y la inclusión, y evita un registro en la red de pagos.<sup>[[2]](#references)</sup> No evita el CCTV, los testigos, la ubicación del dispositivo, los recibos, el rastreo mediante números de serie en casos especiales ni las obligaciones legales de declaración.

### Flujo de trabajo legal

1. Comprueba la aceptación y los límites locales de efectivo antes de la transacción. Los límites varían según el país y el tipo de parte, y cambian con el tiempo.
2. Realiza la compra ordinaria en una única transacción honesta. **Nunca la fracciones** para evitar un umbral o una declaración.
3. Rechaza el seguimiento opcional de fidelización o la recopilación con fines de marketing. Proporciona de forma veraz los datos exigidos para la garantía, la seguridad, la entrega, los impuestos o la legislación.
4. Conserva la prueba de compra necesaria y los registros contables obligatorios en almacenamiento cifrado con una fecha de retención.
5. En una organización, solicita el reembolso mediante el proceso aprobado y registra el operador, la autorización, la finalidad, el importe, la fecha y el recibo.

En Estados Unidos, ciertas actividades comerciales presentan el Formulario 8300 por recibos en efectivo superiores a 10.000 USD, incluidas las transacciones relacionadas; separar intencionadamente las transacciones puede constituir por sí mismo una estructuración ilegal.<sup>[[3]](#references)</sup> Otras jurisdicciones son diferentes; por ejemplo, España publica su propia restricción legal de los pagos en efectivo.<sup>[[4]](#references)</sup>

## Tarjetas prepago y de regalo

“Prepago” no significa anónimo. Una tienda, un emisor, un gestor del programa, un banco financiador y un comerciante pueden correlacionar la compra, la activación, el dispositivo, la IP, la ubicación y los gastos. Las recargas, el acceso a cajeros automáticos, el uso internacional, los límites superiores o la protección frente a pérdidas suelen requerir registro.

La orientación para consumidores de Estados Unidos explica que los emisores pueden solicitar datos de identidad para la verificación legal y pueden rechazar una tarjeta registrada cuando la verificación falla.<sup>[[5]](#references)</sup> Las normas de FinCEN definen qué programas y participantes de prepago tienen obligaciones AML.<sup>[[6]](#references)</sup> En la UE, las excepciones limitadas para el dinero electrónico anónimo se redujeron mediante la Directiva (UE) 2018/843; el Reglamento (UE) 2024/1624 vuelve a modificar el marco, pero generalmente se aplica a partir del **10 de julio de 2027**, por lo que no debe describirse como ya operativo en 2026.<sup>[[7]](#references)</sup>

Utiliza valor prepago únicamente cuando se haya obtenido legalmente de un emisor identificable, sus condiciones permitan el uso previsto y el beneficio sea la presupuestación o la separación respecto de una credencial de pago principal. Evita los mercados de reventa y los brokers que anuncian tarjetas “sin nombre” no verificables: el valor puede haber sido robado, canjeado anteriormente, estar restringido geográficamente o sujeto a incautación.

## Tarjetas virtuales y tokens de wallets

Un número de tarjeta virtual (VCN) normalmente se emite detrás de una cuenta real y verificada. Los números específicos para un comerciante o de un solo uso reducen el riesgo de filtración y la correlación del PAN entre comerciantes; **no** ocultan la transacción al emisor. La tokenización de red sustituye de forma similar una credencial de tarjeta por un token restringido.<sup>[[8]](#references)</sup>

### Flujo de trabajo compartimentado por comerciante

1. Abre una cuenta con un emisor regulado utilizando datos exactos de identidad, residencia y financiación.
2. Protégela con una contraseña única, MFA resistente al phishing cuando esté disponible, alertas de inicio de sesión y códigos de recuperación almacenados offline.
3. Genera un VCN bloqueado para el comerciante o de un solo uso. Establece un límite razonable de importe/tiempo si es compatible.
4. Utiliza el checkout como invitado y omite únicamente los campos **opcionales** de perfil, fidelización y marketing. Proporciona datos exactos de facturación, entrega e impuestos cuando sean necesarios.
5. Evita iniciar sesión en proveedores de identidad no relacionados; utiliza un compartimento de navegador para la actividad/cuenta y la ruta de red aprobada.
6. Guarda el recibo y la correspondencia entre el VCN y la finalidad en un libro mayor interno cifrado.
7. Congela o revoca el número después del plazo de reembolso/chargeback; supervisa la cuenta principal para detectar autorizaciones inesperadas.

Capital One y Google documentan que los números virtuales siguen vinculados a la cuenta subyacente, mientras que EMVCo/Visa describen la tokenización como sustitución de credenciales y restricción por dominio, no como anonimato del pagador.<sup>[[8]](#references)</sup>

## Entrega, cuentas y reembolsos

El pago es solo un extremo del grafo de vinculación:

- Una tarjeta única queda anulada al reutilizar un correo electrónico personal, teléfono, perfil de navegador, dirección IP o cuenta de fidelización.
- La entrega física normalmente necesita un destinatario y una ubicación legales. No utilices la dirección de una persona no involucrada ni suplantes a un residente. Los servicios aprobados de recepción empresarial son más seguros que los datos inventados.
- Los bienes digitales pueden registrar la identidad de la cuenta, la IP, la huella del dispositivo, la activación de la licencia y las descargas.
- Los reembolsos suelen devolverse al rail original. Las solicitudes para recibir fondos y reenviarlos/reembolsarlos en otro lugar son una señal de fraude y de mula de dinero.
- Los descriptores del comerciante, el texto de las facturas y las notificaciones de envío pueden exponer una compra sensible a los delegados de la cuenta; configura deliberadamente el acceso y las alertas.

## Compras autorizadas de red team

Una actividad debe ser discreta externamente y sujeta a rendición de cuentas internamente:

1. Obtén el alcance por escrito, la finalidad, el límite de gasto, el aprobador, los comerciantes/activos permitidos y la norma de reembolso.
2. Utiliza una cuenta de pago controlada por la organización y un VCN o subcuenta separados por actividad o comerciante.
3. Mantén datos exactos de facturación y registro con los proveedores. La privacidad del registro público puede reducir la exposición, pero no autoriza a mentir.
4. Mantén un libro mayor cifrado con el operador, la aprobación, la finalidad, la fecha, el importe, la contraparte, el identificador del activo y el recibo.
5. Examina las contrapartes cuando sea necesario y cumple las obligaciones del proveedor, de sanciones, fiscales y de declaración.
6. Concede a finanzas solo el acceso que necesite; concede a los operadores únicamente la capacidad de gasto limitada que necesiten.
7. Cierra o congela las credenciales de pago durante el teardown, concilia los cargos/reembolsos pendientes y conserva los registros conforme a la política.

Para opciones específicas de crypto, continúa en [Privacidad de Cryptocurrency](cryptocurrency-privacy.md). Para la infraestructura que respaldan esas compras, consulta [Infraestructura autorizada de red team](authorized-red-team-infrastructure.md).

## Lista de comprobación de verificación

- [ ] La propiedad de privacidad y los observadores deseados están documentados.
- [ ] Se han comprobado recientemente las normas del proveedor, del comerciante y de la jurisdicción.
- [ ] Las declaraciones de identidad y origen de fondos son veraces.
- [ ] Los datos opcionales del comerciante se han minimizado sin impedir la verificación obligatoria.
- [ ] Se comprenden las vinculaciones de financiación, dispositivo, red, cuenta, entrega y reembolso.
- [ ] No intervienen la elusión de umbrales, una contraparte prohibida, una mula, una credencial robada ni la identidad de un tercero.
- [ ] Los recibos, aprobaciones, registros fiscales y datos de recuperación obligatorios están cifrados y tienen el acceso controlado.

## References

- [1] [US CFPB — Solicitud de información relativa a la recopilación, uso y monetización de los datos financieros personales de los consumidores y de otros datos de pagos](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf) and [State Consumer Privacy Laws and the Monetization of Consumer Financial Data](https://www.consumerfinance.gov/data-research/research-reports/state-consumer-privacy-laws-and-the-monetization-of-consumer-financial-data/)
- [2] [Banco Central Europeo — Estudio sobre las actitudes de pago de los consumidores en la zona del euro (SPACE) 2024](https://www.ecb.europa.eu/stats/ecb_surveys/space/html/ecb.space2024~19d46f0f17.en.html)
- [3] [US IRS — Instrucciones para el Formulario 8300](https://www.irs.gov/instructions/i8300) and [FinCEN — Currency Transaction Reporting Requirement](https://www.fincen.gov/fincen-educational-pamphlet-currency-transaction-reporting-requirement)
- [4] [Agencia Tributaria española — Declaración de pagos en efectivo](https://sede.agenciatributaria.gob.es/Sede/colaborar-agencia-tributaria/denuncias/denuncia-pagos-efectivo.html)
- [5] US CFPB — [¿Por qué se me solicitan datos personales para activar o registrar una tarjeta prepago?](https://www.consumerfinance.gov/ask-cfpb/why-am-i-being-asked-for-personal-information-to-activate-or-register-a-prepaid-card-en-443/) y [¿Se me puede denegar una tarjeta prepago?](https://www.consumerfinance.gov/ask-cfpb/can-i-be-declined-for-a-prepaid-card-en-437/)
- [6] [FinCEN — Norma final sobre el acceso prepago](https://www.fincen.gov/resources/statutes-regulations/guidance/final-rule-definitions-and-other-regulations-relating)
- [7] [Directiva (UE) 2018/843](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32018L0843) and [Regulation (EU) 2024/1624](https://eur-lex.europa.eu/eli/reg/2024/1624)
- [8] [Capital One — Uso de tarjetas de crédito virtuales](https://www.capitalone.com/help-center/credit-cards/using-virtual-credit-cards/), [Google Pay — Virtual cards](https://support.google.com/googlepay/answer/7643925?hl=en), [EMVCo — Payment Tokenisation](https://www.emvco.com/emv-technologies/payment-tokenisation/), and [Visa — Token Service Provisioning](https://developer.visa.com/capabilities/token-service-provisioning)
{{#include ../banners/hacktricks-training.md}}
