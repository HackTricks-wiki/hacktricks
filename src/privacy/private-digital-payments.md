# Pagos digitales privados

La privacidad de los pagos es la divulgación controlada de los datos de las transacciones. No es una forma de legitimar fondos ilegales, evadir impuestos o sanciones, eludir KYC, usar identidades falsas ni ocultar una actividad no autorizada. Un pago puede ser privado frente a un comerciante y, al mismo tiempo, totalmente visible para un emisor, una red, un empleador, una autoridad fiscal o un investigador.

El [Catálogo de técnicas de pago anónimo](anonymous-payment-techniques.md) es el inventario normalizado con `Pros`, `Cons`, `Procedure` legal paso a paso y `Detection` para cada familia. Esta página amplía los métodos de pago convencionales.

{% hint style="danger" %}
Nunca uses cuentas robadas, identidades sintéticas, mulas de dinero, residencias ficticias o declaraciones falsas sobre el origen de los fondos, fraccionamiento de transacciones («structuring») ni intermediarios opacos de «tarjetas sin KYC». Comprueba la legislación vigente y las condiciones del proveedor en cada jurisdicción relevante.
{% endhint %}

## Define la propiedad de privacidad

Identifica al observador antes de elegir un canal:

| Observador | Datos habituales | Control útil | Lo que permanece |
|---|---|---|---|
| Comerciante | Nombre, correo electrónico, dirección, token de tarjeta, IP/dispositivo, cesta | Checkout como invitado, mínimo de datos opcionales, tarjeta virtual específica para el comerciante | Datos de entrega, cuenta y telemetría antifraude |
| Emisor/procesador de pagos | Identidad legal, fuente de fondos, comerciante, importe, hora, dispositivo | Elegir un proveedor regulado con buenas condiciones de privacidad/seguridad | El proveedor sigue procesando y puede conservar o divulgar registros |
| Empleador/propietario de la actividad | Gasto, operador y propósito | Presupuesto separado para la actividad y registro con acceso controlado | La gobernanza legítima requiere atribución interna |
| Observador de una blockchain pública | Direcciones, flujos, importes y hora, según la cadena | Protocolo adecuado y disciplina con la wallet | La adquisición, los endpoints y los gastos posteriores pueden volver a vincular la actividad |
| Operador de red/RPC/nodo | IP, consultas de wallet, difusión de transacciones | Nodo local o red de privacidad adecuada | El momento y el comportamiento del endpoint aún pueden correlacionarse |
| Observador físico | Rostro, ubicación, vehículo, CCTV, recibo | Privacidad situacional ordinaria | El efectivo no hace físicamente invisible a una persona |

La CFPB describe las apps de pago como capaces de recopilar datos de identidad, dispositivo, ubicación, contactos, transacciones y comportamiento; las normas estatales de privacidad no necesariamente impiden la monetización ni todos los usos secundarios.<sup>[[1]](#references)</sup> Lee el aviso real del proveedor en lugar de inferir la privacidad a partir del nombre de un producto.

## Compara los métodos de pago

| Método | Beneficio de privacidad | Principales observadores/vínculos | Uso adecuado |
|---|---|---|---|
| Efectivo | No hay registro de la red de pagos | Receptor, cámaras, testigos, normas de declaración de efectivo | Compras locales legales donde se acepte |
| Tarjeta prepago/de regalo open-loop | Separa el número de tarjeta de una tarjeta principal | Vendedor, proveedor de activación/registro, fuente de fondos, comerciante | Presupuestación o compartimentación limitada por comerciante |
| Número de tarjeta virtual/de un solo uso | Oculta el PAN reutilizable al comerciante; revocación sencilla | El emisor sigue conociendo la identidad y la transacción | Compartimentación de comerciantes online |
| Token de mobile-wallet | El dispositivo/comerciante recibe un token en lugar del PAN subyacente | Proveedor de la wallet, emisor, red de pagos y comerciante | Seguridad de credenciales, no anonimato |
| Transferencia bancaria/app | Registro de auditoría cómodo | Banco/app, contraparte e identidad vinculada | Pagos organizativos sujetos a rendición de cuentas |
| Criptomoneda | Varía según el protocolo; la autocustodia puede reducir la exposición al custodio | Registro público o protocolo de privacidad, exchange, endpoint, contraparte | Transferencias legales después de un análisis específico del protocolo |

## Efectivo

El efectivo sigue considerándose importante para la privacidad y la inclusión, y evita un registro de la red de pagos.<sup>[[2]](#references)</sup> No permite eludir CCTV, testigos, la ubicación del dispositivo, los recibos, el rastreo mediante números de serie en casos especiales ni las obligaciones legales de declaración.

### Flujo de trabajo legal

1. Comprueba la aceptación y los límites locales de efectivo antes de la transacción. Los límites varían según el país y el tipo de parte, y cambian con el tiempo.
2. Realiza la compra ordinaria en una única transacción honesta. **Nunca la fracciones** para evitar un umbral o una declaración.
3. Rechaza el seguimiento opcional de fidelización o la recopilación con fines de marketing. Proporciona verazmente los datos necesarios para garantía, seguridad, entrega, impuestos o requisitos legales.
4. Conserva las pruebas de compra necesarias y los registros contables obligatorios en almacenamiento cifrado con una fecha de conservación.
5. En una organización, solicita el reembolso mediante el proceso aprobado y registra el operador, la autorización, el propósito, el importe, la fecha y el recibo.

En Estados Unidos, determinadas actividades comerciales presentan el Formulario 8300 por cobros en efectivo superiores a 10.000 USD, incluidas las transacciones relacionadas; separar intencionadamente las transacciones puede constituir por sí mismo un fraccionamiento ilegal («structuring»).<sup>[[3]](#references)</sup> Otras jurisdicciones son diferentes; por ejemplo, España publica su propia restricción legal sobre los pagos en efectivo.<sup>[[4]](#references)</sup>

## Tarjetas prepago y de regalo

«Prepago» no significa anónimo. Una tienda, un emisor, un gestor del programa, un banco financiador y un comerciante pueden correlacionar la compra, la activación, el dispositivo, la IP, la ubicación y los gastos. Las recargas, el acceso a cajeros automáticos, el uso internacional, los límites superiores o la protección frente a pérdida suelen requerir registro.

La guía estadounidense para consumidores explica que los emisores pueden solicitar datos de identidad para la verificación legal y rechazar una tarjeta registrada cuando la verificación falla.<sup>[[5]](#references)</sup> Las normas de FinCEN definen qué programas y participantes de prepago tienen obligaciones AML.<sup>[[6]](#references)</sup> En la UE, las excepciones limitadas para dinero electrónico anónimo se redujeron mediante la Directiva (UE) 2018/843; el Reglamento (UE) 2024/1624 vuelve a modificar el marco, pero generalmente se aplica a partir del **10 de julio de 2027**, por lo que no debe describirse como ya operativo en 2026.<sup>[[7]](#references)</sup>

Usa valor prepago únicamente cuando se haya obtenido legalmente de un emisor identificable, sus condiciones permitan el uso previsto y el beneficio sea la presupuestación o la separación de una credencial de pago principal. Evita los mercados de reventa y los intermediarios que anuncien tarjetas «sin nombre» no verificables: el valor puede haber sido robado, canjeado ya, estar restringido geográficamente o sujeto a incautación.

## Tarjetas virtuales y tokens de wallet

Un número de tarjeta virtual (VCN) normalmente se emite detrás de una cuenta real y verificada. Los números específicos para un comerciante o de un solo uso reducen el riesgo de filtraciones y la correlación del PAN entre comerciantes; **no** ocultan la transacción al emisor. La tokenización de red sustituye de forma similar una credencial de tarjeta por un token restringido.<sup>[[8]](#references)</sup>

### Flujo de trabajo compartimentado por comerciante

1. Abre una cuenta con un emisor regulado usando datos exactos de identidad, residencia y financiación.
2. Protégela con una contraseña única, MFA resistente al phishing cuando esté disponible, alertas de inicio de sesión y códigos de recuperación almacenados offline.
3. Genera un VCN bloqueado para el comerciante o de un solo uso. Establece un límite razonable de importe/tiempo si es compatible.
4. Usa el checkout como invitado y omite únicamente los campos **opcionales** de perfil, fidelización y marketing. Proporciona datos exactos de facturación, entrega e impuestos cuando sean necesarios.
5. Evita iniciar sesión en proveedores de identidad no relacionados; usa un navegador compartimentado para la actividad/cuenta y la ruta de red aprobada.
6. Guarda el recibo y la correspondencia entre el VCN y el propósito en un registro interno cifrado.
7. Congela o revoca el número después del plazo de reembolso/chargeback; supervisa la cuenta principal para detectar autorizaciones inesperadas.

Capital One y Google documentan que los números virtuales siguen vinculados a la cuenta subyacente, mientras que EMVCo/Visa describen la tokenización como una sustitución de credenciales y una restricción de dominio, no como anonimato del pagador.<sup>[[8]](#references)</sup>

## Entrega, cuentas y reembolsos

El pago es solo un extremo del grafo de vinculación:

- Una tarjeta única queda anulada al reutilizar un correo electrónico personal, teléfono, perfil del navegador, dirección IP o cuenta de fidelización.
- La entrega física normalmente necesita un destinatario y una ubicación legales. No uses la dirección de una persona no involucrada ni suplantes a un residente. Los servicios aprobados de recepción empresarial son más seguros que los datos inventados.
- Los bienes digitales pueden registrar la identidad de la cuenta, la IP, la huella del dispositivo, la activación de la licencia y las descargas.
- Los reembolsos suelen devolverse por el canal original. Las solicitudes para recibir fondos y reenviarlos/reembolsarlos por otro medio son una señal de fraude y de mula de dinero.
- Los descriptores del comerciante, el texto de las facturas y las notificaciones de envío pueden exponer una compra sensible a los delegados de la cuenta; configura deliberadamente el acceso y las alertas.

## Compras autorizadas de red team

Una actividad debe ser discreta externamente y sujeta a rendición de cuentas internamente:

1. Obtén el alcance por escrito, el propósito, el límite de gasto, el aprobador, los comerciantes/activos permitidos y la regla de reembolso.
2. Usa una cuenta de pago controlada por la organización y un VCN o subcuenta separados por actividad o comerciante.
3. Mantén datos exactos de facturación y registro con los proveedores. La privacidad del registro público puede minimizar la exposición, pero no autoriza a mentir.
4. Mantén un registro cifrado del operador, la aprobación, el propósito, la fecha, el importe, la contraparte, el identificador del activo y el recibo.
5. Examina a las contrapartes según sea necesario y cumple las obligaciones del proveedor, de sanciones, fiscales y de declaración.
6. Concede a finanzas únicamente el acceso que necesite; concede a los operadores únicamente la capacidad de gasto limitada que necesiten.
7. Cierra o congela las credenciales de pago durante el desmontaje, concilia los cargos/reembolsos pendientes y conserva los registros conforme a la política.

Para decisiones específicas sobre crypto, continúa en [Privacidad de las criptomonedas](cryptocurrency-privacy.md). Para la infraestructura que respaldan esas compras, consulta [Infraestructura autorizada de red team](authorized-red-team-infrastructure.md).

## Lista de comprobación de verificación

- [ ] La propiedad de privacidad deseada y los observadores están documentados.
- [ ] Las normas del proveedor, del comerciante y de la jurisdicción se comprobaron recientemente.
- [ ] Las declaraciones de identidad y de origen de fondos son veraces.
- [ ] Los datos opcionales del comerciante se minimizan sin impedir la verificación requerida.
- [ ] Se comprenden las vinculaciones de financiación, dispositivo, red, cuenta, entrega y reembolso.
- [ ] No intervienen la evasión de umbrales, una contraparte prohibida, una mula, una credencial robada ni la identidad de un tercero.
- [ ] Los recibos, aprobaciones, registros fiscales y datos de recuperación necesarios están cifrados y sujetos a control de acceso.

## References

- [1] [US CFPB — Solicitud de información sobre la recopilación, el uso y la monetización de los datos de pagos de los consumidores y otros datos financieros personales](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf) and [State Consumer Privacy Laws and the Monetization of Consumer Financial Data](https://www.consumerfinance.gov/data-research/research-reports/state-consumer-privacy-laws-and-the-monetization-of-consumer-financial-data/)
- [2] [Banco Central Europeo — Estudio sobre las actitudes de pago de los consumidores de la zona del euro (SPACE) 2024](https://www.ecb.europa.eu/stats/ecb_surveys/space/html/ecb.space2024~19d46f0f17.en.html)
- [3] [US IRS — Instrucciones para el Formulario 8300](https://www.irs.gov/instructions/i8300) and [FinCEN — Currency Transaction Reporting Requirement](https://www.fincen.gov/fincen-educational-pamphlet-currency-transaction-reporting-requirement)
- [4] [Agencia Tributaria española — Declaración de pagos en efectivo](https://sede.agenciatributaria.gob.es/Sede/colaborar-agencia-tributaria/denuncias/denuncia-pagos-efectivo.html)
- [5] US CFPB — [¿Por qué me solicitan información personal para activar o registrar una tarjeta prepago?](https://www.consumerfinance.gov/ask-cfpb/why-am-i-being-asked-for-personal-information-to-activate-or-register-a-prepaid-card-en-443/) y [¿Pueden rechazarme una tarjeta prepago?](https://www.consumerfinance.gov/ask-cfpb/can-i-be-declined-for-a-prepaid-card-en-437/)
- [6] [FinCEN — Norma definitiva sobre el acceso prepago](https://www.fincen.gov/resources/statutes-regulations/guidance/final-rule-definitions-and-other-regulations-relating)
- [7] [Directiva (UE) 2018/843](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32018L0843) and [Regulation (EU) 2024/1624](https://eur-lex.europa.eu/eli/reg/2024/1624)
- [8] [Capital One — Uso de tarjetas de crédito virtuales](https://www.capitalone.com/help-center/credit-cards/using-virtual-credit-cards/), [Google Pay — Virtual cards](https://support.google.com/googlepay/answer/7643925?hl=en), [EMVCo — Payment Tokenisation](https://www.emvco.com/emv-technologies/payment-tokenisation/), and [Visa — Token Service Provisioning](https://developer.visa.com/capabilities/token-service-provisioning)
