# Blockchain y criptomonedas

{{#include ../../banners/hacktricks-training.md}}

## Conceptos básicos

- Los **Smart Contracts** se definen como programas que se ejecutan en una blockchain cuando se cumplen ciertas condiciones y automatizan la ejecución de acuerdos sin intermediarios.
- Las **aplicaciones descentralizadas (dApps)** se basan en smart contracts y cuentan con una interfaz de usuario intuitiva y un back-end transparente y auditable.
- **Tokens y monedas** se diferencian en que las monedas sirven como dinero digital, mientras que los tokens representan valor o propiedad en contextos específicos.
  - Los **Utility Tokens** permiten acceder a servicios y los **Security Tokens** representan la propiedad de activos.
- **DeFi** significa Finanzas Descentralizadas y ofrece servicios financieros sin autoridades centrales.
- **DEX** y **DAO** hacen referencia, respectivamente, a plataformas de intercambio descentralizadas y organizaciones autónomas descentralizadas.

## Mecanismos de consenso

Los mecanismos de consenso garantizan que las transacciones en la blockchain se validen de forma segura y consensuada:

- **Proof of Work (PoW)** se basa en la potencia de cálculo para verificar las transacciones.
- **Proof of Stake (PoS)** exige que los validadores posean una cierta cantidad de tokens, lo que reduce el consumo de energía en comparación con PoW.<sup>[[1]](#references)</sup>

## Aspectos esenciales de Bitcoin

### Transacciones

Las transacciones de Bitcoin implican transferir fondos entre direcciones. Se validan mediante firmas digitales, lo que garantiza que solo el propietario de la clave privada pueda iniciar transferencias.<sup>[[2]](#references)</sup>

#### Componentes clave:

- Las **transacciones Multisignature** requieren varias firmas para autorizar una transacción.<sup>[[3]](#references)</sup>
- Las transacciones constan de **entradas** (origen de los fondos), **salidas** (destino), **comisiones** (pagadas a los mineros) y **scripts** (reglas de la transacción).

### Lightning Network

Su objetivo es mejorar la escalabilidad de Bitcoin al permitir varias transacciones dentro de un canal y publicar en la blockchain únicamente el estado final.

## Problemas de privacidad de Bitcoin

Los ataques a la privacidad, como la **propiedad común de entradas** y la **detección de direcciones de cambio UTXO**, aprovechan los patrones de las transacciones. Estrategias como los **Mixers** y **CoinJoin** mejoran el anonimato al ocultar los vínculos entre las transacciones de los usuarios.

## Adquisición anónima de bitcoins

Entre los métodos se incluyen las transacciones en efectivo, la minería y el uso de mixers. **CoinJoin** combina varias transacciones para dificultar su rastreo, mientras que **PayJoin** disfraza las transacciones CoinJoin como transacciones normales para aumentar la privacidad.

# Resumen de los ataques a la privacidad de Bitcoin

En el mundo de Bitcoin, la privacidad de las transacciones y el anonimato de los usuarios suelen ser motivo de preocupación. A continuación, se presenta una descripción simplificada de varios métodos comunes mediante los cuales los atacantes pueden comprometer la privacidad de Bitcoin.<sup>[[6]](#references)</sup>

## **Suposición de propiedad común de entradas**

Por lo general, es poco habitual que se combinen en una sola transacción entradas de distintos usuarios, debido a la complejidad que implica. Por ello, a menudo se **supone que dos direcciones de entrada de una misma transacción pertenecen al mismo propietario**.

## **Detección de direcciones de cambio UTXO**

Un UTXO, o **salida de transacción no gastada**, debe gastarse por completo en una transacción. Si solo se envía una parte a otra dirección, el resto se envía a una nueva dirección de cambio. Los observadores pueden suponer que esta nueva dirección pertenece al remitente, lo que compromete su privacidad.

### Ejemplo

Para mitigar este riesgo, los servicios de mezcla o el uso de varias direcciones pueden ayudar a ocultar la propiedad.

## **Exposición en redes sociales y foros**

A veces, los usuarios comparten sus direcciones de Bitcoin en línea, lo que **facilita vincular la dirección con su propietario**.

## **Análisis del grafo de transacciones**

Las transacciones pueden representarse como grafos, lo que revela posibles conexiones entre usuarios según el flujo de fondos.

## **Heurística de entradas innecesarias (heurística de cambio óptimo)**

Esta heurística se basa en analizar transacciones con varias entradas y salidas para deducir qué salida corresponde al cambio que se devuelve al remitente.

### Ejemplo

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Si añadir más entradas hace que el resultado de cambio sea mayor que cualquiera de las entradas, puede confundir la heurística.

## **Reutilización forzada de direcciones**

Los atacantes pueden enviar pequeñas cantidades a direcciones utilizadas anteriormente, con la esperanza de que el destinatario las combine con otras entradas en transacciones futuras y, de ese modo, vincule las direcciones entre sí.

### Comportamiento correcto de la wallet

Las wallets deberían evitar usar monedas recibidas en direcciones vacías que ya se hayan usado, para prevenir este leak de privacidad.

## **Otras técnicas de análisis de blockchain**

- **Importes de pago exactos:** Es probable que las transacciones sin cambio se realicen entre dos direcciones propiedad del mismo usuario.
- **Números redondos:** Un número redondo en una transacción sugiere que se trata de un pago, y es probable que la salida con un número no redondo sea el cambio.
- **Fingerprinting de wallets:** Cada wallet tiene patrones únicos de creación de transacciones, lo que permite a los analistas identificar el software utilizado y, potencialmente, la dirección de cambio.
- **Correlaciones de importes y tiempos:** Revelar los horarios o importes de las transacciones puede hacer que estas sean rastreables.

## **Análisis del tráfico**

Al monitorizar el tráfico de red, los atacantes pueden vincular transacciones o bloques con direcciones IP, lo que pone en riesgo la privacidad de los usuarios. Esto es especialmente cierto si una entidad opera muchos nodos de Bitcoin, lo que aumenta su capacidad para monitorizar las transacciones.

## Más

Para obtener una lista completa de ataques y defensas de privacidad, visita [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Transacciones anónimas de Bitcoin

## Formas de obtener bitcoins de forma anónima

- **Transacciones en efectivo**: Obtener bitcoin mediante efectivo.
- **Alternativas al efectivo**: Comprar tarjetas de regalo e intercambiarlas por bitcoin en línea.
- **Minería**: El método más privado para obtener bitcoins es la minería, especialmente si se realiza en solitario, ya que los pools de minería pueden conocer la dirección IP del minero. [Información sobre pools de minería](https://en.bitcoin.it/wiki/Pooled_mining)
- **Robo**: En teoría, robar bitcoin podría ser otra forma de obtenerlo de manera anónima, aunque es ilegal y no se recomienda.

## Servicios de mixing

Al usar un servicio de mixing, un usuario puede **enviar bitcoins** y recibir **otros bitcoins a cambio**, lo que dificulta rastrear al propietario original. Sin embargo, esto requiere confiar en que el servicio no guarde registros y devuelva realmente los bitcoins. Los casinos de Bitcoin son una alternativa para hacer mixing.

## CoinJoin

**CoinJoin** combina varias transacciones de distintos usuarios en una sola, lo que complica el proceso de relacionar las entradas con las salidas. Aunque es eficaz, las transacciones con cantidades únicas de entradas y salidas aún pueden rastrearse.

Algunas transacciones que podrían haber utilizado CoinJoin son `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` y `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Para obtener más información, visita [CoinJoin](https://coinjoin.io/en). Para ver un mixer de smart contracts de Ethereum que separa los depósitos de los retiros posteriores, consulta [Tornado Cash](https://tornado.cash).

## PayJoin

Una variante de CoinJoin, **PayJoin** (o P2EP), disfraza como una transacción normal la transacción entre dos partes (por ejemplo, un cliente y un comerciante), sin las salidas iguales características de CoinJoin. Esto hace que sea extremadamente difícil de detectar y podría invalidar la heurística de propiedad común de entradas utilizada por las entidades que vigilan las transacciones.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Transacciones como la anterior podrían ser PayJoin, mejorando la privacidad y siendo indistinguibles de las transacciones estándar de bitcoin.

**El uso de PayJoin podría alterar significativamente los métodos tradicionales de vigilancia**, lo que lo convierte en un avance prometedor en la búsqueda de privacidad transaccional.

# Mejores prácticas para la privacidad en las criptomonedas

## **Técnicas de sincronización de billeteras**

Para mantener la privacidad y la seguridad, es fundamental sincronizar las billeteras con la blockchain. Se destacan dos métodos:

- **Nodo completo**: Al descargar toda la blockchain, un nodo completo garantiza la máxima privacidad. Todas las transacciones realizadas se almacenan localmente, por lo que los adversarios no pueden identificar qué transacciones o direcciones le interesan al usuario.
- **Filtrado de bloques del lado del cliente**: Este método consiste en crear filtros para cada bloque de la blockchain, lo que permite a las billeteras identificar las transacciones pertinentes sin revelar intereses específicos a quienes observan la red. Las billeteras ligeras descargan estos filtros y solo obtienen bloques completos cuando encuentran una coincidencia con las direcciones del usuario.

## **Uso de Tor para el anonimato**

Dado que Bitcoin opera en una red peer-to-peer, se recomienda usar Tor para ocultar la dirección IP y mejorar la privacidad al interactuar con la red.

## **Cómo evitar la reutilización de direcciones**

Para proteger la privacidad, es fundamental usar una dirección nueva en cada transacción. Reutilizar direcciones puede comprometer la privacidad al vincular transacciones con una misma entidad. Las billeteras modernas desaconsejan la reutilización de direcciones mediante su diseño.

## **Estrategias para la privacidad de las transacciones**

- **Varias transacciones**: Dividir un pago en varias transacciones puede ocultar el importe de la transacción y frustrar los ataques a la privacidad.
- **Evitar el cambio**: Optar por transacciones que no requieran salidas de cambio mejora la privacidad al dificultar los métodos de detección del cambio.
- **Varias salidas de cambio**: Si no es posible evitar el cambio, generar varias salidas de cambio puede mejorar la privacidad.

# **Monero: un referente del anonimato**

Monero está diseñado para priorizar la privacidad de las transacciones.

# **Ethereum: gas y transacciones**

## **Comprender el gas**

El gas mide el esfuerzo computacional necesario para ejecutar operaciones en Ethereum y se cotiza en **gwei**. Por ejemplo, una transacción que cuesta 2,310,000 gwei (o 0.00231 ETH) tiene un límite de gas y una tarifa base, además de una tarifa de prioridad para incentivar a los validadores a incluirla. Los usuarios pueden establecer una tarifa máxima para evitar pagar de más; el excedente se reembolsa.<sup>[[5]](#references)</sup>

## **Ejecución de transacciones**

Las transacciones en Ethereum involucran un remitente y un destinatario, que pueden ser direcciones de usuario o de contratos inteligentes. Requieren una tarifa y deben incluirse en un bloque. La información esencial de una transacción incluye el destinatario, la firma del remitente, el valor, los datos opcionales, el límite de gas y las tarifas. Cabe destacar que la dirección del remitente se deduce de la firma, por lo que no es necesario incluirla en los datos de la transacción.<sup>[[4]](#references)</sup>

Estas prácticas y mecanismos son fundamentales para quienes desean interactuar con criptomonedas priorizando la privacidad y la seguridad.

## Red Teaming de Web3 centrado en el valor

- Inventariar los componentes que contienen valor (firmantes, oráculos, bridges, automatización) para entender quién puede mover fondos y cómo.
- Asociar cada componente con las tácticas MITRE AADAPT pertinentes para identificar vías de escalada de privilegios.
- Ensayar cadenas de ataque con flash loans, oráculos, credenciales y ataques cross-chain para validar el impacto y documentar las precondiciones explotables.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Compromiso del flujo de firma de Web3

- La manipulación de la cadena de suministro de las interfaces de billeteras puede modificar los payloads EIP-712 justo antes de la firma y obtener firmas válidas para la toma de control de proxies basada en delegatecall (por ejemplo, sobrescribir slot-0 de masterCopy de Safe).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Abstracción de cuentas (ERC-4337)

- Entre los modos de fallo comunes de las smart accounts se incluyen eludir el control de acceso de `EntryPoint`, campos de gas sin firmar, validación con estado, repetición de ERC-1271 y agotamiento de tarifas mediante revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Seguridad de contratos inteligentes

- Pruebas de mutación para encontrar puntos ciegos en las suites de pruebas:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integridad de las pruebas ZK / los guests de zkVM

Cuando un prover usa una **zkVM** o un circuito de pruebas específico de una aplicación para demostrar una afirmación, el verifier solo aprende que el **programa guest se ejecutó tal como está escrito**. Si el guest contiene **deserialización insegura**, **comportamiento indefinido** o **restricciones semánticas ausentes**, un prover malicioso puede generar una prueba que se verifica aunque las **métricas públicas o el invariante afirmado sean falsos**.<sup>[[7]](#references)</sup>

### Deserialización insegura dentro de los guests de pruebas

- Tratar los bytes de witness/circuito privados como **entradas no confiables controladas por un atacante**, aunque estén ocultos por la prueba.
- Evitar deserializarlos con helpers sin comprobaciones, como `rkyv::access_unchecked`, salvo que los bytes ya se hayan validado por otros medios.
- Validar los discriminantes de enum, los punteros relativos, las longitudes y los índices cargados desde datos serializados no confiables antes de que influyan en el flujo de control o el acceso a memoria.

Patrón práctico de auditoría:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Si un campo como `op.kind` es un enum y un atacante puede inyectar un **discriminante fuera de rango**, todas las instrucciones `match` posteriores sobre ese valor se vuelven sospechosas.

### Bypass de contadores mediante jump table / UB

Si Rust compila un `match` grande como una **jump table**, un discriminante de enum no válido puede provocar un **flujo de control indefinido**. Un patrón peligroso es:<sup>[[7]](#references)[[9]](#references)</sup>

1. Un `match` actualiza **contadores/restricciones críticos para la seguridad**.
2. Un segundo `match` implementa la **semántica real de la instrucción**.
3. Un discriminante fuera de rango indexa más allá de la primera jump table y llega a código asociado con la segunda.

Resultado: la operación se ejecuta, pero se omite la ruta de contabilización. En un zkVM, esto puede permitir forjar pruebas que reporten métricas imposibles, como menos gates, menos operaciones costosas u otros recursos acotados falsificados.

Lista de verificación:

- Busca enums controlados por el atacante que se deserialicen desde la entrada witness/privada.
- Inspecciona las instrucciones `match` repetidas sobre el mismo campo opcode/kind.
- Trata la combinación de `unsafe` + deserialización sin comprobaciones + dispatch de opcode grande como de alto riesgo.
- Realiza ingeniería inversa del binario generado cuando sea necesario; la disposición de la jump table puede ser más importante que el código fuente.

### Restricciones semánticas ausentes en intérpretes reversibles/especializados

No valides únicamente la seguridad de memoria; valida también las **reglas semánticas** que la prueba debe hacer cumplir.

Para conjuntos de instrucciones reversibles o similares a los cuánticos, asegúrate de que los operandos que deben ser distintos estén realmente restringidos para que lo sean. Una operación similar a Toffoli/CCX implementada como:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

se vuelve inseguro si el invitado no rechaza:

```text
op.q_control1 == op.q_control2 == op.q_target
```

En ese caso, la transición se reduce a:

```text
q = q ^ (q & q) = 0
```

Esto crea una **primitiva de reinicio determinista**, rompe los supuestos de reversibilidad y permite realizar cálculos no previstos a menor costo. En sistemas de prueba que certifican el uso de recursos, esto puede permitir que los atacantes superen las comprobaciones funcionales y, a la vez, eludan el modelo de costos que el verificador cree estar aplicando.

### Qué probar en sistemas ZK

- Aplicar fuzzing a todos los parsers del guest con codificaciones malformadas de witness/entrada privada.
- Asegurarse de validar el rango de los enums antes del despacho de opcodes.
- Añadir comprobaciones semánticas para aliasing de operandos y otras formas de instrucciones inválidas.
- Comparar los contadores reportados/públicos con una implementación de referencia independiente.
- Recordar que una prueba válida aún puede demostrar el **enunciado incorrecto** si el programa del guest tiene errores.

## Autorización dependiente del estado

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Explotación de DeFi/AMM

Si investigas la explotación práctica de DEX y AMM (hooks de Uniswap v4, abuso de redondeo/precisión, swaps amplificados con préstamos flash que cruzan umbrales), consulta:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Para pools ponderados de múltiples activos que almacenan en caché saldos virtuales y pueden ser envenenados cuando `supply == 0`, consulta:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Prueba de participación - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Clave pública y clave privada explicadas - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [¿Qué son las transacciones multifirma? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transacciones | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas y comisiones | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privacidad - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Vencimos la prueba de conocimiento cero de Google sobre criptoanálisis cuántico](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Protección de las criptomonedas de curva elíptica frente a vulnerabilidades cuánticas: estimaciones de recursos y mitigaciones (versión corregida)](https://arxiv.org/abs/2603.28846v2)
- [9] [Repositorio de prueba de concepto de Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
