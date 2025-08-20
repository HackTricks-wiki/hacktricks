# Construyendo un Clonador Móvil HID MaxiProx de 125 kHz Portátil

{{#include ../../banners/hacktricks-training.md}}

## Objetivo
Convertir un lector HID MaxiProx 5375 de 125 kHz de largo alcance alimentado por la red en un clonador de insignias portátil y alimentado por batería que coseche silenciosamente tarjetas de proximidad durante evaluaciones de seguridad física.

La conversión cubierta aquí se basa en la serie de investigación de TrustedSec “Let’s Clone a Cloner – Part 3: Putting It All Together” y combina consideraciones mecánicas, eléctricas y de RF para que el dispositivo final pueda ser guardado en una mochila y utilizado inmediatamente en el sitio.

> [!warning]
> Manipular equipos alimentados por la red y bancos de energía de litio puede ser peligroso. Verifique cada conexión **antes** de energizar el circuito y mantenga las antenas, coaxiales y planos de tierra exactamente como estaban en el diseño de fábrica para evitar desajustar el lector.

## Lista de Materiales (BOM)

* Lector HID MaxiProx 5375 (o cualquier lector HID Prox® de largo alcance de 12 V)
* Herramienta ESP RFID v2.2 (sniffer/logger Wiegand basado en ESP32)
* Módulo de activación USB-PD (Power-Delivery) capaz de negociar 12 V @ ≥3 A
* Banco de energía USB-C de 100 W (salidas 12 V perfil PD)
* Cable de conexión de silicona de 26 AWG – rojo/blanco
* Interruptor de palanca SPST de montaje en panel (para el interruptor de apagado del beeper)
* Protector de interruptor NKK AT4072 / tapa a prueba de accidentes
* Soldador, trenza de soldadura y bomba de desoldar
* Herramientas manuales clasificadas ABS: sierra de calar, cuchillo utility, limas planas y de media caña
* Brocas de 1/16″ (1.5 mm) y 1/8″ (3 mm)
* Cinta de doble cara 3 M VHB y bridas

## 1. Subsistema de Alimentación

1. Desolde y retire la placa hija del convertidor reductor de fábrica utilizada para generar 5 V para la PCB lógica.
2. Monte un activador USB-PD junto a la herramienta ESP RFID y dirija el receptáculo USB-C del activador hacia el exterior del recinto.
3. El activador PD negocia 12 V del banco de energía y lo alimenta directamente al MaxiProx (el lector espera nativamente 10–14 V). Se toma un riel secundario de 5 V de la placa ESP para alimentar cualquier accesorio.
4. El paquete de batería de 100 W se posiciona a ras contra el espaciador interno para que **no** haya cables de alimentación colgando sobre la antena de ferrita, preservando el rendimiento de RF.

## 2. Interruptor de Apagado del Beeper – Operación Silenciosa

1. Localice las dos almohadillas del altavoz en la placa lógica del MaxiProx.
2. Limpie *ambas* almohadillas, luego vuelva a soldar solo la almohadilla **negativa**.
3. Suelde cables de 26 AWG (blanco = negativo, rojo = positivo) a las almohadillas del beeper y diríjalos a través de una ranura recién cortada hacia un interruptor SPST de montaje en panel.
4. Cuando el interruptor está abierto, el circuito del beeper se interrumpe y el lector opera en completo silencio, ideal para la recolección encubierta de insignias.
5. Coloque una tapa de seguridad de resorte NKK AT4072 sobre el interruptor. Amplíe cuidadosamente el orificio con una sierra de calar / lima hasta que encaje sobre el cuerpo del interruptor. El guardia previene la activación accidental dentro de una mochila.

## 3. Trabajo Mecánico y de Recinto

• Use cortadores a ras y luego un cuchillo y lima para *eliminar* el “bump-out” interno de ABS para que la gran batería USB-C se asiente plana sobre el espaciador.
• Crea dos canales paralelos en la pared del recinto para el cable USB-C; esto bloquea la batería en su lugar y elimina el movimiento/vibración.
• Crea una abertura rectangular para el botón de **encendido** de la batería:
1. Cinta un stencil de papel sobre la ubicación.
2. Perfore agujeros piloto de 1/16″ en las cuatro esquinas.
3. Amplíe con una broca de 1/8″.
4. Una las perforaciones con una sierra de calar; termine los bordes con una lima.
✱ Se *evitó* un Dremel rotativo: la broca de alta velocidad derrite el ABS grueso y deja un borde feo.

## 4. Ensamblaje Final

1. Vuelva a instalar la placa lógica del MaxiProx y vuelva a soldar el pigtail SMA a la almohadilla de tierra de la PCB del lector.
2. Monte la herramienta ESP RFID y el activador USB-PD usando 3 M VHB.
3. Organice todo el cableado con bridas, manteniendo los cables de alimentación **lejos** del bucle de antena.
4. Apriete los tornillos del recinto hasta que la batería esté ligeramente comprimida; la fricción interna evita que el paquete se desplace cuando el dispositivo retrocede después de cada lectura de tarjeta.

## 5. Pruebas de Alcance y Apantallamiento

* Usando una tarjeta de prueba **Pupa** de 125 kHz, el clonador portátil logró lecturas consistentes a **≈ 8 cm** en aire libre, idéntico a la operación alimentada por la red.
* Colocar el lector dentro de una caja de metal delgada (para simular un escritorio de lobby bancario) redujo el alcance a ≤ 2 cm, confirmando que los recintos metálicos sustanciales actúan como escudos de RF efectivos.

## Flujo de Trabajo de Uso

1. Cargue la batería USB-C, conéctela y encienda el interruptor de alimentación principal.
2. (Opcional) Abra el guardia del beeper y habilite la retroalimentación audible al probar en banco; asegúrelo antes del uso encubierto en el campo.
3. Pase junto al titular de la insignia objetivo: el MaxiProx energizará la tarjeta y la herramienta ESP RFID capturará el flujo Wiegand.
4. Transfiera las credenciales capturadas a través de Wi-Fi o USB-UART y repita/clonéelas según sea necesario.

## Solución de Problemas

| Síntoma | Causa Probable | Solución |
|---------|----------------|----------|
| El lector se reinicia al presentar la tarjeta | El activador PD negoció 9 V en lugar de 12 V | Verifique los jumpers del activador / pruebe un cable USB-C de mayor potencia |
| Sin rango de lectura | Batería o cableado sentado *sobre* la antena | Redirija los cables y mantenga 2 cm de separación alrededor del bucle de ferrita |
| El beeper aún chirría | Interruptor conectado en el cable positivo en lugar de negativo | Mueva el interruptor de apagado para romper la traza del altavoz **negativo** |

## Referencias

- [Let’s Clone a Cloner – Part 3 (TrustedSec)](https://trustedsec.com/blog/lets-clone-a-cloner-part-3-putting-it-all-together)

{{#include ../../banners/hacktricks-training.md}}
