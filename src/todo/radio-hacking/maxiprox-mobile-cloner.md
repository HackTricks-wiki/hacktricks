# Construcción de un cloner móvil HID MaxiProx de 125 kHz portátil

{{#include ../../banners/hacktricks-training.md}}

## Objetivo
Convertir un lector HID MaxiProx 5375 de largo alcance y 125 kHz, alimentado por la red eléctrica, en un cloner de badges portátil y alimentado por batería que recopile silenciosamente tarjetas de proximidad durante evaluaciones de seguridad física.

La conversión descrita aquí se basa en la serie de investigaciones de TrustedSec “Let’s Clone a Cloner – Part 3: Putting It All Together” y combina aspectos mecánicos, eléctricos y de RF para que el dispositivo final pueda llevarse en una mochila y utilizarse inmediatamente en el lugar.<sup>[[1]](#references)</sup>

> [!warning]
> Manipular equipos alimentados por la red eléctrica y power-banks de ion-litio puede ser peligroso. Verifica cada conexión **antes** de energizar el circuito y mantén las antenas, el coaxial y los planos de tierra exactamente como estaban en el diseño de fábrica para evitar desafinar el lector.

## Lista de materiales (BOM)

* Lector HID MaxiProx 5375 (o cualquier lector HID Prox® de largo alcance y 12 V)
* ESP RFID Tool v2.2 (sniffer/logger Wiegand basado en ESP32)
* Módulo trigger USB-PD (Power-Delivery) capaz de negociar 12 V a ≥3 A
* Power-bank USB-C de 100 W (ofrece un perfil PD de 12 V)
* Cableado de conexión de silicona de 26 AWG con aislamiento – rojo/blanco
* Interruptor de palanca SPST para montaje en panel (para el kill-switch del zumbador)
* Protector de interruptor / tapa a prueba de accidentes NKK AT4072
* Soldador, malla para desoldar y bomba desoldadora
* Herramientas manuales aptas para ABS: sierra de marquetería, cúter, limas planas y de media caña
* Brocas de 1/16″ (1,5 mm) y 1/8″ (3 mm)
* Cinta adhesiva de doble cara VHB 3 M y bridas

## 1. Subsistema de alimentación

1. Desuelda y retira la daughter-board del convertidor buck de fábrica utilizada para generar 5 V para la PCB lógica.
2. Monta un trigger USB-PD junto al ESP RFID Tool y lleva el conector USB-C del trigger hasta el exterior de la carcasa.
3. El trigger PD negocia 12 V desde el power-bank y los suministra directamente al MaxiProx (el lector espera nativamente entre 10 y 14 V). Se toma un rail secundario de 5 V de la placa ESP para alimentar cualquier accesorio.
4. La batería de 100 W se coloca a ras contra el separador interno, de modo que **no haya** cables de alimentación extendidos sobre la antena de ferrita, preservando el rendimiento de RF.

## 2. Kill-switch del zumbador – Funcionamiento silencioso

1. Localiza los dos pads del altavoz en la placa lógica del MaxiProx.
2. Limpia con malla **ambos** pads y después vuelve a soldar únicamente el pad **negativo**.
3. Suelda cables de 26 AWG (blanco = negativo, rojo = positivo) a los pads del zumbador y llévalos a través de una ranura recién cortada hasta un interruptor SPST para montaje en panel.
4. Cuando el interruptor está abierto, el circuito del zumbador se interrumpe y el lector funciona en completo silencio, ideal para la recopilación encubierta de badges.
5. Coloca una tapa de seguridad con resorte NKK AT4072 sobre la palanca. Amplía cuidadosamente el orificio con una sierra de marquetería / lima hasta que encaje a presión sobre el cuerpo del interruptor. El protector evita la activación accidental dentro de una mochila.

## 3. Carcasa y trabajo mecánico

• Utiliza cortadores al ras y después un cúter y una lima para *eliminar* el “saliente” interno de ABS, de modo que la batería USB-C grande quede plana sobre el separador.
• Excava dos canales paralelos en la pared de la carcasa para el cable USB-C; esto bloquea la batería en su posición y elimina el movimiento y la vibración.
• Crea una abertura rectangular para el botón de **encendido** de la batería:
1. Fija una plantilla de papel con cinta sobre la ubicación.
2. Taladra orificios piloto de 1/16″ en las cuatro esquinas.
3. Amplíalos con una broca de 1/8″.
4. Une los orificios con una sierra de marquetería y termina los bordes con una lima.
✱  Se *evitó* utilizar una Dremel giratoria: la broca de alta velocidad derrite el ABS grueso y deja un borde antiestético.

## 4. Montaje final

1. Vuelve a instalar la placa lógica del MaxiProx y vuelve a soldar el pigtail SMA al pad de tierra de la PCB del lector.
2. Fija el ESP RFID Tool y el trigger USB-PD con VHB 3 M.
3. Ordena todo el cableado con bridas, manteniendo los cables de alimentación **lejos** del bucle de la antena.
4. Aprieta los tornillos de la carcasa hasta que la batería quede ligeramente comprimida; la fricción interna evita que el pack se desplace cuando el dispositivo retrocede después de cada lectura de tarjeta.

## 5. Pruebas de alcance y blindaje

* Utilizando una tarjeta de prueba **Pupa** de 125 kHz, el cloner portátil logró lecturas constantes a **≈ 8 cm** en aire libre, idénticas a las obtenidas con alimentación de red.<sup>[[1]](#references)</sup>
* Colocar el lector dentro de una caja metálica de paredes finas (para simular el mostrador de un vestíbulo bancario) redujo el alcance a ≤ 2 cm, confirmando que las carcasas metálicas sustanciales actúan como blindajes de RF eficaces.<sup>[[1]](#references)</sup>

## Flujo de uso

1. Carga la batería USB-C, conéctala y activa el interruptor principal de alimentación.
2. (Opcional) Abre el protector del zumbador y activa la retroalimentación audible durante las pruebas de banco; bloquéalo antes del uso encubierto en campo.
3. Pasa junto al portador del badge objetivo: el MaxiProx energizará la tarjeta y el ESP RFID Tool capturará el flujo Wiegand.
4. Extrae las credenciales capturadas mediante Wi-Fi o USB-UART y repítelas/clónalas según sea necesario.

## Solución de problemas

| Síntoma | Causa probable | Solución |
|---------|----------------|----------|
| El lector se reinicia al presentar una tarjeta | El trigger PD negoció 9 V en lugar de 12 V | Verifica los jumpers del trigger / prueba con un cable USB-C de mayor potencia |
| No hay alcance de lectura | La batería o el cableado están situados *encima* de la antena | Reubica los cables y mantén una separación de 2 cm alrededor del bucle de ferrita |
| El zumbador sigue emitiendo pitidos | El interruptor está cableado en el conductor positivo en lugar del negativo | Mueve el kill-switch para interrumpir la traza del altavoz **negativa** |

## Referencias

- [1] [Let’s Clone a Cloner – Part 3 (TrustedSec)](https://trustedsec.com/blog/lets-clone-a-cloner-part-3-putting-it-all-together)

{{#include ../../banners/hacktricks-training.md}}
