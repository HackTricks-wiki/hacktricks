# Construcción de un cloner portátil HID MaxiProx de 125 kHz

{{#include ../../banners/hacktricks-training.md}}

## Objetivo
Convertir un lector HID MaxiProx 5375 de largo alcance y 125 kHz, alimentado por la red eléctrica, en un cloner de credenciales portátil alimentado por batería que recopila silenciosamente tarjetas de proximidad durante evaluaciones de seguridad física.

La conversión descrita aquí se basa en la serie de investigación de TrustedSec «Let’s Clone a Cloner – Part 3: Putting It All Together» y combina consideraciones mecánicas, eléctricas y de RF para que el dispositivo final pueda llevarse en una mochila y usarse de inmediato en el sitio.<sup>[[1]](#references)</sup>

> [!warning]
> Manipular equipos alimentados por la red eléctrica y power banks de ion-litio puede ser peligroso. Verifica todas las conexiones **antes** de energizar el circuito y mantén las antenas, el cable coaxial y los planos de tierra exactamente como estaban en el diseño de fábrica para evitar desintonizar el lector.

## Lista de materiales (BOM)

* Lector HID MaxiProx 5375 (o cualquier lector HID Prox® de largo alcance y 12 V)
* ESP RFID Tool v2.2 (sniffer/logger Wiegand basado en ESP32)
* Módulo disparador USB-PD (Power-Delivery) capaz de negociar 12 V a ≥3 A
* Power bank USB-C de 100 W (con perfil PD de salida de 12 V)
* Cable de conexión de 26 AWG con aislamiento de silicona: rojo/blanco
* Interruptor de palanca SPST para montaje en panel (para silenciar el beeper)
* Protector NKK AT4072 para el interruptor / tapa a prueba de accidentes
* Soldador, malla desoldadora y bomba desoldadora
* Herramientas manuales aptas para ABS: sierra de marquetería, cúter, limas planas y de media caña
* Brocas de 1/16″ (1,5 mm) y 1/8″ (3 mm)
* Cinta de doble cara 3 M VHB y bridas

## 1. Subsistema de alimentación

1. Desuelda y retira la placa hija del convertidor buck de fábrica que se usa para generar 5 V para la PCB lógica.
2. Monta un disparador USB-PD junto al ESP RFID Tool y lleva el receptáculo USB-C del disparador al exterior de la carcasa.
3. El disparador PD negocia 12 V desde el power bank y los suministra directamente al MaxiProx (el lector admite de forma nativa entre 10 y 14 V). Se toma una línea secundaria de 5 V de la placa ESP para alimentar los accesorios.
4. Coloca la batería de 100 W al ras del soporte interno para que **no** haya cables de alimentación pasando por encima de la antena de ferrita, preservando así el rendimiento de RF.

## 2. Interruptor para silenciar el beeper: funcionamiento silencioso

1. Localiza los dos pads del altavoz en la placa lógica del MaxiProx.
2. Limpia *ambos* pads con malla desoldadora y luego vuelve a soldar únicamente el pad **negativo**.
3. Suelda cables de 26 AWG (blanco = negativo, rojo = positivo) a los pads del beeper y pásalos por una ranura recién cortada hasta un interruptor SPST para montaje en panel.
4. Cuando el interruptor está abierto, el circuito del beeper queda interrumpido y el lector funciona en completo silencio, ideal para recopilar credenciales de forma encubierta.
5. Coloca una tapa de seguridad con resorte NKK AT4072 sobre el interruptor. Agranda cuidadosamente el orificio con una sierra de marquetería o una lima hasta que encaje sobre el cuerpo del interruptor. El protector evita que se active accidentalmente dentro de una mochila.

## 3. Carcasa y trabajo mecánico

• Usa un alicate de corte al ras y luego un cúter y una lima para *eliminar* el «saliente» interno de ABS, de modo que la batería USB-C grande quede plana sobre el soporte.
• Haz dos canales paralelos en la pared de la carcasa para el cable USB-C; así la batería queda fija y se elimina el movimiento y la vibración.
• Crea una abertura rectangular para el botón de **encendido** de la batería:
  1. Pega una plantilla de papel sobre la ubicación.
  2. Taladra orificios piloto de 1/16″ en las cuatro esquinas.
  3. Agrándalos con una broca de 1/8″.
  4. Une los orificios con una sierra de marquetería y termina los bordes con una lima.  
  ✱  Se *evitó* usar una herramienta rotativa Dremel: la broca de alta velocidad derrite el ABS grueso y deja un borde desprolijo.

## 4. Ensamblaje final

1. Vuelve a instalar la placa lógica del MaxiProx y vuelve a soldar el cable flexible SMA al pad de tierra de la PCB del lector.
2. Monta el ESP RFID Tool y el disparador USB-PD con cinta 3 M VHB.
3. Ordena todo el cableado con bridas y mantén los cables de alimentación **lejos** del lazo de la antena.
4. Aprieta los tornillos de la carcasa hasta que la batería quede ligeramente comprimida; la fricción interna evita que el paquete se desplace cuando el dispositivo retrocede después de cada lectura de tarjeta.

## 5. Pruebas de alcance y apantallamiento

* Con una tarjeta de prueba **Pupa** de 125 kHz, el cloner portátil logró lecturas consistentes a **≈ 8 cm** al aire libre, idénticas a las del funcionamiento conectado a la red eléctrica.<sup>[[1]](#references)</sup>
* Al colocar el lector dentro de una caja metálica de paredes delgadas (para simular el mostrador de un vestíbulo bancario), el alcance se redujo a ≤ 2 cm, lo que confirma que las carcasas metálicas sustanciales actúan como eficaces blindajes de RF.<sup>[[1]](#references)</sup>

## Flujo de uso

1. Carga la batería USB-C, conéctala y activa el interruptor principal.
2. (Opcional) Abre el protector del beeper y activa la respuesta audible durante las pruebas en banco; asegúralo antes del uso encubierto en campo.
3. Pasa junto a la persona objetivo que lleva la credencial: el MaxiProx energizará la tarjeta y el ESP RFID Tool capturará el flujo Wiegand.
4. Vuelca las credenciales capturadas por Wi-Fi o USB-UART y reprodúcelas o clónalas según sea necesario.

## Solución de problemas

| Síntoma | Causa probable | Solución |
|---------|--------------|------|
| El lector se reinicia al presentar una tarjeta | El disparador PD negoció 9 V en vez de 12 V | Verifica los jumpers del disparador o prueba con un cable USB-C de mayor potencia |
| No hay alcance de lectura | La batería o el cableado están *encima* de la antena | Reubica los cables y deja 2 cm de espacio alrededor del lazo de ferrita |
| El beeper sigue sonando | El interruptor está conectado al cable positivo en vez de al negativo | Mueve el interruptor para que interrumpa la pista **negativa** del altavoz |

## References

- [1] [Let’s Clone a Cloner – Part 3 (TrustedSec)](https://trustedsec.com/blog/lets-clone-a-cloner-part-3-putting-it-all-together)

{{#include ../../banners/hacktricks-training.md}}