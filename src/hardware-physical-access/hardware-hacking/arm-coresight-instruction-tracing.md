# Trazado de instrucciones ARM CoreSight sobre SWO

{{#include ../../banners/hacktricks-training.md}}

Un [puerto de depuración SWD/JTAG](jtag.md) accesible puede usarse para habilitar una traza de ejecución Cortex-M en vivo, sin instrumentar el firmware. Esto requiere un MCU con ETM y TPIU, una ruta SWO expuesta, una copia del firmware exacto para la decodificación y un analizador lógico lo bastante rápido para la velocidad de bits SWO seleccionada. A diferencia de las [mediciones de canal lateral de potencia o EM](side_channel_analysis.md), ETM es una traza de depuración; grabar ambas permite alinear la fuga observada con el código ejecutado. La misma alineación puede ayudar a temporizar la [inyección de fallos](fault_injection_attacks.md).<sup>[[1]](#references)</sup>

ETM emite eventos comprimidos de flujo de control, no bytes de instrucciones. Un decodificador reconstruye la ejecución usando la imagen de firmware correspondiente. ITM transporta instrumentación de software, mientras que TPIU enmarca las fuentes de trazas y controla la salida serial-wire. Antes de aplicar valores de registros, consulta los componentes CoreSight y la multiplexación de pines del objetivo en su manual de referencia: el ejemplo siguiente es para un STM32F401, no para una configuración universal de Cortex-M.<sup>[[1]](#references)</sup>

## Localizar la salida de trazas

En el STM32F401, SWO asíncrono usa PB3. En el controlador investigado, PB3 estaba conectado a la resistencia R15, que proporcionaba un punto de prueba accesible. Cuando el encapsulado o la red están ocultos, configura temporalmente el pin candidato compatible con SWO como GPIO y conmútalo mediante escrituras de memoria SWD. Comprueba los puntos de la placa para encontrar la forma de onda correspondiente y luego restaura la configuración del pin de trazas. Conecta el analizador con una tierra común y un nivel lógico compatible.<sup>[[1]](#references)</sup>

## Habilitar TPIU y ETM con OpenOCD

Los siguientes comandos deben incluirse en una configuración de OpenOCD después de seleccionar el adaptador adecuado y `target/stm32f4x.cfg`. `setbits` conserva los bits no relacionados de los registros de control, mientras que `mww` sobrescribe la palabra completa. Primero, TPIU enruta la traza asíncrona; después, se desbloquea ETM, se configura en modo de programación, se le asigna el ID de fuente de traza `1` y se inicia. Estos valores corresponden a la configuración STM32F401 funcional del autor, así que adáptalos al mapa de registros y al árbol de reloj del objetivo.<sup>[[1]](#references)[[2]](#references)</sup>

<details>
<summary>Configuración de registros de trazas STM32F401 en OpenOCD</summary>

```tcl
proc setbits {addr mask} {
    mem2array value 32 $addr 1
    set value(0) [expr {$value(0) | $mask}]
    array2mem value 32 $addr 1
}
init
reset halt
setbits 0xe0042004 0x20       ;# DBGMCU_CR: trace I/O, async SWO
setbits 0xe000edfc 0x1000000  ;# DEMCR: TRCENA
mww 0xe0040004 1              ;# TPIU_CPSR: port size
mww 0xe0040010 3              ;# TPIU_ACPR: 16 MHz / (3 + 1) = 4 Mbaud
mww 0xe00400f0 2              ;# TPIU_SPPR: async UART framing
mww 0xe0040304 0x102          ;# TPIU_FFCR: formatter
mww 0xe0041fb0 0xC5ACCE55     ;# ETM_LAR: unlock
mww 0xe0041000 0x00201d0e     ;# ETM_CR: programming mode
mww 0xe0041200 1              ;# ETM_TRACEIDR: source ID 1
mww 0xe0041008 0x0000406F     ;# ETM_TER: trigger event
mww 0xe0041020 0x0000006F     ;# ETM_TEE: trace-enable event
mww 0xe0041024 0x00000001     ;# ETM_TSSR: start trace
mww 0xe0041000 0x0000191E     ;# ETM_CR: leave programming mode
```

</details>

La velocidad de SWO es `HCLK / (TPIU_ACPR + 1)`. Con un HCLK de 16 MHz y `ACPR=3`, captura a 4 Mbaud. En PulseView, coloca el decodificador ETM encima de un decodificador UART en el canal del analizador SWO, configura el UART con la velocidad real de la señal y usa el ID de origen ETM configurado anteriormente. El ejemplo usó una frecuencia de muestreo de 24 MHz (seis muestras por bit), un disparo por flanco descendente y una captura con un 25 % de pretrigger. Tras la configuración, detén y reinicia el target, arma la captura y luego ejecuta `resume`; verifica la sincronización ETM y una ruta de PC plausible comparándola con el firmware, en lugar de confiar únicamente en una salida que parezca decodificada.<sup>[[1]](#references)</sup>

## Recuperarse de cambios de reloj y de configuración de pines

Dos acciones de firmware independientes pueden detener una traza válida. Un cambio de PLL aumenta HCLK y, por tanto, la velocidad de transmisión de SWO mientras `ACPR` permanece fijo; la capa UART recupera bytes incorrectos y la reproducción de ETM deja de tener sentido. Inspecciona la configuración de RCC/PLL en [análisis de firmware](../firmware-analysis/) y, en el ejemplo de STM32F401, carga la imagen de Cortex-M en `0x08000000` e importa su SVD en Ghidra para que los registros de reloj tengan nombres. Establece un breakpoint de hardware en una instrucción Thumb de dos bytes *después* de la inicialización del reloj. En el ejemplo, `bp 0x080001fa 2 hw` seguido de `resume` detiene la ejecución tras la configuración de PLL; mientras el procesador está detenido, `mww 0xe0040010 31` establece el nuevo divisor. Calcula y configura la nueva velocidad UART, arma la captura y ejecuta `resume` de nuevo. Esto captura la ruta posterior a la transición; no recupera la transición perdida.<sup>[[1]](#references)</sup>

Por separado, el firmware puede reasignar el pad SWO a otro periférico. En el ejemplo, la configuración de función alternativa de GPIO cambió PB3 a SDA de I2C2, por lo que ningún ajuste del decodificador podía restaurar la traza en ese cable. Busca la inicialización GPIO pertinente en el firmware y, después, reemplaza sus puntos de llamada por NOP Thumb del mismo tamaño (`0xBF00` por cada medio word) o detén el core y restaura mediante SWD la configuración de pines compatible con la traza. Ambos métodos pueden deshabilitar el periférico desplazado; además, el firmware podría volver a sobrescribir una restauración en tiempo de ejecución. Al restaurar el pin en tiempo de ejecución, configura el divisor SWO para el HCLK actual.<sup>[[1]](#references)</sup>

## References

- [1] [Seguir las instrucciones: trazado ARM en vivo con ETM, ITM y TPIU](https://voidstarsec.com/blog/arm-tracing-etm-itm)
- [2] [wrongbaud/etm-examples: configuración STM32F4 OpenOCD ETM/TPIU](https://github.com/wrongbaud/etm-examples/blob/main/openocd-configs/prescaler.cfg)
{{#include ../../banners/hacktricks-training.md}}
