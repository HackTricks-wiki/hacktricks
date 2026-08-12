# Ataques de Fault Injection

{{#include ../../banners/hacktricks-training.md}}

Fault injection —a menudo denominado **glitching** en el ámbito de la seguridad del hardware— altera deliberadamente un dispositivo mientras está funcionando para que realice un cálculo incorrecto. Un fault útil puede omitir una instrucción, corromper datos, evadir una comprobación de seguridad o producir una salida criptográfica defectuosa de la que se pueda derivar información secreta.<sup>[[1]](#references)</sup>

Las técnicas comunes manipulan la tensión de alimentación o el reloj, inyectan interferencias electromagnéticas o utilizan estimulación óptica o láser.<sup>[[1]](#references)</sup> Su precisión e invasividad varían, pero las pruebas exitosas generalmente requieren un trigger repetible y barridos sistemáticos de la temporización, la duración del pulso y la intensidad. Comienza con una línea base estable, registra por separado los reinicios y las salidas malformadas, y cambia un parámetro cada vez.<sup>[[2]](#references)</sup>

## References

- [1] [Hayashi et al. - Método de Fault Injection no invasivo y sin trigger basado en interferencia electromagnética intencionada](https://csrc.nist.gov/csrc/media/events/non-invasive-attack-testing-workshop/documents/04_hayashi.pdf)
- [2] [Documentación de ChipWhisperer - Descripción general y comparación del hardware de captura](https://chipwhisperer.readthedocs.io/en/latest/Capture/overview.html)
{{#include ../../banners/hacktricks-training.md}}
