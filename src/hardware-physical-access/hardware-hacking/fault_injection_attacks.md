# Ataques de Fault Injection

{{#include ../../banners/hacktricks-training.md}}

Fault injection —a menudo llamada **glitching** en el ámbito de la seguridad de hardware— altera deliberadamente un dispositivo mientras está en funcionamiento para que realice un cálculo incorrecto. Una falla útil puede omitir una instrucción, corromper datos, eludir una comprobación de seguridad o producir resultados criptográficos defectuosos de los que se pueda obtener información secreta.<sup>[[1]](#references)</sup>

Las técnicas comunes manipulan la tensión de alimentación o el reloj, inyectan interferencias electromagnéticas o usan estimulación óptica o láser.<sup>[[1]](#references)</sup> Su precisión e invasividad varían, pero las pruebas exitosas suelen requerir un disparador repetible y barridos sistemáticos de la temporización, el ancho del pulso y la intensidad. Empieza con una línea base estable, registra por separado los reinicios y las salidas malformadas, y cambia un parámetro a la vez.<sup>[[2]](#references)</sup>

## References

- [1] [Hayashi et al. - Método de fault injection sin disparador y no invasivo basado en interferencia electromagnética intencional](https://csrc.nist.gov/csrc/media/events/non-invasive-attack-testing-workshop/documents/04_hayashi.pdf)
- [2] [Documentación de ChipWhisperer - Descripción general y comparación del hardware de captura](https://chipwhisperer.readthedocs.io/en/latest/Capture/overview.html)
{{#include ../../banners/hacktricks-training.md}}
