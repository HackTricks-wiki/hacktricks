# Número de serie de macOS

{{#include ../../../banners/hacktricks-training.md}}

## Información básica

No asumas que todos los Mac tienen un número de serie decodificable de 12 caracteres. El formato antiguo de Apple codificaba información de fabricación y configuración, pero Apple comenzó a introducir números de serie aleatorizados con nuevos productos en 2021. El formato aleatorizado no expone detalles de fabricación ni de configuración.<sup>[[1]](#references)</sup>

### Formato antiguo de 12 caracteres

Para muchos dispositivos fabricados desde 2010 hasta la transición al formato aleatorizado, el formato de 12 caracteres todavía puede proporcionar indicios útiles sobre el inventario:<sup>[[3]](#references)</sup>

- Los caracteres 1–3 identifican la ubicación de fabricación.
- Los caracteres 4–5 codifican el semestre y la semana de producción.
- Los caracteres 6–8 distinguen las unidades producidas en la misma ubicación y momento.
- Los caracteres 9–12 identifican el modelo o código de configuración.

Por ejemplo, `C02L13ECF8J2` sigue esta estructura antigua. Las asignaciones de fábricas mantenidas por la comunidad incluyen prefijos como `FC`, `F`, `XA`, `XB`, `QP` y `G8` para ubicaciones de Estados Unidos; `RN` para México; `CK` para Cork; `VM` para una ubicación de Foxconn en la República Checa; `SG` o `E` para Singapur; `MB` para Malasia; `PT` o `CY` para Corea; y `EE`, `QT` o `UV` para Taiwán. Numerosos prefijos —incluidos `FK`, `F1`, `F2`, `W8`, `DL`, `DM`, `DN`, `YM`, `7J`, `1C`, `4H`, `WQ`, `F7`, `C0`, `C3` y `C7`— se han asociado con instalaciones chinas; `RM` se ha asociado con dispositivos reacondicionados.<sup>[[3]](#references)</sup>

Los códigos de fecha del cuarto carácter van desde `C` (primer semestre de 2010) hasta `Z` (segundo semestre de 2019), y la secuencia vuelve a utilizarse posteriormente. Para el quinto carácter, los dígitos `1`–`9` representan las semanas 1–9, mientras que las letras `C`–`Y`, excluyendo las vocales y `S`, representan las semanas 10–27; suma 26 cuando el cuarto carácter indica el segundo semestre de un año.<sup>[[3]](#references)</sup>

Estas asignaciones son útiles para el triage de dispositivos antiguos, pero no constituyen una prueba concluyente del origen, la antigüedad o la autenticidad. Confirma el resultado mediante los datos de inventario de Apple.

Para una identificación fiable, obtén el número de serie del dispositivo y utiliza la consulta de cobertura o de especificaciones técnicas de Apple, en lugar de intentar inferir el modelo a partir de las posiciones de los caracteres.<sup>[[2]](#references)</sup>

### Obtener el número de serie

La interfaz gráfica lo muestra en **menú Apple > Acerca de este Mac**.<sup>[[2]](#references)</sup> Desde un shell, cualquiera de los siguientes comandos lee el número de serie de la plataforma:
```bash
system_profiler SPHardwareDataType | awk -F ': ' '/Serial Number/ {print $2}'
ioreg -rd1 -c IOPlatformExpertDevice | awk -F '"' '/IOPlatformSerialNumber/ {print $4}'
```
Trata un número de serie como un identificador, no como un autenticador: confirma el dispositivo mediante el flujo de inventario correspondiente de Apple o MDM antes de tomar decisiones de inscripción o propiedad.

## References

- [1] [MacRumors - Apple comienza la transición a números de serie aleatorizados](https://www.macrumors.com/2021/05/05/purple-iphone-12-randomized-serial-number/)
- [2] [Apple Support - Encuentra el nombre del modelo y el número de serie de tu Mac](https://support.apple.com/en-us/102767)
- [3] [Beetstech - Descifra el significado detrás de un número de serie de Apple](https://beetstech.com/blog/decode-meaning-behind-apple-serial-number)
{{#include ../../../banners/hacktricks-training.md}}
