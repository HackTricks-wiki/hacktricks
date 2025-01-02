# Inyección de Chromium en macOS

{{#include ../../../banners/hacktricks-training.md}}

## Información Básica

Los navegadores basados en Chromium como Google Chrome, Microsoft Edge, Brave y otros. Estos navegadores están construidos sobre el proyecto de código abierto Chromium, lo que significa que comparten una base común y, por lo tanto, tienen funcionalidades y opciones de desarrollador similares.

#### Bandera `--load-extension`

La bandera `--load-extension` se utiliza al iniciar un navegador basado en Chromium desde la línea de comandos o un script. Esta bandera permite **cargar automáticamente una o más extensiones** en el navegador al inicio.

#### Bandera `--use-fake-ui-for-media-stream`

La bandera `--use-fake-ui-for-media-stream` es otra opción de línea de comandos que se puede usar para iniciar navegadores basados en Chromium. Esta bandera está diseñada para **eludir los mensajes de usuario normales que piden permiso para acceder a los flujos de medios de la cámara y el micrófono**. Cuando se utiliza esta bandera, el navegador otorga automáticamente permiso a cualquier sitio web o aplicación que solicite acceso a la cámara o al micrófono.

### Herramientas

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop)
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO)

### Ejemplo
```bash
# Intercept traffic
voodoo intercept -b chrome
```
Encuentra más ejemplos en los enlaces de herramientas

## Referencias

- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)

{{#include ../../../banners/hacktricks-training.md}}
