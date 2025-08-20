# Phishing Móvil y Distribución de Aplicaciones Maliciosas (Android e iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Esta página cubre técnicas utilizadas por actores de amenazas para distribuir **APKs maliciosos de Android** y **perfiles de configuración móvil de iOS** a través de phishing (SEO, ingeniería social, tiendas falsas, aplicaciones de citas, etc.).
> El material está adaptado de la campaña SarangTrap expuesta por Zimperium zLabs (2025) y otras investigaciones públicas.

## Flujo de Ataque

1. **Infraestructura SEO/Phishing**
* Registrar docenas de dominios similares (citas, compartir en la nube, servicio de coches…).
– Usar palabras clave en el idioma local y emojis en el elemento `<title>` para posicionarse en Google.
– Alojar *tanto* las instrucciones de instalación de Android (`.apk`) como de iOS en la misma página de destino.
2. **Descarga de Primera Etapa**
* Android: enlace directo a un APK *sin firmar* o de “tienda de terceros”.
* iOS: `itms-services://` o enlace HTTPS simple a un perfil **mobileconfig** malicioso (ver abajo).
3. **Ingeniería Social Post-instalación**
* En la primera ejecución, la aplicación solicita un **código de invitación/verificación** (ilusión de acceso exclusivo).
* El código se **envía por POST a través de HTTP** al Comando y Control (C2).
* C2 responde `{"success":true}` ➜ el malware continúa.
* Un análisis dinámico en sandbox/AV que nunca envía un código válido no ve **comportamiento malicioso** (evasión).
4. **Abuso de Permisos en Tiempo de Ejecución** (Android)
* Los permisos peligrosos solo se solicitan **después de una respuesta positiva del C2**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Las versiones más antiguas también solicitaban permisos de SMS -->
```
* Las variantes recientes **eliminan `<uses-permission>` para SMS de `AndroidManifest.xml`** pero dejan la ruta de código Java/Kotlin que lee SMS a través de reflexión ⇒ disminuye la puntuación estática mientras sigue siendo funcional en dispositivos que otorgan el permiso a través del abuso de `AppOps` o objetivos antiguos.
5. **Interfaz de Facade y Recolección en Segundo Plano**
* La aplicación muestra vistas inofensivas (visor de SMS, selector de galería) implementadas localmente.
* Mientras tanto, exfiltra:
- IMEI / IMSI, número de teléfono
- Volcado completo de `ContactsContract` (array JSON)
- JPEG/PNG de `/sdcard/DCIM` comprimido con [Luban](https://github.com/Curzibn/Luban) para reducir tamaño
- Contenido opcional de SMS (`content://sms`)
Los payloads son **comprimidos en lotes** y enviados a través de `HTTP POST /upload.php`.
6. **Técnica de Entrega en iOS**
* Un solo **perfil de configuración móvil** puede solicitar `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration`, etc. para inscribir el dispositivo en una supervisión similar a “MDM”.
* Instrucciones de ingeniería social:
1. Abrir Configuración ➜ *Perfil descargado*.
2. Tocar *Instalar* tres veces (capturas de pantalla en la página de phishing).
3. Confiar en el perfil sin firmar ➜ el atacante obtiene derechos de *Contactos* y *Fotos* sin revisión de la App Store.
7. **Capa de Red**
* HTTP simple, a menudo en el puerto 80 con encabezado HOST como `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (sin TLS → fácil de detectar).

## Pruebas Defensivas / Consejos para Red-Team

* **Evasión de Análisis Dinámico** – Durante la evaluación de malware, automatizar la fase del código de invitación con Frida/Objection para llegar a la rama maliciosa.
* **Diferencia entre Manifest y Runtime** – Comparar `aapt dump permissions` con `PackageManager#getRequestedPermissions()` en tiempo de ejecución; la falta de permisos peligrosos es una señal de alerta.
* **Canario de Red** – Configurar `iptables -p tcp --dport 80 -j NFQUEUE` para detectar ráfagas de POST no sólidas después de la entrada del código.
* **Inspección de mobileconfig** – Usar `security cms -D -i profile.mobileconfig` en macOS para listar `PayloadContent` y detectar derechos excesivos.

## Ideas de Detección para Blue-Team

* **Transparencia de Certificados / Análisis de DNS** para detectar ráfagas repentinas de dominios ricos en palabras clave.
* **Regex de User-Agent y Ruta**: `(?i)POST\s+/(check|upload)\.php` de clientes Dalvik fuera de Google Play.
* **Telemetría de Código de Invitación** – POST de códigos numéricos de 6 a 8 dígitos poco después de la instalación del APK puede indicar preparación.
* **Firma de MobileConfig** – Bloquear perfiles de configuración no firmados a través de políticas de MDM.

## Fragmento Útil de Frida: Bypass Automático del Código de Invitación
```python
# frida -U -f com.badapp.android -l bypass.js --no-pause
# Hook HttpURLConnection write to always return success
Java.perform(function() {
var URL = Java.use('java.net.URL');
URL.openConnection.implementation = function() {
var conn = this.openConnection();
var HttpURLConnection = Java.use('java.net.HttpURLConnection');
if (Java.cast(conn, HttpURLConnection)) {
conn.getResponseCode.implementation = function(){ return 200; };
conn.getInputStream.implementation = function(){
return Java.use('java.io.ByteArrayInputStream').$new("{\"success\":true}".getBytes());
};
}
return conn;
};
});
```
## Indicadores (Genéricos)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
## Referencias

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)

{{#include ../../banners/hacktricks-training.md}}
