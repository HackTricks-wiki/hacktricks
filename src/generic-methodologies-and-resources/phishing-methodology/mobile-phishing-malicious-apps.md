# Phishing Móvel & Distribuição de Aplicativos Maliciosos (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Esta página cobre técnicas usadas por atores de ameaça para distribuir **APKs maliciosos do Android** e **perfis de configuração móvel do iOS** através de phishing (SEO, engenharia social, lojas falsas, aplicativos de namoro, etc.).
> O material é adaptado da campanha SarangTrap exposta pela Zimperium zLabs (2025) e outras pesquisas públicas.

## Fluxo de Ataque

1. **Infraestrutura de SEO/Phishing**
* Registrar dezenas de domínios semelhantes (namoro, compartilhamento em nuvem, serviço de carro…).
– Usar palavras-chave e emojis em língua local no elemento `<title>` para ranquear no Google.
– Hospedar *tanto* as instruções de instalação do Android (`.apk`) quanto do iOS na mesma página de destino.
2. **Download da Primeira Etapa**
* Android: link direto para um APK *não assinado* ou “loja de terceiros”.
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
* Um único **perfil de configuração móvel** pode solicitar `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` etc. para inscrever o dispositivo em supervisão semelhante ao “MDM”.
* Instruções de engenharia social:
1. Abra Configurações ➜ *Perfil baixado*.
2. Toque em *Instalar* três vezes (capturas de tela na página de phishing).
3. Confie no perfil não assinado ➜ o atacante ganha direitos de *Contatos* & *Foto* sem revisão da App Store.
7. **Camada de Rede**
* HTTP simples, muitas vezes na porta 80 com cabeçalho HOST como `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (sem TLS → fácil de detectar).

## Testes Defensivos / Dicas de Red-Team

* **Bypass de Análise Dinâmica** – Durante a avaliação de malware, automatize a fase do código de convite com Frida/Objection para alcançar o ramo malicioso.
* **Diferença entre Manifesto e Tempo de Execução** – Compare `aapt dump permissions` com `PackageManager#getRequestedPermissions()` em tempo de execução; permissões perigosas ausentes são um sinal de alerta.
* **Canário de Rede** – Configure `iptables -p tcp --dport 80 -j NFQUEUE` para detectar explosões de POST não sólidas após a entrada do código.
* **Inspeção de mobileconfig** – Use `security cms -D -i profile.mobileconfig` no macOS para listar `PayloadContent` e identificar direitos excessivos.

## Ideias de Detecção para Blue-Team

* **Transparência de Certificado / Análise de DNS** para capturar explosões repentinas de domínios ricos em palavras-chave.
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
## Referências

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)

{{#include ../../banners/hacktricks-training.md}}
