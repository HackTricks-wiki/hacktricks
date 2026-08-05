# Перевірка процесу, що підключається до macOS XPC

{{#include ../../../../../../banners/hacktricks-training.md}}

## Перевірка процесу, що підключається до XPC

Коли встановлюється з’єднання з XPC service, server перевіряє, чи дозволене це з’єднання. Зазвичай виконуються такі перевірки:

1. Перевірити, чи **процес підписаний сертифікатом, підписаним Apple** (його видає лише Apple).
- Якщо це **не перевірено**, attacker може створити **підроблений сертифікат**, щоб відповідати будь-якій іншій перевірці.
2. Перевірити, чи процес, що підключається, підписаний **сертифікатом організації** (перевірка team ID).
- Якщо це **не перевірено**, для підпису та підключення до service можна використати **будь-який developer certificate** від Apple.
3. Перевірити, чи процес, що підключається, **містить правильний bundle ID**.
- Якщо це **не перевірено**, будь-який інструмент, **підписаний тією самою організацією**, можна використати для взаємодії з XPC service.
4. (4 або 5) Перевірити, чи процес, що підключається, має **правильний номер версії software**.
- Якщо це **не перевірено**, для підключення до XPC service можна використати старих, небезпечних clients, вразливих до process injection, навіть за наявності інших перевірок.
5. (4 або 5) Перевірити, чи процес, що підключається, має hardened runtime без небезпечних entitlements (наприклад, таких, що дозволяють завантажувати довільні libraries або використовувати DYLD env vars).
1. Якщо це **не перевірено**, client може бути **вразливим до code injection**.
6. Перевірити, чи процес, що підключається, має **entitlement**, який дозволяє йому підключатися до service. Це застосовується до Apple binaries.
7. **Перевірка** має ґрунтуватися **на audit token клієнта, що підключається**, а не на його ідентифікаторі процесу (**PID**), оскільки перший варіант запобігає **PID reuse attacks**.
- Developers **рідко використовують audit token** API call, оскільки він **private**, тому Apple може **змінити його** будь-коли. Крім того, використання private API не дозволене в Mac App Store apps.
- Якщо використовується метод **`processIdentifier`**, він може бути вразливим.
- Слід використовувати **`xpc_dictionary_get_audit_token`** замість **`xpc_connection_get_audit_token`**, оскільки останній також може бути [вразливим за певних обставин](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).<sup>[[5]](#references)</sup>

### Communication Attacks

Докладніше про PID reuse attack:


{{#ref}}
macos-pid-reuse.md
{{#endref}}

Докладніше про атаку на **`xpc_connection_get_audit_token`**:


{{#ref}}
macos-xpc_connection_get_audit_token-attack.md
{{#endref}}

### Trustcache - Запобігання Downgrade Attacks

Trustcache — це захисний метод, представлений у машинах з Apple Silicon, який зберігає базу даних CDHSAH Apple binaries, щоб можна було виконувати лише дозволені незміненi binaries. Це запобігає виконанню downgrade versions.

### Code Examples

Server реалізує цю **перевірку** у функції **`shouldAcceptNewConnection`**.
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
Об'єкт NSXPCConnection має **приватну** властивість **`auditToken`** (ту, яку слід використовувати, але яка може змінитися) та **публічну** властивість **`processIdentifier`** (ту, яку не слід використовувати).

Процес, що встановлює з'єднання, можна перевірити приблизно так:<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
```objectivec
[...]
SecRequirementRef requirementRef = NULL;
NSString requirementString = @"anchor apple generic and identifier \"xyz.hacktricks.service\" and certificate leaf [subject.CN] = \"TEAMID\" and info [CFBundleShortVersionString] >= \"1.0\"";
/* Check:
- Signed by a cert signed by Apple
- Check the bundle ID
- Check the TEAMID of the signing cert
- Check the version used
*/

// Check the requirements with the PID (vulnerable)
SecRequirementCreateWithString(requirementString, kSecCSDefaultFlags, &requirementRef);
SecCodeCheckValidity(code, kSecCSDefaultFlags, requirementRef);

// Check the requirements wuing the auditToken (secure)
SecTaskRef taskRef = SecTaskCreateWithAuditToken(NULL, ((ExtendedNSXPCConnection*)newConnection).auditToken);
SecTaskValidateForRequirement(taskRef, (__bridge CFStringRef)(requirementString))
```
Якщо розробник не хоче перевіряти версію клієнта, він принаймні може перевірити, що клієнт не вразливий до process injection:
```objectivec
[...]
CFDictionaryRef csInfo = NULL;
SecCodeCopySigningInformation(code, kSecCSDynamicInformation, &csInfo);
uint32_t csFlags = [((__bridge NSDictionary *)csInfo)[(__bridge NSString *)kSecCodeInfoStatus] intValue];
const uint32_t cs_hard = 0x100;        // don't load invalid page.
const uint32_t cs_kill = 0x200;        // Kill process if page is invalid
const uint32_t cs_restrict = 0x800;    // Prevent debugging
const uint32_t cs_require_lv = 0x2000; // Library Validation
const uint32_t cs_runtime = 0x10000;   // hardened runtime
if ((csFlags & (cs_hard | cs_require_lv)) {
return Yes; // Accept connection
}
```
Константи `cs_*` вище — це прапорці code-signing, визначені у `osfmk/kern/cs_blobs.h` XNU, тому їх можна перевірити за вихідним кодом, а не вгадувати:<sup>[[4]](#references)</sup>
```c
#define CS_HARD                     0x00000100  /* don't load invalid pages */
#define CS_KILL                     0x00000200  /* kill process if it becomes invalid */
#define CS_RESTRICT                 0x00000800  /* tell dyld to treat restricted */
#define CS_REQUIRE_LV               0x00002000  /* require library validation */
#define CS_RUNTIME                  0x00010000  /* Apply hardened runtime policies */
```
## Посилання

- [1] [Apple Developer — Мова вимог підписування коду](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html)
- [2] [Apple Developer — `SecCodeCheckValidity`](https://developer.apple.com/documentation/security/seccodecheckvalidity(_:_:_:))
- [3] [Apple Developer — `SecTaskCreateWithAuditToken`](https://developer.apple.com/documentation/security/sectaskcreatewithaudittoken(_:_:))
- [4] [XNU — `osfmk/kern/cs_blobs.h` (прапорці підписування коду `CS_*`)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [5] [Sector 7 — XPC audit token spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

{{#include ../../../../../../banners/hacktricks-training.md}}
