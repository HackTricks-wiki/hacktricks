# Перевірка процесу, що підключається до macOS XPC

{{#include ../../../../../../banners/hacktricks-training.md}}

## Перевірка процесу, що підключається до XPC

Коли встановлюється з'єднання з XPC service, сервер перевіряє, чи дозволене це з'єднання. Зазвичай виконуються такі перевірки:

1. Перевірка, чи **процес підписаний сертифікатом, підписаним Apple** (його видає лише Apple).
- Якщо це **не перевіряється**, attacker може створити **підроблений сертифікат**, який відповідатиме будь-якій іншій перевірці.
2. Перевірка, чи процес підписаний **сертифікатом організації** (перевірка team ID).
- Якщо це **не перевіряється**, для підпису та підключення до service можна використати **будь-який developer certificate** від Apple.
3. Перевірка, чи **процес містить правильний bundle ID**.
- Якщо це **не перевіряється**, для взаємодії з XPC service можна використати будь-який інструмент, **підписаний тією самою організацією**.
4. (4 або 5) Перевірка, чи процес має **правильний номер версії програмного забезпечення**.
- Якщо це **не перевіряється**, для підключення до XPC service можна використати старий, небезпечний клієнт, вразливий до process injection, навіть за наявності інших перевірок.
5. (4 або 5) Перевірка, чи процес використовує hardened runtime без небезпечних entitlements (наприклад, таких, що дозволяють завантажувати довільні бібліотеки або використовувати змінні середовища DYLD).
1. Якщо це **не перевіряється**, клієнт може бути **вразливим до code injection**.
6. Перевірка, чи процес має **entitlement**, який дозволяє йому підключатися до service. Це застосовується до Apple binaries.
7. **Перевірка** має ґрунтуватися на **audit token клієнта**, що підключається, **замість** його ідентифікатора процесу (**PID**), оскільки перший підхід запобігає **PID reuse attacks**.
- **Розробники рідко використовують API audit token**, оскільки він є **приватним**, тому Apple може **змінити його** в будь-який момент. Крім того, використання private API не дозволене в програмах Mac App Store.
- Якщо використовується метод **`processIdentifier`**, він може бути вразливим.
- Слід використовувати **`xpc_dictionary_get_audit_token`** замість **`xpc_connection_get_audit_token`**, оскільки останній також може бути [вразливим у певних ситуаціях](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).<sup>[[5]](#references)</sup>

### Атаки на комунікацію

Докладнішу інформацію про PID reuse attack дивіться тут:


{{#ref}}
macos-pid-reuse.md
{{#endref}}

Докладнішу інформацію про атаку на **`xpc_connection_get_audit_token`** дивіться тут:


{{#ref}}
macos-xpc_connection_get_audit_token-attack.md
{{#endref}}

### Trustcache - Запобігання downgrade attacks

Trustcache — це захисний метод, представлений у машинах Apple Silicon, який зберігає базу даних CDHSAH Apple binaries, щоб можна було виконувати лише дозволені незмінені binaries. Це запобігає виконанню downgrade versions.

### Приклади коду

Сервер реалізує цю **перевірку** у функції **`shouldAcceptNewConnection`**.
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
Об’єкт `NSXPCConnection` має **private** властивість **`auditToken`** (саме її слід використовувати, хоча private API може змінитися) і **public** властивість **`processIdentifier`** (її не слід використовувати для аутентифікації).

Процес, що встановлює з’єднання, можна перевірити приблизно так:<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
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
Якщо розробник не хоче перевіряти версію клієнта, він принаймні міг би перевірити, що клієнт не вразливий до process injection:
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
Константи `cs_*` вище — це прапорці code-signing, визначені в `osfmk/kern/cs_blobs.h` XNU, тому їх можна перевірити за вихідним кодом, а не вгадувати:<sup>[[4]](#references)</sup>
```c
#define CS_HARD                     0x00000100  /* don't load invalid pages */
#define CS_KILL                     0x00000200  /* kill process if it becomes invalid */
#define CS_RESTRICT                 0x00000800  /* tell dyld to treat restricted */
#define CS_REQUIRE_LV               0x00002000  /* require library validation */
#define CS_RUNTIME                  0x00010000  /* Apply hardened runtime policies */
```
## References

- [1] [Apple Developer — Мова вимог Code Signing](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html)
- [2] [Apple Developer — `SecCodeCheckValidity`](https://developer.apple.com/documentation/security/seccodecheckvalidity(_:_:_:))
- [3] [Apple Developer — `SecTaskCreateWithAuditToken`](https://developer.apple.com/documentation/security/sectaskcreatewithaudittoken(_:_:))
- [4] [XNU — `osfmk/kern/cs_blobs.h` (прапорці підпису коду `CS_*`)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [5] [Sector 7 — підміна audit token у XPC](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
{{#include ../../../../../../banners/hacktricks-training.md}}
