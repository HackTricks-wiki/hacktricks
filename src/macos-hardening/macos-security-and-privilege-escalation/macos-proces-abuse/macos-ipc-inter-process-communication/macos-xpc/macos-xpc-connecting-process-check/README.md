# Перевірка процесу, що підключається до macOS XPC

{{#include ../../../../../../banners/hacktricks-training.md}}

## Перевірка процесу, що підключається до XPC

Коли встановлюється з'єднання з XPC-сервісом, сервер перевіряє, чи дозволене це з'єднання. Зазвичай він виконує такі перевірки:

1. Перевіряє, чи **процес, що підключається, підписаний сертифікатом, підписаним Apple** (такі сертифікати видає лише Apple).
- Якщо це **не перевіряється**, атакувальник може створити **підроблений сертифікат**, який відповідатиме будь-якій іншій перевірці.
2. Перевіряє, чи процес, що підключається, підписаний **сертифікатом організації** (перевірка team ID).
- Якщо це **не перевіряється**, для підпису та підключення до сервісу можна використати **будь-який сертифікат розробника** від Apple.
3. Перевіряє, чи **процес, що підключається, містить правильний bundle ID**.
- Якщо це **не перевіряється**, будь-який інструмент, **підписаний тією самою організацією**, можна використати для взаємодії з XPC-сервісом.
4. (4 або 5) Перевіряє, чи процес, що підключається, має **правильний номер версії програмного забезпечення**.
- Якщо це **не перевіряється**, для підключення до XPC-сервісу можна використати старих, небезпечних клієнтів, вразливих до ін'єкції в процес, навіть за наявності інших перевірок.
5. (4 або 5) Перевіряє, чи процес, що підключається, має hardened runtime без небезпечних entitlements (наприклад, таких, що дозволяють завантажувати довільні бібліотеки або використовувати змінні середовища DYLD)
1. Якщо це **не перевіряється**, клієнт може бути **вразливим до ін'єкції коду**
6. Перевіряє, чи процес, що підключається, має **entitlement**, який дозволяє йому підключатися до сервісу. Це застосовується до бінарних файлів Apple.
7. **Перевірка** має **ґрунтуватися** на **audit token клієнта**, що підключається, **а не** на його ідентифікаторі процесу (**PID**), оскільки перший запобігає **атакам із повторним використанням PID**.
- Розробники **рідко використовують API audit token**, оскільки він є **приватним**, тому Apple може **змінити** його будь-коли. Крім того, використання приватних API заборонене в застосунках Mac App Store.
- Якщо використовується метод **`processIdentifier`**, він може бути вразливим
- Замість **`xpc_connection_get_audit_token`** слід використовувати **`xpc_dictionary_get_audit_token`**, оскільки останній також може бути [вразливим за певних обставин](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).<sup>[[5]](#references)</sup>

### Атаки на комунікацію

Докладнішу інформацію про атаку з повторним використанням PID дивіться тут:


{{#ref}}
macos-pid-reuse.md
{{#endref}}

Докладнішу інформацію про атаку **`xpc_connection_get_audit_token`** дивіться тут:


{{#ref}}
macos-xpc_connection_get_audit_token-attack.md
{{#endref}}

### Trustcache — запобігання атакам зі зниженням версії

Trustcache — це захисний метод, представлений у машинах з Apple Silicon, який зберігає базу даних CDHSAH бінарних файлів Apple, щоб можна було виконувати лише дозволені незміненені бінарні файли. Це запобігає виконанню версій зі зниженим рівнем.

### Приклади коду

Сервер реалізує цю **перевірку** у функції під назвою **`shouldAcceptNewConnection`**.
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
Об'єкт NSXPCConnection має **приватну** властивість **`auditToken`** (саме її слід використовувати, але її можуть змінити) і **публічну** властивість **`processIdentifier`** (саме її не слід використовувати).

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
Якщо розробник не хоче перевіряти версію клієнта, він принаймні міг би перевірити, що клієнт не вразливий до ін'єкції процесів:
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
Константи `cs_*` вище — це прапори code-signing, визначені у `osfmk/kern/cs_blobs.h` XNU, тому їх можна звірити з вихідним кодом, а не вгадувати:<sup>[[4]](#references)</sup>
```c
#define CS_HARD                     0x00000100  /* don't load invalid pages */
#define CS_KILL                     0x00000200  /* kill process if it becomes invalid */
#define CS_RESTRICT                 0x00000800  /* tell dyld to treat restricted */
#define CS_REQUIRE_LV               0x00002000  /* require library validation */
#define CS_RUNTIME                  0x00010000  /* Apply hardened runtime policies */
```
## Посилання

- [1] [Apple Developer — Мова вимог Code Signing](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html)
- [2] [Apple Developer — `SecCodeCheckValidity`](https://developer.apple.com/documentation/security/seccodecheckvalidity(_:_:_:))
- [3] [Apple Developer — `SecTaskCreateWithAuditToken`](https://developer.apple.com/documentation/security/sectaskcreatewithaudittoken(_:_:))
- [4] [XNU — `osfmk/kern/cs_blobs.h` (прапорці Code Signing `CS_*`)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [5] [Sector 7 — spoofing audit token у XPC](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

{{#include ../../../../../../banners/hacktricks-training.md}}
