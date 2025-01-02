# macOS XPC Connecting Process Check

{{#include ../../../../../../banners/hacktricks-training.md}}

## XPC Connecting Process Check

Коли встановлюється з'єднання з XPC сервісом, сервер перевіряє, чи дозволено це з'єднання. Ось перевірки, які зазвичай виконуються:

1. Перевірте, чи **підписаний процес Apple-сертифікатом** (видається тільки Apple).
- Якщо це **не перевірено**, зловмисник може створити **підроблений сертифікат**, щоб відповідати будь-якій іншій перевірці.
2. Перевірте, чи підписаний процес **сертифікатом організації** (перевірка ID команди).
- Якщо це **не перевірено**, **будь-який сертифікат розробника** від Apple може бути використаний для підпису та підключення до сервісу.
3. Перевірте, чи **містить процес правильний ідентифікатор пакета**.
- Якщо це **не перевірено**, будь-який інструмент, **підписаний тією ж організацією**, може бути використаний для взаємодії з XPC сервісом.
4. (4 або 5) Перевірте, чи має процес **правильний номер версії програмного забезпечення**.
- Якщо це **не перевірено**, старі, небезпечні клієнти, вразливі до ін'єкцій процесів, можуть бути використані для підключення до XPC сервісу, навіть якщо інші перевірки виконані.
5. (4 або 5) Перевірте, чи має процес **захищений час виконання без небезпечних прав** (як ті, що дозволяють завантажувати довільні бібліотеки або використовувати змінні середовища DYLD).
1. Якщо це **не перевірено**, клієнт може бути **вразливим до ін'єкцій коду**.
6. Перевірте, чи має процес **право**, яке дозволяє йому підключатися до сервісу. Це стосується бінарних файлів Apple.
7. **Перевірка** повинна **базуватися** на **аудитному токені клієнта** **замість** його ідентифікатора процесу (**PID**), оскільки перше запобігає **атакам повторного використання PID**.
- Розробники **рідко використовують API виклик аудитного токена**, оскільки він **приватний**, тому Apple може **змінити** його в будь-який момент. Крім того, використання приватних API не дозволено в додатках Mac App Store.
- Якщо використовується метод **`processIdentifier`**, він може бути вразливим.
- **`xpc_dictionary_get_audit_token`** слід використовувати замість **`xpc_connection_get_audit_token`**, оскільки останній також може бути [вразливим у певних ситуаціях](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).

### Communication Attacks

Для отримання додаткової інформації про атаку повторного використання PID дивіться:

{{#ref}}
macos-pid-reuse.md
{{#endref}}

Для отримання додаткової інформації про атаку **`xpc_connection_get_audit_token`** дивіться:

{{#ref}}
macos-xpc_connection_get_audit_token-attack.md
{{#endref}}

### Trustcache - Downgrade Attacks Prevention

Trustcache - це захисний метод, введений в машинах Apple Silicon, який зберігає базу даних CDHSAH бінарних файлів Apple, щоб лише дозволені, не модифіковані бінарні файли могли виконуватися. Це запобігає виконанню версій з пониженим рівнем.

### Code Examples

Сервер реалізує цю **перевірку** в функції, яка називається **`shouldAcceptNewConnection`**.
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
Об'єкт NSXPCConnection має **приватну** властивість **`auditToken`** (ту, що повинна використовуватися, але може змінитися) та **публічну** властивість **`processIdentifier`** (ту, що не повинна використовуватися).

З'єднуючий процес можна перевірити за допомогою чогось на кшталт:
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
Якщо розробник не хоче перевіряти версію клієнта, він може принаймні перевірити, що клієнт не вразливий до ін'єкцій процесів:
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
{{#include ../../../../../../banners/hacktricks-training.md}}
