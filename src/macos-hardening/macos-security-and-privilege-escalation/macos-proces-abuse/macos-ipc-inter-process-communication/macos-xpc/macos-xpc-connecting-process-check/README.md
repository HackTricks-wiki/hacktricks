# Vérification du processus de connexion XPC

{{#include ../../../../../../banners/hacktricks-training.md}}

## Vérification du processus de connexion XPC

Lorsqu’une connexion est établie avec un service XPC, le serveur vérifie si la connexion est autorisée. Voici les vérifications qu’il effectuerait généralement :

1. Vérifier si le **processus de connexion est signé avec un certificat signé par Apple** (délivré uniquement par Apple).
- Si cela **n’est pas vérifié**, un attaquant pourrait créer un **faux certificat** correspondant à n’importe quelle autre vérification.
2. Vérifier si le processus de connexion est signé avec le **certificat de l’organisation** (vérification de l’identifiant d’équipe).
- Si cela **n’est pas vérifié**, **n’importe quel certificat de développeur** d’Apple peut être utilisé pour signer le processus et se connecter au service.
3. Vérifier si le processus de connexion **contient un bundle ID approprié**.
- Si cela **n’est pas vérifié**, n’importe quel outil **signé par la même organisation** pourrait être utilisé pour interagir avec le service XPC.
4. (4 ou 5) Vérifier si le processus de connexion possède un **numéro de version logicielle approprié**.
- Si cela **n’est pas vérifié**, un ancien client non sécurisé vulnérable à l’injection de processus pourrait être utilisé pour se connecter au service XPC, même si les autres vérifications sont en place.
5. (4 ou 5) Vérifier si le processus de connexion dispose du hardened runtime sans entitlements dangereux (comme ceux qui permettent de charger des bibliothèques arbitraires ou d’utiliser des variables d’environnement DYLD)
1. Si cela **n’est pas vérifié,** le client pourrait être **vulnérable à l’injection de code**
6. Vérifier si le processus de connexion possède un **entitlement** qui lui permet de se connecter au service. Cela s’applique aux binaires Apple.
7. La **vérification** doit être **basée** sur l’**audit token** du **client de connexion**, **plutôt** que sur son identifiant de processus (**PID**), car le premier empêche les **PID reuse attacks**.
- Les développeurs utilisent **rarement l’API audit token** puisqu’elle est **privée** et qu’Apple pourrait donc la **modifier** à tout moment. De plus, l’utilisation d’API privées n’est pas autorisée dans les applications du Mac App Store.
- Si la méthode **`processIdentifier`** est utilisée, elle pourrait être vulnérable
- **`xpc_dictionary_get_audit_token`** doit être utilisée à la place de **`xpc_connection_get_audit_token`**, car cette dernière pourrait également être [vulnérable dans certaines situations](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).<sup>[[5]](#references)</sup>

### Attaques de communication

Pour plus d’informations sur l’attaque PID reuse, consultez :


{{#ref}}
macos-pid-reuse.md
{{#endref}}

Pour plus d’informations sur l’attaque **`xpc_connection_get_audit_token`**, consultez :


{{#ref}}
macos-xpc_connection_get_audit_token-attack.md
{{#endref}}

### Trustcache - Prévention des attaques de downgrade

Trustcache est une méthode défensive introduite sur les machines Apple Silicon qui stocke une base de données de CDHSAH des binaires Apple, afin que seuls les binaires non modifiés autorisés puissent être exécutés. Cela empêche l’exécution de versions downgrade.

### Exemples de code

Le serveur implémentera cette **vérification** dans une fonction appelée **`shouldAcceptNewConnection`**.
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
L’objet `NSXPCConnection` possède une propriété **privée** **`auditToken`** (celle qui devrait être utilisée, bien qu’une API privée puisse changer) et une propriété **publique** **`processIdentifier`** (qui ne devrait pas être utilisée pour l’authentification).

Le processus de connexion pourrait être vérifié comme suit :<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
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
Si un développeur ne souhaite pas vérifier la version du client, il pourrait au moins vérifier que le client n'est pas vulnérable à l'injection de processus :
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
Les constantes `cs_*` ci-dessus sont les indicateurs de code-signing définis dans `osfmk/kern/cs_blobs.h` de XNU ; elles peuvent donc être vérifiées à partir du code source plutôt que devinées :<sup>[[4]](#references)</sup>
```c
#define CS_HARD                     0x00000100  /* don't load invalid pages */
#define CS_KILL                     0x00000200  /* kill process if it becomes invalid */
#define CS_RESTRICT                 0x00000800  /* tell dyld to treat restricted */
#define CS_REQUIRE_LV               0x00002000  /* require library validation */
#define CS_RUNTIME                  0x00010000  /* Apply hardened runtime policies */
```
## References

- [1] [Apple Developer — Langage des exigences de signature de code](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html)
- [2] [Apple Developer — `SecCodeCheckValidity`](https://developer.apple.com/documentation/security/seccodecheckvalidity(_:_:_:))
- [3] [Apple Developer — `SecTaskCreateWithAuditToken`](https://developer.apple.com/documentation/security/sectaskcreatewithaudittoken(_:_:))
- [4] [XNU — `osfmk/kern/cs_blobs.h` (indicateurs de signature de code `CS_*`)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [5] [Sector 7 — usurpation de l’audit token XPC](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
{{#include ../../../../../../banners/hacktricks-training.md}}
