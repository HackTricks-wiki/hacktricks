# macOS XPC Connecting Process Check

{{#include ../../../../../../banners/hacktricks-training.md}}

## XPC Connecting Process Check

Lorsqu'une connexion est établie à un service XPC, le serveur vérifiera si la connexion est autorisée. Voici les vérifications qu'il effectuerait généralement :

1. Vérifiez si le **processus de connexion est signé avec un certificat signé par Apple** (uniquement délivré par Apple).
- Si cela **n'est pas vérifié**, un attaquant pourrait créer un **certificat falsifié** pour correspondre à toute autre vérification.
2. Vérifiez si le processus de connexion est signé avec le **certificat de l'organisation** (vérification de l'ID d'équipe).
- Si cela **n'est pas vérifié**, **tout certificat de développeur** d'Apple peut être utilisé pour signer et se connecter au service.
3. Vérifiez si le processus de connexion **contient un ID de bundle approprié**.
- Si cela **n'est pas vérifié**, tout outil **signé par la même org** pourrait être utilisé pour interagir avec le service XPC.
4. (4 ou 5) Vérifiez si le processus de connexion a un **numéro de version de logiciel approprié**.
- Si cela **n'est pas vérifié**, un ancien client non sécurisé, vulnérable à l'injection de processus, pourrait être utilisé pour se connecter au service XPC même avec les autres vérifications en place.
5. (4 ou 5) Vérifiez si le processus de connexion a un runtime durci sans droits dangereux (comme ceux qui permettent de charger des bibliothèques arbitraires ou d'utiliser des variables d'environnement DYLD).
1. Si cela **n'est pas vérifié**, le client pourrait être **vulnérable à l'injection de code**.
6. Vérifiez si le processus de connexion a un **droit** qui lui permet de se connecter au service. Cela s'applique aux binaires Apple.
7. La **vérification** doit être **basée** sur le **jeton d'audit du client de connexion** **au lieu** de son ID de processus (**PID**) puisque le premier empêche les **attaques de réutilisation de PID**.
- Les développeurs **utilisent rarement l'API de jeton d'audit** car elle est **privée**, donc Apple pourrait **changer** à tout moment. De plus, l'utilisation d'API privées n'est pas autorisée dans les applications du Mac App Store.
- Si la méthode **`processIdentifier`** est utilisée, elle pourrait être vulnérable.
- **`xpc_dictionary_get_audit_token`** devrait être utilisé à la place de **`xpc_connection_get_audit_token`**, car ce dernier pourrait également être [vulnérable dans certaines situations](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).

### Communication Attacks

Pour plus d'informations sur l'attaque de réutilisation de PID, consultez :

{{#ref}}
macos-pid-reuse.md
{{#endref}}

Pour plus d'informations sur l'attaque **`xpc_connection_get_audit_token`**, consultez :

{{#ref}}
macos-xpc_connection_get_audit_token-attack.md
{{#endref}}

### Trustcache - Downgrade Attacks Prevention

Trustcache est une méthode défensive introduite dans les machines Apple Silicon qui stocke une base de données de CDHSAH des binaires Apple afin que seuls les binaires non modifiés autorisés puissent être exécutés. Cela empêche l'exécution de versions rétrogrades.

### Code Examples

Le serveur mettra en œuvre cette **vérification** dans une fonction appelée **`shouldAcceptNewConnection`**.
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
L'objet NSXPCConnection a une propriété **privée** **`auditToken`** (celle qui devrait être utilisée mais qui pourrait changer) et une propriété **publique** **`processIdentifier`** (celle qui ne devrait pas être utilisée).

Le processus de connexion pourrait être vérifié avec quelque chose comme :
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
Si un développeur ne veut pas vérifier la version du client, il pourrait vérifier que le client n'est pas vulnérable à l'injection de processus au moins :
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
