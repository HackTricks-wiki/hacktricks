# Verificação do Processo de Conexão XPC

{{#include ../../../../../../banners/hacktricks-training.md}}

## Verificação do Processo de Conexão XPC

Quando uma conexão é estabelecida com um serviço XPC, o servidor verificará se a conexão é permitida. Estas são as verificações que ele normalmente executaria:

1. Verificar se o **processo de conexão está assinado com um** certificado **assinado pela Apple** (fornecido apenas pela Apple).
- Se isso **não for verificado**, um atacante poderia criar um **certificado falso** para corresponder a qualquer outra verificação.
2. Verificar se o processo de conexão está assinado com o **certificado da organização** (verificação do team ID).
- Se isso **não for verificado**, qualquer **certificado de desenvolvedor** da Apple poderá ser usado para assinar e conectar-se ao serviço.
3. Verificar se o processo de conexão **contém um bundle ID apropriado**.
- Se isso **não for verificado**, qualquer ferramenta **assinada pela mesma organização** poderá ser usada para interagir com o serviço XPC.
4. (4 ou 5) Verificar se o processo de conexão possui um **número de versão de software apropriado**.
- Se isso **não for verificado**, um cliente antigo e inseguro vulnerável a process injection poderá ser usado para conectar-se ao serviço XPC, mesmo com as outras verificações implementadas.
5. (4 ou 5) Verificar se o processo de conexão possui hardened runtime sem entitlements perigosos (como os que permitem carregar bibliotecas arbitrárias ou usar variáveis de ambiente DYLD)
1. Se isso **não for verificado,** o cliente poderá estar **vulnerável a code injection**
6. Verificar se o processo de conexão possui um **entitlement** que permita conectá-lo ao serviço. Isso se aplica a binários da Apple.
7. A **verificação** deve ser **baseada** no **audit token** do **cliente** de conexão, **em vez** do seu ID de processo (**PID**), pois o primeiro impede **PID reuse attacks**.
- Os desenvolvedores **raramente usam a** API de **audit token** porque ela é **privada**, portanto a Apple pode **alterá-la** a qualquer momento. Além disso, o uso de APIs privadas não é permitido em aplicativos da Mac App Store.
- Se o método **`processIdentifier`** for usado, ele poderá estar vulnerável
- **`xpc_dictionary_get_audit_token`** deve ser usado em vez de **`xpc_connection_get_audit_token`**, pois o último também pode estar [vulnerável em determinadas situações](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).<sup>[[5]](#references)</sup>

### Ataques de Comunicação

Para obter mais informações sobre o ataque de PID reuse, consulte:


{{#ref}}
macos-pid-reuse.md
{{#endref}}

Para obter mais informações sobre o ataque **`xpc_connection_get_audit_token`**, consulte:


{{#ref}}
macos-xpc_connection_get_audit_token-attack.md
{{#endref}}

### Trustcache - Prevenção contra Ataques de Downgrade

Trustcache é um método defensivo introduzido nas máquinas Apple Silicon que armazena um banco de dados de CDHSAH de binários da Apple, para que apenas binários permitidos e não modificados possam ser executados. Isso impede a execução de versões downgrade.

### Exemplos de Código

O servidor implementará essa **verificação** em uma função chamada **`shouldAcceptNewConnection`**.
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
O objeto `NSXPCConnection` tem uma propriedade **privada** **`auditToken`** (a que deve ser usada, embora uma API privada possa mudar) e uma propriedade **pública** **`processIdentifier`** (que não deve ser usada para autenticação).

O processo de conexão poderia ser verificado com algo como:<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
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
Se um desenvolvedor não quiser verificar a versão do cliente, ele poderia pelo menos verificar se o cliente não é vulnerável a process injection:
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
As constantes `cs_*` acima são as flags de code-signing definidas em `osfmk/kern/cs_blobs.h` do XNU, portanto podem ser verificadas no código-fonte em vez de serem deduzidas:<sup>[[4]](#references)</sup>
```c
#define CS_HARD                     0x00000100  /* don't load invalid pages */
#define CS_KILL                     0x00000200  /* kill process if it becomes invalid */
#define CS_RESTRICT                 0x00000800  /* tell dyld to treat restricted */
#define CS_REQUIRE_LV               0x00002000  /* require library validation */
#define CS_RUNTIME                  0x00010000  /* Apply hardened runtime policies */
```
## References

- [1] [Apple Developer — Linguagem de requisitos de Code Signing](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html)
- [2] [Apple Developer — `SecCodeCheckValidity`](https://developer.apple.com/documentation/security/seccodecheckvalidity(_:_:_:))
- [3] [Apple Developer — `SecTaskCreateWithAuditToken`](https://developer.apple.com/documentation/security/sectaskcreatewithaudittoken(_:_:))
- [4] [XNU — `osfmk/kern/cs_blobs.h` (flags de code signing `CS_*`)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [5] [Sector 7 — XPC audit token spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
{{#include ../../../../../../banners/hacktricks-training.md}}
