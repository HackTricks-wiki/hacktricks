# macOS XPC Connecting Process Check

{{#include ../../../../../../banners/hacktricks-training.md}}

## XPC Connecting Process Check

Quando uma conexão é estabelecida a um serviço XPC, o servidor verificará se a conexão é permitida. Estas são as verificações que geralmente seriam realizadas:

1. Verifique se o **processo de conexão está assinado com um certificado assinado pela Apple** (somente fornecido pela Apple).
- Se isso **não for verificado**, um atacante poderia criar um **certificado falso** para corresponder a qualquer outra verificação.
2. Verifique se o processo de conexão está assinado com o **certificado da organização** (verificação do ID da equipe).
- Se isso **não for verificado**, **qualquer certificado de desenvolvedor** da Apple pode ser usado para assinatura e conectar-se ao serviço.
3. Verifique se o processo de conexão **contém um ID de pacote apropriado**.
- Se isso **não for verificado**, qualquer ferramenta **assinada pela mesma organização** poderia ser usada para interagir com o serviço XPC.
4. (4 ou 5) Verifique se o processo de conexão tem um **número de versão de software apropriado**.
- Se isso **não for verificado**, um cliente antigo e inseguro, vulnerável a injeção de processos, poderia ser usado para conectar-se ao serviço XPC, mesmo com as outras verificações em vigor.
5. (4 ou 5) Verifique se o processo de conexão tem um runtime endurecido sem direitos perigosos (como aqueles que permitem carregar bibliotecas arbitrárias ou usar variáveis de ambiente DYLD).
1. Se isso **não for verificado**, o cliente pode ser **vulnerável a injeção de código**.
6. Verifique se o processo de conexão tem um **direito** que permite conectar-se ao serviço. Isso é aplicável para binários da Apple.
7. A **verificação** deve ser **baseada** no **token de auditoria do cliente de conexão** **em vez** de seu ID de processo (**PID**), uma vez que o primeiro previne **ataques de reutilização de PID**.
- Os desenvolvedores **raramente usam a chamada de API do token de auditoria** uma vez que é **privada**, então a Apple poderia **mudar** a qualquer momento. Além disso, o uso de API privada não é permitido em aplicativos da Mac App Store.
- Se o método **`processIdentifier`** for usado, ele pode ser vulnerável.
- **`xpc_dictionary_get_audit_token`** deve ser usado em vez de **`xpc_connection_get_audit_token`**, pois o último também pode ser [vulnerável em certas situações](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).

### Communication Attacks

Para mais informações sobre o ataque de reutilização de PID, verifique:

{{#ref}}
macos-pid-reuse.md
{{#endref}}

Para mais informações sobre o ataque **`xpc_connection_get_audit_token`**, verifique:

{{#ref}}
macos-xpc_connection_get_audit_token-attack.md
{{#endref}}

### Trustcache - Prevenção de Ataques de Downgrade

Trustcache é um método defensivo introduzido em máquinas Apple Silicon que armazena um banco de dados de CDHSAH de binários da Apple, de modo que apenas binários não modificados permitidos possam ser executados. Isso previne a execução de versões de downgrade.

### Code Examples

O servidor implementará essa **verificação** em uma função chamada **`shouldAcceptNewConnection`**.
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
O objeto NSXPCConnection tem uma propriedade **privada** **`auditToken`** (a que deve ser usada, mas pode mudar) e uma propriedade **pública** **`processIdentifier`** (a que não deve ser usada).

O processo de conexão pode ser verificado com algo como:
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
Se um desenvolvedor não quiser verificar a versão do cliente, ele poderia verificar se o cliente não é vulnerável a injeção de processo, pelo menos:
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
