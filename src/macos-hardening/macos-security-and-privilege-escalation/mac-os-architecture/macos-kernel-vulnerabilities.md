# Vulnerabilidades do Kernel do macOS

{{#include ../../../banners/hacktricks-training.md}}

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

[**Neste relatório**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) são explicadas várias vulnerabilidades que permitiram comprometer o kernel comprometendo o atualizador de software.\
[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: Kernel 0-days em uso (CVE-2024-23225 & CVE-2024-23296)

A Apple corrigiu dois bugs de corrupção de memória que estavam sendo explorados ativamente contra iOS e macOS em março de 2024 (corrigido no macOS 14.4/13.6.5/12.7.4).

* **CVE-2024-23225 – Kernel**
• Escrita fora dos limites no subsistema de memória virtual XNU permite que um processo não privilegiado obtenha leitura/escrita arbitrária no espaço de endereços do kernel, contornando PAC/KTRR.
• Acionado a partir do espaço do usuário via uma mensagem XPC manipulada que transborda um buffer em `libxpc`, então pivota para o kernel quando a mensagem é analisada.
* **CVE-2024-23296 – RTKit**
• Corrupção de memória no RTKit da Apple Silicon (coprocessador em tempo real).
• Cadeias de exploração observadas usaram CVE-2024-23225 para R/W do kernel e CVE-2024-23296 para escapar da sandbox do coprocessador seguro e desativar o PAC.

Detecção do nível de patch:
```bash
sw_vers                 # ProductVersion 14.4 or later is patched
authenticate sudo sysctl kern.osversion  # 23E214 or later for Sonoma
```
Se a atualização não for possível, mitigue desativando serviços vulneráveis:
```bash
launchctl disable system/com.apple.analyticsd
launchctl disable system/com.apple.rtcreportingd
```
---

## 2023: MIG Type-Confusion – CVE-2023-41075

`mach_msg()` solicitações enviadas para um cliente IOKit de usuário não privilegiado levam a uma **confusão de tipo** no código de cola gerado pelo MIG. Quando a mensagem de resposta é reinterpretada com um descritor fora da linha maior do que o originalmente alocado, um atacante pode conseguir uma **escrita OOB** controlada nas zonas de heap do kernel e, eventualmente, escalar para `root`.

Esboço primitivo (Sonoma 14.0-14.1, Ventura 13.5-13.6):
```c
// userspace stub
typed_port_t p = get_user_client();
uint8_t spray[0x4000] = {0x41};
// heap-spray via IOSurfaceFastSetValue
io_service_open_extended(...);
// malformed MIG message triggers confusion
mach_msg(&msg.header, MACH_SEND_MSG|MACH_RCV_MSG, ...);
```
Explorações públicas armam o bug da seguinte forma:
1. Pulverizando buffers `ipc_kmsg` com ponteiros de porta ativos.
2. Sobrescrevendo `ip_kobject` de uma porta pendente.
3. Pulando para shellcode mapeado em um endereço forjado por PAC usando `mprotect()`.

---

## 2024-2025: Bypass do SIP através de Kexts de Terceiros – CVE-2024-44243 (também conhecido como “Sigma”)

Pesquisadores de segurança da Microsoft mostraram que o daemon de alto privilégio `storagekitd` pode ser forçado a carregar uma **extensão de kernel não assinada** e, assim, desativar completamente a **Proteção de Integridade do Sistema (SIP)** em macOS totalmente atualizado (anterior a 15.2). O fluxo de ataque é:

1. Abusar do direito privado `com.apple.storagekitd.kernel-management` para gerar um helper sob controle do atacante.
2. O helper chama `IOService::AddPersonalitiesFromKernelModule` com um dicionário de informações elaborado apontando para um pacote de kext malicioso.
3. Como as verificações de confiança do SIP são realizadas *após* o kext ser preparado pelo `storagekitd`, o código é executado em ring-0 antes da validação e o SIP pode ser desativado com `csr_set_allow_all(1)`.

Dicas de detecção:
```bash
kmutil showloaded | grep -v com.apple   # list non-Apple kexts
log stream --style syslog --predicate 'senderImagePath contains "storagekitd"'   # watch for suspicious child procs
```
A remediação imediata é atualizar para o macOS Sequoia 15.2 ou posterior.

---

### Cheatsheet de Enumeração Rápida
```bash
uname -a                          # Kernel build
kmutil showloaded                 # List loaded kernel extensions
kextstat | grep -v com.apple      # Legacy (pre-Catalina) kext list
sysctl kern.kaslr_enable          # Verify KASLR is ON (should be 1)
csrutil status                    # Check SIP from RecoveryOS
spctl --status                    # Confirms Gatekeeper state
```
---

## Fuzzing & Research Tools

* **Luftrauser** – Fuzzer de mensagens Mach que visa subsistemas MIG (`github.com/preshing/luftrauser`).
* **oob-executor** – Gerador de primitivos de IPC fora dos limites usado na pesquisa CVE-2024-23225.
* **kmutil inspect** – Utilitário embutido da Apple (macOS 11+) para analisar estaticamente kexts antes de carregar: `kmutil inspect -b io.kext.bundleID`.



## References

* Apple. “About the security content of macOS Sonoma 14.4.” https://support.apple.com/en-us/120895
* Microsoft Security Blog. “Analyzing CVE-2024-44243, a macOS System Integrity Protection bypass through kernel extensions.” https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/
{{#include ../../../banners/hacktricks-training.md}}
