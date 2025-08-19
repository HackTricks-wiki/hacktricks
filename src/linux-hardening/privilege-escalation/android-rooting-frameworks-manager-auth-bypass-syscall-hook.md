# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

Frameworks de rooting como KernelSU, APatch, SKRoot e Magisk frequentemente patcham o kernel Linux/Android e expõem funcionalidades privilegiadas a um aplicativo "gerenciador" de espaço de usuário não privilegiado através de uma syscall hookada. Se a etapa de autenticação do gerenciador for falha, qualquer aplicativo local pode acessar esse canal e escalar privilégios em dispositivos já rootados.

Esta página abstrai as técnicas e armadilhas descobertas em pesquisas públicas (notavelmente a análise da Zimperium do KernelSU v0.5.7) para ajudar tanto equipes vermelhas quanto azuis a entender superfícies de ataque, primitivas de exploração e mitigações robustas.

---
## Padrão de arquitetura: canal de gerenciador com syscall hookada

- O módulo/patch do kernel hooka uma syscall (comumente prctl) para receber "comandos" do espaço de usuário.
- O protocolo geralmente é: magic_value, command_id, arg_ptr/len ...
- Um aplicativo gerenciador de espaço de usuário autentica primeiro (por exemplo, CMD_BECOME_MANAGER). Uma vez que o kernel marca o chamador como um gerenciador confiável, comandos privilegiados são aceitos:
- Conceder root ao chamador (por exemplo, CMD_GRANT_ROOT)
- Gerenciar listas de permissão/rejeição para su
- Ajustar a política SELinux (por exemplo, CMD_SET_SEPOLICY)
- Consultar versão/configuração
- Porque qualquer aplicativo pode invocar syscalls, a correção da autenticação do gerenciador é crítica.

Exemplo (design do KernelSU):
- Syscall hookada: prctl
- Valor mágico para desviar para o manipulador do KernelSU: 0xDEADBEEF
- Comandos incluem: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, etc.

---
## Fluxo de autenticação do KernelSU v0.5.7 (como implementado)

Quando o espaço de usuário chama prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...), o KernelSU verifica:

1) Verificação de prefixo de caminho
- O caminho fornecido deve começar com um prefixo esperado para o UID do chamador, por exemplo, /data/data/<pkg> ou /data/user/<id>/<pkg>.
- Referência: core_hook.c (v0.5.7) lógica de prefixo de caminho.

2) Verificação de propriedade
- O caminho deve ser de propriedade do UID do chamador.
- Referência: core_hook.c (v0.5.7) lógica de propriedade.

3) Verificação de assinatura APK via varredura da tabela FD
- Iterar os descritores de arquivo abertos (FDs) do processo chamador.
- Escolher o primeiro arquivo cujo caminho corresponda a /data/app/*/base.apk.
- Analisar a assinatura APK v2 e verificar contra o certificado oficial do gerenciador.
- Referências: manager.c (iterando FDs), apk_sign.c (verificação APK v2).

Se todas as verificações passarem, o kernel armazena temporariamente o UID do gerenciador e aceita comandos privilegiados desse UID até ser redefinido.

---
## Classe de vulnerabilidade: confiar no “primeiro APK correspondente” da iteração FD

Se a verificação de assinatura se vincula ao "primeiro /data/app/*/base.apk correspondente" encontrado na tabela FD do processo, na verdade não está verificando o próprio pacote do chamador. Um atacante pode pré-posicionar um APK assinado legitimamente (o verdadeiro gerenciador) para que ele apareça antes na lista de FD do que seu próprio base.apk.

Essa confiança por indireção permite que um aplicativo não privilegiado se passe pelo gerenciador sem possuir a chave de assinatura do gerenciador.

Propriedades-chave exploradas:
- A varredura de FD não se vincula à identidade do pacote do chamador; ela apenas combina padrões de strings de caminho.
- open() retorna o menor FD disponível. Ao fechar FDs de números mais baixos primeiro, um atacante pode controlar a ordem.
- O filtro apenas verifica se o caminho corresponde a /data/app/*/base.apk – não que corresponda ao pacote instalado do chamador.

---
## Pré-condições de ataque

- O dispositivo já está rootado com um framework de rooting vulnerável (por exemplo, KernelSU v0.5.7).
- O atacante pode executar código arbitrário não privilegiado localmente (processo de aplicativo Android).
- O verdadeiro gerenciador ainda não autenticou (por exemplo, logo após uma reinicialização). Alguns frameworks armazenam em cache o UID do gerenciador após o sucesso; você deve vencer a corrida.

---
## Esboço de exploração (KernelSU v0.5.7)

Passos de alto nível:
1) Construir um caminho válido para o diretório de dados do seu próprio aplicativo para satisfazer as verificações de prefixo e propriedade.
2) Garantir que um base.apk genuíno do KernelSU Manager esteja aberto em um FD de número mais baixo do que seu próprio base.apk.
3) Invocar prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) para passar nas verificações.
4) Emitir comandos privilegiados como CMD_GRANT_ROOT, CMD_ALLOW_SU, CMD_SET_SEPOLICY para persistir a elevação.

Notas práticas sobre o passo 2 (ordenação de FD):
- Identificar o FD do seu processo para seu próprio /data/app/*/base.apk caminhando pelos symlinks de /proc/self/fd.
- Fechar um FD baixo (por exemplo, stdin, fd 0) e abrir o APK legítimo do gerenciador primeiro para que ele ocupe o fd 0 (ou qualquer índice inferior ao seu próprio fd base.apk).
- Agrupar o APK legítimo do gerenciador com seu aplicativo para que seu caminho satisfaça o filtro ingênuo do kernel. Por exemplo, colocá-lo sob um subcaminho correspondente a /data/app/*/base.apk.

Exemplos de trechos de código (Android/Linux, apenas ilustrativos):

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
Force um FD de número mais baixo a apontar para o APK do gerente legítimo:
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
Autenticação do gerente via hook prctl:
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
- CMD_ALLOW_SU: adicionar seu pacote/UID à lista de permissões para su persistente
- CMD_SET_SEPOLICY: ajustar a política SELinux conforme suportado pelo framework

Dica de corrida/persistência:
- Registre um receptor BOOT_COMPLETED no AndroidManifest (RECEIVE_BOOT_COMPLETED) para iniciar cedo após a reinicialização e tentar autenticação antes do gerenciador real.

---
## Orientações de detecção e mitigação

Para desenvolvedores de frameworks:
- Vincule a autenticação ao pacote/UID do chamador, não a FDs arbitrários:
- Resolva o pacote do chamador a partir de seu UID e verifique contra a assinatura do pacote instalado (via PackageManager) em vez de escanear FDs.
- Se for apenas kernel, use identidade de chamador estável (credenciais de tarefa) e valide em uma fonte de verdade estável gerenciada por init/ajudante de userspace, não FDs de processo.
- Evite verificações de prefixo de caminho como identidade; elas são trivialmente satisfatórias pelo chamador.
- Use desafio-resposta baseado em nonce sobre o canal e limpe qualquer identidade de gerenciador em cache na inicialização ou em eventos-chave.
- Considere IPC autenticado baseado em binder em vez de sobrecarregar syscalls genéricos quando viável.

Para defensores/equipe azul:
- Detecte a presença de frameworks de rooting e processos de gerenciador; monitore chamadas prctl com constantes mágicas suspeitas (por exemplo, 0xDEADBEEF) se você tiver telemetria do kernel.
- Em frotas gerenciadas, bloqueie ou alerte sobre receptores de inicialização de pacotes não confiáveis que tentam rapidamente comandos privilegiados de gerenciador após a inicialização.
- Certifique-se de que os dispositivos estejam atualizados para versões de framework corrigidas; invalide IDs de gerenciador em cache na atualização.

Limitações do ataque:
- Afeta apenas dispositivos já enraizados com um framework vulnerável.
- Normalmente requer uma janela de reinicialização/corrida antes que o gerenciador legítimo autentique (alguns frameworks armazenam em cache o UID do gerenciador até a redefinição).

---
## Notas relacionadas entre frameworks

- A autenticação baseada em senha (por exemplo, versões históricas do APatch/SKRoot) pode ser fraca se as senhas forem adivinháveis/bruteforceáveis ou se as validações forem com falhas.
- A autenticação baseada em pacote/assinatura (por exemplo, KernelSU) é mais forte em princípio, mas deve estar vinculada ao chamador real, não a artefatos indiretos como escaneamentos de FD.
- Magisk: CVE-2024-48336 (MagiskEoP) mostrou que até ecossistemas maduros podem ser suscetíveis a falsificação de identidade levando à execução de código com root dentro do contexto do gerenciador.

---
## Referências

- [Zimperium – The Rooting of All Evil: Security Holes That Could Compromise Your Mobile Device](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [KernelSU v0.5.7 – core_hook.c path checks (L193, L201)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L193)
- [KernelSU v0.5.7 – manager.c FD iteration/signature check (L43+)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L43)
- [KernelSU – apk_sign.c APK v2 verification (main)](https://github.com/tiann/KernelSU/blob/main/kernel/apk_sign.c#L319)
- [KernelSU project](https://kernelsu.org/)
- [APatch](https://github.com/bmax121/APatch)
- [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [KSU PoC demo video (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)

{{#include ../../banners/hacktricks-training.md}}
