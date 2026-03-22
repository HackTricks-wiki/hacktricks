# Avaliação e Hardening

{{#include ../../../banners/hacktricks-training.md}}

## Visão geral

Uma boa avaliação de container deve responder a duas perguntas paralelas. Primeiro, o que um atacante pode fazer a partir do workload atual? Segundo, quais escolhas do operador tornaram isso possível? Ferramentas de enumeration ajudam com a primeira pergunta, e orientações de hardening ajudam com a segunda. Manter ambas em uma única página torna a seção mais útil como referência de campo em vez de apenas um catálogo de truques de escape.

## Ferramentas de Enumeração

Várias ferramentas permanecem úteis para caracterizar rapidamente um ambiente de container:

- `linpeas` pode identificar muitos indicadores de container, sockets montados, conjuntos de capability, sistemas de arquivos perigosos e pistas de breakout.
- `CDK` foca especificamente em ambientes de container e inclui enumeração além de algumas verificações automatizadas de escape.
- `amicontained` é leve e útil para identificar restrições de container, capabilities, exposição de namespace e classes prováveis de breakout.
- `deepce` é outro enumerador focado em container com verificações orientadas a breakout.
- `grype` é útil quando a avaliação inclui revisão de vulnerabilidades de pacotes da image em vez de apenas análise de escape em runtime.

O valor dessas ferramentas é velocidade e cobertura, não certeza. Elas ajudam a revelar rapidamente a postura geral, mas as descobertas interessantes ainda precisam de interpretação manual contra o modelo real de runtime, namespace, capability e mount.

## Prioridades de Hardening

Os princípios de hardening mais importantes são conceitualmente simples, embora sua implementação varie por plataforma. Evite containers privilegiados. Evite sockets de runtime montados. Não dê containers caminhos host graváveis a menos que haja uma razão muito específica. Use user namespaces ou execução rootless quando viável. Remova todas as capabilities e adicione de volta apenas as que o workload realmente precisa. Mantenha seccomp, AppArmor e SELinux habilitados em vez de desabilitá-los para resolver problemas de compatibilidade de aplicações. Limite recursos para que um container comprometido não possa, trivialmente, negar serviço ao host.

Higiene de image e build importa tanto quanto a postura em runtime. Use images mínimas, reconstrua com frequência, escaneie-as, exija proveniência quando prático e mantenha secrets fora das layers. Um container rodando como non-root com uma image pequena e uma superfície estreita de syscall e capability é muito mais fácil de defender do que uma image grande de conveniência rodando como root equivalente ao host com ferramentas de debug pré-instaladas.

## Exemplos de Exaustão de Recursos

Controles de recurso não são glamourosos, mas fazem parte da segurança de container porque limitam o raio de explosão do comprometimento. Sem limites de memória, CPU ou PID, um shell simples pode ser suficiente para degradar o host ou workloads vizinhos.

Exemplos de testes com impacto no host:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Estes exemplos são úteis porque mostram que nem todo resultado perigoso de container é um "escape" limpo. Limites fracos de cgroup ainda podem transformar a execução de código em impacto operacional real.

## Ferramentas de hardening

Para ambientes centrados em Docker, `docker-bench-security` continua sendo uma linha de base útil de auditoria no host porque verifica problemas comuns de configuração contra diretrizes de benchmark amplamente reconhecidas:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
A ferramenta não substitui threat modeling, mas ainda é valiosa para encontrar configurações padrão descuidadas de daemon, mount, network e runtime que se acumulam ao longo do tempo.

## Verificações

Use estes como comandos rápidos de primeira triagem durante a avaliação:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
O que é interessante aqui:

- Um processo root com capacidades amplas e `Seccomp: 0` merece atenção imediata.
- Mounts suspeitos e sockets de runtime frequentemente fornecem um caminho mais rápido para impacto do que qualquer kernel exploit.
- A combinação de uma postura de runtime fraca e limites de recursos frouxos geralmente indica um ambiente de container permissivo, em vez de um único erro isolado.
{{#include ../../../banners/hacktricks-training.md}}
