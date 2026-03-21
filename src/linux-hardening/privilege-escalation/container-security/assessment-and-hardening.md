# Avaliação e Endurecimento

{{#include ../../../banners/hacktricks-training.md}}

## Visão geral

Uma boa avaliação de container deve responder a duas perguntas paralelas. Primeiro, o que um atacante pode fazer a partir do workload atual? Segundo, quais escolhas do operador tornaram isso possível? Ferramentas de enumeração ajudam com a primeira pergunta, e orientações de hardening ajudam com a segunda. Manter ambos em uma única página torna a seção mais útil como referência de campo em vez de apenas um catálogo de truques de escape.

## Ferramentas de Enumeração

Várias ferramentas continuam úteis para caracterizar rapidamente um ambiente de container:

- `linpeas` pode identificar muitos indicadores de container, sockets montados, conjuntos de capabilities, sistemas de arquivos perigosos e breakout hints.
- `CDK` foca especificamente em ambientes de container e inclui enumeração mais alguns automated escape checks.
- `amicontained` é leve e útil para identificar container restrictions, capabilities, namespace exposure e prováveis breakout classes.
- `deepce` é outro enumerador focado em container com checagens orientadas a breakout.
- `grype` é útil quando a avaliação inclui revisão de vulnerabilidades de image-package em vez de apenas análise de runtime escape.

O valor dessas ferramentas é velocidade e cobertura, não certeza. Elas ajudam a revelar rapidamente a postura geral, mas as descobertas interessantes ainda precisam de interpretação manual em relação ao modelo real de runtime, namespace, capability e mounts.

## Prioridades de Endurecimento

Os princípios de hardening mais importantes são conceitualmente simples, embora sua implementação varie por plataforma. Evite containers privilegiados. Evite sockets de runtime montados. Não dê aos containers host paths graváveis a menos que haja uma razão muito específica. Use user namespaces ou rootless execution quando viável. Drop all capabilities e adicione de volta apenas as que o workload realmente precisa. Mantenha seccomp, AppArmor e SELinux habilitados em vez de desativá-los para resolver problemas de compatibilidade de aplicação. Limite recursos para que um container comprometido não possa trivialmente causar denial of service ao host.

Higiene de image e do processo de build importam tanto quanto a postura de runtime. Use imagens mínimas, reconstrua com frequência, escaneie-as, exija provenance quando prático e mantenha secrets fora das layers. Um container rodando como non-root com uma imagem pequena e uma superfície de syscall e capability estreita é muito mais fácil de defender do que uma imagem grande de conveniência rodando como host-equivalent root com ferramentas de debugging pré-instaladas.

## Exemplos de Exaustão de Recursos

Resource controls não são glamourosos, mas fazem parte da segurança de container porque limitam o raio de ação de uma comprometida. Sem limites de memory, CPU ou PID, um shell simples pode ser suficiente para degradar o host ou workloads vizinhos.

Example host-impacting tests:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Esses exemplos são úteis porque mostram que nem todo resultado perigoso de container é um "escape" limpo. Limites fracos de cgroup ainda podem transformar code execution em impacto operacional real.

## Ferramentas de hardening

Para ambientes centrados em Docker, `docker-bench-security` continua sendo uma linha de base útil de auditoria no host porque verifica problemas comuns de configuração em relação a orientações de benchmark amplamente reconhecidas:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
A ferramenta não substitui o threat modeling, mas ainda é valiosa para encontrar defaults descuidados de daemon, mount, network e runtime que se acumulam ao longo do tempo.

## Verificações

Use estes como comandos rápidos de primeira passagem durante a avaliação:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
O que é interessante aqui:

- Um processo root com capacidades amplas e `Seccomp: 0` merece atenção imediata.
- Mounts suspeitas e sockets de runtime frequentemente oferecem um caminho mais rápido para impacto do que qualquer kernel exploit.
- A combinação de postura de runtime fraca e limites de recursos frouxos geralmente indica um ambiente de contêiner permissivo em vez de um único erro isolado.
