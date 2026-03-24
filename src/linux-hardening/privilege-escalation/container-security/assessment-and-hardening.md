# Avaliação e Endurecimento

{{#include ../../../banners/hacktricks-training.md}}

## Visão Geral

Uma boa avaliação de contêiner deve responder duas perguntas paralelas. Primeiro, o que um atacante pode fazer a partir da workload atual? Segundo, quais escolhas do operador tornaram isso possível? Ferramentas de enumeração ajudam na primeira pergunta, e orientações de hardening ajudam na segunda. Manter ambos em uma única página torna a seção mais útil como referência de campo em vez de apenas um catálogo de truques de escape.

## Ferramentas de Enumeração

Diversas ferramentas continuam úteis para caracterizar rapidamente um ambiente de contêiner:

- `linpeas` pode identificar muitos indicadores de contêiner, sockets montados, capability sets, sistemas de arquivos perigosos e indícios de breakout.
- `CDK` foca especificamente em ambientes de contêiner e inclui enumeração além de algumas verificações automatizadas de escape.
- `amicontained` é leve e útil para identificar restrições de contêiner, capabilities, exposição de namespace e classes prováveis de breakout.
- `deepce` é outro enumerador focado em contêiner com verificações orientadas a breakout.
- `grype` é útil quando a avaliação inclui revisão de vulnerabilidades de pacotes da imagem em vez de apenas análise de escape em tempo de execução.

O valor dessas ferramentas está na velocidade e na cobertura, não na certeza. Elas ajudam a revelar rapidamente a postura aproximada, mas as descobertas interessantes ainda precisam de interpretação manual em relação ao modelo real de runtime, namespace, capability e mount.

## Prioridades de Hardening

Os princípios de hardening mais importantes são conceitualmente simples, embora sua implementação varie por plataforma. Evite contêineres privilegiados. Evite sockets de runtime montados. Não forneça caminhos do host com permissão de escrita para contêineres a menos que haja um motivo muito específico. Use user namespaces ou rootless execution quando viável. Remova todas as capabilities e adicione de volta apenas as que a workload realmente precisa. Mantenha seccomp, AppArmor e SELinux habilitados em vez de desativá-los para resolver problemas de compatibilidade de aplicações. Limite recursos para que um contêiner comprometido não consiga, trivialmente, negar serviço ao host.

Higiene de imagem e de build importa tanto quanto a postura em runtime. Use imagens mínimas, reconstrua frequentemente, escaneie-as, exija proveniência quando prático e mantenha segredos fora das camadas. Um contêiner rodando como non-root com uma imagem pequena e uma superfície de syscall e capability reduzida é muito mais fácil de defender do que uma imagem grande de conveniência rodando como root equivalente ao host com ferramentas de debugging pré-instaladas.

## Exemplos de Exaustão de Recursos

Controles de recursos não são glamorosos, mas fazem parte da segurança de contêiner porque limitam o raio de impacto de um comprometimento. Sem limites de memória, CPU ou PID, um shell simples pode ser suficiente para degradar o host ou workloads vizinhos.

Exemplos de testes que impactam o host:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Estes exemplos são úteis porque mostram que nem todo resultado perigoso de container é uma "escape" limpa. Limites fracos de cgroup ainda podem transformar code execution em impacto operacional real.

## Ferramentas de hardening

Para ambientes centrados em Docker, `docker-bench-security` continua sendo uma linha de base útil de auditoria do host porque verifica problemas de configuração comuns em relação a diretrizes de benchmark amplamente reconhecidas:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
A ferramenta não é um substituto para threat modeling, mas ainda é valiosa para encontrar configurações padrão descuidadas de daemon, mount, network e runtime que se acumulam com o tempo.

## Verificações

Use estes como comandos rápidos de primeira triagem durante a avaliação:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
- Um processo root com capacidades amplas e `Seccomp: 0` merece atenção imediata.
- Mounts suspeitos e runtime sockets frequentemente oferecem um caminho mais rápido para impacto do que qualquer kernel exploit.
- A combinação de postura de runtime fraca e limites de recursos fracos geralmente indica um ambiente de container permissivo em vez de um erro isolado.
{{#include ../../../banners/hacktricks-training.md}}
