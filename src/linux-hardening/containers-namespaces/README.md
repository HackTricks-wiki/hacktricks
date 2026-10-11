# Contêineres e Namespaces

{{#include ../../banners/hacktricks-training.md}}

Um contêiner é um processo Linux executado com uma configuração de isolamento e privilégios. Avalie em conjunto o runtime, os recursos do host montados, as capabilities concedidas e as configurações de namespaces. A [visão geral de segurança de contêineres](container-security/README.md) explica essas camadas e contém links para cada controle.

- [Escalação de privilégios no Containerd (`ctr`)](containerd-ctr-privilege-escalation.md) foca no acesso à interface de gerenciamento do containerd.
- [Escalação de privilégios no RunC](runc-privilege-escalation.md) aborda técnicas de escalação específicas do runtime.
- [Segurança de contêineres](container-security/README.md) explica runtimes, APIs expostas, riscos de imagens, montagens sensíveis, contêineres privilegiados, avaliação e proteções como namespaces, seccomp e controle de acesso obrigatório.
{{#include ../../banners/hacktricks-training.md}}
