# Containers e Namespaces

{{#include ../../banners/hacktricks-training.md}}

Um container é um processo Linux executado com uma configuração de isolamento e privilégios. Avalie em conjunto o runtime, os recursos do host montados, as capabilities concedidas e as configurações de namespaces. A [visão geral de segurança de containers](container-security/README.md) explica essas camadas e contém links para cada controle.

- [Escalada de privilégios no containerd (`ctr`)](containerd-ctr-privilege-escalation.md) foca no acesso à interface de gerenciamento do containerd.
- [Escalada de privilégios no RunC](runc-privilege-escalation.md) aborda material sobre escalada específica do runtime.
- [Segurança de containers](container-security/README.md) explica runtimes, APIs expostas, riscos de imagens, montagens sensíveis, containers privilegiados, avaliação e proteções como namespaces, seccomp e controle de acesso obrigatório.
{{#include ../../banners/hacktricks-training.md}}
