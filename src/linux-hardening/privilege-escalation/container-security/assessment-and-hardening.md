# Evaluación y hardening

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Una buena evaluación de container debe responder dos preguntas paralelas. Primero, ¿qué puede hacer un atacante desde la workload actual? Segundo, ¿qué elecciones del operador hicieron eso posible? Las herramientas de enumeración ayudan con la primera pregunta, y las guías de hardening ayudan con la segunda. Mantener ambas en una sola página hace que la sección sea más útil como referencia de campo en lugar de solo un catálogo de escape tricks.

## Enumeration Tools

A number of tools remain useful for quickly characterizing a container environment:

- `linpeas` can identify many container indicators, mounted sockets, capability sets, dangerous filesystems, and breakout hints.
- `CDK` focuses specifically on container environments and includes enumeration plus some automated escape checks.
- `amicontained` is lightweight and useful for identifying container restrictions, capabilities, namespace exposure, and likely breakout classes.
- `deepce` is another container-focused enumerator with breakout-oriented checks.
- `grype` is useful when the assessment includes image-package vulnerability review instead of only runtime escape analysis.

El valor de estas herramientas es velocidad y cobertura, no certeza. Ayudan a revelar rápidamente la postura aproximada, pero los hallazgos interesantes aún necesitan interpretación manual frente al modelo real de runtime, namespace, capability y mount.

## Hardening Priorities

Los principios más importantes de hardening son conceptualmente simples aunque su implementación varíe según la plataforma. Evita containers privilegiados. Evita mounted runtime sockets. No des a los containers rutas de host con permisos de escritura a menos que haya una razón muy específica. Usa user namespaces o rootless execution cuando sea factible. Elimina todas las capabilities y vuelve a añadir solo las que la workload realmente necesita. Mantén seccomp, AppArmor y SELinux habilitados en lugar de deshabilitarlos para solucionar problemas de compatibilidad de aplicaciones. Limita los recursos para que un container comprometido no pueda trivialmente negar servicio al host.

La higiene de image y build importa tanto como la postura en runtime. Usa imágenes mínimas, rebuild con frecuencia, scanéalas, exige provenance cuando sea práctico y mantiene secrets fuera de las layers. Un container que corre como non-root con una imagen pequeña y una superficie reducida de syscall y capability es mucho más fácil de defender que una imagen grande de conveniencia que corre como host-equivalent root con herramientas de debugging preinstaladas.

## Resource-Exhaustion Examples

Los controles de recursos no son glamorosos, pero forman parte de la seguridad de container porque limitan el blast radius de un compromiso. Sin límites de memory, CPU, o PID, una simple shell puede ser suficiente para degradar el host o workloads vecinos.

Example host-impacting tests:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Estos ejemplos son útiles porque muestran que no todo resultado peligroso en un contenedor es un "escape" limpio. Los límites débiles de cgroup aún pueden convertir la ejecución de código en un impacto operativo real.

## Herramientas de hardening

Para entornos centrados en Docker, `docker-bench-security` sigue siendo una línea base útil de auditoría en el host porque comprueba problemas de configuración comunes frente a directrices de benchmark ampliamente reconocidas:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
La herramienta no sustituye al modelado de amenazas, pero sigue siendo valiosa para detectar daemon, mount, network y valores predeterminados de runtime descuidados que se acumulan con el tiempo.

## Comprobaciones

Utiliza estos como comandos rápidos de primera pasada durante la evaluación:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
Lo interesante aquí:

- Un proceso root con capacidades amplias y `Seccomp: 0` merece atención inmediata.
- Montajes sospechosos y sockets de runtime suelen ofrecer una vía más rápida hacia el impacto que cualquier kernel exploit.
- La combinación de una postura de runtime débil y límites de recursos laxos normalmente indica un entorno de contenedores permisivo en general, más que un único error aislado.
