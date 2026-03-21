# Image Security, Signing, And Secrets

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Container security starts before the workload is launched. The image determines which binaries, interpreters, libraries, startup scripts, and embedded configuration reach production. If the image is backdoored, stale, or built with secrets baked into it, the runtime hardening that follows is already operating on a compromised artifact.

This is why image provenance, vulnerability scanning, signature verification, and secret handling belong in the same conversation as namespaces and seccomp. They protect a different phase of the lifecycle, but failures here often define the attack surface the runtime later has to contain.

## Image Registries And Trust

Images may come from public registries such as Docker Hub or from private registries operated by an organization. The security question is not simply where the image lives, but whether the team can establish provenance and integrity. Pulling unsigned or poorly tracked images from public sources increases the risk of malicious or tampered content entering production. Even internally hosted registries need clear ownership, review, and trust policy.

Docker Content Trust historically used Notary and TUF concepts to require signed images. The exact ecosystem has evolved, but the enduring lesson remains useful: image identity and integrity should be verifiable rather than assumed.

Example historical Docker Content Trust workflow:

```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```

The point of the example is not that every team must still use the same tooling, but that signing and key management are operational tasks, not abstract theory.

## Vulnerability Scanning

Image scanning helps answer two different questions. First, does the image contain known vulnerable packages or libraries? Second, does the image carry unnecessary software that expands the attack surface? An image full of debugging tools, shells, interpreters, and stale packages is both easier to exploit and harder to reason about.

Examples of commonly used scanners include:

```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```

Results from these tools should be interpreted carefully. A vulnerability in an unused package is not identical in risk to an exposed RCE path, but both are still relevant to hardening decisions.

## Build-Time Secrets

One of the oldest mistakes in container build pipelines is embedding secrets directly into the image or passing them through environment variables that later become visible through `docker inspect`, build logs, or recovered layers. Build-time secrets should be mounted ephemerally during the build rather than copied into the image filesystem.

BuildKit improved this model by allowing dedicated build-time secret handling. Instead of writing a secret into a layer, the build step can consume it transiently:

```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```

This matters because image layers are durable artifacts. Once a secret enters a committed layer, later deleting the file in another layer does not truly remove the original disclosure from the image history.

## Runtime Secrets

Secrets needed by a running workload should also avoid ad hoc patterns such as plain environment variables whenever possible. Volumes, dedicated secret-management integrations, Docker secrets, and Kubernetes Secrets are common mechanisms. None of these removes all risk, especially if the attacker already has code execution in the workload, but they are still preferable to storing credentials permanently in the image or exposing them casually through inspection tooling.

A simple Docker Compose style secret declaration looks like:

```yaml
version: "3.7"
services:
  my_service:
    image: centos:7
    entrypoint: "cat /run/secrets/my_secret"
    secrets:
      - my_secret
secrets:
  my_secret:
    file: ./my_secret_file.txt
```

In Kubernetes, Secret objects, projected volumes, service-account tokens, and cloud workload identities create a broader and more powerful model, but they also create more opportunities for accidental exposure through host mounts, broad RBAC, or weak Pod design.

## Abuse

When reviewing a target, the aim is to discover whether secrets were baked into the image, leaked into layers, or mounted into predictable runtime locations:

```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```

These commands help distinguish between three different problems: application configuration leaks, image-layer leaks, and runtime-injected secret files. If a secret appears under `/run/secrets`, a projected volume, or a cloud identity token path, the next step is to understand whether it grants access only to the current workload or to a much larger control plane.

### Full Example: Embedded Secret In Image Filesystem

If a build pipeline copied `.env` files or credentials into the final image, post-exploitation becomes simple:

```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```

The impact depends on the application, but embedded signing keys, JWT secrets, or cloud credentials can easily turn container compromise into API compromise, lateral movement, or forgery of trusted application tokens.

### Full Example: Build-Time Secret Leakage Check

If the concern is that the image history captured a secret-bearing layer:

```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```

This kind of review is useful because a secret may have been deleted from the final filesystem view while still remaining in an earlier layer or in build metadata.

## Checks

These checks are intended to establish whether the image and secret-handling pipeline are likely to have increased the attack surface before runtime.

```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```

What is interesting here:

- A suspicious build history may reveal copied credentials, SSH material, or unsafe build steps.
- Secrets under projected volume paths may lead to cluster or cloud access, not just local application access.
- Large numbers of configuration files with plaintext credentials usually indicate that the image or deployment model is carrying more trust material than necessary.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker / BuildKit | Supports secure build-time secret mounts, but not automatically | Secrets can be mounted ephemerally during `build`; image signing and scanning require explicit workflow choices | copying secrets into the image, passing secrets by `ARG` or `ENV`, disabling provenance checks |
| Podman / Buildah | Supports OCI-native builds and secret-aware workflows | Strong build workflows are available, but operators must still choose them intentionally | embedding secrets in Containerfiles, broad build contexts, permissive bind mounts during builds |
| Kubernetes | Native Secret objects and projected volumes | Runtime secret delivery is first-class, but exposure depends on RBAC, pod design, and host mounts | overbroad Secret mounts, service-account token misuse, `hostPath` access to kubelet-managed volumes |
| Registries | Integrity is optional unless enforced | Public and private registries both depend on policy, signing, and admission decisions | pulling unsigned images freely, weak admission control, poor key management |
