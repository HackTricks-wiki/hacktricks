# Dependency Confusion

{{#include ../banners/hacktricks-training.md}}


## Basic Information

Dependency Confusion (a.k.a. substitution attacks) happens when a package manager resolves a dependency name from an unintended, less-trusted registry/source (usually a public registry) instead of the intended private/internal one. This typically leads to the installation of an attacker-controlled package.

Common root causes:
- Typosquatting/misspelling: Importing `reqests` instead of `requests` (resolves from public registry).
- Non-existent/abandoned internal package: Importing `company-logging` that no longer exists internally, so the resolver looks in public registries and finds an attacker’s package.
- Version preference across multiple registries: Importing an internal `company-requests` while the resolver is allowed to also query public registries and prefers the “best”/newer version published publicly by an attacker.

Key idea: If the resolver can see multiple registries for the same package name and is allowed to pick the “best” candidate globally, you’re vulnerable unless you constrain resolution.


## Exploitation

> [!WARNING]
> In all cases, the attacker only needs to publish a malicious package with the same name as the dependency your build resolves from a public registry. Installation-time hooks (e.g., npm scripts) or import-time code paths often give code execution.

### Misspelled & Inexistent

If your project references a library that isn’t available in the private registry, and your tooling falls back to a public registry, an attacker can seed a malicious package with that name in the public registry. Your runners/CI/dev machines will fetch and execute it.

### Unspecified Version / “Best-version” selection across indexes

Developers frequently leave versions unpinned or allow wide ranges. When a resolver is configured with both internal and public indexes, it may select the newest version regardless of source. For internal names like `requests-company`, if the internal index has `1.0.1` but an attacker publishes `1.0.2` to the public registry and your resolver considers both, the public package may win.


## AWS Fix

This vulnerability was found in AWS CodeArtifact (read the details in this blog post). AWS added controls to mark dependencies/feeds as internal vs external so the client won’t fetch “internal” names from upstream public registries.


## Finding Vulnerable Libraries

In the original post about dependency confusion the author looked for thousands of exposed manifests (e.g., `package.json`, `requirements.txt`, lockfiles) to infer internal package names and then published higher-versioned packages to public registries.


## Practical Attacker Playbook (for red teams in authorized tests)

- Enumerate names:
  - Grep repos and CI configs for manifest/lock files and internal namespaces.
  - Look for organization-specific prefixes (e.g., `@company/*`, `company-*`, internal groupIds, NuGet ID patterns, private module paths for Go, etc.).
- Check public registries for availability:
  - If the name is unregistered publicly, register it; if it exists, attempt subdependency hijacking by targeting internal transitive names.
- Publish with precedence:
  - Choose a semver that “wins” (e.g., a very high version) or matches resolver rules.
  - Include minimal install-time execution where applicable (e.g., npm `preinstall`/`install`/`postinstall` scripts). For Python, prefer import-time execution paths, as wheels typically don’t execute arbitrary code on install.
- Exfil control:
  - Ensure outbound is allowed from CI to your controlled endpoint; otherwise use DNS queries or error messages as a side-channel to prove code execution.

> [!CAUTION]
> Always get written authorization, use unique package names/versions for the engagement, and immediately unpublish or coordinate cleanup when testing concludes.


## Defender Playbook (what actually prevents confusion)

High-level strategies that work across ecosystems:
- Use unique internal namespaces and bind them to a single registry.
- Avoid mixing trust levels at resolution time. Prefer a single internal registry that proxies approved public packages instead of giving package managers both internal and public endpoints.
- For managers that support it, map packages to specific sources (no global “best-version” across registries).
- Pin and lock:
  - Use lockfiles that record the resolved registry URLs (npm/yarn/pnpm) or use hash/attestation pinning (pip `--require-hashes`, Gradle dependency verification).
- Block public fallback for internal names at the registry/network layer.
- Reserve your internal names in public registries when feasible to prevent future squat.


## Ecosystem Notes and Secure Config Snippets

Below are pragmatic, minimal configs to reduce or eliminate dependency confusion. Prefer enforcing these in CI and developer environments.

### JavaScript/TypeScript (npm, Yarn, pnpm)

- Use scoped packages for all internal code and pin the scope to your private registry.
- Keep installs immutable in CI (npm lockfile, `yarn install --immutable`).

.npmrc (project-level)
```
# Bind internal scope to private registry; do not allow public fallback for @company/*
@company:registry=https://registry.corp.example/npm/
# Always authenticate to the private registry
//registry.corp.example/npm/:_authToken=${NPM_TOKEN}
strict-ssl=true
```

package.json (for internal package)
```
{
  "name": "@company/api-client",
  "version": "1.2.3",
  "private": false,
  "publishConfig": {
    "registry": "https://registry.corp.example/npm/",
    "access": "restricted"
  }
}
```

Yarn Berry (.yarnrc.yml)
```
npmScopes:
  company:
    npmRegistryServer: "https://registry.corp.example/npm/"
    npmAlwaysAuth: true
# CI should fail if lockfile would change
enableImmutableInstalls: true
```

Operational tips:
- Only publish internal packages within the `@company` scope.
- For third-party packages, allow public registry via your private proxy/mirror, not directly from clients.
- Consider enabling npm package provenance for public packages you publish to increase traceability (doesn’t by itself prevent confusion).

### Python (pip / Poetry)

Core rule: Don’t use `--extra-index-url` to mix trust levels. Either:
- Expose a single internal index that proxies and caches approved PyPI packages, or
- Use explicit index selection and hash pinning.

pip.conf
```
[global]
index-url = https://pypi.corp.example/simple
# Disallow source distributions when possible
only-binary = :all:
# Lock with hashes generated via pip-tools
require-hashes = true
```

Generate hashed requirements with pip-tools:
```
# From pyproject.toml or requirements.in
pip-compile --generate-hashes -o requirements.txt
pip install --require-hashes -r requirements.txt
```

If you must reach public PyPI, do it via your internal proxy and maintain an explicit allowlist there. Avoid `--extra-index-url` in CI.

### .NET (NuGet)

Use Package Source Mapping to tie package ID patterns to explicit sources and prevent resolution from unexpected feeds.

nuget.config
```
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
    <add key="corp" value="https://nuget.corp.example/v3/index.json" />
  </packageSources>
  <packageSourceMapping>
    <packageSource key="nuget.org">
      <package pattern="*" />
    </packageSource>
    <packageSource key="corp">
      <package pattern="Company.*" />
      <package pattern="Internal.Utilities" />
    </packageSource>
  </packageSourceMapping>
</configuration>
```

### Java (Maven/Gradle)

Maven settings.xml (mirror all to internal; disallow ad-hoc repos in POMs via Enforcer):
```
<settings>
  <mirrors>
    <mirror>
      <id>internal-mirror</id>
      <mirrorOf>*</mirrorOf>
      <url>https://maven.corp.example/repository/group</url>
    </mirror>
  </mirrors>
</settings>
```

Add Enforcer to ban repositories declared in POMs and force usage of your mirror:
```
<plugin>
  <groupId>org.apache.maven.plugins</groupId>
  <artifactId>maven-enforcer-plugin</artifactId>
  <version>3.6.1</version>
  <executions>
    <execution>
      <id>enforce-no-repositories</id>
      <goals><goal>enforce</goal></goals>
      <configuration>
        <rules>
          <requireNoRepositories />
        </rules>
      </configuration>
    </execution>
  </executions>
</plugin>
```

Gradle: Centralize and lock dependencies.
- Enforce repositories in `settings.gradle(.kts)` only:
```
dependencyResolutionManagement {
  repositoriesMode = RepositoriesMode.FAIL_ON_PROJECT_REPOS
  repositories {
    maven { url = uri("https://maven.corp.example/repository/group") }
  }
}
```
- Enable dependency verification (checksums/signatures) and commit `gradle/verification-metadata.xml`.

### Go Modules

Configure private modules so the public proxy and checksum DB aren’t used for them.

```
# Use corporate proxy first, then public proxy as fallback
export GOPROXY=https://goproxy.corp.example,https://proxy.golang.org
# Mark private paths to skip proxy and checksum db
export GOPRIVATE=*.corp.example.com,github.com/your-org/*
export GONOSUMDB=*.corp.example.com,github.com/your-org/*
```

### Rust (Cargo)

Replace crates.io with an approved internal mirror or vendor directory for builds; do not allow arbitrary public fallback.

.cargo/config.toml
```
[source.crates-io]
replace-with = "corp-mirror"

[source.corp-mirror]
registry = "https://crates-mirror.corp.example/index"
```

For publishing, be explicit with `--registry` and keep credentials scoped to the target registry.

### Ruby (Bundler)

Use source blocks and disable multisource Gemfiles so gems come only from the intended repository.

Gemfile
```
source "https://gems.corp.example"

source "https://rubygems.org" do
  gem "rails"
  gem "pg"
end

source "https://gems.corp.example" do
  gem "company-logging"
end
```

Enforce at config level:
```
bundle config set disable_multisource true
```


## CI/CD and Registry Controls That Help

- Private registry as a single ingress:
  - Use Artifactory/Nexus/CodeArtifact/GitHub Packages/Azure Artifacts as the only endpoint developers/CI can reach.
  - Implement block/allow rules so internal namespaces never resolve from upstream public sources.
- Lockfiles are immutable in CI:
  - npm: commit `package-lock.json`, use `npm ci`.
  - Yarn: commit `yarn.lock`, use `yarn install --immutable`.
  - Python: commit hashed `requirements.txt`, enforce `--require-hashes`.
  - Gradle: commit `verification-metadata.xml` and fail on unknown artifacts.
- Outbound egress control: block direct access from CI to public registries except via the approved proxy.
- Name reservation: pre-register your internal names/namespaces in public registries where supported.
- Package provenance / attestations: when publishing public packages, enable provenance/attestations to make tampering more detectable downstream.


## References

- [https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610)
- [https://zego.engineering/dependency-confusion-in-aws-codeartifact-86b9ff68963d](https://zego.engineering/dependency-confusion-in-aws-codeartifact-86b9ff68963d)
- [https://learn.microsoft.com/en-us/nuget/consume-packages/package-source-mapping](https://learn.microsoft.com/en-us/nuget/consume-packages/package-source-mapping)
- [https://yarnpkg.com/configuration/yarnrc/](https://yarnpkg.com/configuration/yarnrc/)


{{#include ../banners/hacktricks-training.md}}
