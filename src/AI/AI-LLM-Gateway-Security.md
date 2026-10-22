# LLM Gateway Trust Boundaries

{{#include ../banners/hacktricks-training.md}}

An LLM gateway handles model routing and often holds provider credentials, so its ordinary API callers must not inherit configuration or provider-level authority. The LiteLLM gateway assessment on version 1.77.7 illustrates two separate boundaries: UI-session authorization for administrative configuration and caller-supplied routing configuration for inference. The reported issues were fixed in version 1.83.9.<sup>[[1]](#references)</sup>

## UI route classification is not authorization

In the assessed LiteLLM version, UI login keys belonged to the `litellm-dashboard` team. Authorization classified a key as a UI token from that team identifier, regardless of the user's role. The UI route check then accepted any route beginning with an allowlisted prefix. As a result, the `/config` entry also matched the administrative `/config/update` handler. That handler required generic authentication but did not independently require `PROXY_ADMIN`, so a lower-privileged UI session crossed into configuration write access.<sup>[[1]](#references)</sup>

This differs from a proxy/backend path-normalization mismatch: the authorization code and handler disagree about the authority of the *same* route.<sup>[[1]](#references)</sup> When reviewing a gateway, compare token classification, exact route and method matching, and the handler's own role check.<sup>[[1]](#references)</sup> See [web API authorization](../pentesting-web/web-api-pentesting.md), [401/403 bypasses](../pentesting-web/403-and-401-bypasses.md), and [proxy prefix exemptions](../pentesting-web/proxy-waf-protections-bypass.md#prefix-exemptions-become-routing-keys) for related but distinct boundaries.

## Configuration writes reach more than the configuration store

The same LiteLLM configuration update accepted environment-variable values and applied them to the running process. One consumer treated `UI_LOGO_PATH` as a local path for a `FileResponse`, without validating that it identified a logo; another read `UI_USERNAME` and `UI_PASSWORD` during non-SSO login and assigned `PROXY_ADMIN` when they matched. Thus a configuration-write permission could become both local-file disclosure and an administrative identity change, depending on the downstream consumer. The response media type does not establish that a served file is an image.<sup>[[1]](#references)</sup>

The pass-through endpoint configuration was another downstream sink. Initialization accepted remote S3/GCS adapter targets, downloaded Python modules, and imported them using `importlib`'s `exec_module`. Import executes top-level code before an adapter instance is used; merely restricting invocation of the adapter would not remove that execution boundary. Treat this as configuration-controlled code loading, not model-file deserialization.<sup>[[1]](#references)</sup> For the separate file-read primitive, see [file inclusion and path traversal](../pentesting-web/file-inclusion/).

## Per-request model routing can leak gateway credentials

LiteLLM's client-side credential feature accepted a `user_config` object in an LLM request. The assessed route created a temporary `litellm.Router` from that object, including its model list and provider `api_base`. A caller-controlled provider destination could receive the gateway's outbound completion request and configured provider authentication headers. Restrictions on top-level `api_base` or `api_key` fields did not cover this separate nested configuration path. This is a credential-bearing SSRF boundary, rather than a prompt-injection issue.<sup>[[1]](#references)</sup>

For an authorized gateway assessment, compare every path that can construct a router or provider client, including per-request configuration, against the destination and credential policy used by the normal configured route.<sup>[[1]](#references)</sup> The [SSRF guide](../pentesting-web/ssrf-server-side-request-forgery/) covers general server-side destination control; the gateway-specific failure is allowing a less-trusted request object to select a destination while reusing privileged outbound credentials.<sup>[[1]](#references)</sup>

## References

- [1] [Check Point Research — When LLM Gateways Go Wrong: Findings from LiteLLM](https://research.checkpoint.com/2026/when-llm-gateways-go-wrong-findings-from-litellm/)

{{#include ../banners/hacktricks-training.md}}
