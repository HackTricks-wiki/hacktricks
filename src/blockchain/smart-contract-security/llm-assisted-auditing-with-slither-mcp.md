# LLM-assisted Solidity auditing with Slither-MCP

{{#include ../../banners/hacktricks-training.md}}

Slither-MCP is a Model Context Protocol (MCP) server that exposes Slither’s static analysis to LLM clients (Claude Desktop/Code, Cursor, etc.). Instead of brittle grep/read_file flows, an agent can query a deterministic Slither index of your Foundry/Hardhat project to resolve sources, traverse call graphs, inspect inheritance, and run detectors in-scope.

Why it matters
- Deterministic program analysis as ground truth (fewer hallucinations and wrong-file selections).
- Lower token/tool churn: ask for the exact implementation and usage paths directly.

Core capabilities (via MCP tools)
- Source extraction: return canonical source for a contract/function across imports/inheritance.
- Call graph navigation: enumerate callers and callees for precise usage mapping.
- Inheritance introspection: list base/derived classes and resolved members/overrides.
- Signature resolution: map interface signatures (e.g., `IOracle.price(uint256)`) to concrete implementations.
- Detectors: run Slither’s detectors and filter results to specific contracts/functions.

Auditing workflow example (ERC20.transfer)
- Resolve the canonical implementation even in large trees with multiple ERC20s:
  - get_function_source for `transfer(address,uint256)` to fetch the true implementation (accounts for imports/overrides).
- Map usage precisely:
  - List callers of `transfer(address,uint256)` to see where it’s invoked (e.g., fee controllers, test doubles, adapters).
  - List callees from the resolved function to understand downstream effects.
- Focused triage:
  - Run Slither detectors scoped to the resolved contract/function to surface high-signal findings first.

Signature-to-implementation mapping
- Query by interface signature (e.g., `IOracle.price(uint256)`) to locate concrete implementations before tracing calls or running detectors. This avoids analyzing mocks/stubs by mistake.

Setup in common MCP clients
- Claude Code (stdio transport):

```bash
claude mcp add --transport stdio slither -- uvx --from git+https://github.com/trailofbits/slither-mcp slither-mcp
```

- Cursor IDE (append to `~/.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "slither-mcp": {
      "command": "uvx --from git+https://github.com/trailofbits/slither-mcp slither-mcp",
      "env": {
        "PYTHONUNBUFFERED": "1"
      }
    }
  }
}
```

Usage tips
- Start from a function of interest and use signature resolution to anchor analysis on the real implementation.
- Pivot through callers/callees to build accurate usage paths before running detectors.
- Scope detector runs to relevant contracts/functions to keep output actionable on large codebases.

## References

- [Level up your Solidity LLM tooling with Slither-MCP (Trail of Bits)](https://blog.trailofbits.com/2025/11/15/level-up-your-solidity-llm-tooling-with-slither-mcp/)
- [Slither-MCP (GitHub)](https://github.com/trailofbits/slither-mcp)

{{#include ../../banners/hacktricks-training.md}}
