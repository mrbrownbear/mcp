# REST Ability Contract v1 Fixtures

These fixtures freeze the server contract consumed by `@novamira/cli` 1.x.
The full normative contract is in `../../../../novamira-cli/docs/v1-contract.md`.
The REST-only Phase 1 integration path and fixed CLI server floor are documented
in [`SERVER_CONTRACT.md`](SERVER_CONTRACT.md).
The JSON files must remain byte-identical to
`../../../../novamira-cli/fixtures/v1`.

The first compatible server is WordPress 6.9 with Novamira 1.10.0, REST API
contract `1`, and all of these feature values strictly `true`:

```text
abilities_bearer_auth
abilities_read_scope
agent_context
rest_skills
generalized_execution_shim
```

Protected-resource metadata publishes the compatibility block as `novamira`;
`novamira/agent-context` returns the identical block as `server`.

The v1 OAuth audience remains `rest_url('mcp/novamira-oauth')`. Scope
`abilities:read` permits Ability list/item access and execution only when the
resolved Ability explicitly has `readonly: true`. Scope `abilities` includes
read access and execution of every otherwise-permitted REST-visible Ability.
`mcp` and its legacy aliases remain isolated to the legacy endpoint.

Full access intentionally includes third-party abilities with
`meta.show_in_rest: true`; consent must state that compatible third-party
plugin abilities can execute code, modify files/content or settings, and
create temporary administrator access. Normal Novamira, user-capability,
`show_in_rest`, and target permission checks remain authoritative.

The Bearer route allowlist is only:

```text
GET|HEAD /wp-abilities/v1/abilities
GET      /wp-abilities/v1/abilities/{complete-name}
POST     /novamira/v1/abilities/{complete-name}/run
```

The shim accepts exactly `{}` (meaning `input: null`) or
`{"input": <any JSON value>}` and preserves raw successful JSON values. It
rejects malformed JSON, scalar/array top-level bodies, and unexpected fields
with a WordPress REST error at status 400. Complete validated slash-delimited
Ability names are supported.
