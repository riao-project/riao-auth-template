# auth-template - Readme

## Authentication driver contract

This template targets IAM 5. Keep your credential-specific implementation in
`src/`; the credential-format-neutral example in [examples/index.ts](examples/index.ts)
demonstrates the lifecycle without supplying a production credential verifier.
Supply a trusted verifier and persistence implementation before using it.

- Return an active principal on success and `null` for ordinary rejection.
- Let database, verifier configuration, transport, and persistence failures
  reject. Do not count them as incorrect credentials.
- Call `beforeAuthenticationAttempt` before credential work. A blocked attempt
  records neither success nor failure.
- Record exactly one failure for an invalid credential or missing/inactive
  principal, and success only after required persistence completes.
- Never put credential secrets in protection subjects, metadata, or logs.
- For token exchange or other APIs whose success is not a principal, throw
  `AuthenticationRejectedError` for ordinary rejection or
  `AuthenticationBlockedError(retryAfterSeconds)` for blocking. `authenticate`
  still returns principal/`null`; do not hide operational errors with broad catches.
- Issue application-owned sessions separately and expose the trusted principal
  as `session.principal`. Login credentials are not session bearer tokens.

[Contract tests](test/spec/authentication-contract.spec.ts) use repository stubs
and require no database. After building, run just those tests with:

```sh
npm run build
npm run test:run -- dist/test/spec/authentication-contract.spec.js
```

The full suite uses database fixtures; only run it against an isolated database.

## Coordinated release prerequisite

IAM 5 must be published before normal dependency restoration for this template.
Until then, validate with the local IAM 5 build. The lockfile intentionally omits
the previous IAM 4 archive URL/integrity; regenerate it against the published
IAM 5 package before releasing or distributing this template. Do not retain
local filesystem dependencies in the released manifest or lockfile.

## Contributing & Development

See [contributing.md](docs/contributing/contributing.md) for information on how to develop or contribute to this project!
