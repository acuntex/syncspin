# Security policy

`syncspin` speaks an encrypted protocol, and it refuses a peer that does not complete the Noise
handshake. A weakness in that path is worth reporting privately, not in a public issue.

## Supported versions

Only the 0.1 line is supported. It is a pre-release: nothing is published on crates.io, and the
`v0.1.0` tag is the reference. Older commits, forks and downstream copies are not supported here.

## Reporting a vulnerability

Use GitHub's private reporting form:
[Report a vulnerability](https://github.com/acuntex/syncspin/security/advisories/new). The report
stays private until a fix is ready and a disclosure date is agreed.

Please include: what the weakness is, which crate and revision it affects, the smallest sequence
that shows it, and what an attacker gains. A working test is worth more than a description.

## What is in scope

- `syncspin-core`: the Noise `KKpsk2` handshake, the Sentinel key, framing and fragmentation,
  message parsing, the clock filter.
- `syncspin-client`: session state handling, role handling, reconnect, volume bounds, how key
  material and identity are passed in and kept.
- `examples/player-pipe`: identity handling and file permissions.

## What is out of scope

- An application that uses the crates: its audio pipeline, its device integration, its own
  configuration, its own HTTP surface.
- A Sendspin server's behaviour, including Music Assistant. Report those to the server's project.
- Anything that needs physical access to a device, or an attack that assumes the attacker already
  controls the host.
- The absence of a feature that is documented as missing, such as pairing or the server side.

## What must never be in a report

No private key, PSK, pairing record, identity file or Noise handshake hash. These are the values an
attacker would want, and a public advisory is permanent. Redact them:

- keep the shape, not the value: `key=<redacted, 32 bytes>`, `psk_id=0x1a2b…`;
- cut log excerpts to the lines before and after the suspicious one;
- replace a server address with `<server>` and a device name with `<device>`.

## What to expect

This is a small project without a security team: reports are handled on a best-effort basis, with
no response-time commitment and no bug bounty. You will get an answer that says whether the report
is accepted, and a credit in the advisory if you want one.
