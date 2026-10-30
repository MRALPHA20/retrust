# Security policy

ReTrust is a procurement-review tool. It reads public advisory data, scores it
locally and serves read-only pages to a browser. This document describes what
the project treats as a security issue and how to report one.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability.

Use GitHub's private vulnerability reporting on this repository (**Security**
tab, then **Report a vulnerability**). If that option is not available, open an
issue that asks for a private contact without describing the problem, and a
maintainer will reply with one.

Include the commit or version, the command or page involved, the input that
triggers the behaviour and what you observed. Sanitised reproductions are
enough; please do not send confidential procurement data.

Reports are acknowledged once a maintainer has read them, normally within a
week. Fixes land on `main` with a changelog entry. Reporters are credited
unless they ask not to be.

## Scope

In scope:

- The `retrust` package: parsing of CSAF, KEV and EPSS inputs, product
  matching, scoring, exports and the interactive terminal.
- The HTTP server (`retrust serve`): routing, escaping, response headers, the
  content security policy and the DNS-rebinding guard.
- Snapshot and archive handling (`retrust snapshot`), including decompression
  of untrusted archives.
- Digest and signature verification (`retrust verify`), including key fetching.
- Data acquisition (`retrust setup`, `refresh`, `provider`, `lev --update`):
  what is fetched, from where, and how it is validated.

Out of scope:

- Availability of the hosted demo, which runs on a free hosting plan.
- Errors in upstream public data (CISA advisories, KEV, EPSS). Report those to
  the source.
- Scoring outcomes you disagree with. The methodology is documented and open to
  discussion in ordinary issues.
- Findings that require a modified local configuration or a deliberately
  weakened deployment.

## Design assumptions

- The server is intended for a local workstation. It answers GET and HEAD only,
  reads no request body, writes nothing, runs no subprocess and never uses a
  request path as a filename. Every value that reaches a page is HTML-escaped.
- Pages contain no JavaScript and load nothing from any origin. Every response
  carries `Content-Security-Policy: default-src 'none'` with inline styles as
  the only allowance, is never cached, cannot be framed and sends no referrer.
- On a loopback bind the `Host` header must name this machine, which stops a
  DNS-rebinding page from reading the local index.
- There is no authentication and no multi-user support. Do not expose the
  server to an untrusted network. Hosted mode (`RETRUST_HOSTED=1`) keeps the
  same read-only surface and never exposes the commands that fetch data or
  change local state.
- Data acquisition is a separate, explicit step. `retrust verify` checks
  digests and signatures on demand and reports origin and content separately;
  `--strict` makes a pipeline fail unless both were positively established.

Regression tests cover injection, server-side request forgery and
decompression-bomb inputs. The [technical manual](docs/manual.md) describes the
architecture in more detail.

## Supported versions

Security fixes land on `main`. Use the latest commit on `main` or the latest
tagged release.
