# Contributing to KeySeal

Thanks for your interest in KeySeal. Issues and pull requests are welcome in English.

Everyone taking part in the project is expected to follow the [code of conduct](CODE_OF_CONDUCT.md).

## Before you start

- For a bug, open an issue with the component, the version and, for helper or token problems, the output of `keyseal doctor`.
- For a token KeySeal doesn't find, use the token or driver issue form; catalogue entries need the token's USB id and the driver's module path on each platform.
- For a larger change, especially one to the protocol, open an issue first so the design can be agreed before the code.
- Security problems go through a private advisory, never a public issue. See [SECURITY.md](SECURITY.md).

## Issues handed to an agent

A maintainer can hand an open issue to an agent by labelling it `agent` (Claude Opus) or `agent:codex` (Codex). The agent swaps that label for `agent:working`, then for `agent:pr` once it links a pull request for review, or for `agent:blocked` after asking a question on the issue. Leave an issue labelled `agent:working` to the agent.

To retry an issue labelled `agent:blocked`, answer the question on the issue, remove `agent:blocked` and add `agent` or `agent:codex` again.

## Making a change

[docs/development.md](docs/development.md) has the repository layout, the prerequisites and the checks CI runs. Run the checks for every component you touch before opening a pull request.

- Keep a pull request to one change, and match the surrounding code's style and comment density.
- Add focused tests where the change carries risk, in the component's existing test style.
- The helper, the TypeScript packages, the signing service and the spec live in one repository so a protocol change lands in one pull request. A change to the wire format updates `spec/protocol-v1.md`, `spec/openapi.yaml` and every side of the protocol together.
- A change users of a component would notice adds a line under that component's Unreleased heading in [CHANGELOG.md](CHANGELOG.md). The release pull request moves those lines under the new version.
- Strings the helper shows live in `helper/crates/keyseal-ui/src/strings.rs`, in plain English, without jargon where a plain word works.

## Commits

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/): `fix(helper): ...`, `feat(server): ...`, `docs: ...`, `ci: ...`.

## Licence

KeySeal is licensed under Apache-2.0. As section 5 of the licence sets out, a contribution you submit is licensed under the same terms unless you state otherwise.
