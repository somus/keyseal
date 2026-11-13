# Documentation

| Document | For |
| --- | --- |
| [quickstart.md](quickstart.md) | Trying KeySeal without a USB token: the service and the reference server in Docker Compose, a SoftHSM test token and the released helper |
| [integrating.md](integrating.md) | Adding token signing to a web application: the service, `@keyseal/server`, `@keyseal/browser` and the helper |
| [design.md](design.md) | How KeySeal is built and the security rules the code follows: protocol flow, trust model, token access, updates |
| [development.md](development.md) | Working on KeySeal: layout, prerequisites, checks, the end-to-end test, previewing the windows |
| [releasing.md](releasing.md) | Releasing each component; cutting, reproducing and signing a helper release |
| [code-signing-policy.md](code-signing-policy.md) | What KeySeal signs, who may sign it and how the keys are kept |

The protocol itself is specified in [spec/](../spec/). Each component has its own README with its internals: [helper](../helper/README.md), [server](../packages/server/README.md), [browser](../packages/browser/README.md), [service](../service/README.md), [catalogue](../catalogue/README.md) and [reference server](../examples/reference-server/README.md).
