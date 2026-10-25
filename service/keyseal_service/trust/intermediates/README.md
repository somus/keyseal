# Intermediate certificates

CA certificates between a signer and a root in `../roots/`, as `.pem`, `.cer` or `.crt` files (PEM or DER). They only help build a certificate path when a signed PDF doesn't carry its own chain; they are never trust anchors, so a certificate here is trusted only if it chains to a root.

Shipped, for documents the Income Tax Department signs (its officers' certificates come from eMudhra and their PDFs carry no chain):

| File | Certificate | Issued by | Valid | SHA-256 |
|---|---|---|---|---|
| `emudhra-ca-2022.crt` | e-Mudhra CA 2022 | CCA India 2022 | 2022-02-16 to 2032-02-16 | `21:BE:69:EA:F1:B6:37:62:74:08:7A:EB:6A:0B:0C:A3:C1:DB:FD:3A:C1:AC:51:8B:EF:38:EE:BB:B2:B8:0C:D3` |
| `emudhra-sub-ca-class-3-organisation-2022.crt` | e-Mudhra Sub CA for Class 3 Organisation 2022 | e-Mudhra CA 2022 | 2022-02-18 to 2032-02-15 | `D6:D7:F6:2B:12:4C:37:E7:2C:38:0B:DE:51:A8:65:AC:AD:37:F6:8E:2F:94:A6:2B:D4:9D:1D:37:D6:BA:FD:CB` |

Both come from the issuer links (AIA) in the certificates themselves, under http://www.e-mudhra.com/repository/cacerts/, and each signature was checked against its issuer up to CCA India 2022.
