# Trust roots

Root certificates signatures must chain to, as `.pem`, `.cer` or `.crt` files (PEM or DER). For Indian DSCs that is the Controller of Certifying Authorities (CCA) India root in force when the certificate was issued, for example "CCA India 2022" from https://cca.gov.in (Repository, Root Certificates).

`SIGNING_TRUST_ROOTS_DIR` replaces this directory and `../intermediates/` at runtime. With no roots, signatures are still checked for integrity and coverage, but every signer is reported as not trusted and every certificate check fails.

Shipped: `cca-india-2022.cer`, CCA India 2022 (valid 2022-02-02 to 2042-02-02), from https://cca.gov.in/root_certificate.html, SHA-256 `9A:3F:D3:17:67:98:E8:42:DD:CB:12:C2:62:F1:1C:FA:CC:A7:0A:8B:84:C6:EA:6F:DA:30:84:2A:95:A9:4C:D8`. CCA India 2014 expired in March 2024, so DSCs issued under it have expired too.
