//! What you see is what you sign (section 8.4): the prepared PDF must hash
//! to the messageDigest the helper signs. Only the last `/ByteRange` and
//! the `/Contents` gap it leaves are read; nothing else is parsed.

use crate::cms::DigestAlgorithm;

const BYTE_RANGE: &[u8] = b"/ByteRange";

/// Checks that the last `/ByteRange` in `pdf` is `[0 a b c]`, that it covers
/// the file except the `/Contents` hex string from `a` to `b`, and that the
/// covered bytes hash to `message_digest` with `algorithm`.
pub fn check(pdf: &[u8], algorithm: DigestAlgorithm, message_digest: &[u8]) -> Result<(), String> {
    let [start, a, b, c] = last_byte_range(pdf)?;
    if start != 0 {
        return Err("its signed bytes don't start at the beginning of the file".into());
    }
    if a > pdf.len() || b.checked_add(c).is_none_or(|end| end > pdf.len()) {
        return Err("its byte ranges go past the end of the file".into());
    }
    if a >= b {
        return Err("its byte ranges overlap".into());
    }
    if b + c != pdf.len() {
        return Err("its byte ranges don't reach the end of the file".into());
    }
    let gap = &pdf[a..b];
    // At least one hex digit: an empty `<>` leaves no room for a signature.
    let hex_string = gap.len() > 2
        && gap[0] == b'<'
        && gap[gap.len() - 1] == b'>'
        && gap[1..gap.len() - 1].iter().all(u8::is_ascii_hexdigit);
    if !hex_string || !skip_space_back(&pdf[..a]).ends_with(b"/Contents") {
        return Err("the bytes left out of its byte ranges aren't only the signature".into());
    }
    if algorithm.digest(&[&pdf[..a], &pdf[b..]].concat()) != message_digest {
        return Err("the document's digest isn't the digest to be signed".into());
    }
    Ok(())
}

/// PDF whitespace (ISO 32000-1, 7.2.2).
fn is_space(byte: &u8) -> bool {
    matches!(byte, b'\0' | b'\t' | b'\n' | b'\x0c' | b'\r' | b' ')
}

fn skip_space(bytes: &[u8]) -> &[u8] {
    &bytes[bytes.iter().take_while(|b| is_space(b)).count()..]
}

fn skip_space_back(bytes: &[u8]) -> &[u8] {
    &bytes[..bytes.len() - bytes.iter().rev().take_while(|b| is_space(b)).count()]
}

/// The four integers of the last `/ByteRange [w x y z]` in `pdf`.
fn last_byte_range(pdf: &[u8]) -> Result<[usize; 4], String> {
    let malformed = || "its last /ByteRange isn't an array of four integers".to_owned();
    let at = pdf
        .windows(BYTE_RANGE.len())
        .rposition(|window| window == BYTE_RANGE)
        .ok_or("it has no /ByteRange")?;
    let mut rest = skip_space(&pdf[at + BYTE_RANGE.len()..])
        .strip_prefix(b"[")
        .ok_or_else(malformed)?;
    let mut values = [0; 4];
    for value in &mut values {
        rest = skip_space(rest);
        let digits = rest.iter().take_while(|b| b.is_ascii_digit()).count();
        *value = std::str::from_utf8(&rest[..digits])
            .ok()
            .and_then(|number| number.parse().ok())
            .ok_or_else(malformed)?;
        rest = &rest[digits..];
    }
    if !skip_space(rest).starts_with(b"]") {
        return Err(malformed());
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A prepared PDF from the signing service's `remote_sign.start`, with
    /// the messageDigest of its SignedAttributes.
    const PREPARED: &[u8] = include_bytes!("../tests/fixtures/prepared.pdf");
    const PREPARED_DIGEST: &str =
        "34982404fa50efc7cb94fcfe261e809eaa195a285723da1f5279d0248c20cfc1";

    const END: &[u8] = b" >>\nendobj\n%%EOF\n";
    const RANGE_WIDTH: usize = 64;

    /// `before` followed by a signature dictionary with a 16-digit
    /// `/Contents` placeholder and a space-padded `/ByteRange` of `range(a, b, c)`.
    fn sample(before: &[u8], range: impl Fn(usize, usize, usize) -> [usize; 4]) -> Vec<u8> {
        sample_with(before, b"<0000000000000000>", range)
    }

    /// [`sample`] with `contents` as the placeholder.
    fn sample_with(
        before: &[u8],
        contents: &[u8],
        range: impl Fn(usize, usize, usize) -> [usize; 4],
    ) -> Vec<u8> {
        let mut pdf = [before, b"1 0 obj\n<< /Type /Sig /Contents "].concat();
        let a = pdf.len();
        pdf.extend(contents);
        let b = pdf.len();
        let [w, x, y, z] = range(a, b, RANGE_WIDTH + END.len());
        pdf.extend(format!("\n/ByteRange [{w} {x}\r\n{y} {z} ]").bytes());
        pdf.resize(b + RANGE_WIDTH, b' ');
        pdf.extend(END);
        pdf
    }

    fn valid(a: usize, b: usize, c: usize) -> [usize; 4] {
        [0, a, b, c]
    }

    fn digest(pdf: &[u8]) -> Vec<u8> {
        let [_, a, b, _] = last_byte_range(pdf).unwrap();
        DigestAlgorithm::Sha256.digest(&[&pdf[..a], &pdf[b..]].concat())
    }

    #[test]
    fn accepts_a_prepared_pdf_from_the_service() {
        let expected = hex::decode(PREPARED_DIGEST).unwrap();
        check(PREPARED, DigestAlgorithm::Sha256, &expected).unwrap();
        assert!(check(PREPARED, DigestAlgorithm::Sha384, &expected).is_err());
        let mut tampered = PREPARED.to_vec();
        tampered[100] ^= 1;
        assert_eq!(
            check(&tampered, DigestAlgorithm::Sha256, &expected).unwrap_err(),
            "the document's digest isn't the digest to be signed"
        );
    }

    #[test]
    fn accepts_a_minimal_pdf_and_refuses_a_changed_byte() {
        let pdf = sample(b"%PDF-1.7\n", valid);
        check(&pdf, DigestAlgorithm::Sha256, &digest(&pdf)).unwrap();
        let sha384 = DigestAlgorithm::Sha384.digest(&[&pdf[..41], &pdf[59..]].concat());
        assert_eq!(&pdf[41..59], b"<0000000000000000>");
        check(&pdf, DigestAlgorithm::Sha384, &sha384).unwrap();
        let mut tampered = pdf.clone();
        tampered[3] = b'X';
        assert!(check(&tampered, DigestAlgorithm::Sha256, &digest(&pdf)).is_err());
    }

    #[test]
    fn only_the_last_byte_range_counts() {
        // An incremental update: a signed revision, then a new placeholder.
        let first = sample(b"%PDF-1.7\n", valid);
        let pdf = sample(&first, valid);
        assert_eq!(last_byte_range(&pdf).unwrap()[1], first.len() + 32);
        check(&pdf, DigestAlgorithm::Sha256, &digest(&pdf)).unwrap();
        // The first revision's ranges no longer cover the file.
        let mut stale = pdf.clone();
        stale.extend(b"\n/ByteRange [0 41 59 81]\n");
        assert_eq!(
            check(&stale, DigestAlgorithm::Sha256, &digest(&pdf)).unwrap_err(),
            "its byte ranges don't reach the end of the file"
        );
    }

    #[test]
    fn refuses_bad_byte_ranges() {
        let refusal = |pdf: Vec<u8>| {
            let digest = DigestAlgorithm::Sha256.digest(&pdf);
            check(&pdf, DigestAlgorithm::Sha256, &digest).unwrap_err()
        };
        let head = b"%PDF-1.7\n";
        for (range, reason) in [
            (
                [1, 41, 59, 81],
                "its signed bytes don't start at the beginning of the file",
            ),
            (
                [0, 41, 59, 82],
                "its byte ranges go past the end of the file",
            ),
            (
                [0, 999, 59, 81],
                "its byte ranges go past the end of the file",
            ),
            (
                [0, 41, usize::MAX, 1],
                "its byte ranges go past the end of the file",
            ),
            ([0, 59, 41, 99], "its byte ranges overlap"),
            ([0, 59, 59, 81], "its byte ranges overlap"),
            (
                [0, 41, 59, 74],
                "its byte ranges don't reach the end of the file",
            ),
            (
                [0, 42, 59, 81],
                "the bytes left out of its byte ranges aren't only the signature",
            ),
            (
                [0, 41, 58, 82],
                "the bytes left out of its byte ranges aren't only the signature",
            ),
        ] {
            assert_eq!(refusal(sample(head, |_, _, _| range)), reason, "{range:?}");
        }
        assert_eq!(sample(head, valid), sample(head, |_, _, _| [0, 41, 59, 81]));

        let mut not_hex = sample(head, valid);
        not_hex[50] = b'x';
        assert_eq!(
            refusal(not_hex),
            "the bytes left out of its byte ranges aren't only the signature"
        );
        assert_eq!(
            refusal(sample_with(head, b"<>", valid)),
            "the bytes left out of its byte ranges aren't only the signature"
        );
        let mut not_contents = sample(head, valid);
        not_contents[33] = b'X';
        assert_eq!(
            refusal(not_contents),
            "the bytes left out of its byte ranges aren't only the signature"
        );

        for malformed in [
            &b"/ByteRange 0 1 2 3"[..],
            b"/ByteRange [0 1 2]",
            b"/ByteRange [0 1 2 3 4]",
            b"/ByteRange [0 -1 2 3]",
            b"/ByteRange [0 1.5 2 3]",
            b"/ByteRange [0 1 2 99999999999999999999999]",
        ] {
            assert_eq!(
                refusal(malformed.to_vec()),
                "its last /ByteRange isn't an array of four integers"
            );
        }
        assert_eq!(refusal(b"%PDF-1.7\n".to_vec()), "it has no /ByteRange");
    }

    /// A `/ByteRange` in the bytes after the signature, describing a gap of
    /// its own, is the one checked; the digest of the real ranges then
    /// doesn't match.
    #[test]
    fn a_fake_byte_range_in_trailing_bytes_is_refused() {
        let mut pdf = b"%PDF-1.7\n1 0 obj\n<< /Type /Sig /Contents ".to_vec();
        let a = pdf.len();
        pdf.extend(b"<0000000000000000>");
        let b = pdf.len();
        let real_at = pdf.len();
        pdf.resize(real_at + RANGE_WIDTH, b' ');
        pdf.extend(b" >>\nendobj\n% /Contents ");
        let fake_a = pdf.len();
        pdf.extend(b"<00>");
        let fake_b = pdf.len();
        let fake_at = pdf.len();
        pdf.resize(fake_at + RANGE_WIDTH, b' ');
        pdf.extend(END);
        let len = pdf.len();
        for (at, [x, y]) in [(real_at, [a, b]), (fake_at, [fake_a, fake_b])] {
            let range = format!("\n/ByteRange [0 {x} {y} {}]", len - y);
            pdf[at..at + range.len()].copy_from_slice(range.as_bytes());
        }
        assert_eq!(
            last_byte_range(&pdf).unwrap(),
            [0, fake_a, fake_b, len - fake_b]
        );
        let signed = DigestAlgorithm::Sha256.digest(&[&pdf[..a], &pdf[b..]].concat());
        assert_eq!(
            check(&pdf, DigestAlgorithm::Sha256, &signed).unwrap_err(),
            "the document's digest isn't the digest to be signed"
        );
    }
}
