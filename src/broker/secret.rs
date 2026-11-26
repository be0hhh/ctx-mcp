//! Fast zero-dependency secret-pattern detector used to block secret leakage in memos and paths.

pub fn contains_known_secret(text: &str) -> bool {
    if text.lines().any(|line| {
        let line = line.trim();
        line.contains("-----BEGIN ") && line.contains("PRIVATE KEY-----")
    }) {
        return true;
    }
    const PREFIXES: &[(&str, usize)] = &[
        ("github_pat_", 20),
        ("ghp_", 20),
        ("gho_", 20),
        ("ghu_", 20),
        ("ghs_", 20),
        ("ghr_", 20),
        ("sk-live-", 16),
        ("sk_live_", 16),
        ("sk-proj-", 16),
        ("sk-", 20),
        ("xoxb-", 16),
        ("xoxp-", 16),
        ("xapp-", 16),
        ("glpat-", 16),
    ];
    let tokens = text.split(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')));
    let has_prefixed_secret = tokens.clone().any(|token| {
        PREFIXES.iter().any(|(prefix, min_suffix)| {
            token
                .strip_prefix(*prefix)
                .is_some_and(|suffix| suffix.len() >= *min_suffix)
        }) || ((token.starts_with("AKIA") || token.starts_with("ASIA"))
            && token.len() == 20
            && token
                .bytes()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()))
    });
    has_prefixed_secret
        || tokens
            .filter(|token| !token.is_empty())
            .scan(false, |after_bearer, token| {
                let found = *after_bearer && token.len() >= 24;
                *after_bearer = token.eq_ignore_ascii_case("bearer");
                Some(found)
            })
            .any(|found| found)
}
