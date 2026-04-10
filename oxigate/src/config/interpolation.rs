//! Stateless `{{env:VAR}}` placeholder interpolation for configuration strings.
//!
//! Any configuration value that is a plain `String` may contain one or more
//! `{{env:VAR_NAME}}` placeholders.  At startup time (before any request is
//! handled) the [`interpolate`] function replaces every placeholder with the
//! value of the corresponding environment variable.
//!
//! # Syntax
//!
//! | Placeholder          | Resolved to                                          |
//! |----------------------|------------------------------------------------------|
//! | `{{env:VAR}}`        | Value of the `VAR` environment variable              |
//! | `{{env:VAR}}`        | Empty string when `VAR` is not set                   |
//!
//! Placeholders can appear anywhere inside a string and multiple placeholders
//! are supported within the same value:
//!
//! ```text
//! "https://{{env:HOST}}:{{env:PORT}}/path"
//! ```
//!
//! # Usage
//!
//! Call [`interpolate`] on every `String` configuration field before using
//! it at runtime:
//!
//! ```
//! use oxigate::config::interpolation::interpolate;
//!
//! // With VAR set to "world":
//! // std::env::set_var("GREETING", "world");
//! let result = interpolate("hello-{{env:GREETING}}");
//! // result == "hello-world"  (or "hello-" if GREETING is not set)
//! ```
//!
//! # Relationship to `HeaderValue` interpolation
//!
//! [`HeaderValue`](crate::config::route::HeaderValue) supports two additional
//! placeholders (`{{access_token}}` and `{{id_token}}`) that are resolved at
//! *request time* against the current session.  This module only handles
//! `{{env:VAR}}` and is intended for *startup-time* resolution of static
//! configuration fields (URLs, credentials, file paths, …).

// ---------------------------------------------------------------------------
// Core interpolation
// ---------------------------------------------------------------------------

/// Replace every `{{env:VAR_NAME}}` placeholder in `input` with the value of
/// the corresponding environment variable.
///
/// - If the variable is set, its value is substituted.
/// - If the variable is **not** set, the placeholder is replaced with an
///   empty string (no error is returned).
/// - Text that does not contain any placeholder is returned unchanged.
/// - Malformed placeholders (e.g. `{{env:}}`, unclosed `{{`) are left as-is.
///
/// # Examples
///
/// ```
/// use oxigate::config::interpolation::interpolate;
///
/// // Literal — returned unchanged.
/// assert_eq!(interpolate("no-placeholders"), "no-placeholders");
///
/// // Unknown variable — replaced with empty string.
/// assert_eq!(interpolate("{{env:DOES_NOT_EXIST_OXIGATE}}"), "");
///
/// // Mixed literal and placeholder.
/// unsafe { std::env::set_var("OXIGATE_INTERP_TEST", "bar") };
/// assert_eq!(interpolate("foo-{{env:OXIGATE_INTERP_TEST}}"), "foo-bar");
/// unsafe { std::env::remove_var("OXIGATE_INTERP_TEST") };
/// ```
pub fn interpolate(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut remaining = input;

    while let Some(start) = remaining.find("{{") {
        // Append everything before the opening `{{`.
        result.push_str(&remaining[..start]);
        let after_open = &remaining[start + 2..];

        match after_open.find("}}") {
            None => {
                // No closing `}}` — treat the rest as a literal.
                result.push_str("{{");
                remaining = after_open;
            }
            Some(end) => {
                let inner = after_open[..end].trim();

                if let Some(var_name) = inner.strip_prefix("env:") {
                    let var_name = var_name.trim();
                    if var_name.is_empty() {
                        // `{{env:}}` — malformed, keep as-is.
                        result.push_str("{{");
                        result.push_str(&after_open[..end]);
                        result.push_str("}}");
                    } else {
                        // Valid `{{env:VAR}}` — resolve from environment.
                        result.push_str(&std::env::var(var_name).unwrap_or_default());
                    }
                } else {
                    // Unknown placeholder type — keep as-is so that
                    // `{{access_token}}` and `{{id_token}}` are left for the
                    // request-time HeaderValue resolver.
                    result.push_str("{{");
                    result.push_str(&after_open[..end]);
                    result.push_str("}}");
                }

                remaining = &after_open[end + 2..];
            }
        }
    }

    // Append any trailing text after the last placeholder.
    result.push_str(remaining);
    result
}

/// Interpolate an `Option<String>`, returning `None` unchanged.
pub fn interpolate_opt(input: Option<&str>) -> Option<String> {
    input.map(interpolate)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: set an env var, run the closure, then clean up.
    fn with_env<F: FnOnce()>(key: &str, value: &str, f: F) {
        // SAFETY: tests that call this helper are single-threaded.
        unsafe { std::env::set_var(key, value) };
        f();
        unsafe { std::env::remove_var(key) };
    }

    #[test]
    fn literal_returned_unchanged() {
        assert_eq!(interpolate("no placeholders here"), "no placeholders here");
    }

    #[test]
    fn empty_string_returned_unchanged() {
        assert_eq!(interpolate(""), "");
    }

    #[test]
    fn single_env_placeholder_resolved() {
        with_env("OXIGATE_TEST_SINGLE", "resolved", || {
            assert_eq!(interpolate("{{env:OXIGATE_TEST_SINGLE}}"), "resolved");
        });
    }

    #[test]
    fn placeholder_embedded_in_string() {
        with_env("OXIGATE_TEST_HOST", "example.com", || {
            assert_eq!(
                interpolate("https://{{env:OXIGATE_TEST_HOST}}/path"),
                "https://example.com/path"
            );
        });
    }

    #[test]
    fn multiple_placeholders_in_one_string() {
        with_env("OXIGATE_TEST_SCHEME", "https", || {
            with_env("OXIGATE_TEST_PORT", "8443", || {
                assert_eq!(
                    interpolate("{{env:OXIGATE_TEST_SCHEME}}://host:{{env:OXIGATE_TEST_PORT}}"),
                    "https://host:8443"
                );
            });
        });
    }

    #[test]
    fn unset_variable_becomes_empty_string() {
        // Ensure the variable is definitely not set.
        unsafe { std::env::remove_var("OXIGATE_TEST_UNSET_XYZ") };
        assert_eq!(
            interpolate("prefix-{{env:OXIGATE_TEST_UNSET_XYZ}}-suffix"),
            "prefix--suffix"
        );
    }

    #[test]
    fn unknown_placeholder_type_kept_as_is() {
        // {{access_token}} must NOT be consumed by this interpolator.
        assert_eq!(interpolate("{{access_token}}"), "{{access_token}}");
        assert_eq!(interpolate("{{id_token}}"), "{{id_token}}");
        assert_eq!(interpolate("{{unknown:foo}}"), "{{unknown:foo}}");
    }

    #[test]
    fn malformed_empty_env_name_kept_as_is() {
        assert_eq!(interpolate("{{env:}}"), "{{env:}}");
    }

    #[test]
    fn unclosed_placeholder_kept_as_is() {
        assert_eq!(interpolate("{{env:MISSING_CLOSE"), "{{env:MISSING_CLOSE");
    }

    #[test]
    fn whitespace_trimmed_in_placeholder_name() {
        with_env("OXIGATE_TEST_WS", "trimmed", || {
            assert_eq!(interpolate("{{ env:OXIGATE_TEST_WS }}"), "trimmed");
        });
    }

    #[test]
    fn interpolate_opt_none_returns_none() {
        assert_eq!(interpolate_opt(None), None);
    }

    #[test]
    fn interpolate_opt_some_resolves() {
        with_env("OXIGATE_TEST_OPT", "optval", || {
            assert_eq!(
                interpolate_opt(Some("{{env:OXIGATE_TEST_OPT}}")),
                Some("optval".to_string())
            );
        });
    }
}
