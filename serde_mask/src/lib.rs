extern crate self as serde_mask;

pub use serde_mask_derive::Anonymize;
use std::collections::HashMap;

pub trait AnonymizeTrait {
    fn anonymize(&self, builder: &mut MaskStateBuilder) -> Self;
}

/// Builder for creating a MaskState. It collects patterns and their corresponding replacements during the anonymization process.
/// Since AC requires all patterns to be known upfront, this builder allows us to gather that information as we anonymize fields.
#[allow(clippy::new_without_default)]
pub struct MaskStateBuilder {
    patterns: Vec<String>,
    replacements: Vec<String>,
}

impl MaskStateBuilder {
    pub fn new() -> Self {
        Self {
            patterns: Vec::new(),
            replacements: Vec::new(),
        }
    }

    pub fn add(&mut self, fake_serialized: String, real_serialized: String) {
        self.patterns.push(fake_serialized);
        self.replacements.push(real_serialized);
    }

    pub fn build(self) -> MaskState {
        let ac =
            aho_corasick::AhoCorasick::new(&self.patterns).expect("failed to create AhoCorasick");
        MaskState {
            ac,
            replacements: self.replacements,
        }
    }
}

#[derive(Debug)]
pub struct MaskState {
    ac: aho_corasick::AhoCorasick,
    replacements: Vec<String>,
}

impl MaskState {
    pub fn deanonymize(&self, text: &str) -> String {
        self.ac.replace_all(text, &self.replacements)
    }
}

#[must_use]
pub struct Masked<T: Clone + serde::Serialize> {
    inner: T,
    state: MaskState,
}

impl<T: Clone + serde::Serialize> Masked<T> {
    pub fn new(inner: T, state: MaskState) -> Self {
        Self { inner, state }
    }

    pub fn deanonymize(&self, text: &str) -> String {
        self.state.deanonymize(text)
    }
}

impl<T: Clone + serde::Serialize> serde::Serialize for Masked<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.inner.serialize(serializer)
    }
}

impl AnonymizeTrait for String {
    fn anonymize(&self, builder: &mut MaskStateBuilder) -> Self {
        let fake: String = (0..10).map(|_| fastrand::alphanumeric()).collect();
        let fake = format!("ANON_{fake}");
        builder.add(fake.clone(), self.clone());
        fake
    }
}

macro_rules! impl_anonymize_for_int {
    ($($t:ident),*) => {
        $(
            impl AnonymizeTrait for $t {
                fn anonymize(&self, builder: &mut MaskStateBuilder) -> Self {
                    let fake = fastrand::$t(..);
                    builder.add(fake.to_string(), self.to_string());
                    fake
                }
            }
        )*
    };
}

impl_anonymize_for_int!(
    u8, u16, u32, u64, u128, i8, i16, i32, i64, i128, usize, isize
);

impl AnonymizeTrait for bool {
    fn anonymize(&self, builder: &mut MaskStateBuilder) -> Self {
        let fake = fastrand::bool();
        builder.add(fake.to_string(), self.to_string());
        fake
    }
}

macro_rules! impl_anonymize_for_float {
    ($($t:ident),*) => {
        $(
            impl AnonymizeTrait for $t {
                fn anonymize(&self, builder: &mut MaskStateBuilder) -> Self {
                    let fake: $t = fastrand::$t() * 1000.0;
                    builder.add(fake.to_string(), self.to_string());
                    fake
                }
            }
        )*
    };
}

impl_anonymize_for_float!(f32, f64);

impl<T: AnonymizeTrait> AnonymizeTrait for Option<T> {
    fn anonymize(&self, builder: &mut MaskStateBuilder) -> Self {
        self.as_ref().map(|v| v.anonymize(builder))
    }
}

impl<T: AnonymizeTrait> AnonymizeTrait for Vec<T> {
    fn anonymize(&self, builder: &mut MaskStateBuilder) -> Self {
        self.iter().map(|item| item.anonymize(builder)).collect()
    }
}

impl<K, V> AnonymizeTrait for HashMap<K, V>
where
    K: AnonymizeTrait + Eq + std::hash::Hash,
    V: AnonymizeTrait,
{
    fn anonymize(&self, builder: &mut MaskStateBuilder) -> Self {
        self.iter()
            .map(|(k, v)| (k.anonymize(builder), v.anonymize(builder)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_string_anonymization() {
        #[derive(Clone, Anonymize, serde::Serialize, Debug)]
        struct TestStruct {
            name: String,
            #[anon]
            secret: String,
        }

        let data = TestStruct {
            name: "public".to_string(),
            secret: "sensitive".to_string(),
        };

        let masked = data.mask();
        let serialized = serde_json::to_string(&masked).unwrap();

        assert!(serialized.contains("\"name\":\"public\""));
        assert!(!serialized.contains("sensitive"));
        assert!(serialized.contains("ANON_"));

        let deanonymized = masked.deanonymize(&serialized);
        assert!(deanonymized.contains("\"secret\":\"sensitive\""));
    }

    #[test]
    fn test_primitive_number_anonymization() {
        #[derive(Clone, Anonymize, serde::Serialize, Debug)]
        struct TestStruct {
            #[anon]
            age: isize,
            #[anon]
            count: usize,
        }

        let data = TestStruct {
            age: 42,
            count: 1337,
        };

        let masked = data.mask();
        let serialized = serde_json::to_string(&masked).unwrap();

        assert!(!serialized.contains(":42"));
        assert!(!serialized.contains(":1337"));

        let deanonymized = masked.deanonymize(&serialized);
        assert!(deanonymized.contains("42"));
        assert!(deanonymized.contains("1337"));
    }

    #[test]
    fn test_vec_string_anonymization() {
        #[derive(Clone, Anonymize, serde::Serialize, Debug)]
        struct TestStruct {
            #[anon]
            secrets: Vec<String>,
        }

        let data = TestStruct {
            secrets: vec![
                "secret1".to_string(),
                "secret2".to_string(),
                "secret3".to_string(),
            ],
        };

        let masked = data.mask();
        let serialized = serde_json::to_string(&masked).unwrap();

        assert!(!serialized.contains("secret1"));
        assert!(!serialized.contains("secret2"));
        assert!(!serialized.contains("secret3"));
        assert!(serialized.contains("ANON_"));
        assert!(serialized.contains("["));
        assert!(serialized.contains("]"));

        let deanonymized = masked.deanonymize(&serialized);
        assert!(deanonymized.contains("secret1"));
        assert!(deanonymized.contains("secret2"));
        assert!(deanonymized.contains("secret3"));
    }

    #[test]
    fn test_hashmap_anonymization() {
        #[derive(Clone, Anonymize, serde::Serialize, Debug)]
        struct TestStruct {
            #[anon]
            data: HashMap<String, String>,
        }

        let mut map = HashMap::new();
        map.insert("key1".to_string(), "value1".to_string());
        map.insert("key2".to_string(), "value2".to_string());

        let data = TestStruct { data: map };

        let masked = data.mask();
        let serialized = serde_json::to_string(&masked).unwrap();

        assert!(!serialized.contains("key1"));
        assert!(!serialized.contains("key2"));
        assert!(!serialized.contains("value1"));
        assert!(!serialized.contains("value2"));
        assert!(serialized.contains("ANON_"));

        let deanonymized = masked.deanonymize(&serialized);
        assert!(deanonymized.contains("key1"));
        assert!(deanonymized.contains("key2"));
        assert!(deanonymized.contains("value1"));
        assert!(deanonymized.contains("value2"));
    }

    #[test]
    fn test_option_some_anonymization() {
        #[derive(Clone, Anonymize, serde::Serialize, Debug)]
        struct TestStruct {
            #[anon]
            maybe_secret: Option<String>,
        }

        let data = TestStruct {
            maybe_secret: Some("confidential".to_string()),
        };

        let masked = data.mask();
        let serialized = serde_json::to_string(&masked).unwrap();

        assert!(!serialized.contains("confidential"));
        assert!(serialized.contains("ANON_"));

        let deanonymized = masked.deanonymize(&serialized);
        assert!(deanonymized.contains("confidential"));
    }

    #[test]
    fn test_option_none_preserved() {
        #[derive(Clone, Anonymize, serde::Serialize, Debug)]
        struct TestStruct {
            #[anon]
            maybe_secret: Vec<Option<String>>,
        }

        let data = TestStruct {
            maybe_secret: vec![Some("value".to_string()), None, Some("other".to_string())],
        };

        let masked = data.mask();
        let serialized = serde_json::to_string(&masked).unwrap();

        assert!(serialized.contains("null"));

        let deanonymized = masked.deanonymize(&serialized);
        assert!(deanonymized.contains("value"));
        assert!(deanonymized.contains("null"));
        assert!(deanonymized.contains("other"));
    }

    #[test]
    fn test_no_substring_collision() {
        #[derive(Clone, Anonymize, serde::Serialize, Debug)]
        struct TestStruct {
            #[anon]
            age: isize,
            #[anon]
            code: String,
        }

        let data = TestStruct {
            age: 47,
            code: "code_47_suffix".to_string(),
        };

        let masked = data.mask();
        let serialized = serde_json::to_string(&masked).unwrap();
        let deanonymized = masked.deanonymize(&serialized);

        assert!(deanonymized.contains("code_47_suffix"));
    }

    #[test]
    fn test_serde_skip_serializing() {
        #[derive(Clone, Anonymize, serde::Serialize, Debug)]
        struct TestStruct {
            #[serde(skip_serializing)]
            internal: String,
            #[anon]
            public: String,
        }

        let data = TestStruct {
            internal: "hidden".to_string(),
            public: "visible".to_string(),
        };

        let masked = data.mask();
        let serialized = serde_json::to_string(&masked).unwrap();

        assert!(!serialized.contains("internal"));
        assert!(!serialized.contains("hidden"));
    }

    #[test]
    fn test_empty_vec() {
        #[derive(Clone, Anonymize, serde::Serialize, Debug)]
        struct TestStruct {
            #[anon]
            items: Vec<String>,
        }

        let data = TestStruct { items: vec![] };

        let masked = data.mask();
        let serialized = serde_json::to_string(&masked).unwrap();
        assert_eq!(serialized, r#"{"items":[]}"#);

        let deanonymized = masked.deanonymize(&serialized);
        assert_eq!(deanonymized, r#"{"items":[]}"#);
    }

    #[test]
    fn test_empty_hashmap() {
        #[derive(Clone, Anonymize, serde::Serialize, Debug)]
        struct TestStruct {
            #[anon]
            data: HashMap<String, String>,
        }

        let data = TestStruct {
            data: HashMap::new(),
        };

        let masked = data.mask();
        let serialized = serde_json::to_string(&masked).unwrap();
        assert_eq!(serialized, r#"{"data":{}}"#);

        let deanonymized = masked.deanonymize(&serialized);
        assert_eq!(deanonymized, r#"{"data":{}}"#);
    }

    #[test]
    fn test_empty_string() {
        #[derive(Clone, Anonymize, serde::Serialize, Debug)]
        struct TestStruct {
            #[anon]
            value: String,
        }

        let data = TestStruct {
            value: "".to_string(),
        };

        let masked = data.mask();
        let serialized = serde_json::to_string(&masked).unwrap();
        assert!(serialized.contains("ANON_"));

        let deanonymized = masked.deanonymize(&serialized);
        assert!(deanonymized.contains("\"value\":\"\""));
    }

    #[test]
    fn test_unicode_strings() {
        #[derive(Clone, Anonymize, serde::Serialize, Debug)]
        struct TestStruct {
            #[anon]
            greeting: String,
            #[anon]
            emoji: String,
        }

        let data = TestStruct {
            greeting: "こんにちは".to_string(),
            emoji: "🔐🔑".to_string(),
        };

        let masked = data.mask();
        let serialized = serde_json::to_string(&masked).unwrap();
        assert!(!serialized.contains("こんにちは"));
        assert!(!serialized.contains("🔐"));

        let deanonymized = masked.deanonymize(&serialized);
        assert!(deanonymized.contains("こんにちは"));
        assert!(deanonymized.contains("🔐🔑"));
    }

    #[test]
    fn test_negative_numbers() {
        #[derive(Clone, Anonymize, serde::Serialize, Debug)]
        struct TestStruct {
            #[anon]
            negative: isize,
            #[anon]
            also_negative: i32,
        }

        let data = TestStruct {
            negative: -42,
            also_negative: -1337,
        };

        let masked = data.mask();
        let serialized = serde_json::to_string(&masked).unwrap();
        let deanonymized = masked.deanonymize(&serialized);
        assert!(deanonymized.contains("-42"));
        assert!(deanonymized.contains("-1337"));
    }

    #[test]
    fn test_duplicate_values_get_unique_anonymization() {
        #[derive(Clone, Anonymize, serde::Serialize, Debug)]
        struct TestStruct {
            #[anon]
            first: String,
            #[anon]
            second: String,
        }

        let data = TestStruct {
            first: "same_value".to_string(),
            second: "same_value".to_string(),
        };

        let masked = data.mask();
        let serialized = serde_json::to_string(&masked).unwrap();

        let anon_count = serialized.matches("ANON_").count();
        assert_eq!(anon_count, 2);

        let deanonymized = masked.deanonymize(&serialized);
        let same_count = deanonymized.matches("same_value").count();
        assert_eq!(same_count, 2);
    }

    #[test]
    fn test_nested_option_in_vec() {
        #[derive(Clone, Anonymize, serde::Serialize, Debug)]
        struct TestStruct {
            #[anon]
            nested: Vec<Option<String>>,
        }

        let data = TestStruct {
            nested: vec![
                Some("first".to_string()),
                None,
                Some("third".to_string()),
                None,
            ],
        };

        let masked = data.mask();
        let serialized = serde_json::to_string(&masked).unwrap();
        assert!(!serialized.contains("first"));
        assert!(!serialized.contains("third"));
        assert_eq!(serialized.matches("null").count(), 2);

        let deanonymized = masked.deanonymize(&serialized);
        assert!(deanonymized.contains("first"));
        assert!(deanonymized.contains("third"));
        assert_eq!(deanonymized.matches("null").count(), 2);
    }

    #[test]
    fn test_hashmap_with_option_values() {
        #[derive(Clone, Anonymize, serde::Serialize, Debug)]
        struct TestStruct {
            #[anon]
            data: HashMap<String, Option<String>>,
        }

        let mut map = HashMap::new();
        map.insert("key1".to_string(), Some("value1".to_string()));
        map.insert("key2".to_string(), None);

        let data = TestStruct { data: map };

        let masked = data.mask();
        let serialized = serde_json::to_string(&masked).unwrap();
        assert!(!serialized.contains("key1"));
        assert!(!serialized.contains("key2"));
        assert!(!serialized.contains("value1"));

        let deanonymized = masked.deanonymize(&serialized);
        assert!(deanonymized.contains("key1"));
        assert!(deanonymized.contains("key2"));
        assert!(deanonymized.contains("value1"));
    }

    #[test]
    fn test_serde_rename() {
        #[derive(Clone, Anonymize, serde::Serialize, Debug)]
        struct TestStruct {
            #[serde(rename = "secretData")]
            #[anon]
            secret: String,
        }

        let data = TestStruct {
            secret: "sensitive".to_string(),
        };

        let masked = data.mask();
        let serialized = serde_json::to_string(&masked).unwrap();

        assert!(serialized.contains("secretData"));
        assert!(!serialized.contains("\"secret\""));
        assert!(!serialized.contains("sensitive"));

        let deanonymized = masked.deanonymize(&serialized);
        assert!(deanonymized.contains("sensitive"));
    }

    #[test]
    fn test_no_anon_fields() {
        #[derive(Clone, Anonymize, serde::Serialize, Debug)]
        struct TestStruct {
            name: String,
            count: usize,
        }

        let data = TestStruct {
            name: "public".to_string(),
            count: 42,
        };

        let masked = data.mask();
        let serialized = serde_json::to_string(&masked).unwrap();

        assert!(serialized.contains("public"));
        assert!(serialized.contains("42"));
        assert!(!serialized.contains("ANON_"));
    }

    #[test]
    fn test_all_fields_anonymized() {
        #[derive(Clone, Anonymize, serde::Serialize, Debug)]
        struct TestStruct {
            #[anon]
            field1: String,
            #[anon]
            field2: usize,
            #[anon]
            field3: Vec<String>,
        }

        let data = TestStruct {
            field1: "secret1".to_string(),
            field2: 12345,
            field3: vec!["a".to_string(), "b".to_string()],
        };

        let masked = data.mask();
        let serialized = serde_json::to_string(&masked).unwrap();
        assert!(!serialized.contains("secret1"));
        assert!(!serialized.contains("12345"));

        let deanonymized = masked.deanonymize(&serialized);
        assert!(deanonymized.contains("secret1"));
        assert!(deanonymized.contains("12345"));
    }

    #[test]
    fn test_special_characters_in_strings() {
        #[derive(Clone, Anonymize, serde::Serialize, Debug)]
        struct TestStruct {
            #[anon]
            with_quotes: String,
            #[anon]
            with_newlines: String,
            #[anon]
            with_backslash: String,
        }

        let data = TestStruct {
            with_quotes: r#"say "hello""#.to_string(),
            with_newlines: "line1\nline2".to_string(),
            with_backslash: r"path\to\file".to_string(),
        };

        let masked = data.mask();
        let serialized = serde_json::to_string(&masked).unwrap();
        assert!(!serialized.contains("hello"));
        assert!(!serialized.contains("line1"));
        assert!(!serialized.contains("path"));

        let deanonymized = masked.deanonymize(&serialized);
        assert!(deanonymized.contains("hello"));
        assert!(deanonymized.contains("line1"));
        assert!(deanonymized.contains("path"));
    }

    #[test]
    fn test_vec_of_integers() {
        #[derive(Clone, Anonymize, serde::Serialize, Debug)]
        struct TestStruct {
            #[anon]
            numbers: Vec<i32>,
        }

        let data = TestStruct {
            numbers: vec![100, 200, 300, -400, -500],
        };

        let masked = data.mask();
        let serialized = serde_json::to_string(&masked).unwrap();

        let deanonymized = masked.deanonymize(&serialized);
        assert!(deanonymized.contains("100"));
        assert!(deanonymized.contains("200"));
        assert!(deanonymized.contains("-400"));
    }

    #[test]
    fn test_option_none_standalone() {
        #[derive(Clone, Anonymize, serde::Serialize, Debug)]
        struct TestStruct {
            #[anon]
            maybe: Option<String>,
        }

        let data = TestStruct { maybe: None };

        let masked = data.mask();
        let serialized = serde_json::to_string(&masked).unwrap();
        assert!(serialized.contains("null"));

        let deanonymized = masked.deanonymize(&serialized);
        assert!(deanonymized.contains("null"));
    }

    #[test]
    fn test_large_vec() {
        #[derive(Clone, Anonymize, serde::Serialize, Debug)]
        struct TestStruct {
            #[anon]
            items: Vec<String>,
        }

        let items: Vec<String> = (0..100).map(|i| format!("item_{}", i)).collect();
        let data = TestStruct { items };

        let masked = data.mask();
        let serialized = serde_json::to_string(&masked).unwrap();
        assert!(!serialized.contains("item_0"));
        assert!(!serialized.contains("item_99"));

        let deanonymized = masked.deanonymize(&serialized);
        assert!(deanonymized.contains("item_0"));
        assert!(deanonymized.contains("item_50"));
        assert!(deanonymized.contains("item_99"));
    }
}
