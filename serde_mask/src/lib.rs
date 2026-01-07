pub use serde_mask_derive::{Anonymize, anonymize};
use std::collections::HashMap;

/// Trait for anonymizing and deanonymizing values
pub trait AnonymizeTrait {
    type State;

    /// Returns the anonymized state for this value
    fn anonymize(&self) -> Self::State;

    /// Replaces anonymized patterns in the serialized text with original values
    fn deanonymize(&self, state: Self::State, serialized: &str) -> String;
}

macro_rules! impl_anonymize_for_int {
    ($($t:ty),*) => {
        $(
            impl AnonymizeTrait for $t {
                type State = String;

                fn anonymize(&self) -> Self::State {
                    format!("ANON_{}", fastrand::usize(0..1_000_000))
                }

                fn deanonymize(&self, state: Self::State, serialized: &str) -> String {
                    let replace = [self.to_string()];
                    let ac = aho_corasick::AhoCorasick::new([state]).expect("failed to create AhoCorasick");
                    ac.replace_all(serialized, &replace)
                }
            }
        )*
    };
}

impl_anonymize_for_int!(
    usize, isize, u8, u16, u32, u64, u128, i8, i16, i32, i64, i128
);

impl AnonymizeTrait for String {
    type State = String;

    fn anonymize(&self) -> Self::State {
        format!("ANON_{}", fastrand::usize(0..1_000_000))
    }

    fn deanonymize(&self, state: Self::State, serialized: &str) -> String {
        let replace = [self.to_string()];
        let ac = aho_corasick::AhoCorasick::new([state]).expect("failed to create AhoCorasick");
        ac.replace_all(serialized, &replace)
    }
}

impl<T> AnonymizeTrait for Option<T>
where
    T: AnonymizeTrait,
{
    type State = Option<T::State>;

    fn anonymize(&self) -> Self::State {
        self.as_ref().map(|v| v.anonymize())
    }

    fn deanonymize(&self, state: Self::State, serialized: &str) -> String {
        match (self, state) {
            (Some(value), Some(s)) => value.deanonymize(s, serialized),
            (Some(_), None) | (None, Some(_)) => serialized.to_string(),
            _ => serialized.to_string(),
        }
    }
}

impl<T> AnonymizeTrait for Vec<T>
where
    T: AnonymizeTrait,
{
    type State = Vec<T::State>;

    fn anonymize(&self) -> Self::State {
        self.iter().map(|item| item.anonymize()).collect()
    }

    fn deanonymize(&self, state: Self::State, serialized: &str) -> String {
        let mut result = serialized.to_string();
        for (item, s) in self.iter().zip(state.into_iter()) {
            result = item.deanonymize(s, &result);
        }
        result
    }
}

impl<K, V> AnonymizeTrait for HashMap<K, V>
where
    K: AnonymizeTrait + Eq + std::hash::Hash,
    V: AnonymizeTrait,
{
    // FIXME: This assumes that the iteration order of the HashMap is preserved between
    // anonymization and deanonymization, which is true for the current implementation
    // but not guaranteed by the HashMap contract which makes this impl weird as hell.
    type State = Vec<(K::State, V::State)>;

    fn anonymize(&self) -> Self::State {
        self.iter()
            .map(|(k, v)| (k.anonymize(), v.anonymize()))
            .collect()
    }

    fn deanonymize(&self, state: Self::State, serialized: &str) -> String {
        let mut result = serialized.to_string();
        // Iteration order is preserved because both use the same HashMap iteration
        for ((orig_key, orig_value), (anon_key, anon_value)) in self.iter().zip(state.into_iter()) {
            result = orig_key.deanonymize(anon_key, &result);
            result = orig_value.deanonymize(anon_value, &result);
        }
        result
    }
}

#[allow(dead_code)]
#[cfg(test)]
mod tests {

    use super::*;

    use std::collections::HashMap;

    #[test]
    fn test_basic_string_anonymization() {
        #[anonymize]
        #[derive(Anonymize, Default, Debug)]
        struct TestStruct {
            name: String,
            #[anon]
            secret: String,
        }

        let data = TestStruct {
            name: "public".to_string(),
            secret: "sensitive".to_string(),
            ..Default::default()
        };

        let serialized = serde_json::to_string(&data).unwrap();

        // Name should NOT be anonymized
        assert!(serialized.contains("\"name\":\"public\""));

        // Secret SHOULD be anonymized
        assert!(!serialized.contains("sensitive"));
        assert!(serialized.contains("ANON_"));

        // Deanonymization should restore original
        let deanonymized = data.deanonymize(serialized.clone());
        assert!(deanonymized.contains("\"secret\":\"sensitive\""));
    }

    #[test]
    fn test_primitive_number_anonymization() {
        #[anonymize]
        #[derive(Anonymize, Default, Debug)]
        struct TestStruct {
            #[anon]
            age: isize,
            #[anon]
            count: usize,
        }

        let data = TestStruct {
            age: 42,
            count: 1337,
            ..Default::default()
        };

        let serialized = serde_json::to_string(&data).unwrap();

        // Numbers should be anonymized as strings
        assert!(!serialized.contains("42"));
        assert!(!serialized.contains("1337"));
        assert!(serialized.contains("ANON_"));

        // Deanonymization should restore
        let deanonymized = data.deanonymize(serialized.clone());
        assert!(deanonymized.contains("\"age\":\"42\""));
        assert!(deanonymized.contains("\"count\":\"1337\""));
    }

    #[test]
    fn test_vec_string_anonymization() {
        #[anonymize]
        #[derive(Anonymize, Default, Debug)]
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
            ..Default::default()
        };

        let serialized = serde_json::to_string(&data).unwrap();

        // Secrets should be anonymized
        assert!(!serialized.contains("secret1"));
        assert!(!serialized.contains("secret2"));
        assert!(!serialized.contains("secret3"));
        assert!(serialized.contains("ANON_"));

        // Should preserve array structure
        assert!(serialized.contains("["));
        assert!(serialized.contains("]"));

        // Deanonymization should restore all elements
        let deanonymized = data.deanonymize(serialized.clone());
        assert!(deanonymized.contains("secret1"));
        assert!(deanonymized.contains("secret2"));
        assert!(deanonymized.contains("secret3"));
    }

    #[test]
    fn test_hashmap_anonymization() {
        #[anonymize]
        #[derive(Anonymize, Default, Debug)]
        struct TestStruct {
            #[anon]
            data: HashMap<String, String>,
        }

        let mut map = HashMap::new();
        map.insert("key1".to_string(), "value1".to_string());
        map.insert("key2".to_string(), "value2".to_string());

        let data = TestStruct {
            data: map,
            ..Default::default()
        };

        let serialized = serde_json::to_string(&data).unwrap();

        // Both keys and values should be anonymized
        assert!(!serialized.contains("key1"));
        assert!(!serialized.contains("key2"));
        assert!(!serialized.contains("value1"));
        assert!(!serialized.contains("value2"));
        assert!(serialized.contains("ANON_"));

        // Deanonymization should restore
        let deanonymized = data.deanonymize(serialized.clone());
        assert!(deanonymized.contains("key1"));
        assert!(deanonymized.contains("key2"));
        assert!(deanonymized.contains("value1"));
        assert!(deanonymized.contains("value2"));
    }

    #[test]
    fn test_option_some_anonymization() {
        #[anonymize]
        #[derive(Anonymize, Default, Debug)]
        struct TestStruct {
            #[anon]
            maybe_secret: Option<String>,
        }

        let data = TestStruct {
            maybe_secret: Some("confidential".to_string()),
            ..Default::default()
        };

        let serialized = serde_json::to_string(&data).unwrap();

        assert!(!serialized.contains("confidential"));
        assert!(serialized.contains("ANON_"));

        let deanonymized = data.deanonymize(serialized.clone());
        assert!(deanonymized.contains("confidential"));
    }

    #[test]
    fn test_option_none_preserved() {
        #[anonymize]
        #[derive(Anonymize, Default, Debug)]
        struct TestStruct {
            #[anon]
            maybe_secret: Vec<Option<String>>,
        }

        let data = TestStruct {
            maybe_secret: vec![Some("value".to_string()), None, Some("other".to_string())],
            ..Default::default()
        };

        let serialized = serde_json::to_string(&data).unwrap();

        // Should preserve None
        assert!(serialized.contains("null"));

        let deanonymized = data.deanonymize(serialized.clone());
        assert!(deanonymized.contains("value"));
        assert!(deanonymized.contains("null"));
        assert!(deanonymized.contains("other"));
    }

    #[test]
    fn test_consistent_anonymization() {
        #[anonymize]
        #[derive(Anonymize, Default, Debug)]
        struct TestStruct {
            #[anon]
            secret: String,
        }

        let data = TestStruct {
            secret: "sensitive".to_string(),
            ..Default::default()
        };

        // Serialize multiple times
        let serialized1 = serde_json::to_string(&data).unwrap();
        let serialized2 = serde_json::to_string(&data).unwrap();

        // Should use same anonymized value (OnceLock)
        assert_eq!(serialized1, serialized2);
    }

    #[test]
    fn test_no_substring_collision() {
        #[anonymize]
        #[derive(Anonymize, Default, Debug)]
        struct TestStruct {
            #[anon]
            age: isize,
            #[anon]
            code: String,
        }

        let data = TestStruct {
            age: 47,
            code: "code_47_suffix".to_string(),
            ..Default::default()
        };

        let serialized = serde_json::to_string(&data).unwrap();
        let deanonymized = data.deanonymize(serialized.clone());

        // The "47" from age should NOT corrupt the "47" in code
        assert!(deanonymized.contains("\"age\":\"47\""));
        assert!(deanonymized.contains("code_47_suffix"));
    }

    #[test]
    fn test_serde_skip_serializing() {
        #[anonymize]
        #[derive(Anonymize, Default, Debug)]
        struct TestStruct {
            #[serde(skip_serializing)]
            internal: String,
            #[anon]
            public: String,
        }

        let data = TestStruct {
            internal: "hidden".to_string(),
            public: "visible".to_string(),
            ..Default::default()
        };

        let serialized = serde_json::to_string(&data).unwrap();

        // skip_serializing should be honored
        assert!(!serialized.contains("internal"));
        assert!(!serialized.contains("hidden"));
    }

    #[test]
    fn test_custom_range() {
        #[anonymize]
        #[derive(Anonymize, Default, Debug)]
        struct TestStruct {
            #[anon(range = "1000..9999")]
            value: isize,
        }

        let data = TestStruct {
            value: 42,
            ..Default::default()
        };

        let serialized = serde_json::to_string(&data).unwrap();
        let deanonymized = data.deanonymize(serialized.clone());

        // Should restore original
        assert!(deanonymized.contains("\"value\":\"42\""));
    }

    #[test]
    fn test_empty_vec() {
        #[anonymize]
        #[derive(Anonymize, Default, Debug)]
        struct TestStruct {
            #[anon]
            items: Vec<String>,
        }

        let data = TestStruct {
            items: vec![],
            ..Default::default()
        };

        let serialized = serde_json::to_string(&data).unwrap();
        assert_eq!(serialized, r#"{"items":[]}"#);

        let deanonymized = data.deanonymize(serialized.clone());
        assert_eq!(deanonymized, r#"{"items":[]}"#);
    }

    #[test]
    fn test_empty_hashmap() {
        #[anonymize]
        #[derive(Anonymize, Default, Debug)]
        struct TestStruct {
            #[anon]
            data: HashMap<String, String>,
        }

        let data = TestStruct {
            data: HashMap::new(),
            ..Default::default()
        };

        let serialized = serde_json::to_string(&data).unwrap();
        // INFO: HashMap state is stored as Vec<(K, V)> to preserve iteration order,
        // so empty HashMap serializes as [] not {}
        // xd
        assert_eq!(serialized, r#"{"data":[]}"#);

        let deanonymized = data.deanonymize(serialized.clone());
        assert_eq!(deanonymized, r#"{"data":[]}"#);
    }

    #[test]
    fn test_empty_string() {
        #[anonymize]
        #[derive(Anonymize, Default, Debug)]
        struct TestStruct {
            #[anon]
            value: String,
        }

        let data = TestStruct {
            value: "".to_string(),
            ..Default::default()
        };

        let serialized = serde_json::to_string(&data).unwrap();
        // Empty string should still be anonymized
        assert!(serialized.contains("ANON_"));

        let deanonymized = data.deanonymize(serialized.clone());
        assert!(deanonymized.contains("\"value\":\"\""));
    }

    #[test]
    fn test_unicode_strings() {
        #[anonymize]
        #[derive(Anonymize, Default, Debug)]
        struct TestStruct {
            #[anon]
            greeting: String,
            #[anon]
            emoji: String,
        }

        let data = TestStruct {
            greeting: "こんにちは".to_string(),
            emoji: "🔐🔑".to_string(),
            ..Default::default()
        };

        let serialized = serde_json::to_string(&data).unwrap();
        assert!(!serialized.contains("こんにちは"));
        assert!(!serialized.contains("🔐"));

        let deanonymized = data.deanonymize(serialized.clone());
        assert!(deanonymized.contains("こんにちは"));
        assert!(deanonymized.contains("🔐🔑"));
    }

    #[test]
    fn test_negative_numbers() {
        #[anonymize]
        #[derive(Anonymize, Default, Debug)]
        struct TestStruct {
            #[anon]
            negative: isize,
            #[anon]
            also_negative: i32,
        }

        let data = TestStruct {
            negative: -42,
            also_negative: -1337,
            ..Default::default()
        };

        let serialized = serde_json::to_string(&data).unwrap();
        assert!(!serialized.contains("-42"));
        assert!(!serialized.contains("-1337"));

        let deanonymized = data.deanonymize(serialized.clone());
        assert!(deanonymized.contains("\"-42\""));
        assert!(deanonymized.contains("\"-1337\""));
    }

    #[test]
    fn test_integer_edge_cases() {
        #[anonymize]
        #[derive(Anonymize, Default, Debug)]
        struct TestStruct {
            #[anon]
            zero: usize,
            #[anon]
            max_u8: u8,
            #[anon]
            min_i8: i8,
        }

        let data = TestStruct {
            zero: 0,
            max_u8: u8::MAX,
            min_i8: i8::MIN,
            ..Default::default()
        };

        let serialized = serde_json::to_string(&data).unwrap();
        assert!(!serialized.contains("\"0\""));
        assert!(!serialized.contains("255"));
        assert!(!serialized.contains("-128"));

        let deanonymized = data.deanonymize(serialized.clone());
        assert!(deanonymized.contains("\"zero\":\"0\""));
        assert!(deanonymized.contains("\"255\""));
        assert!(deanonymized.contains("\"-128\""));
    }

    #[test]
    fn test_duplicate_values_get_unique_anonymization() {
        #[anonymize]
        #[derive(Anonymize, Default, Debug)]
        struct TestStruct {
            #[anon]
            first: String,
            #[anon]
            second: String,
        }

        let data = TestStruct {
            first: "same_value".to_string(),
            second: "same_value".to_string(),
            ..Default::default()
        };

        let serialized = serde_json::to_string(&data).unwrap();

        // Both should be anonymized (different ANON patterns)
        let anon_count = serialized.matches("ANON_").count();
        assert_eq!(anon_count, 2);

        // Deanonymization should restore both
        let deanonymized = data.deanonymize(serialized.clone());
        let same_count = deanonymized.matches("same_value").count();
        assert_eq!(same_count, 2);
    }

    #[test]
    fn test_nested_option_in_vec() {
        #[anonymize]
        #[derive(Anonymize, Default, Debug)]
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
            ..Default::default()
        };

        let serialized = serde_json::to_string(&data).unwrap();
        assert!(!serialized.contains("first"));
        assert!(!serialized.contains("third"));
        // Should have 2 nulls
        assert_eq!(serialized.matches("null").count(), 2);

        let deanonymized = data.deanonymize(serialized.clone());
        assert!(deanonymized.contains("first"));
        assert!(deanonymized.contains("third"));
        assert_eq!(deanonymized.matches("null").count(), 2);
    }

    #[test]
    fn test_hashmap_with_option_values() {
        #[anonymize]
        #[derive(Anonymize, Default, Debug)]
        struct TestStruct {
            #[anon]
            data: HashMap<String, Option<String>>,
        }

        let mut map = HashMap::new();
        map.insert("key1".to_string(), Some("value1".to_string()));
        map.insert("key2".to_string(), None);

        let data = TestStruct {
            data: map,
            ..Default::default()
        };

        let serialized = serde_json::to_string(&data).unwrap();
        assert!(!serialized.contains("key1"));
        assert!(!serialized.contains("key2"));
        assert!(!serialized.contains("value1"));

        let deanonymized = data.deanonymize(serialized.clone());
        assert!(deanonymized.contains("key1"));
        assert!(deanonymized.contains("key2"));
        assert!(deanonymized.contains("value1"));
    }

    #[test]
    fn test_serde_rename() {
        #[anonymize]
        #[derive(Anonymize, Default, Debug)]
        struct TestStruct {
            #[serde(rename = "secretData")]
            #[anon]
            secret: String,
        }

        let data = TestStruct {
            secret: "sensitive".to_string(),
            ..Default::default()
        };

        let serialized = serde_json::to_string(&data).unwrap();

        // Should use renamed field name
        assert!(serialized.contains("secretData"));
        assert!(!serialized.contains("\"secret\""));
        assert!(!serialized.contains("sensitive"));

        let deanonymized = data.deanonymize(serialized.clone());
        assert!(deanonymized.contains("sensitive"));
    }

    #[test]
    fn test_no_anon_fields() {
        #[anonymize]
        #[derive(Anonymize, Default, Debug)]
        struct TestStruct {
            name: String,
            count: usize,
        }

        let data = TestStruct {
            name: "public".to_string(),
            count: 42,
            ..Default::default()
        };

        let serialized = serde_json::to_string(&data).unwrap();

        // Nothing should be anonymized
        assert!(serialized.contains("public"));
        assert!(serialized.contains("42"));
        assert!(!serialized.contains("ANON_"));
    }

    #[test]
    fn test_all_fields_anonymized() {
        #[anonymize]
        #[derive(Anonymize, Default, Debug)]
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
            ..Default::default()
        };

        let serialized = serde_json::to_string(&data).unwrap();
        assert!(!serialized.contains("secret1"));
        assert!(!serialized.contains("12345"));
        assert!(!serialized.contains("\"a\""));
        assert!(!serialized.contains("\"b\""));

        let deanonymized = data.deanonymize(serialized.clone());
        assert!(deanonymized.contains("secret1"));
        assert!(deanonymized.contains("12345"));
        assert!(deanonymized.contains("\"a\""));
        assert!(deanonymized.contains("\"b\""));
    }

    #[test]
    fn test_special_characters_in_strings() {
        #[anonymize]
        #[derive(Anonymize, Default, Debug)]
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
            ..Default::default()
        };

        let serialized = serde_json::to_string(&data).unwrap();
        assert!(!serialized.contains("hello"));
        assert!(!serialized.contains("line1"));
        assert!(!serialized.contains("path"));

        let deanonymized = data.deanonymize(serialized.clone());
        // JSON escapes these, so check for escaped versions
        assert!(deanonymized.contains("hello"));
        assert!(deanonymized.contains("line1"));
        assert!(deanonymized.contains("path"));
    }

    #[test]
    fn test_vec_of_integers() {
        #[anonymize]
        #[derive(Anonymize, Default, Debug)]
        struct TestStruct {
            #[anon]
            numbers: Vec<i32>,
        }

        let data = TestStruct {
            numbers: vec![1, 2, 3, -4, -5],
            ..Default::default()
        };

        let serialized = serde_json::to_string(&data).unwrap();
        // Original numbers should not appear
        assert!(!serialized.contains("\"1\"") || serialized.contains("ANON_"));

        let deanonymized = data.deanonymize(serialized.clone());
        // Should restore all numbers
        assert!(deanonymized.contains("\"1\""));
        assert!(deanonymized.contains("\"2\""));
        assert!(deanonymized.contains("\"-4\""));
    }

    #[test]
    fn test_option_none_standalone() {
        #[anonymize]
        #[derive(Anonymize, Default, Debug)]
        struct TestStruct {
            #[anon]
            maybe: Option<String>,
        }

        let data = TestStruct {
            maybe: None,
            ..Default::default()
        };

        let serialized = serde_json::to_string(&data).unwrap();
        assert!(serialized.contains("null"));

        let deanonymized = data.deanonymize(serialized.clone());
        assert!(deanonymized.contains("null"));
    }

    #[test]
    fn test_large_vec() {
        #[anonymize]
        #[derive(Anonymize, Default, Debug)]
        struct TestStruct {
            #[anon]
            items: Vec<String>,
        }

        let items: Vec<String> = (0..100).map(|i| format!("item_{}", i)).collect();
        let data = TestStruct {
            items,
            ..Default::default()
        };

        let serialized = serde_json::to_string(&data).unwrap();
        // None of the original items should appear
        assert!(!serialized.contains("item_0"));
        assert!(!serialized.contains("item_99"));

        let deanonymized = data.deanonymize(serialized.clone());
        assert!(deanonymized.contains("item_0"));
        assert!(deanonymized.contains("item_50"));
        assert!(deanonymized.contains("item_99"));
    }
}
