pub use serde_mask_derive::{Anonymize, anonymize};

#[cfg(test)]
mod tests {

    use super::*;
    use std::collections::HashMap;

    #[anonymize]
    #[derive(Anonymize, Default, Debug)]
    struct Query {
        name: String,
        #[serde(skip_serializing)]
        email: String,
        #[anon(range = "-10..99")]
        age: isize,
        #[anon]
        some_value: HashMap<String, Option<String>>,
    }

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
        assert!(serialized.contains("ANON_secret"));

        // Deanonymization should restore original
        let deanonymized = data.deanonymize(&serialized);
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
        assert!(serialized.contains("ANON_age"));
        assert!(serialized.contains("ANON_count"));

        // Deanonymization should restore
        let deanonymized = data.deanonymize(&serialized);
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
        assert!(serialized.contains("ANON_secrets"));

        // Should preserve array structure
        assert!(serialized.contains("["));
        assert!(serialized.contains("]"));

        // Deanonymization should restore all elements
        let deanonymized = data.deanonymize(&serialized);
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
        assert!(serialized.contains("ANON_data"));

        // Deanonymization should restore
        let deanonymized = data.deanonymize(&serialized);
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
        assert!(serialized.contains("ANON_maybe_secret"));

        let deanonymized = data.deanonymize(&serialized);
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

        let deanonymized = data.deanonymize(&serialized);
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
        let deanonymized = data.deanonymize(&serialized);

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
        let deanonymized = data.deanonymize(&serialized);

        // Should restore original
        assert!(deanonymized.contains("\"value\":\"42\""));
    }
}
