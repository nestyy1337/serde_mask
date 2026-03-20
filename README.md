# serde_mask

Mask sensitive data during serde serialization for LLM ingestion.

The derive macro generates a `mask()` method that returns a `Masked<T>` wrapper. The wrapper serializes with sensitive fields replaced by placeholders, and provides a `deanonymize()` method to restore original values in LLM responses.

## Usage

```rust
use serde_mask::Anonymize;

#[derive(Clone, Anonymize, serde::Serialize)]
struct Query {
    #[anon]
    username: String,
    public: String,
}

let q = Query {
    username: "my_secret_username".to_string(),
    public: "visible".to_string(),
};

let masked = q.mask();

// Serializes with secret masked
let json = serde_json::to_string(&masked).unwrap();
// {"username":"ANON_aBcDeFgHiJ","public":"visible"}

// LLM responds with something like "Contact user ANON_aBcDeFgHiJ immediately."
// then we deanonymize it back to "Contact user my_secret_username immediately."
let response = "Contact user ANON_aBcDeFgHiJ immediately.";
let restored = masked.deanonymize(response);
// "Contact user my_secret_username immediately."
```

## Supported types

`#[anon]` works on fields of the following types out of the box:

- `String`
- Integer types (`u8`, `u16`, `u32`, `u64`, `u128`, `i8`, `i16`, `i32`, `i64`, `i128`, `usize`, `isize`)
- `f32`, `f64`
- `bool`
- `Option<T>`, `Vec<T>`, `HashMap<K, V>` where the inner types implement `AnonymizeTrait`

## Custom types

Implement `AnonymizeTrait` for your own types:

```rust
use serde_mask::{AnonymizeTrait, MaskStateBuilder};

struct Email(String);

impl AnonymizeTrait for Email {
    fn anonymize(&self, builder: &mut MaskStateBuilder) -> Self {
        let fake = format!("EMAIL_{}", fastrand::u32(..));
        builder.add(fake.clone(), self.0.clone());
        Email(fake)
    }
}
```

## Caveats

### Numeric and boolean anonymization

Anonymization of numeric types (`u8`, `i32`, `f64`, etc.) and `bool` works via string replacement on the serialized output. This means:

- **Substring collisions**: a fake value like `3` could match other occurrences of `3` in the JSON (inside field names, other numbers, etc.). String fields avoid this thanks to the `ANON_` prefix, but numeric fields have no such prefix.
- **Small type ranges**: types like `u8` or `bool` have very few possible values, increasing the chance of the fake value equaling the real one.
- **Type invariant breaking**: numeric fields get replaced at the string level. For JSON this means an integer field might briefly appear as a different integer, which is generally fine for LLM consumption but would break strict schema validation.

For high-reliability use cases, prefer anonymizing string fields or implementing a custom `AnonymizeTrait` that maps values to prefixed string placeholders.
