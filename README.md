# serde_mask

Mask sensitive data during serde serialization for LLM ingestion, with secrets attached to the object, not a separate struct like expunge does.

The crate intercepts serde serialization and substitutes sensitive values with placeholders. A `deanonymize` method on the struct lets you replace placeholders in LLM responses with the original values.

## Usage

```rust
use serde_mask::{anonymize, Anonymize, AnonymizeTrait};

#[anonymize]
#[derive(Debug, Anonymize)]
struct Query {
    #[anon]
    username: String,
    public: String,
}

let q = Query {
    username: "my_secret_username".to_string(),
    public: "visible".to_string(),
    __state: std::sync::OnceLock::new(),
};

// Serializes with secret masked
let json = serde_json::to_string(&q).unwrap();
// {"secret":"ANON_123456","public":"visible"}

// LLM responds with something like "Contact user ANON_123456 immediately."
// then we deanonymize it back to "Contact user my_secret_username immediately."
let response = "Contact user ANON_123456 immediately.";
let restored = q.deanonymize(response.to_string());
// "Contact user my_secret_username immediately."
```

## Custom types

Implement `AnonymizeTrait` for your own types:

```rust
use serde_mask::AnonymizeTrait;

struct Email(String);

impl AnonymizeTrait for Email {
    type State = String;

    fn anonymize(&self) -> Self::State {
        format!("EMAIL_{}", fastrand::usize(0..1_000_000))
    }

    fn deanonymize(&self, state: Self::State, serialized: &str) -> String {
        serialized.replace(&state, &self.0)
    }
}
```

## Design notes

The state is stored in a `OnceLock` field on the struct itself. This means the anonymization mapping is computed once on first serialize and reused, so `deanonymize` always uses the same placeholders that were serialized.

Alternative approaches considered:
- Separate derived struct (like snafu/expunge): more complex, requires conversion
- Thread locals: doesn't work well with async

Crate is breaking invariant of types, for example:

```rust
struct Age {
    age: usize
}
```
`age` type would get converted to String type at serialization. For JSON serde would wrap the value with double quotes, but I bet LLM wouldn't notice.
