# serde_mask

## Currently just a proof of concept, its missing pub traits

Implementation of masking secrets at serialization for LLM ingestion with secrets attached to the OBJECT, not a struct like expunge does.

Crate aims to intercept serde serialization for a given struct and substitute sensitive values as masked ones.

Crate attatches `deanonymize` function to the derived struct allowing to convert response (we dont deserialize it back!) with sensitive data replaced for the placeholders:
```
Original: Query { val: Some(42) }
Serialized: {"val":"ANON_val_-11"}
Patterns: ["ANON_val_-11"]
Replacements: ["42"]
Deanonymized response: "The value 42 is very important!"}
```


key points:
I did not go with the snafu/expunge route of creating separate instance of derived struct.
The other option would be to store serialization state in thread_locals.
