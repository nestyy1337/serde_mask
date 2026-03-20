use serde_mask::Anonymize;

#[derive(Clone, Anonymize, serde::Serialize, Debug)]
struct Foo {
    #[anon]
    a: usize,
    b: String,
}

fn main() {
    let foo = Foo {
        a: 42,
        b: "World".to_string(),
    };
    let masked = foo.mask();
    let masked_json = serde_json::to_string(&masked).unwrap();

    println!("Original: {:?}", foo);
    println!("Masked: {:?}", masked_json);

    let response = format!(
        "Regarding the user: {}, we have some information.",
        masked.state.replacements[0]
    );

    let deanonymized: String = masked.deanonymize(&response);
    println!("Deanonymized: {}", deanonymized);
}
