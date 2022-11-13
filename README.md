# ed25519-proj
_A simple CLI signer for ed25519 signatures using Rust programming language._

## Description
The implementation of ed25519 signatures using ed25519-dalek library.

## Usage
### To run unit tests:
Go to the `signature_module`:

`cd signature_module`

Run testing in a sequential order:

`cargo test -- --test-threads 1`

### Help command:

`cargo run -- -h `

    ed25519 1.0.0

    Maksym Ostapenko

    A simple CLI signer for ed25519 signatures

    USAGE:

        ed25519-proj --file <file_name> --operation <operation_type> --signature <signature>

    FLAGS:

        -h, --help       Prints help information
 
        -V, --version    Prints version information

    OPTIONS:
        -f, --file <file_name>              File names for public and private keys. (They will be created '[file].pub' and
                                            '[file]') respectively [default: key]
        -o, --operation <operation_type>    Operation type: generate/sign/verify
        -s, --signature <signature>         Flag whether the signature file should be used (for verification)

### To run keys generation
From the root folder of this project run
`cargo run -- -o generate`
or
`cargo run -- -o generate -f files`

### To sign a message
Write message into the `message.txt` file and run
`cargo run -- -o sign`
or 
`cargo run -- -o sign -f files`

### To verify signature on the message
Run `cargo run -- -o verify`
