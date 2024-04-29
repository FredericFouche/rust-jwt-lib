// import base64, hmac, sha2 crates
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use sha2::Sha256;

fn main() {
    // Example usage defined in the main function
    let secret = "THIS_IS_A_SECRET_KEY_1234567890_1234567890";
    let iat: i64 = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    let payload = format!(r#"{{"sub":"1234567890","name":"John Doe","iat":{}}}"#, iat);
    let algorithm = "HS256";

    // Generate JWT
    let jwt = jwt_gen(secret, &payload, algorithm);
    println!("{}", jwt);

    // Verify JWT
    let is_valid = jwt_verify(secret, &jwt);
    println!("{}", is_valid);
}

// check if the algorithm is supported
fn input_handler_algo(algorithm: &str) {
    match algorithm {
        "HS256" => (),
        _ => panic!("Algorithm not supported")
    }
}

// check if the secret key is at least 32 characters long
fn input_handler_secret(secret: &str) {
    if secret.len() < 32 {
        panic!("Secret key must be at least 32 characters long")
    }
}

// Generate JWT
fn jwt_gen(secret: &str, payload: &str, algorithm: &str) -> String {
    // check if the algorithm is supported
    input_handler_algo(algorithm);
    // check if the secret key is at least 32 characters long
    input_handler_secret(secret);

    // encode header and payload
    // declare header
    // format! is used to format the string, the first argument is the format string, and the rest are the arguments to be formatted
    // the format string is a template string that contains placeholders, which are replaced by the arguments
    let header = format!(r#"{{"alg":"{}", "typ":"jwt"}}"#, algorithm);
    // encode the header with URL safe no padding
    let header_encoded = URL_SAFE_NO_PAD.encode(header.as_bytes());
    // encode the payload with URL safe no padding
    let payload_encoded = URL_SAFE_NO_PAD.encode(payload.as_bytes());

    // sign the header and payload
    // format the signing input by concatenating the header and payload with a dot
    let signing_input = format!("{}.{}", header_encoded, payload_encoded);
    // create a new HMAC instance with the secret key -> HMAC is a type of message authentication code (MAC) involving a cryptographic hash function and a secret cryptographic key
    // the HMAC instance is created with the SHA-256 hash function and the secret key
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(signing_input.as_bytes());
    // finalize the HMAC instance and get the result
    let result = mac.finalize();
    // convert the result into bytes which means the result is converted into a byte array
    let signature_bytes = result.into_bytes();
    // encode the signature with URL safe no padding
    let signature_encoded = URL_SAFE_NO_PAD.encode(&signature_bytes);

    // concatenate the header, payload, and signature with dots to form the JWT and return it
    format!("{}.{}.{}", header_encoded, payload_encoded, signature_encoded)
}

// Verify JWT
fn jwt_verify(secret: &str, jwt: &str) -> bool {
    // cut the JWT into parts by splitting it at the dots
    let parts: Vec<&str> = jwt.split('.').collect();
    // if the JWT does not have exactly 3 parts, return false
    if parts.len() != 3 {
        return false;
    }
    // declare the header, payload, and signature and assign them the corresponding parts of jwt
    let header_encoded = parts[0];
    let payload_encoded = parts[1];
    let signature_encoded = parts[2];

    // reconstruct the signing input by concatenating the header and payload with a dot
    let signing_input = format!("{}.{}", header_encoded, payload_encoded);
    // new HMAC instance with the secret key
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(signing_input.as_bytes());
    // finalize the HMAC instance and get the result
    let result = mac.finalize();
    let calculated_signature_bytes = result.into_bytes();
    let calculated_signature_encoded = URL_SAFE_NO_PAD.encode(&calculated_signature_bytes);

    // compare the calculated signature with the signature from the JWT and return the result
    signature_encoded == calculated_signature_encoded
}