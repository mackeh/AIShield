use std::process::Command;

fn insecure_demo(user_input: &str, token: &str, provided: &str, request: &str) {
    let digest = md5::compute(token);
    let _ = digest;
    let _legacy = sha1::Sha1::from(token);
    let _weak_cipher = des::Des::new();

    let mut rng = rand::thread_rng();
    let _weak_rsa = rsa::RsaPrivateKey::new(&mut rng, 1024);

    let cmd = Command::new("sh")
        .arg("-c")
        .arg(format!("cat {}", user_input))
        .output();
    let _ = cmd;

    let query = format!("SELECT * FROM users WHERE id = {}", user_input);
    let query2 = format!("SELECT * FROM users WHERE name = {}", user_input);
    let _ = query;
    let _ = query2;

    let _ = std::fs::read_to_string(format!("/var/data/{}", user_input));
    let _ = tera.render_str(user_input, &context);

    if token == provided {
        println!("timing-unsafe compare");
    }

    let api_key = "hardcoded_secret_key";
    let incoming_api_key = std::env::var("INCOMING_API_KEY").unwrap_or_default();
    if api_key == incoming_api_key {
        println!("insecure api key compare");
    }

    let password = "hunter2";
    let expected_password = std::env::var("EXPECTED_PASSWORD").unwrap_or_default();
    if password == expected_password {
        println!("insecure password compare");
    }

    if token.to_lowercase() == provided.to_lowercase() {
        println!("case normalized compare");
    }

    let authorization = "Bearer ".to_string() + token;
    println!("{}", authorization);

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let _ = client;

    response.insert_header(("Access-Control-Allow-Origin", "*"));
    println!("{:?}", request.headers());
    server.bind("0.0.0.0:8080");

    let debug = true;
    println!("debug={}", debug);
}
