use std::process::Command;

fn insecure_demo(user_input: &str, token: &str, provided: &str) {
    let digest = md5::compute(token);
    let _ = digest;

    let cmd = Command::new("sh")
        .arg("-c")
        .arg(format!("cat {}", user_input))
        .output();
    let _ = cmd;

    let query = format!("SELECT * FROM users WHERE id = {}", user_input);
    let _ = query;

    if token == provided {
        println!("timing-unsafe compare");
    }

    let api_key = "hardcoded_secret_key";
    println!("{}", api_key);
}
