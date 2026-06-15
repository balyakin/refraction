fn main() { std::process::Command::new("curl").arg("http://example.invalid").status().unwrap(); }
