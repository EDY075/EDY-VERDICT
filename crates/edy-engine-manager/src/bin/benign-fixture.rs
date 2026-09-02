//! Harmless project-built executable; never a malware fixture.
use std::{
    io::{self, Write},
    process::Command,
    thread,
    time::Duration,
};
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str).unwrap_or("success") {
        "success" => println!("fixture-ok"),
        "echo" => println!("{}", serde_json::to_string(&args[1..]).unwrap()),
        "sleep" => thread::sleep(Duration::from_secs(30)),
        "stdout" => {
            let mut out = io::stdout().lock();
            for _ in 0..100_000 {
                if out.write_all(&[b'x'; 4096]).is_err() {
                    break;
                }
            }
        }
        "stderr-overflow" => {
            let mut out = io::stderr().lock();
            for _ in 0..100_000 {
                if out.write_all(&[b'x'; 4096]).is_err() {
                    break;
                }
            }
        }
        "stderr" => eprintln!("synthetic diagnostic"),
        "nonzero" => std::process::exit(23),
        "tree" => {
            let mut child = Command::new(std::env::current_exe().unwrap())
                .arg("sleep")
                .spawn()
                .unwrap();
            println!("child:{}", child.id());
            io::stdout().flush().unwrap();
            let _ = child.wait();
        }
        _ => std::process::exit(2),
    }
}
