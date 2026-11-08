fn main() -> std::process::ExitCode {
    if let Err(e) = swayshare::cli::run() {
        eprintln!("swayshare: {e:#}");
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}
