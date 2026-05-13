use age_otp::engine::OtpEngine;
use age_otp::types::Charset;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let keypair = age_otp::build_keypair()?;
    let pk = &keypair.public;

    println!("Public key: {}", pk);

    let engine = OtpEngine::from_public_key(pk)?;
    let code_len = 6;
    let step_secs = 30;
    let ttl = 30;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let time_step = now / step_secs;

    let code = engine.generate(code_len, time_step, step_secs, Charset::Numeric)?;
    println!(
        "Generated code: {} (born at {}, valid for {}s)",
        code,
        code.born_at(),
        ttl
    );

    // Perbaiki: tambahkan step_secs sebagai argumen ke-5
    match engine.verify_raw(
        code.as_str(),
        code_len,
        time_step,
        ttl,
        step_secs, // <-- tambahkan ini
        Charset::Numeric,
    ) {
        Ok(()) => println!("Verifikasi RAW berhasil!"),
        Err(e) => println!("Verifikasi RAW gagal: {e}"),
    }

    let skew_steps = 1;
    let wrong_step = time_step - 1;
    match engine.verify_with_skew(
        code.as_str(),
        code_len,
        wrong_step,
        ttl * 2,
        step_secs,
        Charset::Numeric,
        skew_steps,
    ) {
        Ok(()) => println!("Verifikasi SKEW berhasil!"),
        Err(e) => println!("Verifikasi SKEW gagal: {e}"),
    }

    let wrong_code = "000000";
    match engine.verify_raw(
        wrong_code,
        code_len,
        time_step,
        ttl,
        step_secs,
        Charset::Numeric,
    ) {
        Ok(()) => unreachable!(),
        Err(e) => println!("Error yang diharapkan: {e}"),
    }

    let now_code = engine.generate_now(6)?;
    println!("Kode untuk sekarang (30-detik): {now_code}");

    Ok(())
}
