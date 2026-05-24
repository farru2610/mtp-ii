// Run: cargo run --release --bin bench
mod mle;
mod multilinear_kzg;
mod bench_multi_kzg;

fn main() {
    bench_multi_kzg::run();
}
