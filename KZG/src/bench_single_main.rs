// src/bench_single_main.rs
pub mod kzg;
pub mod utils;
pub mod bench_single;

fn main() {
    bench_single::run();
}
