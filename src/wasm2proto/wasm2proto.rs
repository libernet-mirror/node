use prost::Message;
use std::env;
use std::fs::read;

pub mod program {
    tonic::include_proto!("program");
}

mod helpers;
mod program_module;
mod sections;

use program_module::{from_wasm, render_wasm};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!(
            "Usage: {} <input_wasm_file> <output_proto_file> <output_wasm_file>",
            args[0]
        );
        std::process::exit(1);
    }
    let input_wasm_file = &args[1];
    let output_proto_file = &args[2];
    let output_wasm_file = &args[3];

    let in_bytes = read(input_wasm_file).expect("Failed to read wasm file");
    let program_module = from_wasm(&in_bytes).expect("Failed to parse wasm file");
    let proto_bytes = program_module.encode_to_vec();
    let out_bytes = render_wasm(program_module).expect("Failed to render wasm file");

    std::fs::write(output_proto_file, &proto_bytes).expect("Failed to write proto file");
    std::fs::write(output_wasm_file, &out_bytes).expect("Failed to write wasm file");

    println!(
        "in: {}, out: {}, proto: {}",
        in_bytes.len(),
        out_bytes.len(),
        proto_bytes.len()
    );

    if let Err(e) = wasmparser::validate(&out_bytes) {
        eprintln!("WASM validation error: {:?}", e);
        std::process::exit(1);
    }
}
