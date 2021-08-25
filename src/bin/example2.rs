extern crate miracl_core;

use ruby::define::{CURVE_ORDER, MODULUS};

fn main() {

    println!("curve order: {:?}", CURVE_ORDER.tostring());
    println!("curve order bits: {:?}", CURVE_ORDER.nbits());
    println!("moduluis: {:?}", MODULUS.to_str_radix(16));
}
