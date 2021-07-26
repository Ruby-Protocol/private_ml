extern crate miracl_core;

use functional_encryption_schemes::quadratic_sgp::*;
use functional_encryption_schemes::math::matrix::{BigNumMatrix, BigIntMatrix};
use num_bigint::BigInt;

use functional_encryption_schemes::define::{BigNum, CURVE_ORDER, MODULUS};

fn main() {
    //let sgp = Sgp::new(2);
  
    //let (msk, pk) = sgp.generate_sec_key();
    //println!("Key generated");
     

    //let mut x: Vec<BigInt> = Vec::with_capacity(2);
    //let mut y: Vec<BigInt> = Vec::with_capacity(2);
    //for i in 0..2 {
        //x.push(BigInt::from(i));
        //y.push(BigInt::from(i+1));
    //}

    //let cipher = sgp.encrypt(&x, &y, &pk);
    //println!("Encrypted");

    //let a: [i64; 4] = [10, 20, 30, 40];
    //let f = BigNumMatrix::new_ints(&a[..], 2, 2);
    //let dk = sgp.derive_fe_key(&msk, f);
    //println!("FE key derived");

    //let result = sgp.decrypt(&cipher, &dk, &BigInt::from(100)); 
    //println!("result {:?}", result);


    println!("curve order: {:?}", CURVE_ORDER.tostring());
    println!("curve order bits: {:?}", CURVE_ORDER.nbits());
    println!("moduluis: {:?}", MODULUS.to_str_radix(16));
}
