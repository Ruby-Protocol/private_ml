//use lazy_static::lazy_static;
//use miracl_core::bls12381::ecp;
//use miracl_core::bls12381::rom;
/* use  miracl_core::bn254::big;
use miracl_core::bn254::big::BIG;
use miracl_core::bn254::ecp;
use miracl_core::bn254::ecp::ECP;
use miracl_core::bn254::ecp2::ECP2;
use miracl_core::bn254::fp12::FP12;
use miracl_core::bn254::pair;
use miracl_core::bn254::rom; */
//use miracl_core::rand::{RAND, RAND_impl};
use num_bigint::{BigInt};

use crate::define::{BigNum, G1, CURVE_ORDER, MODULUS};
use crate::utils::{baby_step_giant_step_g1, reduce};
use crate::utils::rand_utils::{RandUtilsRAND, Sample};



/**
Implementation of the paper:
[ABDP15] Michel Abdalla, Florian Bourse, Angelo De Caro, and David Pointcheval, "Simple Functional Encryption Schemes for Inner Products", PKC 2015.
*/

#[derive(Debug)]
pub struct Sip<const L: usize> {
    msk: SipMsk<L>,
    mpk: SipMpk<L>
}

#[derive(Debug)]
pub struct SipMsk<const L: usize> {
    s: [BigNum; L]
}

#[derive(Debug)]
pub struct SipMpk<const L: usize> {
    v: [G1; L],
}

#[derive(Debug)]
pub struct SipCipher<const L: usize> {
    c0: G1,
    c: [G1; L]
}

#[derive(Debug)]
pub struct SipDk {
    dk: BigNum
}



impl<const L: usize> Sip<L> {
    pub fn new() -> Sip<L> {
        let (msk, mpk) = Sip::generate_sec_key();
        Sip {
            msk,
            mpk
        }
    }

    pub fn generate_sec_key() -> (SipMsk<L>, SipMpk<L>) {
        let mut rng = RandUtilsRAND::new();
        let msk = SipMsk {
            s: rng.sample_array::<L>(&(CURVE_ORDER)),
        };
        let mut mpk = SipMpk::<L> {
            v: array_init::array_init(|_| G1::generator()),
        };
        for i in 0..L {
            mpk.v[i] = mpk.v[i].mul(&(msk.s[i]));
        }
        (msk, mpk)
    }

    pub fn encrypt(&self, x: &[BigInt; L]) -> SipCipher<L> {
        let mut rng = RandUtilsRAND::new();

        let r = rng.sample(&(CURVE_ORDER));
        let c0 = G1::generator().mul(&r);
        let mut c: [G1; L] = array_init::array_init(|_| G1::generator()); 
        for i in 0..L {
            let xi = reduce(&x[i], &MODULUS);
            let xi = BigNum::fromstring(xi.to_str_radix(16)); 

            c[i] = c[i].mul(&xi);
            c[i].add(&(self.mpk.v[i].mul(&r)));
        }
        SipCipher {
            c0,
            c
        }
    }
    
    pub fn derive_fe_key(&self, y: &[BigInt; L]) -> SipDk {
        let mut dk: BigNum = BigNum::new();
        for i in 0..L {
            let yi = reduce(&y[i], &MODULUS);
            let yi = BigNum::fromstring(yi.to_str_radix(16));
            dk.add(&BigNum::modmul(&yi, &self.msk.s[i], &CURVE_ORDER));
            dk.rmod(&CURVE_ORDER);
        }
        SipDk {
            dk
        }
    }

    pub fn decrypt(&self, ct: &SipCipher<L>, dk: &SipDk, y: &[BigInt; L], bound: &BigInt) -> Option<BigInt> {
        let mut res = G1::new();
        for i in 0..L {
            let yi = reduce(&y[i], &MODULUS);
            let yi = BigNum::fromstring(yi.to_str_radix(16));

            res.add(&ct.c[i].mul(&yi));
        }
        res.sub(&ct.c0.mul(&dk.dk));

        //dlog
        let mut result_bound = BigNum::fromstring(bound.to_str_radix(16));
        result_bound = result_bound.powmod(&BigNum::new_int(2), &CURVE_ORDER);
        result_bound = BigNum::modmul(&result_bound, &BigNum::new_int(L as isize), &CURVE_ORDER);
        println!("result_bound: {:?}", result_bound.tostring());

        baby_step_giant_step_g1(&res, &G1::generator(), &result_bound)
    }
}


