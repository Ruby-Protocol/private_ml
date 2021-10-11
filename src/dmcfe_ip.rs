//use lazy_static::lazy_static;
//use miracl_core::bls12381::ecp;
use miracl_core::bls12381::pair;
//use miracl_core::bls12381::rom;
/* use  miracl_core::bn254::big;
use miracl_core::bn254::big::BIG;
use miracl_core::bn254::ecp;
use miracl_core::bn254::ecp::ECP;
use miracl_core::bn254::ecp2::ECP2;
use miracl_core::bn254::fp12::FP12;
use miracl_core::bn254::pair;
use miracl_core::bn254::rom; */
use miracl_core::hash256::HASH256;
//use miracl_core::rand::{RAND, RAND_impl};
use num_bigint::{BigInt};
use num_traits::{Num};
//use rand::prelude::*;
use std::convert::TryInto;

use crate::define::{BigNum, G1, G2, GT, G1Vector, G2Vector, MB, CURVE_ORDER, MODULUS};
use crate::math::matrix::BigIntMatrix2x2;
use crate::utils::{baby_step_giant_step, hash_to_g1, hash_to_g2, reduce};
use crate::utils::rand_utils::{RandUtilsRAND, Sample};



/// Decentralized Multi-Client Functional Encryption for Inner Product.
///
/// Link: https://eprint.iacr.org/2017/989.pdf
///
/// # Examples
///
/// ```
/// use ruby::dmcfe_ip::Dmcfe; 
/// let client = Dmcfe::new(0);
/// ```
#[derive(Debug)]
#[derive(Clone)]
pub struct Dmcfe {
    /// Index of a client
    index: usize,
    /// Public key  
    pub client_pub_key: G1,
    /// Secret key
    client_sec_key: BigNum,
    /// Secret share matrix
    share: BigIntMatrix2x2,
    /// Functional secret key
    s: [BigNum; 2],
}


impl Dmcfe {

    /// Constructs a new `Dmcfe` for a client with specified `index`. 
    ///
    /// # Examples
    ///
    /// ```
    /// use ruby::dmcfe_ip::Dmcfe; 
    /// let client = Dmcfe::new(0);
    /// ```
    pub fn new(index: usize) -> Dmcfe {
        let mut rng = RandUtilsRAND::new();
        let client_sec_key = rng.sample(&(CURVE_ORDER));

        let client_pub_key = G1::generator();
        client_pub_key.mul(&client_sec_key);

        let share = BigIntMatrix2x2::new();
        let s = [
            rng.sample(&(CURVE_ORDER)),
            rng.sample(&(CURVE_ORDER)),
        ];

        Dmcfe {
            index,
            client_pub_key,
            client_sec_key,
            share,
            s,
        }
    }

    /// Set the secret share matrix with all clients' public keys.
    ///
    /// # Examples
    /// 
    /// ```
    /// for i in 0..num_clients {
    ///     clients.push(Dmcfe::new(i));
    /// }
    /// for i in 0..num_clients {
    ///     temp = clients[i].client_pub_key.clone();
    ///     pub_keys.push(temp);
    /// }
    /// for i in 0..num_clients {
    ///     clients[i].set_share(&pub_keys);
    /// } 
    /// ```
    pub fn set_share(&mut self, pub_keys: &[G1]) {
        let mut shared_g1: G1 = G1::new();
        let mut t: [u8; MB + 1] = [0; MB + 1];
        let p =
            BigInt::from_str_radix(&CURVE_ORDER.tostring(), 16).unwrap();

        for i in 0..pub_keys.len() {
            if i == self.index {
                continue;
            }

            shared_g1.copy(&pub_keys[i]);
            shared_g1 = shared_g1.mul(&self.client_sec_key);
            shared_g1.tobytes(&mut t, true);

            let mut hash256 = HASH256::new();
            hash256.process_array(&t);
            let digest = hash256.hash();

            let mut add = BigIntMatrix2x2::new_random_deterministic(&digest);
            add.modp(&p);

            if i < self.index {
                self.share.add(&add);
            } else {
                self.share.sub(&add);
            }
            self.share.modp(&p);
        }
    }

    /// Encrypt a number, together with a label. Label should be the same for all clients. 
    ///
    /// # Examples
    ///
    /// ```
    /// let x = BigInt::from(10);
    /// let label = "dmcfe-label";
    /// let cipher = client.encrypt(&x, label);
    /// ``` 
    pub fn encrypt(&self, x: &BigInt, label: &str) -> G1 {
        let x = reduce(&x, &MODULUS);
        let x = BigNum::fromstring(x.to_str_radix(16));
        let mut cipher: G1 = G1::new();
        cipher.inf();

        for i in 0..2 {
            let ex_label = format!("{} {}", i.to_string(), label);
            let mut h = hash_to_g1(&ex_label);
            h = h.mul(&self.s[i]);
            cipher.add(&h);
        }
        let mut g = G1::generator();
        g = g.mul(&x);
        cipher.add(&g);

        cipher
    }

    /// Encrypt a vector fo numbers. Only used when there is a single client.
    pub fn encrypt_vec(&self, x: &[BigInt], label: &str) -> G1Vector {
        let mut ciphers: G1Vector = Vec::with_capacity(x.len());
        for i in 0..x.len() {
            ciphers.push(self.encrypt(&(x[i]), label));
        }
        ciphers
    }

    /// Derive a share of the functional evaluation key for a vector of numbers.
    ///
    /// # Examples
    ///
    /// ```
    /// let y: Vec<BigInt> = ... // Construct a vector 
    /// let fe_share = client.derive_fe_key_share(&y[..]); 
    /// ```
    pub fn derive_fe_key_share(&self, y: &[BigInt]) -> G2Vector {
        let mut fe_key_share: G2Vector = vec![G2::new(); 2];
        let mut hs: G2Vector = vec![G2::new(); 2];
        let mut y_str = "".to_string();
        for yi in y.iter() {
            y_str = y_str + " " + &yi.to_str_radix(16);
        }

        for i in 0..2 {
            let ex_label = format!("{} {}", i.to_string(), y_str);
            hs[i] = hash_to_g2(&ex_label);
        }

        let yi = reduce(&y[self.index], &MODULUS);
        let yi = BigNum::fromstring(yi.to_str_radix(16));

        let mut h = G2::generator();
        for i in 0..2 {
            fe_key_share[i].inf();
            for j in 0..2 {
                h.copy(&hs[j]);
                let share_i = BigNum::fromstring(self.share.get_element(i, j).to_str_radix(16));
                let temp = h.mul(&share_i);
                fe_key_share[i].add(&temp);
            }

            let temp = BigNum::modmul(&yi, &self.s[i], &CURVE_ORDER);
            h = G2::generator();
            h = h.mul(&temp);
            fe_key_share[i].add(&h);
        }
        fe_key_share
    }
    
    /// Derive the functional evaluation key for a vector of numbers. Only used when there is a single client.
    ///
    /// # Examples
    ///
    /// ```
    /// let y: Vec<BigInt> = ... // Construct a vector 
    /// let fe_share = client.derive_fe_key(&y[..]); 
    /// ```
    pub fn derive_fe_key(&self, y: &[BigInt]) -> G2Vector {
        let mut fe_key: G2Vector = vec![G2::new(); 2];
        let mut hs: G2Vector = vec![G2::new(); 2];
        let mut y_str = "".to_string();
        for yi in y.iter() {
            y_str = y_str + " " + &yi.to_str_radix(16);
        }

        for i in 0..2 {
            let ex_label = format!("{} {}", i.to_string(), y_str);
            hs[i] = hash_to_g2(&ex_label);
            fe_key[i].inf();
        }

        for i in 0..y.len() {
            let yi = reduce(&y[i], &MODULUS);
            let yi = BigNum::fromstring(yi.to_str_radix(16));

            for i in 0..2 {

                let temp = BigNum::modmul(&yi, &self.s[i], &CURVE_ORDER);
                let mut h = G2::generator();
                h = h.mul(&temp);
                fe_key[i].add(&h);
            }
        }
        fe_key
    }
    
    /// Combining shares into the functional evaluation key.
    ///
    /// # Examples
    ///
    /// ```
    /// // fe_key: Vec<G2Vector>
    /// let dk = Dmcfe::key_comb(&fe_key);
    /// ```
    pub fn key_comb(key_shares: &[G2Vector]) -> G2Vector {
        let mut keys_sum: G2Vector = vec![G2::new(); 2];

        for i in 0..2 {
            keys_sum[i].inf();
        }

        for i in 0..key_shares.len() {
            for j in 0..2 {
                keys_sum[j].add(&key_shares[i][j]);
            }
        }
        keys_sum
    }

    /// Decrypt a ciphertext with the functional evaluation key `dk`, associated with a specified label. The parameter `bound` is the absolute value bound for numbers used in the quadratic polynomial.
    ///
    /// # Examples
    ///
    /// ```
    /// // Following the example of `key_comb`
    /// let bound = BigInt::from(100);
    /// let xfy = Dmcfe::decrypt(&ciphers, &y[..], &dk, label, &bound); 
    /// ```
    pub fn decrypt(
        ciphers: &[G1],
        y: &[BigInt],
        dk: &G2Vector, 
        label: &str,
        bound: &BigInt,
    ) -> Option<BigInt> {
        let ylen: isize = y.len().try_into().unwrap();

        let (g1, mut ciphers_sum, mut cipher_i) = (G1::generator(), G1::new(), G1::new());
        let g2 = G2::generator();

        ciphers_sum.inf();

        for i in 0..y.len() {
            let yi = reduce(&y[i], &MODULUS);
            let mut temp = BigNum::fromstring(yi.to_str_radix(16));
            cipher_i.copy(&ciphers[i]);
            temp.rmod(&CURVE_ORDER);
            cipher_i = cipher_i.mul(&temp);
            ciphers_sum.add(&cipher_i);
        }

        let mut s = pair::ate(&g2, &ciphers_sum);
        s = pair::fexp(&s);

        let mut t = GT::new();
        let mut pair: GT;
        t.one();
        for i in 0..2 {
            let ex_label = format!("{} {}", i.to_string(), label);
            let h = hash_to_g1(&ex_label);
            pair = pair::ate(&dk[i], &h);
            pair = pair::fexp(&pair);
            t.mul(&pair);
        }
        t.inverse();
        s.mul(&t);

        pair = pair::ate(&g2, &g1);
        pair = pair::fexp(&pair);

        //dlog
        let mut result_bound = BigNum::fromstring(bound.to_str_radix(16));
        result_bound = result_bound.powmod(&BigNum::new_int(2), &CURVE_ORDER);
        result_bound = BigNum::modmul(&result_bound, &BigNum::new_int(ylen), &CURVE_ORDER);

        baby_step_giant_step(&s, &pair, &result_bound)
    }
}


