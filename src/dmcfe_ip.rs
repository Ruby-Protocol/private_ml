use miracl_core::bls12381::pair;
use miracl_core::hash256::HASH256;
use num_bigint::{BigInt};
use num_traits::{Num};

use crate::define::{BigNum, G1, G2, Gt, G1Vector, G2Vector, MB, CURVE_ORDER, MODULUS};
use crate::math::matrix::BigIntMatrix2x2;
use crate::utils::{baby_step_giant_step, hash_to_g1, hash_to_g2, reduce};
use crate::utils::rand_utils::{RandUtilsRand, Sample};
use crate::traits::FunctionalEncryption;



/// Decentralized Multi-Client Functional Encryption for Inner Product.
///
/// Link: https://eprint.iacr.org/2017/989.pdf
///
/// # Examples
///
/// ```
/// use ruby::dmcfe_ip::Dmcfe; 
/// use ruby::traits::FunctionalEncryption;
/// const L: usize = 2;
/// let client = Dmcfe::<L>::new();
/// ```
#[derive(Debug)]
#[derive(Clone)]
pub struct Dmcfe<const L: usize> {
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

/// Functional evaluation key
#[derive(Debug)]
pub struct DmcfeDecKey<const L: usize> {
    key: G2Vector,
    y: [BigNum; L],
}

impl<const L: usize> FunctionalEncryption for Dmcfe<L> {
    type CipherText = G1Vector;
    type PlainData = [BigInt; L];
    type FEKeyData = [BigInt; L];
    type EvaluationKey = DmcfeDecKey<L>;

    /// Constructs a new `Dmcfe` for a client with specified `index`. 
    ///
    /// # Examples
    ///
    /// ```
    /// use ruby::dmcfe_ip::Dmcfe; 
    /// use ruby::traits::FunctionalEncryption;
    /// const L: usize = 2;
    /// let client = Dmcfe::<L>::new();
    /// ```
    fn new() -> Self {
        Dmcfe::<L>::new_single(0) 
    }

    /// Encrypt a number, together with a label. Label should be the same for all clients. 
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use ruby::dmcfe_ip::Dmcfe; 
    /// let client = Dmcfe::new(0);
    /// let x = BigInt::from(10);
    /// let label = "dmcfe-label";
    /// let cipher = client.encrypt(&x, label);
    /// ``` 
    fn encrypt(&self, x: &Self::PlainData) -> Self::CipherText {
        self.encrypt_with_label(x, "dmcfe-label") 
    }

    /// Derive the functional evaluation key for a vector of numbers. Only used when there is a single client.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let y: Vec<BigInt> = ... // Construct a vector 
    /// let fe_share = client.derive_fe_key(&y[..]); 
    /// ```
    fn derive_fe_key(&self, y: &Self::FEKeyData) -> Self::EvaluationKey {
        let mut new_y: [BigNum; L] = [BigNum::new(); L];
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
            new_y[i] = yi;
        }
        DmcfeDecKey {
            key: fe_key,
            y: new_y
        }
    }

    /// Decrypt a ciphertext with the functional evaluation key `dk`, associated with a specified label. The parameter `bound` is the absolute value bound for numbers used in the quadratic polynomial.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Following the example of `key_comb`
    /// let bound = BigInt::from(100);
    /// let xfy = Dmcfe::decrypt(&ciphers, &y[..], &dk, label, &bound); 
    /// ```
    fn decrypt(
        &self,
        ciphers: &Self::CipherText,
        dk: &Self::EvaluationKey, 
        bound: &BigInt,
    ) -> Option<BigInt> {
        self.decrypt_with_label(ciphers, dk, bound, "dmcfe-label")
    }
}

impl<const L: usize> Dmcfe<L> {

    /// Constructs a new `Dmcfe` for a client with specified `index`. 
    ///
    /// # Examples
    ///
    /// ```
    /// use ruby::dmcfe_ip::Dmcfe; 
    /// const L: usize = 2;
    /// let client = Dmcfe::<L>::new_single(0);
    /// ```
    pub fn new_single(index: usize) -> Self {
        let mut rng = RandUtilsRand::new();
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
    /// ```ignore
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
    /// ```ignore
    /// use ruby::dmcfe_ip::Dmcfe; 
    /// let client = Dmcfe::new(0);
    /// let x = BigInt::from(10);
    /// let label = "dmcfe-label";
    /// let cipher = client.encrypt(&x, label);
    /// ``` 
    pub fn encrypt_single(&self, x: &BigInt, label: &str) -> G1 {
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
    pub fn encrypt_with_label(&self, x: &[BigInt; L], label: &str) -> G1Vector {
        let mut ciphers: G1Vector = Vec::with_capacity(x.len());
        for i in 0..x.len() {
            ciphers.push(self.encrypt_single(&(x[i]), label));
        }
        ciphers
    }

    /// Derive a share of the functional evaluation key for a vector of numbers.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let y: Vec<BigInt> = ... // Construct a vector 
    /// let fe_share = client.derive_fe_key_share(&y[..]); 
    /// ```
    pub fn derive_fe_key_share(&self, y: &[BigInt; L]) -> G2Vector {
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
    
    /// Combining shares into the functional evaluation key.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // fe_key: Vec<G2Vector>
    /// let dk = Dmcfe::key_comb(&fe_key);
    /// ```
    pub fn key_comb(&self, key_shares: &[G2Vector], y: &[BigInt; L]) -> DmcfeDecKey<L> {
        let mut new_y: [BigNum; L] = [BigNum::new(); L];
        let mut keys_sum: G2Vector = vec![G2::new(); 2];

        for i in 0..2 {
            keys_sum[i].inf();
        }

        for i in 0..key_shares.len() {
            for j in 0..2 {
                keys_sum[j].add(&key_shares[i][j]);
            }

            let yi = reduce(&y[i], &MODULUS);
            let yi = BigNum::fromstring(yi.to_str_radix(16));
            new_y[i] = yi;
        }
        DmcfeDecKey {
            key: keys_sum,
            y: new_y
        }
    }

    /// Decrypt a ciphertext with the functional evaluation key `dk`, associated with a specified label. The parameter `bound` is the absolute value bound for numbers used in the quadratic polynomial.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Following the example of `key_comb`
    /// let bound = BigInt::from(100);
    /// let xfy = Dmcfe::decrypt(&ciphers, &y[..], &dk, label, &bound); 
    /// ```
    pub fn decrypt_with_label(
        &self,
        ciphers: &G1Vector,
        dk: &DmcfeDecKey<L>, 
        bound: &BigInt,
        label: &str,
    ) -> Option<BigInt> {
        let ylen: isize = L as isize;

        let (g1, mut ciphers_sum, mut cipher_i) = (G1::generator(), G1::new(), G1::new());
        let g2 = G2::generator();

        ciphers_sum.inf();

        for i in 0..L {
            let mut temp = dk.y[i]; 
            cipher_i.copy(&ciphers[i]);
            temp.rmod(&CURVE_ORDER);
            cipher_i = cipher_i.mul(&temp);
            ciphers_sum.add(&cipher_i);
        }

        let mut s = pair::ate(&g2, &ciphers_sum);
        s = pair::fexp(&s);

        let mut t = Gt::new();
        let mut pair: Gt;
        t.one();
        for i in 0..2 {
            let ex_label = format!("{} {}", i.to_string(), label);
            let h = hash_to_g1(&ex_label);
            pair = pair::ate(&dk.key[i], &h);
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


