use num_bigint::{BigInt};

use crate::define::{BigNum, G1, CURVE_ORDER, MODULUS};
use crate::utils::{baby_step_giant_step_g1, reduce};
use crate::utils::rand_utils::{RandUtilsRand, Sample};
use crate::traits::FunctionalEncryption;



/// Michel Abdalla, Florian Bourse, Angelo De Caro, and David Pointcheval, "Simple Functional Encryption Schemes for Inner Products", PKC 2015.
///
/// `L` is the length of input vectors for the inner product.
///
/// # Examples
/// 
/// ```
/// use crate::ruby::traits::FunctionalEncryption;
/// use ruby::simple_ip::Sip; 
/// const L: usize = 20;
/// let sip = Sip::<L>::new();
/// ```
#[derive(Debug)]
pub struct Sip<const L: usize> {
    /// Master secret key
    msk: SipMsk<L>,
    /// Master public key
    mpk: SipMpk<L>
}

/// Master secret key: a secret of length L.
#[derive(Debug)]
pub struct SipMsk<const L: usize> {
    s: [BigNum; L]
}

/// Master public key
#[derive(Debug)]
pub struct SipMpk<const L: usize> {
    v: [G1; L],
}

/// Functional encryption ciphertext
#[derive(Debug)]
pub struct SipCipher<const L: usize> {
    c0: G1,
    c: [G1; L]
}

/// Functional evaluation key
#[derive(Debug)]
pub struct SipDk<const L: usize> {
    y: [BigNum; L],
    dk: BigNum
}


impl<const L: usize> FunctionalEncryption for Sip<L> {
    type CipherText = SipCipher<L>;
    type PlainData = [BigInt; L];
    type FEKeyData = [BigInt; L];
    type EvaluationKey = SipDk<L>;

    /// Constructs a new `Sip<L>`.
    ///
    /// # Examples
    /// 
    /// ```
    /// use crate::ruby::traits::FunctionalEncryption;
    /// use ruby::simple_ip::Sip; 
    /// const L: usize = 20;
    /// let sip = Sip::<L>::new();
    /// ```
    fn new() -> Sip<L> {
        let (msk, mpk) = Sip::generate_sec_key();
        Sip {
            msk,
            mpk
        }
    }

    /// Encrypt a vector of numbers.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let mut rng = RandUtilsRng::new(); 
    /// const L: usize = 20;
    /// let bound: i32 = 100;
    /// let low = (-bound).to_bigint().unwrap();
    /// let high = bound.to_bigint().unwrap();
    /// let sip = Sip::<L>::new();
    /// let x: [BigInt; L] = rng.sample_range_array::<L>(&low, &high); 
    /// let cipher = sip.encrypt(&x);
    /// ```
    fn encrypt(&self, x: &Self::PlainData) -> Self::CipherText {
        let mut rng = RandUtilsRand::new();

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

    /// Derive functional evaluation key for a vector of numbers.
    ///
    /// # Examples
    /// ```ignore
    /// // Following the example of `encrypt`
    /// let y: [BigInt; L] = rng.sample_range_array::<L>(&low, &high); 
    /// let dk = sip.derive_fe_key(&y);
    /// ```
    fn derive_fe_key(&self, y: &Self::FEKeyData) -> Self::EvaluationKey {
        let mut new_y: [BigNum; L] = [BigNum::new(); L];
        let mut dk: BigNum = BigNum::new();
        for i in 0..L {
            let yi = reduce(&y[i], &MODULUS);
            let yi = BigNum::fromstring(yi.to_str_radix(16));
            dk.add(&BigNum::modmul(&yi, &self.msk.s[i], &CURVE_ORDER));
            dk.rmod(&CURVE_ORDER);
            new_y[i] = yi;
        }
        SipDk {
            y: new_y,
            dk
        }
    }

    /// Decrypt a ciphertext with the functional evaluation key.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Following the example of `derive_fe_key`
    /// let result = sip.decrypt(&cipher, &y, &dk, &BigInt::from(bound)); 
    /// ```
    //fn decrypt(&self, ct: &Self::CipherText, y: &Self::FEKeyData, dk: &Self::EvaluationKey, bound: &BigInt) -> Option<BigInt> {
    fn decrypt(&self, ct: &Self::CipherText, dk: &Self::EvaluationKey, bound: &BigInt) -> Option<BigInt> {
        let mut res = G1::new();
        for i in 0..L {
            //let yi = reduce(&dk.y[i], &MODULUS);
            //let yi = BigNum::fromstring(yi.to_str_radix(16));

            //res.add(&ct.c[i].mul(&yi));
            res.add(&ct.c[i].mul(&(dk.y[i])));
        }
        res.sub(&ct.c0.mul(&dk.dk));

        //dlog
        let mut result_bound = BigNum::fromstring(bound.to_str_radix(16));
        result_bound = result_bound.powmod(&BigNum::new_int(2), &CURVE_ORDER);
        result_bound = BigNum::modmul(&result_bound, &BigNum::new_int(L as isize), &CURVE_ORDER);

        baby_step_giant_step_g1(&res, &G1::generator(), &result_bound)
    }

}


impl<const L: usize> Sip<L> {

    /// Generate a pair of master secret key and master public key.
    pub fn generate_sec_key() -> (SipMsk<L>, SipMpk<L>) {
        let mut rng = RandUtilsRand::new();
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

}


