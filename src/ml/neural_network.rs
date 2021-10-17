use num_bigint::{BigInt};

use crate::quadratic_sgp::{Sgp, SgpPlain, SgpCipher};
use crate::math::matrix::{BigIntMatrix};
use crate::traits::FunctionalEncryption;

/// The neural network application in the following papers:
///
/// \[MSHBM2019\] Marc, T., Stopar, M., Hartman, J., Bizjak, M., & Modic, J. (2019, September). Privacy-Enhanced Machine Learning with Functional Encryption. In European Symposium on Research in Computer Security (pp. 3-21). Springer, Cham.
///
/// \[SGP2018\] Sans, E.D., Gay, R., Pointcheval, D.: Reading in the dark: Classifying encrypted digits with functional encryption. IACR Cryptology ePrint Archive 2018, 206, (2018).
pub struct NeuralNetwork<const L: usize> {
    pub p: BigIntMatrix,
    pub q: Vec<BigIntMatrix>,
    pub bound: BigInt,
    sgp: Sgp<L> 
}

impl<const L: usize> NeuralNetwork<L> {

    /// Constructs a new `NeuralNetwork` application. `p` is the projection matrix for dimensionality reduction.
    /// `q` is a vector of model matrices, each of which denotes a model for a binary prediction of a class. 
    ///
    /// # Examples
    /// ```ignore
    /// let mut rng = RandUtilsRng::new();
    /// let n = 10;
    /// let d = 5;
    /// let p_low = BigInt::from(-2); 
    /// let p_high = BigInt::from(2);
    /// let p = BigIntMatrix::new_random(n, d, &p_low, &p_high);
    /// let q_low = BigInt::from(-3);
    /// let q_high = BigInt::from(3);
    /// let mut q: Vec<BigIntMatrix> = Vec::with_capacity(2);
    /// for _i in 0..q.capacity() {
    ///     q.push(BigIntMatrix::new_random(d, d, &q_low, &q_high));
    /// }
    /// let service = NeuralNetwork::new(&p, &q); 
    /// ```
    pub fn new(p: &BigIntMatrix, q: &Vec<BigIntMatrix>) -> Self {
        let bound = BigInt::from(256);
        let sgp = Sgp::<L>::new(); 
        Self {
            p: p.clone(),
            q: q.clone(),
            bound,
            sgp
        }
    }
 
    /// Encrypt client's input: a vector of integer values.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let data_low = -&service.bound;
    /// let data_high = service.bound.clone();
    /// let x: Vec<BigInt> = rng.sample_range_vec(n, &data_low, &data_high);
    /// let cipher = service.encrypt(&x); 
    /// ```
    pub fn encrypt(&self, x: &[BigInt; L]) -> SgpCipher<L> {
        let plain = SgpPlain {x: x.clone(), y: x.clone()};
        let cipher = self.sgp.encrypt(&plain);
        cipher
    }

    /// Compute the one-laye neural network model. 
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let result = service.compute(&cipher); 
    /// ```
    pub fn compute(&self, cipher: &SgpCipher<L>) -> Vec<BigInt> {
        let new_cipher = self.sgp.project(cipher, &self.p);
        let mut res: Vec<BigInt> = Vec::with_capacity(self.q.len());
        
        for i in 0..self.q.len() {
            let dk_i = self.sgp.derive_fe_key_projected(&self.q[i], &self.p);
            let res_i = self.sgp.decrypt(&new_cipher, &dk_i, &self.bound).unwrap();
            res.push(res_i);
        }
        res
    }

}




