use num_bigint::{BigInt};

use crate::quadratic_sgp::{Sgp, SgpCipher};
use crate::math::matrix::{BigIntMatrix};

/*
   The neural network application in the following papers:
   [MSHBM2019] Marc, T., Stopar, M., Hartman, J., Bizjak, M., & Modic, J. (2019, September). Privacy-Enhanced Machine Learning with Functional Encryption. In European Symposium on Research in Computer Security (pp. 3-21). Springer, Cham.
   [SGP2018] Sans, E.D., Gay, R., Pointcheval, D.: Reading in the dark: Classifying encrypted digits with functional encryption. IACR Cryptology ePrint Archive 2018, 206, (2018).
*/
pub struct NeuralNetwork {
    pub p: BigIntMatrix,
    pub q: Vec<BigIntMatrix>,
    pub bound: BigInt,
    sgp: Sgp 
}

impl NeuralNetwork {
    pub fn new(p: &BigIntMatrix, q: &Vec<BigIntMatrix>) -> Self {
        let bound = BigInt::from(256);
        let sgp = Sgp::new(p.n_rows); 
        Self {
            p: p.clone(),
            q: q.clone(),
            bound,
            sgp
        }
    }

    /* 
       Encrypt client's input: a vector of integer values
    */
    pub fn encrypt(&self, x: &[BigInt]) -> SgpCipher {
        let cipher = self.sgp.encrypt(x, x);
        cipher
    }

    /* 
       Compute the one-laye neural network model 
    */
    pub fn compute(&self, cipher: &SgpCipher) -> Vec<BigInt> {
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




