use num_bigint::BigInt;
use crate::rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use num_integer::Integer;
use std::convert::TryInto;

use crate::utils::{reduce};
use crate::utils::rand_utils::{RandUtilsRng, RandUtilsRAND, Sample};
use crate::define::{BigNum};


pub fn convert(src: &BigIntMatrix, modulus: &BigInt) -> BigNumMatrix {
    let mut dst = BigNumMatrix::new(src.n_rows, src.n_cols, &BigNum::fromstring(modulus.to_str_radix(16)));
    for i in 0..src.n_rows {
        for j in 0..src.n_cols {
            let fij = src.get_element(i, j);
            let fij = reduce(fij, modulus);
            let fij = BigNum::fromstring(fij.to_str_radix(16));
            dst.set_element(i, j, &fij);
        }
    }
    dst
}


#[derive(Debug)]
pub struct BigNumMatrix {
    pub data: Vec<BigNum>,
    pub n_rows: usize,
    pub n_cols: usize,
    pub modulus: BigNum
}

impl BigNumMatrix {
    pub fn new(n_rows: usize, n_cols: usize, modulus: &BigNum) -> Self {
        Self {
            data: vec![BigNum::new(); n_rows * n_cols],
            n_rows,
            n_cols,
            modulus: modulus.clone()
        }
    }

    pub fn new_ints(a: &[i64], n_rows: usize, n_cols: usize, modulus: &BigNum) -> Self {
        let mut data: Vec<BigNum> = Vec::with_capacity(n_rows * n_cols);
        for i in 0..n_rows {
            for j in 0..n_cols {
                data.push(BigNum::new_int(a[i * n_cols + j].try_into().unwrap()));
            }
        }
        Self {
            data,
            n_rows,
            n_cols,
            modulus: modulus.clone()
        }
    }

    pub fn new_bigints(a: &[BigNum], n_rows: usize, n_cols: usize, modulus: &BigNum) -> Self {
        if a.len() != n_rows * n_cols {
            panic!("Malformed input: a.len ({}), n_rows: {}, n_cols: {}", a.len(), n_rows, n_cols);
        }
        let mut data: Vec<BigNum> = Vec::with_capacity(n_rows * n_cols);
        data.extend_from_slice(a);
        Self {
            data,
            n_rows,
            n_cols,
            modulus: modulus.clone()
        }
    }

    pub fn get_element(&self, i: usize, j: usize) -> &BigNum {
        &self.data[i * self.n_cols + j]
    }

    pub fn set_element(&mut self, i: usize, j: usize, e: &BigNum) {
        self.data[i * self.n_cols + j] = *e;
    }

    pub fn matmul(&self, other: &BigNumMatrix) -> BigNumMatrix {
        if self.n_cols != other.n_rows {
            panic!("Malformed input: self.dim ({} x {}), other.dim ({} x {})", self.n_rows, self.n_cols, other.n_rows, other.n_cols);
        }
        let mut data: Vec<BigNum>  = vec![BigNum::new(); self.n_rows * other.n_cols];
        for i in 0..self.n_rows {
            for j in 0..self.n_cols {
                for k in 0..other.n_cols {
                    let tmp = BigNum::modmul(self.get_element(i, j), other.get_element(j, k), &self.modulus);
                    data[i * other.n_cols + k] = BigNum::modadd(&data[i * other.n_cols + k], &tmp, &self.modulus); 
                }
            }
        }
        Self {
            data,
            n_rows: self.n_rows,
            n_cols: other.n_cols,
            modulus: self.modulus
        }
    }

    pub fn transpose(&self) -> Self {
        let mut t = BigNumMatrix::new(self.n_cols, self.n_rows, &self.modulus);
        for i in 0..self.n_rows {
            for j in 0..self.n_cols {
                t.set_element(j, i, self.get_element(i, j));
            }
        }
        t
    }

}


#[derive(Debug)]
pub struct BigNumMatrix2x2 {
    data: Vec<BigNum>,
}

impl BigNumMatrix2x2 {
    pub fn new() -> Self {
        Self {
            data: vec![BigNum::new(); 2 * 2],
        }
    }

    pub fn new_with_data(data: &[BigNum]) -> Self {
        Self {
            data: data.to_vec(),
        }
    }

    pub fn new_random(modulus: &BigNum) -> Self {
        let mut rng = RandUtilsRAND::new();
        Self {
            data: rng.sample_vec(4, modulus),
        }
    }

    pub fn get_element(&self, i: usize, j: usize) -> &BigNum {
        &self.data[i * 2 + j]
    }

    pub fn determinant(&self, modulus: &BigNum) -> BigNum {
        let a: &BigNum = self.get_element(0, 0);
        let b: &BigNum = self.get_element(0, 1);
        let c: &BigNum = self.get_element(1, 0);
        let d: &BigNum = self.get_element(1, 1);
        let ad = BigNum::modmul(a, d, modulus);
        let mut bc = BigNum::modmul(b, c, modulus);
        bc = BigNum::modneg(&bc, modulus);
        BigNum::modadd(&ad, &bc, modulus)
    }

    pub fn invmod(&self, modulus: &BigNum) -> Self {
        let mut det: BigNum = self.determinant(modulus);

        if det.iszilch() {
            panic!("Matrix determinant is zero");
        }
        det.invmodp(modulus); 
        let det_inv = det;
        let e00 = BigNum::modmul(self.get_element(1, 1), &det_inv, modulus);
        let e01 = BigNum::modmul(&(BigNum::modneg(self.get_element(0, 1), modulus)), &det_inv, modulus);
        let e10 = BigNum::modmul(&(BigNum::modneg(self.get_element(1, 0), modulus)), &det_inv, modulus);
        let e11 = BigNum::modmul(self.get_element(0, 0), &det_inv, modulus);
        Self {
            data: vec![e00, e01, e10, e11],
        }
    }

    pub fn transpose(&mut self) {
        self.data.swap(1, 2); 
    }
}


#[derive(Debug)]
#[derive(Clone)]
pub struct BigIntMatrix {
    data: Vec<BigInt>,
    pub n_rows: usize,
    pub n_cols: usize
}

impl BigIntMatrix {
    pub fn new(n_rows: usize, n_cols: usize) -> Self {
        Self {
            data: vec![BigInt::from(0); n_rows * n_cols],
            n_rows,
            n_cols,
        }
    }

    pub fn new_ints(a: &[i64], n_rows: usize, n_cols: usize) -> Self {
        let mut data: Vec<BigInt> = Vec::with_capacity(n_rows * n_cols);
        for i in 0..n_rows {
            for j in 0..n_cols {
                data.push(BigInt::from(a[i * n_cols + j]));
            }
        }
        Self {
            data,
            n_rows,
            n_cols,
        }
    }

    pub fn new_bigints(a: &[BigInt], n_rows: usize, n_cols: usize) -> Self {
        if a.len() != n_rows * n_cols {
            panic!("Malformed input: a.len ({}), n_rows: {}, n_cols: {}", a.len(), n_rows, n_cols);
        }
        let mut data: Vec<BigInt> = Vec::with_capacity(n_rows * n_cols);
        data.extend_from_slice(a);
        Self {
            data,
            n_rows,
            n_cols
        }
    }

    pub fn new_random(n_rows: usize, n_cols: usize, low: &BigInt, high: &BigInt) -> Self {
        let mut rng = RandUtilsRng::new();
        let data: Vec<BigInt> = rng.sample_range_vec(n_rows * n_cols, low, high); 
        Self {
            data, 
            n_rows,
            n_cols
        }
    }

    pub fn get_element(&self, i: usize, j: usize) -> &BigInt {
        &self.data[i * self.n_cols + j]
    }

    pub fn set_element(&mut self, i: usize, j: usize, e: &BigInt) {
        self.data[i * self.n_cols + j] = e.clone();
    }

    pub fn matmul(&self, other: &BigIntMatrix) -> BigIntMatrix {
        if self.n_cols != other.n_rows {
            panic!("Malformed input: self.dim ({} x {}), other.dim ({} x {})", self.n_rows, self.n_cols, other.n_rows, other.n_cols);
        }
        let mut data: Vec<BigInt>  = vec![BigInt::from(0); self.n_rows * other.n_cols];
        for i in 0..self.n_rows {
            for j in 0..self.n_cols {
                for k in 0..other.n_cols {
                    data[i * other.n_cols + k] += self.get_element(i, j) * other.get_element(j, k);
                }
            }
        }
        Self {
            data,
            n_rows: self.n_rows,
            n_cols: other.n_cols
        }
    }

    pub fn transpose(&self) -> Self {
        let mut t = BigIntMatrix::new(self.n_cols, self.n_rows);
        for i in 0..self.n_rows {
            for j in 0..self.n_cols {
                t.set_element(j, i, self.get_element(i, j));
            }
        }
        t
    }
}

#[derive(Debug)]
#[derive(Clone)]
pub struct BigIntMatrix2x2 {
    data: Vec<BigInt>,
}

impl BigIntMatrix2x2 {
    pub fn new() -> Self {
        Self {
            data: vec![BigInt::from(0); 2 * 2],
        }
    }

    pub fn new_random_deterministic(seed: &[u8; 32]) -> Self {
        let mut rand_bytes: [u8; 32] = [0; 32];
        let mut rng = ChaCha20Rng::from_seed(*seed);
        rng.fill_bytes(&mut rand_bytes);
        let mut temp = BigIntMatrix2x2::new();
        for i in 0..2 {
            for j in 0..2 {
                //temp.data[i*2+j] = BigInt::from_bytes_be(Sign::Plus, &rand_bytes);
                //temp.data[i*2+j] = BigInt::from_signed_bytes_be(&rand_bytes);
                temp.data[i * 2 + j] = BigInt::from(1); //FIXME
            }
        }
        temp
    }

    pub fn get_element(&self, i: usize, j: usize) -> &BigInt {
        &self.data[i * 2 + j]
    }

    pub fn add(&mut self, rhs: &BigIntMatrix2x2) {
        for i in 0..2 {
            for j in 0..2 {
                self.data[i * 2 + j] += &rhs.data[i * 2 + j];
            }
        }
    }

    pub fn sub(&mut self, rhs: &BigIntMatrix2x2) {
        for i in 0..2 {
            for j in 0..2 {
                self.data[i * 2 + j] -= &rhs.data[i * 2 + j];
            }
        }
    }

    pub fn modp(&mut self, p: &BigInt) {
        for i in 0..2 {
            for j in 0..2 {
                self.data[i * 2 + j] = self.data[i * 2 + j].mod_floor(p);
            }
        }
    }
}

