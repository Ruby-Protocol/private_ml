use fawkes_crypto::{
    backend::bellman_groth16::{
        engines::{Engine},
        prover::Proof,
        verifier::VK
    },
    ff_uint::{Num, PrimeField},
    BorshSerialize,
};


pub mod dlog;
pub mod qp;
pub mod sip;

pub trait Zk {
    type Fr: PrimeField;
    type E: Engine;
}

pub struct SnarkInfo<E: Engine> {
    pub inputs: Vec<Num<E::Fr>>,
    pub proof: Proof<E>,
    pub vk: VK<E> 
}

pub trait ToEncoding {
    fn encode(&self) -> String;
}

impl<Fr: PrimeField> ToEncoding for Vec<Num<Fr>> {
    fn encode(&self) -> String {
        base64::encode(BorshSerialize::try_to_vec(self).unwrap())
    }
}

impl<E: Engine> ToEncoding for Proof<E> {
    fn encode(&self) -> String {
        base64::encode(BorshSerialize::try_to_vec(self).unwrap())
    }
}

impl<E: Engine> ToEncoding for VK<E> {
    fn encode(&self) -> String {
        base64::encode(BorshSerialize::try_to_vec(self).unwrap())
    }
}

