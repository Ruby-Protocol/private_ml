use fawkes_crypto::{
    backend::bellman_groth16::{
        prover,
        engines::{Bn256},
        setup::setup
    },
    circuit::cs::{CS},
    circuit::num::CNum,
    circuit::bitify::c_into_bits_le_strict,
    circuit::ecc::*,
    core::signal::Signal,
    engines::bn256::{JubJubBN256},
    native::ecc::*,
    ff_uint::{Num},
};

use super::SnarkInfo;

type Fr = fawkes_crypto::engines::bn256::Fr;
type E = Bn256;
type JJParams = JubJubBN256;


pub fn c_dlog<C: CS, J: JubJubParams<Fr = C::Fr>>(g: &CEdwardsPoint<C>, x: &CNum<C>, params: &J) -> CEdwardsPoint<C> {
    let signal_x_bits = c_into_bits_le_strict(&x);
    let signal_y = g.mul(&signal_x_bits, params);

    signal_y
}


pub struct ZkDlog;

impl ZkDlog {
    fn circuit<C: CS<Fr = Fr>>(public: (CEdwardsPoint<C>, CEdwardsPoint<C>), secret: CNum<C>) {
        let jj_params = JJParams::new(); 
        let signal_y = c_dlog(&public.0, &secret, &jj_params);
        signal_y.assert_eq(&public.1);
    }

    pub fn generate(g: &EdwardsPoint<Fr>, x: &Num<Fr>) -> SnarkInfo<E> {
        let jubjub_params = JJParams::new(); 
        let bellman_params = setup::<E, _, _, _>(ZkDlog::circuit);
        let y = g.mul(x.to_other_reduced(), &jubjub_params);
        let (inputs, snark_proof) = prover::prove(&bellman_params, &(*g, y), x, ZkDlog::circuit);
        SnarkInfo::<E> {
            inputs: inputs,
            proof: snark_proof,
            vk: bellman_params.get_vk()
        }
    }

}



