use fawkes_crypto::{
    backend::bellman_groth16::{
        prover,
        engines::{Bn256},
        setup::setup
    },
    circuit::bool::CBool,
    circuit::cs::{CS, RCS},
    circuit::num::CNum,
    circuit::bitify::c_into_bits_le_strict,
    circuit::ecc::*,
    core::signal::Signal,
    core::sizedvec::SizedVec,
    engines::bn256::{JubJubBN256},
    native::ecc::*,
    rand::{thread_rng, Rng},
    ff_uint::{Num, PrimeField},
};

use super::SnarkInfo;

type Fr = fawkes_crypto::engines::bn256::Fr;
type E = Bn256;
type JJParams = JubJubBN256;


#[derive(Clone, Debug)]
pub struct SipProofPublic<Fr: PrimeField, const L: usize> {
    pub g: EdwardsPoint<Fr>,
    pub h: EdwardsPoint<Fr>,
    pub c1: EdwardsPoint<Fr>,
    pub c2: EdwardsPoint<Fr>,
    pub v: SizedVec<EdwardsPoint<Fr>, L>
}

#[derive(Clone, Signal)]
#[Value = "SipProofPublic<C::Fr, L>"]
pub struct CSipProofPublic<C: CS, const L: usize> {
    pub g: CEdwardsPoint<C>,
    pub h: CEdwardsPoint<C>,
    pub c1: CEdwardsPoint<C>,
    pub c2: CEdwardsPoint<C>,
    pub v: SizedVec<CEdwardsPoint<C>, L>,
}

#[derive(Clone, Debug)]
pub struct SipProofSecret<Fr: PrimeField, const L: usize> {
    pub r: Num<Fr>,
    pub s: SizedVec<Num<Fr>, L>,
    pub y: SizedVec<Num<Fr>, L>
}

#[derive(Clone, Signal)]
#[Value = "SipProofSecret<C::Fr, L>"]
pub struct CSipProofSecret<C: CS, const L: usize> {
    pub r: CNum<C>,
    pub s: SizedVec<CNum<C>, L>,
    pub y: SizedVec<CNum<C>, L>
}

/// Zero knowledge proof for the simple inner product functional encryption.
pub struct ZkSip<const L: usize>;

impl<const L: usize> ZkSip<L> {

    fn circuit<C: CS<Fr = Fr>>(public: CSipProofPublic<C, L>, secret: CSipProofSecret<C, L>) {
        let jubjub_params = JJParams::new();
        let cs = secret.get_cs();

        let mut ys = CNum::<C>::from_const(cs, &Num::<Fr>::ZERO); 
        for i in 0..L {
            let yi = secret.y[i].clone();
            ys += &yi * &secret.s[i];
        }
         
        let ys_bits = c_into_bits_le_strict(&ys);
        let r_bits = c_into_bits_le_strict(&secret.r);

        let c1 = public.g.mul(&ys_bits, &jubjub_params)
            .add(&public.h.mul(&r_bits, &jubjub_params), &jubjub_params);
        c1.assert_eq(&public.c1);

        let c2 = public.g.mul(&r_bits, &jubjub_params); 
        c2.assert_eq(&public.c2);

        let v = secret.s.iter()
            .map(|si| public.g.mul(&c_into_bits_le_strict(si), &jubjub_params))
            .collect::<SizedVec<CEdwardsPoint<C>, L>>();
        v.assert_eq(&public.v);
    }

    /// Generate zero knowledge proof for a statement proving that all keys are generated in a valid way. 
    ///
    /// # Examples
    ///
    /// ```
    /// const N: usize = 1;
    /// let mut rng = thread_rng();
    /// let jubjub_params = JubJubBN256::new();
    /// let g = EdwardsPoint::<Bn256Fr>::rand(&mut rng, &jubjub_params).mul(Num::from(8), &jubjub_params);
    /// let sk: Num<Bn256Fr> = rng.gen();
    /// let h = g.mul(sk.to_other_reduced(), &jubjub_params);
    /// let s: SizedVec<Num<Bn256Fr>, N> = (0..N).map(|_| rng.gen()).collect();
    /// let y: SizedVec<Num<Bn256Fr>, N> = (0..N).map(|_| rng.gen()).collect();
    /// let snark = ZkSip::<N>::generate(&g, &h, &s, &y);
    /// ```
    pub fn generate(g: &EdwardsPoint<Fr>, h: &EdwardsPoint<Fr>, s: &SizedVec<Num<Fr>, L>, y: &SizedVec<Num<Fr>, L>) -> SnarkInfo<E> {
        let jubjub_params = JJParams::new();
        let mut rng = thread_rng();

        let r: Num<Fr> = rng.gen();

        //let bigint_mod = BigInt::from_str(&Fr::MODULUS.to_string()).unwrap();
        //let bigint_s: Vec<BigInt> = s.iter().map(|x| BigInt::from_str(&x.to_string()).unwrap()).collect(); 
        //let bigint_t: Vec<BigInt> = t.iter().map(|x| BigInt::from_str(&x.to_string()).unwrap()).collect();
        //let bigint_result = reduce(&quadratic_result(&bigint_s, &bigint_t, &f), &bigint_mod);
        //let f_st = Num::<Fr>::from_str(&bigint_result.to_string()).unwrap();
        //println!("bigint_f(s, t): {}", bigint_result);
        //println!("f(s, t): {}", f_st);

        let mut ys = Num::<Fr>::ZERO; 
        for i in 0..L {
            ys = ys + (y[i] * s[i]);
        }

        let c1 = g.mul(ys.to_other_reduced(), &jubjub_params)
            .add(&h.mul(r.to_other_reduced(), &jubjub_params), &jubjub_params);
        let c2 = g.mul(r.to_other_reduced(), &jubjub_params);
        let v = s.iter()
            .map(|si| g.mul(si.to_other_reduced(), &jubjub_params))
            .collect::<SizedVec<_, L>>();

        let sip_proof_public = SipProofPublic {
            g: g.clone(),
            h: h.clone(),
            c1,
            c2,
            v
        };
        let sip_proof_secret = SipProofSecret {
            r,
            s: s.clone(),
            y: y.clone()
        };

        let bellman_params = setup::<E, _, _, _>(ZkSip::<L>::circuit);
        let (inputs, snark_proof) = prover::prove(&bellman_params, &sip_proof_public, &sip_proof_secret, ZkSip::<L>::circuit);
        SnarkInfo::<E> {
            inputs: inputs,
            proof: snark_proof,
            vk: bellman_params.get_vk()
        }
    }
}
