use num_bigint::BigInt;

pub trait FunctionalEncryption {
    type CipherText;
    type PlainData;
    type FEKeyData;
    type EvaluationKey;
    fn new() -> Self;
    fn encrypt(&self, plain: &Self::PlainData) -> Self::CipherText;
    fn derive_fe_key(&self, f: &Self::FEKeyData) -> Self::EvaluationKey;
    fn decrypt(
        &self,
        ciphers: &Self::CipherText,
        //f: &Self::FEKeyData,
        dk: &Self::EvaluationKey,
        bound: &BigInt,
    ) -> Option<BigInt>;
}
