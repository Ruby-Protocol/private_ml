use num_bigint::BigInt;

pub trait FunctionalEncryption {
    type CipherText;
    type EncryptData;
    type FEKeyData;
    type EvaluationKey;
    fn new() -> Self;
    fn encrypt(&self, x: &Self::EncryptData) -> Self::CipherText;
    fn derive_fe_key(&self, y: &Self::EncryptData) -> Self::EvaluationKey;
    fn decrypt(
        &self,
        ciphers: &Self::CipherText,
        y: &Self::EncryptData,
        dk: &Self::EvaluationKey,
        bound: &BigInt,
    ) -> Option<BigInt>;
}
