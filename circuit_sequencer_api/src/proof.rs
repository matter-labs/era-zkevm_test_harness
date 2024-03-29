use bellman::{
    bn256::Bn256,
    plonk::better_better_cs::{
        cs::{Circuit, Width4MainGateWithDNext},
        proof::Proof,
    },
};

// Wrapper for the final scheduler proof.
// We use generic circuit here, as this is used only for serializing & deserializing in sequencer.
// The exact circuti type does not change the rules of (de)serialization, so we use a very lightweight
// circuit in places that only pass proofs around to avoid unnecessary heavy compilation in most places.
pub type FinalProof = Proof<Bn256, GenericCircuit>;

#[derive(Clone)]
pub struct GenericCircuit {}

impl Circuit<Bn256> for GenericCircuit {
    type MainGate = Width4MainGateWithDNext;

    fn synthesize<CS: bellman::plonk::better_better_cs::cs::ConstraintSystem<Bn256>>(
        &self,
        _: &mut CS,
    ) -> Result<(), bellman::SynthesisError> {
        Ok(())
    }
}
