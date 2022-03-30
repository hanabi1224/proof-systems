//! Mina Poseidon hasher
//!
//! An implementation of Mina's hasher based on the poseidon arithmetic sponge
//!
use std::marker::PhantomData;

use crate::DomainParameter;
use mina_curves::pasta::Fp;
use oracle::{
    constants::{PlonkSpongeConstantsKimchi, PlonkSpongeConstantsLegacy, SpongeConstants},
    pasta,
    poseidon::{ArithmeticSponge, ArithmeticSpongeParams, Sponge, SpongeState},
};

use super::{domain_prefix_to_field, Hashable, Hasher};

/// Poseidon hasher context
//
//  The arithmetic sponge parameters are large and costly to initialize,
//  so we only want to do this once and then re-use the Poseidon context
//  for many hashes. Also, following approach of the mina code we store
//  a backup of the initialized sponge state for efficient reuse.
pub struct Poseidon<SC: SpongeConstants, H: Hashable> {
    sponge: ArithmeticSponge<Fp, SC>,
    sponge_state: SpongeState,
    state: Vec<Fp>,
    domain_param: H::D,
    phantom: PhantomData<H>,
}

impl<SC: SpongeConstants, H: Hashable> Poseidon<SC, H> {
    fn new(domain_param: H::D, sponge_params: ArithmeticSpongeParams<Fp>) -> Self {
        let mut poseidon = Poseidon::<SC, H> {
            sponge: ArithmeticSponge::<Fp, SC>::new(sponge_params),
            sponge_state: SpongeState::Absorbed(0),
            state: vec![],
            domain_param,
            phantom: PhantomData,
        };

        poseidon.init(domain_param);

        poseidon
    }
}

pub(crate) fn new_legacy<H: Hashable>(domain_param: H::D) -> impl Hasher<H> {
    Poseidon::<PlonkSpongeConstantsLegacy, H>::new(domain_param, pasta::fp_legacy::params())
}

pub(crate) fn new_kimchi<H: Hashable>(domain_param: H::D) -> impl Hasher<H> {
    Poseidon::<PlonkSpongeConstantsKimchi, H>::new(domain_param, pasta::fp_kimchi::params())
}

impl<SC: SpongeConstants, H: Hashable> Hasher<H> for Poseidon<SC, H>
where
    H::D: DomainParameter,
{
    fn reset(&mut self) -> &mut dyn Hasher<H> {
        // Efficient reset
        self.sponge.sponge_state = self.sponge_state.clone();
        self.sponge.state = self.state.clone();

        self
    }

    fn init(&mut self, domain_param: H::D) -> &mut dyn Hasher<H> {
        // Set sponge initial state (explicitly init state so hasher context can be reused)
        // N.B. Mina sets the sponge's initial state by hashing the input's domain bytes
        self.sponge.reset();

        if let Some(domain_string) = H::domain_string(None, domain_param) {
            self.sponge.absorb(&[domain_prefix_to_field(domain_string)]);
            self.sponge.squeeze();
        }

        // Save initial state for efficient reset
        self.sponge_state = self.sponge.sponge_state.clone();
        self.state = self.sponge.state.clone();

        self
    }

    fn update(&mut self, input: &H) -> &mut dyn Hasher<H> {
        if let Some(domain_string) = H::domain_string(Some(input), self.domain_param) {
            self.sponge.absorb(&[domain_prefix_to_field(domain_string)]);
        }
        self.sponge.absorb(&input.to_roinput().to_fields());

        self
    }

    fn digest(&mut self) -> Fp {
        let output = self.sponge.squeeze();
        self.sponge.reset();
        output
    }
}
