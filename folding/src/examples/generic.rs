use crate::{
    expressions::{FoldingColumnTrait, FoldingCompatibleExpr, FoldingCompatibleExprInner},
    FoldingConfig, Sponge,
};
use ark_ff::{Field, Zero};
use kimchi::curve::KimchiCurve;
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, ScalarChallenge},
    FqSponge,
};
use poly_commitment::PolyComm;

#[cfg(not(test))]
use log::debug;
#[cfg(test)]
use std::println as debug;

// 0. We start by defining the field and the curve that will be used in the
// constraint system, in addition to the sponge that will be used to generate
// challenges.
pub type Fp = ark_bn254::Fr;
pub type Curve = ark_bn254::G1Affine;
pub type SpongeParams = PlonkSpongeConstantsKimchi;
pub type BaseSponge = DefaultFqSponge<ark_bn254::g1::Parameters, SpongeParams>;

// 1. We continue by defining a generic type of columns and selectors.
// The selectors can be seen as additional (public) columns that are not part of
// the witness.
// The column must implement the trait [Hash] as it will be used by internal
// structures of the library.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Column {
    X(usize),
    Selector(usize),
}

// 2. We implement the trait [FoldingColumnTrait] that allows to distinguish
// between the public and private inputs, often called the "instances" and the
// "witnesses".
// By default, we consider that the columns are all witness values and selectors
// are public.
impl FoldingColumnTrait for Column {
    fn is_witness(&self) -> bool {
        match self {
            Column::X(_) => true,
            Column::Selector(_) => false,
        }
    }
}

// 3. We define different traits that can be used generically by the folding
// examples.
// It can be used by "pseudo-provers".
pub(crate) trait Provide<C: FoldingConfig> {
    fn resolve(&self, inner: FoldingCompatibleExprInner<C>) -> Vec<Fp>;
}

pub(crate) trait Checker<C: FoldingConfig>: Provide<C> {
    fn check_rec(&self, exp: FoldingCompatibleExpr<C>) -> Vec<Fp> {
        let e2 = exp.clone();
        let res = match exp {
            FoldingCompatibleExpr::Atom(inner) => self.resolve(inner),
            FoldingCompatibleExpr::Double(e) => {
                let v = self.check_rec(*e);
                v.into_iter().map(|x| x.double()).collect()
            }
            FoldingCompatibleExpr::Square(e) => {
                let v = self.check_rec(*e);
                v.into_iter().map(|x| x.square()).collect()
            }
            FoldingCompatibleExpr::Add(e1, e2) => {
                let v1 = self.check_rec(*e1);
                let v2 = self.check_rec(*e2);
                v1.into_iter().zip(v2).map(|(a, b)| a + b).collect()
            }
            FoldingCompatibleExpr::Sub(e1, e2) => {
                let v1 = self.check_rec(*e1);
                let v2 = self.check_rec(*e2);
                v1.into_iter().zip(v2).map(|(a, b)| a - b).collect()
            }
            FoldingCompatibleExpr::Mul(e1, e2) => {
                let v1 = self.check_rec(*e1);
                let v2 = self.check_rec(*e2);
                v1.into_iter().zip(v2).map(|(a, b)| a * b).collect()
            }
            FoldingCompatibleExpr::Pow(e, exp) => {
                let v = self.check_rec(*e);
                v.into_iter().map(|x| x.pow([exp])).collect()
            }
        };
        debug!("exp: {:?}", e2);
        debug!("res: [\n");
        for e in res.iter() {
            debug!("{e}\n");
        }
        debug!("]");
        res
    }

    fn check(&self, exp: &FoldingCompatibleExpr<C>) {
        let res = self.check_rec(exp.clone());
        for (i, row) in res.iter().enumerate() {
            if !row.is_zero() {
                panic!("check in row {i} failed, {row} != 0");
            }
        }
    }
}

// TODO: get rid of trait Sponge in folding, and use the one from kimchi
impl Sponge<Curve> for BaseSponge {
    fn challenge(absorb: &[PolyComm<Curve>; 2]) -> Fp {
        // This function does not have a &self because it is meant to absorb and
        // squeeze only once
        let mut s = BaseSponge::new(Curve::other_curve_sponge_params());
        s.absorb_g(&absorb[0].elems);
        s.absorb_g(&absorb[1].elems);
        // Squeeze sponge
        let chal = ScalarChallenge(s.challenge());
        let (_, endo_r) = Curve::endos();
        chal.to_field(endo_r)
    }
}