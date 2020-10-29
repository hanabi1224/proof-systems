/*****************************************************************************************************************

This source file implements Plonk Protocol Index primitive.

*****************************************************************************************************************/

use ff_fft::{DensePolynomial, Radix2EvaluationDomain as D};
use commitment_dlog::{srs::SRS, CommitmentField, commitment::{CommitmentCurve, PolyComm}};
use oracle::poseidon::{ArithmeticSpongeParams, SpongeConstants, PlonkSpongeConstants};
use plonk_circuits::{constraints::ConstraintSystem, wires::COLUMNS};
use array_init::array_init;
use algebra::AffineCurve;
use algebra::PrimeField;

type Fr<G> = <G as AffineCurve>::ScalarField;
type Fq<G> = <G as AffineCurve>::BaseField;

pub enum SRSValue<'a, G : CommitmentCurve> {
    Value(SRS<G>),
    Ref(&'a SRS<G>)
}

impl<'a, G : CommitmentCurve> SRSValue<'a, G> {
    pub fn get_ref(&self) -> & SRS<G> {
        match self {
            SRSValue::Value(x) => &x,
            SRSValue::Ref(x) => x
        }
    }
}

pub enum SRSSpec <'a, G: CommitmentCurve>{
    Use(&'a SRS<G>),
    Generate
}

impl<'a, G: CommitmentCurve> SRSValue<'a, G> where G::BaseField : PrimeField, G::ScalarField : CommitmentField {
    pub fn generate(size: usize, public: usize, circ: usize) -> SRS<G> {
        SRS::<G>::create(size, public, circ)
    }

    pub fn create<'b>(size: usize, public: usize, circ: usize, spec : SRSSpec<'a, G>) -> SRSValue<'a, G>{
        match spec {
            SRSSpec::Use(x) => SRSValue::Ref(x),
            SRSSpec::Generate => SRSValue::Value(Self::generate(size, public, circ))
        }
    }
}

pub struct Index<'a, G: CommitmentCurve> where G::ScalarField : CommitmentField
{
    // constraints system polynoms
    pub cs: ConstraintSystem<Fr<G>>,

    // polynomial commitment keys
    pub srs: SRSValue<'a, G>,

    // maximal size of polynomial section
    pub max_poly_size: usize,

    // maximal size of the quotient polynomial according to the supported constraints
    pub max_quot_size: usize,

    // random oracle argument parameters
    pub fq_sponge_params: ArithmeticSpongeParams<Fq<G>>,
}

pub struct VerifierIndex<'a, G: CommitmentCurve>
{
    pub domain: D<Fr<G>>,                   // evaluation domain
    pub max_poly_size: usize,               // maximal size of polynomial section
    pub max_quot_size: usize,               // maximal size of the quotient polynomial according to the supported constraints
    pub srs: SRSValue<'a, G>,               // polynomial commitment keys

    // index polynomial commitments
    pub sigma_comm: [PolyComm<G>; COLUMNS], // permutation commitment array
    pub qw_comm:    [PolyComm<G>; COLUMNS], // wire commitment array
    pub qm_comm:    PolyComm<G>,            // multiplication commitment
    pub qc_comm:    PolyComm<G>,            // constant wire commitment

    // poseidon polynomial commitments
    pub rcm_comm:   [PolyComm<G>; COLUMNS], // round constant polynomial commitment array
    pub psm_comm:   PolyComm<G>,            // poseidon constraint selector polynomial commitment

    // ECC arithmetic polynomial commitments
    pub add_comm:   PolyComm<G>,            // EC addition selector polynomial commitment
    pub double_comm:PolyComm<G>,            // EC doubling selector polynomial commitment
    pub mul1_comm:  PolyComm<G>,            // EC variable base scalar multiplication selector polynomial commitment
    pub mul2_comm:  PolyComm<G>,            // EC variable base scalar unpacking multiplication selector polynomial commitment
    pub emul_comm:  PolyComm<G>,            // endoscalar multiplication selector polynomial commitment
    pub pack_comm:  PolyComm<G>,            // packing selector polynomial commitment

    pub zkpm:       DensePolynomial<Fr<G>>, // zero-knowledge polynomial
    pub shift:      [Fr<G>; COLUMNS],       // wire coordinate shifts
    pub endo:       Fr<G>,                  // coefficient for the group endomorphism
    pub w:          Fr<G>,                  // root of unity for zero-knowledge

    // random oracle argument parameters
    pub fr_sponge_params: ArithmeticSpongeParams<Fr<G>>,
    pub fq_sponge_params: ArithmeticSpongeParams<Fq<G>>,
}

impl<'a, G: CommitmentCurve> Index<'a, G> where G::BaseField: PrimeField, G::ScalarField : CommitmentField
{
    pub fn verifier_index(&self) -> VerifierIndex<G> {
        let srs = match &self.srs
        {
            SRSValue::Value(s) => SRSValue::Value(s.clone()),
            SRSValue::Ref(x) => SRSValue::Ref(x)
        };

        VerifierIndex
        {
            domain: self.cs.domain.d1,

            sigma_comm: array_init(|i| srs.get_ref().commit(&self.cs.sigmam[i], None)),
            qw_comm: array_init(|i| srs.get_ref().commit(&self.cs.qwm[i], None)),
            qm_comm: srs.get_ref().commit(&self.cs.qmm, None),
            qc_comm: srs.get_ref().commit(&self.cs.qc, None),

            rcm_comm: array_init(|i| srs.get_ref().commit(&self.cs.rcm[i], None)),
            psm_comm: srs.get_ref().commit(&self.cs.psm, None),

            add_comm: srs.get_ref().commit(&self.cs.addm, None),
            double_comm: srs.get_ref().commit(&self.cs.doublem, None),
            mul1_comm: srs.get_ref().commit(&self.cs.mul1m, None),
            mul2_comm: srs.get_ref().commit(&self.cs.mul2m, None),
            emul_comm: srs.get_ref().commit(&self.cs.emulm, None),
            pack_comm: srs.get_ref().commit(&self.cs.packm, None),

            w: self.cs.sid[self.cs.domain.d1.size as usize -3],
            fr_sponge_params: self.cs.fr_sponge_params.clone(),
            fq_sponge_params: self.fq_sponge_params.clone(),
            max_poly_size: self.max_poly_size,
            max_quot_size: self.max_quot_size,
            zkpm: self.cs.zkpm.clone(),
            shift: self.cs.shift,
            endo: self.cs.endo,
            srs,
        }
    }

    // this function compiles the index from constraints
    pub fn create
    (
        mut cs: ConstraintSystem<Fr<G>>,
        max_poly_size: usize,
        fq_sponge_params: ArithmeticSpongeParams<Fq<G>>,
        endo_q: Fr<G>,
        srs : SRSSpec<'a, G>
    ) -> Self
    {
        if cs.public > 0
        {
            assert!(max_poly_size >= cs.domain.d1.size as usize, "polynomial segment size has to be not smaller that that of the circuit!");
        }
        let srs = SRSValue::create(max_poly_size, cs.public, cs.domain.d1.size as usize, srs);
        cs.endo = endo_q;
        Index
        {
            max_quot_size: PlonkSpongeConstants::SPONGE_BOX * (cs.domain.d1.size as usize - 1),
            fq_sponge_params,
            max_poly_size,
            srs,
            cs,
        }
    }
}
