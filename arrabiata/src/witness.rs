use ark_ec::{AffineCurve, SWModelParameters};
use ark_ff::{FpParameters, PrimeField};
use ark_poly::Evaluations;
use kimchi::circuits::domains::EvaluationDomains;
use log::{debug, info};
use num_bigint::BigUint;
use o1_utils::field_helpers::FieldHelpers;
use poly_commitment::{commitment::CommitmentCurve, srs::SRS, PolyComm, SRS as _};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use std::time::Instant;

use crate::{
    columns::Column,
    interpreter::{ECAdditionSide, Instruction, InterpreterEnv},
    poseidon_3_60_0_5_5_fp, poseidon_3_60_0_5_5_fq, NUMBER_OF_COLUMNS, NUMBER_OF_PUBLIC_INPUTS,
    POSEIDON_ROUNDS_FULL, POSEIDON_STATE_SIZE,
};

/// An environment that can be shared between IVC instances
/// It contains all the accumulators that can be picked for a given fold
/// instance k, including the sponges.
/// The environment is run over big unsigned integers to avoid performing
/// reduction at all step. Instead the user implementing the interpreter can
/// reduce in the corresponding field when they want.
pub struct Env<
    Fp: PrimeField,
    Fq: PrimeField,
    E1: AffineCurve<ScalarField = Fp, BaseField = Fq>,
    E2: AffineCurve<ScalarField = Fq, BaseField = Fp>,
> {
    // ----------------
    // Setup related (domains + SRS)
    /// Domain for Fp
    pub domain_fp: EvaluationDomains<Fp>,

    /// Domain for Fq
    pub domain_fq: EvaluationDomains<Fq>,

    /// SRS for the first curve
    pub srs_e1: SRS<E1>,

    /// SRS for the second curve
    pub srs_e2: SRS<E2>,
    // ----------------

    // ----------------
    // Information related to the IVC, which will be used by the prover/verifier
    // at the end of the whole execution
    // FIXME: use a blinded comm and also fold the blinder
    pub ivc_accumulator_e1: Vec<PolyComm<E1>>,

    // FIXME: use a blinded comm and also fold the blinder
    pub ivc_accumulator_e2: Vec<PolyComm<E2>>,

    /// Commitments to the previous instances
    pub previous_commitments_e1: Vec<PolyComm<E1>>,
    pub previous_commitments_e2: Vec<PolyComm<E2>>,
    // ----------------

    // ----------------
    // Data only used by the interpreter while building the witness over time
    /// The index of the latest allocated variable in the circuit.
    /// It is used to allocate new variables without having to keep track of the
    /// position.
    pub idx_var: usize,

    /// The index of the latest allocated public inputs in the circuit.
    /// It is used to allocate new public inputs without having to keep track of
    /// the position.
    pub idx_var_pi: usize,

    /// Current processing row. Used to build the witness.
    pub current_row: usize,

    /// State of the current row in the execution trace
    pub state: [BigUint; NUMBER_OF_COLUMNS],

    /// Contain the public state
    // FIXME: I don't like this design. Feel free to suggest a better solution
    pub public_state: [BigUint; NUMBER_OF_PUBLIC_INPUTS],

    /// Keep the current executed instruction
    /// This can be used to identify which gadget the interpreter is currently
    /// building.
    pub current_instruction: Instruction,

    /// The sponges will be used to simulate the verifier messages, and will
    /// also be used to verify the consistency of the computation by hashing the
    /// public IO.
    // IMPROVEME: use a list of BigUint? It might be faster as the CPU will
    // already have in its cache the values, and we can use a flat array
    pub sponge_e1: [BigUint; POSEIDON_STATE_SIZE],
    pub sponge_e2: [BigUint; POSEIDON_STATE_SIZE],

    /// List of public inputs, used first to verify the consistency of the
    /// previous iteration.
    pub current_iteration: u64,

    /// A previous hash, encoded in 2 chunks of 128 bits.
    pub previous_hash: [u128; 2],

    /// The coin folding combiner will be used to generate the combinaison of
    /// folding instances
    pub r: BigUint,
    // ----------------
    /// The witness of the current instance of the circuit.
    /// The size of the outer vector must be equal to the number of columns in the
    /// circuit.
    /// The size of the inner vector must be equal to the number of rows in
    /// the circuit.
    ///
    /// The layout columns/rows is used to avoid rebuilding the witness per
    /// column when committing to the witness.
    pub witness: Vec<Vec<BigUint>>,

    // --------------
    // Inputs
    /// Initial input
    pub z0: BigUint,

    /// Current input
    pub zi: BigUint,
    // ---------------

    // ---------------
    // Only used to have type safety and think about the design at the
    // type-level
    pub _marker: std::marker::PhantomData<(Fp, Fq, E1, E2)>,
    // ---------------
}

// The condition on the parameters for E1 and E2 is to get the coefficients and
// convert them into biguint.
// The condition SWModelParameters is to get the parameters of the curve as
// biguint to use them to compute the slope in the elliptic curve addition
// algorithm.
impl<
        Fp: PrimeField,
        Fq: PrimeField,
        E1: CommitmentCurve<ScalarField = Fp, BaseField = Fq>,
        E2: CommitmentCurve<ScalarField = Fq, BaseField = Fp>,
    > InterpreterEnv for Env<Fp, Fq, E1, E2>
where
    <E1::Params as ark_ec::ModelParameters>::BaseField: PrimeField,
    <E2::Params as ark_ec::ModelParameters>::BaseField: PrimeField,
{
    type Position = Column;

    /// For efficiency, and for having a single interpreter, we do not use one
    /// of the fields. We use a generic BigUint to represent the values.
    /// When building the witness, we will reduce into the corresponding field
    type Variable = BigUint;

    fn variable(&self, _column: Self::Position) -> Self::Variable {
        todo!();
    }

    fn allocate(&mut self) -> Self::Position {
        assert!(self.idx_var < NUMBER_OF_COLUMNS, "Maximum number of columns reached ({NUMBER_OF_COLUMNS}), increase the number of columns");
        let pos = Column::X(self.idx_var);
        self.idx_var += 1;
        pos
    }

    fn allocate_public_input(&mut self) -> Self::Position {
        assert!(self.idx_var_pi < NUMBER_OF_PUBLIC_INPUTS, "Maximum number of public inputs reached ({NUMBER_OF_PUBLIC_INPUTS}), increase the number of public inputs");
        let pos = Column::PublicInput(self.idx_var_pi);
        self.idx_var_pi += 1;
        pos
    }

    fn write_column(&mut self, col: Self::Position, v: Self::Variable) -> Self::Variable {
        let Column::X(idx) = col else {
            unimplemented!("Only works for private inputs")
        };
        let modulus: BigUint = if self.current_iteration % 2 == 0 {
            Fp::Params::MODULUS.into()
        } else {
            Fq::Params::MODULUS.into()
        };
        self.state[idx] = v.clone() % modulus;
        v
    }

    fn write_public_input(&mut self, col: Self::Position, v: BigUint) -> Self::Variable {
        let Column::PublicInput(idx) = col else {
            unimplemented!("Only works for public input columns")
        };
        self.public_state[idx] = v.clone();
        v
    }

    fn constrain_boolean(&mut self, x: Self::Variable) {
        assert!(x < BigUint::from(2_usize));
    }

    fn constant(&self, v: BigUint) -> Self::Variable {
        v
    }

    fn add_constraint(&mut self, _x: Self::Variable) {
        unimplemented!("Only when building the constraints")
    }

    fn assert_zero(&mut self, var: Self::Variable) {
        assert_eq!(var, BigUint::from(0_usize));
    }

    fn assert_equal(&mut self, x: Self::Variable, y: Self::Variable) {
        assert_eq!(x, y);
    }

    // FIXME: it should not be a check, but it should build the related logup
    // values
    // FIXME: we should have additional columns for the lookups.
    // This will be implemented when the first version of the IVC is
    // implemented and we can make recursive arguments
    fn range_check16(&mut self, col: Self::Position) {
        let Column::X(idx) = col else {
            unimplemented!("Only works for private columns")
        };
        let x = self.state[idx].clone();
        assert!(x < BigUint::from(2_usize).pow(16));
    }

    fn square(&mut self, col: Self::Position, x: Self::Variable) -> Self::Variable {
        let res = x.clone() * x.clone();
        self.write_column(col, res.clone());
        res
    }

    /// Flagged as unsafe as it does require an additional range check
    unsafe fn bitmask_be(
        &mut self,
        x: &Self::Variable,
        highest_bit: u32,
        lowest_bit: u32,
        col: Self::Position,
    ) -> Self::Variable {
        let diff = highest_bit - lowest_bit;
        assert!(
            diff <= 16,
            "The difference between the highest and lowest bit should be less than 16"
        );
        let rht = BigUint::from(1_usize << diff) - BigUint::from(1_usize);
        let lft = x >> lowest_bit;
        let res: BigUint = lft & rht;
        self.write_column(col, res.clone());
        res
    }

    // FIXME: for now, we use the row number and compute the square.
    // This is only for testing purposes, and having something to build the
    // witness.
    fn fetch_input(&mut self, col: Self::Position) -> Self::Variable {
        let x = BigUint::from(self.current_row as u64);
        self.write_column(col, x.clone());
        x
    }

    /// Reset the environment to build the next row
    fn reset(&mut self) {
        // Save the current state in the witness
        self.state.iter().enumerate().for_each(|(i, x)| {
            self.witness[i][self.current_row] = x.clone();
        });
        self.current_row += 1;
        self.idx_var = 0;
        self.idx_var_pi = 0;
        // Rest the state for the next row
        self.state = std::array::from_fn(|_| BigUint::from(0_usize));
    }

    /// FIXME: check if we need to pick the left or right sponge
    fn coin_folding_combiner(&mut self, col: Self::Position) -> Self::Variable {
        let r = if self.current_iteration % 2 == 0 {
            self.sponge_e1[0].clone()
        } else {
            self.sponge_e2[0].clone()
        };
        let Column::X(idx) = col else {
            unimplemented!("Only works for private columns")
        };
        self.state[idx] = r.clone();
        self.r = r.clone();
        r
    }

    unsafe fn get_sixteen_bits_chunks_folding_combiner(
        &mut self,
        pos: Self::Position,
        i: u32,
    ) -> Self::Variable {
        let r = self.r.clone();
        self.bitmask_be(&r, 16 * (i + 1), 16 * i, pos)
    }

    fn get_poseidon_state(&mut self, pos: Self::Position, i: usize) -> Self::Variable {
        let state = if self.current_iteration % 2 == 0 {
            self.sponge_e1[i].clone()
        } else {
            self.sponge_e2[i].clone()
        };
        self.write_column(pos, state)
    }

    fn get_poseidon_round_constant(
        &mut self,
        pos: Self::Position,
        round: usize,
        i: usize,
    ) -> Self::Variable {
        let rc = if self.current_iteration % 2 == 0 {
            poseidon_3_60_0_5_5_fp::static_params().round_constants[round][i].to_biguint()
        } else {
            poseidon_3_60_0_5_5_fq::static_params().round_constants[round][i].to_biguint()
        };
        self.write_public_input(pos, rc)
    }

    fn get_poseidon_mds_matrix(&mut self, i: usize, j: usize) -> Self::Variable {
        if self.current_iteration % 2 == 0 {
            poseidon_3_60_0_5_5_fp::static_params().mds[i][j].to_biguint()
        } else {
            poseidon_3_60_0_5_5_fq::static_params().mds[i][j].to_biguint()
        }
    }

    fn update_poseidon_state(&mut self, x: Self::Variable, i: usize) {
        if self.current_iteration % 2 == 0 {
            let modulus: BigUint = TryFrom::try_from(Fp::Params::MODULUS).unwrap();
            self.sponge_e1[i] = x % modulus
        } else {
            let modulus: BigUint = TryFrom::try_from(Fq::Params::MODULUS).unwrap();
            self.sponge_e2[i] = x % modulus
        }
    }

    fn load_ec_point(
        &mut self,
        pos_x: Self::Position,
        pos_y: Self::Position,
        i: usize,
        side: ECAdditionSide,
    ) -> (Self::Variable, Self::Variable) {
        let (pt_x, pt_y) = match side {
            ECAdditionSide::Left => {
                if self.current_iteration % 2 == 0 {
                    let pt = self.ivc_accumulator_e1[i].elems[0];
                    let (x, y) = pt.to_coordinates().unwrap();
                    (x.to_biguint(), y.to_biguint())
                } else {
                    let pt = self.ivc_accumulator_e2[i].elems[0];
                    let (x, y) = pt.to_coordinates().unwrap();
                    (x.to_biguint(), y.to_biguint())
                }
            }
            ECAdditionSide::Right => {
                // FIXME: we must get the scaled commitment, not simply the commitment
                if self.current_iteration % 2 == 0 {
                    let pt = self.previous_commitments_e1[i].elems[0];
                    let (x, y) = pt.to_coordinates().unwrap();
                    (x.to_biguint(), y.to_biguint())
                } else {
                    let pt = self.previous_commitments_e2[i].elems[0];
                    let (x, y) = pt.to_coordinates().unwrap();
                    (x.to_biguint(), y.to_biguint())
                }
            }
        };
        self.write_column(pos_x, pt_x.clone());
        self.write_column(pos_y, pt_y.clone());
        (pt_x, pt_y)
    }

    fn is_same_ec_point(
        &mut self,
        pos: Self::Position,
        x1: Self::Variable,
        y1: Self::Variable,
        x2: Self::Variable,
        y2: Self::Variable,
    ) -> Self::Variable {
        let res = if x1 == x2 && y1 == y2 {
            BigUint::from(1_usize)
        } else {
            BigUint::from(0_usize)
        };
        self.write_column(pos, res)
    }

    fn one(&self) -> Self::Variable {
        BigUint::from(1_usize)
    }

    fn compute_lambda(
        &mut self,
        pos: Self::Position,
        is_same_point: Self::Variable,
        x1: Self::Variable,
        y1: Self::Variable,
        x2: Self::Variable,
        y2: Self::Variable,
    ) -> Self::Variable {
        let modulus: BigUint = if self.current_iteration % 2 == 0 {
            Fp::Params::MODULUS.into()
        } else {
            Fq::Params::MODULUS.into()
        };
        // If it is not the same point, we compute lambda as:
        // - λ = (Y2 - Y1) / (X2 - X1)
        let (num, denom): (BigUint, BigUint) = if is_same_point == BigUint::from(0_usize) {
            let num = (y2.clone() - y1.clone()) % modulus.clone();
            let x2_minus_x1 = (x2.clone() - x1.clone()) % modulus.clone();
            let denom: BigUint = if self.current_iteration % 2 == 0 {
                Fp::from_biguint_err(&x2_minus_x1)
                    .inverse()
                    .unwrap()
                    .to_biguint()
            } else {
                Fq::from_biguint_err(&x2_minus_x1)
                    .inverse()
                    .unwrap()
                    .to_biguint()
            };
            (num, denom)
        } else {
            // Otherwise, we compute λ as:
            // - λ = (3X1^2 + a) / (2Y1)
            let denom = {
                let double_y1 = y1.clone() + y1.clone();
                if self.current_iteration % 2 == 0 {
                    Fp::from_biguint_err(&double_y1)
                        .inverse()
                        .unwrap()
                        .to_biguint()
                } else {
                    Fq::from_biguint_err(&double_y1)
                        .inverse()
                        .unwrap()
                        .to_biguint()
                }
            };
            let num = {
                let a: BigUint = if self.current_iteration % 2 == 0 {
                    (E1::Params::COEFF_A).to_biguint()
                } else {
                    (E2::Params::COEFF_A).to_biguint()
                };
                let x1_square = x1.clone() * x1.clone();
                let two_x1_square = x1_square.clone() + x1_square.clone();
                (two_x1_square + x1_square + a) % modulus.clone()
            };
            (num, denom)
        };
        let res = (num * denom) % modulus;
        self.write_column(pos, res)
    }
}

impl<
        Fp: PrimeField,
        Fq: PrimeField,
        E1: CommitmentCurve<ScalarField = Fp, BaseField = Fq>,
        E2: CommitmentCurve<ScalarField = Fq, BaseField = Fp>,
    > Env<Fp, Fq, E1, E2>
{
    pub fn new(
        srs_log2_size: usize,
        z0: BigUint,
        sponge_e1: [BigUint; 3],
        sponge_e2: [BigUint; 3],
    ) -> Self {
        let srs_size = 1 << srs_log2_size;
        let domain_fp = EvaluationDomains::<Fp>::create(srs_size).unwrap();
        let domain_fq = EvaluationDomains::<Fq>::create(srs_size).unwrap();

        info!("Create an SRS of size {srs_log2_size} for the first curve");
        let srs_e1: SRS<E1> = {
            let start = Instant::now();
            let mut srs = SRS::create(srs_size);
            debug!("SRS for E1 created in {:?}", start.elapsed());
            let start = Instant::now();
            srs.add_lagrange_basis(domain_fp.d1);
            debug!("Lagrange basis for E1 added in {:?}", start.elapsed());
            srs
        };
        info!("Create an SRS of size {srs_log2_size} for the second curve");
        let srs_e2: SRS<E2> = {
            let start = Instant::now();
            let mut srs = SRS::create(srs_size);
            debug!("SRS for E2 created in {:?}", start.elapsed());
            let start = Instant::now();
            srs.add_lagrange_basis(domain_fq.d1);
            debug!("Lagrange basis for E2 added in {:?}", start.elapsed());
            srs
        };

        let mut witness: Vec<Vec<BigUint>> = Vec::with_capacity(NUMBER_OF_COLUMNS);
        {
            let mut vec: Vec<BigUint> = Vec::with_capacity(srs_size);
            (0..srs_size).for_each(|_| vec.push(BigUint::from(0_usize)));
            (0..NUMBER_OF_COLUMNS).for_each(|_| witness.push(vec.clone()));
        };
        // Default set to the blinders
        let previous_commitments_e1: Vec<PolyComm<E1>> = (0..NUMBER_OF_COLUMNS)
            .map(|_| PolyComm::new(vec![srs_e1.h]))
            .collect();
        let previous_commitments_e2: Vec<PolyComm<E2>> = (0..NUMBER_OF_COLUMNS)
            .map(|_| PolyComm::new(vec![srs_e2.h]))
            .collect();
        // FIXME: zero will not work
        let ivc_accumulator_e1: Vec<PolyComm<E1>> = (0..NUMBER_OF_COLUMNS)
            .map(|_| PolyComm::new(vec![srs_e1.h]))
            .collect();
        let ivc_accumulator_e2: Vec<PolyComm<E2>> = (0..NUMBER_OF_COLUMNS)
            .map(|_| PolyComm::new(vec![srs_e2.h]))
            .collect();
        Self {
            // -------
            // Setup
            domain_fp,
            domain_fq,
            srs_e1,
            srs_e2,
            // -------
            // -------
            // IVC only
            ivc_accumulator_e1,
            ivc_accumulator_e2,
            previous_commitments_e1,
            previous_commitments_e2,
            // ------
            // ------
            idx_var: 0,
            idx_var_pi: 0,
            current_row: 0,
            state: std::array::from_fn(|_| BigUint::from(0_usize)),
            public_state: std::array::from_fn(|_| BigUint::from(0_usize)),
            current_instruction: Instruction::SixteenBitsDecomposition,
            sponge_e1,
            sponge_e2,
            current_iteration: 0,
            previous_hash: [0; 2],
            r: BigUint::from(0_usize),
            // ------
            // ------
            // Used by the interpreter
            // Used to allocate variables
            // Witness builder related
            witness,
            // ------
            // Inputs
            z0: z0.clone(),
            zi: z0,
            // ------
            _marker: std::marker::PhantomData,
        }
    }

    /// Reset the environment to build the next iteration
    pub fn reset_for_next_iteration(&mut self) {
        // Rest the state for the next row
        self.current_row = 0;
        self.state = std::array::from_fn(|_| BigUint::from(0_usize));
        self.idx_var = 0;
    }

    /// The blinder used to commit, to avoid committing to the zero polynomial
    /// and accumulate it in the IVC.
    ///
    /// It is part of the instance, and it is accumulated in the IVC.
    pub fn accumulate_commitment_blinder(&mut self) {
        // TODO
    }

    /// Compute the commitments to the current witness, and update the previous
    /// instances.
    // Might be worth renaming this function
    pub fn compute_and_update_previous_commitments(&mut self) {
        if self.current_iteration % 2 == 0 {
            let comms: Vec<PolyComm<E1>> = self
                .witness
                .par_iter()
                .map(|evals| {
                    let evals: Vec<Fp> = evals
                        .par_iter()
                        .map(|x| Fp::from_biguint(x).unwrap())
                        .collect();
                    let evals = Evaluations::from_vec_and_domain(evals.to_vec(), self.domain_fp.d1);
                    self.srs_e1
                        .commit_evaluations_non_hiding(self.domain_fp.d1, &evals)
                })
                .collect();
            self.previous_commitments_e1 = comms
        } else {
            let comms: Vec<PolyComm<E2>> = self
                .witness
                .iter()
                .map(|evals| {
                    let evals: Vec<Fq> = evals
                        .par_iter()
                        .map(|x| Fq::from_biguint(x).unwrap())
                        .collect();
                    let evals = Evaluations::from_vec_and_domain(evals.to_vec(), self.domain_fq.d1);
                    self.srs_e2
                        .commit_evaluations_non_hiding(self.domain_fq.d1, &evals)
                })
                .collect();
            self.previous_commitments_e2 = comms
        }
    }

    /// Compute the output of the application on the previous output
    // TODO: we should compute the hash of the previous commitments, only on
    // CPU?
    pub fn compute_output(&mut self) {
        self.zi = BigUint::from(42_usize)
    }

    pub fn fetch_instruction(&self) -> Instruction {
        self.current_instruction
    }

    pub fn fetch_next_instruction(&mut self) -> Instruction {
        match self.current_instruction {
            Instruction::SixteenBitsDecomposition => Instruction::BitDecompositionFrom16Bits(0),
            Instruction::Poseidon(i) => {
                if i < POSEIDON_ROUNDS_FULL - 4 {
                    // We perform 4 rounds per row
                    // FIXME: we can do 5 by using the "next row"
                    Instruction::Poseidon(i + 4)
                } else {
                    Instruction::EllipticCurveAddition(0)
                }
            }
            Instruction::BitDecompositionFrom16Bits(i) => {
                if i < 15 {
                    Instruction::BitDecompositionFrom16Bits(i + 1)
                } else {
                    Instruction::Poseidon(0)
                }
            }
            Instruction::EllipticCurveScaling(i_comm) => {
                panic!("Not implemented yet for {i_comm}")
            }
            Instruction::EllipticCurveAddition(i_comm) => {
                if i_comm < NUMBER_OF_COLUMNS - 1 {
                    Instruction::EllipticCurveAddition(i_comm + 1)
                } else {
                    Instruction::NoOp
                }
            }
            Instruction::NoOp => Instruction::NoOp,
        }
    }
}
