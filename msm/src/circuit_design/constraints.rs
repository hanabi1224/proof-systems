use ark_ff::PrimeField;
use kimchi::circuits::{
    expr::{ConstantExpr, ConstantTerm, Expr, ExprInner, Variable},
    gate::CurrOrNext,
};
use std::collections::BTreeMap;

use crate::{
    circuit_design::capabilities::{ColAccessCap, HybridCopyCap, LookupCap},
    columns::{Column, ColumnIndexer},
    expr::E,
    logup::{constraint_lookups, Logup, LookupTableID},
};

pub struct ConstraintBuilderEnv<F: PrimeField, LT: LookupTableID> {
    pub constraints: Vec<Expr<ConstantExpr<F>, Column>>,
    pub lookups: BTreeMap<LT, Vec<Logup<E<F>, LT>>>,
    pub assert_mapper: Box<dyn Fn(E<F>) -> E<F>>,
}

impl<F: PrimeField, LT: LookupTableID> ConstraintBuilderEnv<F, LT> {
    pub fn create() -> Self {
        Self {
            constraints: vec![],
            lookups: BTreeMap::new(),
            assert_mapper: Box::new(|x| x),
        }
    }
}

impl<F: PrimeField, CIx: ColumnIndexer, LT: LookupTableID> ColAccessCap<F, CIx>
    for ConstraintBuilderEnv<F, LT>
{
    type Variable = E<F>;

    fn assert_zero(&mut self, cst: Self::Variable) {
        self.constraints.push((self.assert_mapper)(cst));
    }

    fn set_assert_mapper(&mut self, mapper: Box<dyn Fn(Self::Variable) -> Self::Variable>) {
        self.assert_mapper = mapper;
    }

    fn read_column(&self, position: CIx) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: position.to_column(),
            row: CurrOrNext::Curr,
        }))
    }

    fn constant(value: F) -> Self::Variable {
        let cst_expr_inner = ConstantExpr::from(ConstantTerm::Literal(value));
        Expr::Atom(ExprInner::Constant(cst_expr_inner))
    }
}

impl<F: PrimeField, CIx: ColumnIndexer, LT: LookupTableID> HybridCopyCap<F, CIx>
    for ConstraintBuilderEnv<F, LT>
{
    fn hcopy(&mut self, x: &Self::Variable, position: CIx) -> Self::Variable {
        let y = Expr::Atom(ExprInner::Cell(Variable {
            col: position.to_column(),
            row: CurrOrNext::Curr,
        }));
        <ConstraintBuilderEnv<F, LT> as ColAccessCap<F, CIx>>::assert_zero(
            self,
            y.clone() - x.clone(),
        );
        y
    }
}

impl<F: PrimeField, CIx: ColumnIndexer, LT: LookupTableID> LookupCap<F, CIx, LT>
    for ConstraintBuilderEnv<F, LT>
{
    fn lookup(&mut self, table_id: LT, value: &<Self as ColAccessCap<F, CIx>>::Variable) {
        let one = ConstantExpr::from(ConstantTerm::Literal(F::one()));
        let lookup = Logup {
            table_id,
            numerator: Expr::Atom(ExprInner::Constant(one)),
            value: vec![value.clone()],
        };
        self.lookups.entry(table_id).or_default().push(lookup);
    }
}

impl<F: PrimeField, LT: LookupTableID> ConstraintBuilderEnv<F, LT> {
    /// Get constraints related to the application logic itself.
    pub fn get_relation_constraints(&self) -> Vec<E<F>> {
        self.constraints.clone()
    }

    /// Get constraints related to the lookup argument.
    pub fn get_lookup_constraints(&self) -> Vec<E<F>> {
        constraint_lookups(&self.lookups)
    }

    /// Get all relevant constraints generated by the constraint builder.
    pub fn get_constraints(&self) -> Vec<E<F>> {
        let mut constraints: Vec<E<F>> = vec![];
        constraints.extend(self.get_relation_constraints());
        if !self.lookups.is_empty() {
            constraints.extend(self.get_lookup_constraints());
        }
        constraints
    }
}
