#![deny(missing_docs)]

//! A collection of utility functions and constants that can be reused from multiple projects

pub mod adjacent_pairs;
pub mod chunked_polynomial;
pub mod dense_polynomial;
pub mod evaluations;
pub mod field_helpers;
pub mod foreign_field;
pub mod hasher;
pub mod math;
pub mod serialization;

pub use dense_polynomial::ExtendedDensePolynomial;
pub use evaluations::ExtendedEvaluations;
pub use field_helpers::FieldHelpers;
pub use foreign_field::{ForeignElement, LIMB_COUNT};
