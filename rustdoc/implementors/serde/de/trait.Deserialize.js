(function() {var implementors = {};
implementors["commitment_dlog"] = [{"text":"impl&lt;'de, C&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"commitment_dlog/commitment/struct.PolyComm.html\" title=\"struct commitment_dlog::commitment::PolyComm\">PolyComm</a>&lt;C&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;C: CanonicalDeserialize + CanonicalSerialize,&nbsp;</span>","synthetic":false,"types":["commitment_dlog::commitment::PolyComm"]},{"text":"impl&lt;'de, G&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"commitment_dlog/commitment/struct.BlindedCommitment.html\" title=\"struct commitment_dlog::commitment::BlindedCommitment\">BlindedCommitment</a>&lt;G&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;G: <a class=\"trait\" href=\"commitment_dlog/commitment/trait.CommitmentCurve.html\" title=\"trait commitment_dlog::commitment::CommitmentCurve\">CommitmentCurve</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;G: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt;,&nbsp;</span>","synthetic":false,"types":["commitment_dlog::commitment::BlindedCommitment"]},{"text":"impl&lt;'de, G:&nbsp;AffineCurve&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"commitment_dlog/evaluation_proof/struct.OpeningProof.html\" title=\"struct commitment_dlog::evaluation_proof::OpeningProof\">OpeningProof</a>&lt;G&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;G: CanonicalDeserialize + CanonicalSerialize,&nbsp;</span>","synthetic":false,"types":["commitment_dlog::evaluation_proof::OpeningProof"]},{"text":"impl&lt;'de, G:&nbsp;<a class=\"trait\" href=\"commitment_dlog/commitment/trait.CommitmentCurve.html\" title=\"trait commitment_dlog::commitment::CommitmentCurve\">CommitmentCurve</a>&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"commitment_dlog/srs/struct.SRS.html\" title=\"struct commitment_dlog::srs::SRS\">SRS</a>&lt;G&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;G: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;G::ScalarField: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;G::BaseField: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a>,&nbsp;</span>","synthetic":false,"types":["commitment_dlog::srs::SRS"]}];
implementors["kimchi"] = [{"text":"impl&lt;'de, F&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"kimchi/alphas/struct.Alphas.html\" title=\"struct kimchi::alphas::Alphas\">Alphas</a>&lt;F&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;F: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt;,&nbsp;</span>","synthetic":false,"types":["kimchi::alphas::Alphas"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"enum\" href=\"kimchi/circuits/argument/enum.ArgumentType.html\" title=\"enum kimchi::circuits::argument::ArgumentType\">ArgumentType</a>","synthetic":false,"types":["kimchi::circuits::argument::ArgumentType"]},{"text":"impl&lt;'de, F:&nbsp;PrimeField&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"kimchi/circuits/constraints/struct.ConstraintSystem.html\" title=\"struct kimchi::circuits::constraints::ConstraintSystem\">ConstraintSystem</a>&lt;F&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;<a class=\"struct\" href=\"kimchi/circuits/domains/struct.EvaluationDomains.html\" title=\"struct kimchi::circuits::domains::EvaluationDomains\">EvaluationDomains</a>&lt;F&gt;: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> + <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.DeserializeOwned.html\" title=\"trait serde::de::DeserializeOwned\">DeserializeOwned</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;<a class=\"struct\" href=\"kimchi/circuits/gate/struct.CircuitGate.html\" title=\"struct kimchi::circuits::gate::CircuitGate\">CircuitGate</a>&lt;F&gt;: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> + <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.DeserializeOwned.html\" title=\"trait serde::de::DeserializeOwned\">DeserializeOwned</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.array.html\">[</a><a class=\"struct\" href=\"kimchi/circuits/gate/struct.SelectorPolynomial.html\" title=\"struct kimchi::circuits::gate::SelectorPolynomial\">SelectorPolynomial</a>&lt;F&gt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.array.html\">; 2]</a>: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> + <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.DeserializeOwned.html\" title=\"trait serde::de::DeserializeOwned\">DeserializeOwned</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;<a class=\"struct\" href=\"kimchi/circuits/lookup/index/struct.LookupConstraintSystem.html\" title=\"struct kimchi::circuits::lookup::index::LookupConstraintSystem\">LookupConstraintSystem</a>&lt;F&gt;: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> + <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.DeserializeOwned.html\" title=\"trait serde::de::DeserializeOwned\">DeserializeOwned</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;F: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a>,&nbsp;</span>","synthetic":false,"types":["kimchi::circuits::constraints::ConstraintSystem"]},{"text":"impl&lt;'de, F:&nbsp;FftField&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"kimchi/circuits/domain_constant_evaluation/struct.DomainConstantEvaluations.html\" title=\"struct kimchi::circuits::domain_constant_evaluation::DomainConstantEvaluations\">DomainConstantEvaluations</a>&lt;F&gt;","synthetic":false,"types":["kimchi::circuits::domain_constant_evaluation::DomainConstantEvaluations"]},{"text":"impl&lt;'de, F:&nbsp;FftField&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"kimchi/circuits/domains/struct.EvaluationDomains.html\" title=\"struct kimchi::circuits::domains::EvaluationDomains\">EvaluationDomains</a>&lt;F&gt;","synthetic":false,"types":["kimchi::circuits::domains::EvaluationDomains"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"enum\" href=\"kimchi/circuits/expr/enum.Column.html\" title=\"enum kimchi::circuits::expr::Column\">Column</a>","synthetic":false,"types":["kimchi::circuits::expr::Column"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"kimchi/circuits/expr/struct.Variable.html\" title=\"struct kimchi::circuits::expr::Variable\">Variable</a>","synthetic":false,"types":["kimchi::circuits::expr::Variable"]},{"text":"impl&lt;'de, F&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"enum\" href=\"kimchi/circuits/expr/enum.PolishToken.html\" title=\"enum kimchi::circuits::expr::PolishToken\">PolishToken</a>&lt;F&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;F: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt;,&nbsp;</span>","synthetic":false,"types":["kimchi::circuits::expr::PolishToken"]},{"text":"impl&lt;'de, E&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"kimchi/circuits/expr/struct.Linearization.html\" title=\"struct kimchi::circuits::expr::Linearization\">Linearization</a>&lt;E&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;E: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt;,&nbsp;</span>","synthetic":false,"types":["kimchi::circuits::expr::Linearization"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"enum\" href=\"kimchi/circuits/gate/enum.CurrOrNext.html\" title=\"enum kimchi::circuits::gate::CurrOrNext\">CurrOrNext</a>","synthetic":false,"types":["kimchi::circuits::gate::CurrOrNext"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"enum\" href=\"kimchi/circuits/gate/enum.GateType.html\" title=\"enum kimchi::circuits::gate::GateType\">GateType</a>","synthetic":false,"types":["kimchi::circuits::gate::GateType"]},{"text":"impl&lt;'de, F:&nbsp;PrimeField&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"kimchi/circuits/gate/struct.SelectorPolynomial.html\" title=\"struct kimchi::circuits::gate::SelectorPolynomial\">SelectorPolynomial</a>&lt;F&gt;","synthetic":false,"types":["kimchi::circuits::gate::SelectorPolynomial"]},{"text":"impl&lt;'de, F:&nbsp;PrimeField&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"kimchi/circuits/gate/struct.CircuitGate.html\" title=\"struct kimchi::circuits::gate::CircuitGate\">CircuitGate</a>&lt;F&gt;","synthetic":false,"types":["kimchi::circuits::gate::CircuitGate"]},{"text":"impl&lt;'de, F:&nbsp;FftField&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"kimchi/circuits/lookup/constraints/struct.LookupConfiguration.html\" title=\"struct kimchi::circuits::lookup::constraints::LookupConfiguration\">LookupConfiguration</a>&lt;F&gt;","synthetic":false,"types":["kimchi::circuits::lookup::constraints::LookupConfiguration"]},{"text":"impl&lt;'de, T&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"kimchi/circuits/lookup/index/struct.LookupSelectors.html\" title=\"struct kimchi::circuits::lookup::index::LookupSelectors\">LookupSelectors</a>&lt;T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt;,&nbsp;</span>","synthetic":false,"types":["kimchi::circuits::lookup::index::LookupSelectors"]},{"text":"impl&lt;'de, F:&nbsp;FftField&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"kimchi/circuits/lookup/index/struct.LookupConstraintSystem.html\" title=\"struct kimchi::circuits::lookup::index::LookupConstraintSystem\">LookupConstraintSystem</a>&lt;F&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;<a class=\"struct\" href=\"kimchi/circuits/lookup/constraints/struct.LookupConfiguration.html\" title=\"struct kimchi::circuits::lookup::constraints::LookupConfiguration\">LookupConfiguration</a>&lt;F&gt;: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> + <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.DeserializeOwned.html\" title=\"trait serde::de::DeserializeOwned\">DeserializeOwned</a>,&nbsp;</span>","synthetic":false,"types":["kimchi::circuits::lookup::index::LookupConstraintSystem"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"enum\" href=\"kimchi/circuits/lookup/lookups/enum.LookupsUsed.html\" title=\"enum kimchi::circuits::lookup::lookups::LookupsUsed\">LookupsUsed</a>","synthetic":false,"types":["kimchi::circuits::lookup::lookups::LookupsUsed"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"kimchi/circuits/lookup/lookups/struct.LookupInfo.html\" title=\"struct kimchi::circuits::lookup::lookups::LookupInfo\">LookupInfo</a>","synthetic":false,"types":["kimchi::circuits::lookup::lookups::LookupInfo"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"kimchi/circuits/lookup/lookups/struct.LocalPosition.html\" title=\"struct kimchi::circuits::lookup::lookups::LocalPosition\">LocalPosition</a>","synthetic":false,"types":["kimchi::circuits::lookup::lookups::LocalPosition"]},{"text":"impl&lt;'de, F&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"kimchi/circuits/lookup/lookups/struct.SingleLookup.html\" title=\"struct kimchi::circuits::lookup::lookups::SingleLookup\">SingleLookup</a>&lt;F&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;F: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt;,&nbsp;</span>","synthetic":false,"types":["kimchi::circuits::lookup::lookups::SingleLookup"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"enum\" href=\"kimchi/circuits/lookup/lookups/enum.LookupTableID.html\" title=\"enum kimchi::circuits::lookup::lookups::LookupTableID\">LookupTableID</a>","synthetic":false,"types":["kimchi::circuits::lookup::lookups::LookupTableID"]},{"text":"impl&lt;'de, SingleLookup, LookupTableID&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"kimchi/circuits/lookup/lookups/struct.JointLookup.html\" title=\"struct kimchi::circuits::lookup::lookups::JointLookup\">JointLookup</a>&lt;SingleLookup, LookupTableID&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;SingleLookup: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt;,<br>&nbsp;&nbsp;&nbsp;&nbsp;LookupTableID: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt;,&nbsp;</span>","synthetic":false,"types":["kimchi::circuits::lookup::lookups::JointLookup"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"enum\" href=\"kimchi/circuits/lookup/lookups/enum.LookupPattern.html\" title=\"enum kimchi::circuits::lookup::lookups::LookupPattern\">LookupPattern</a>","synthetic":false,"types":["kimchi::circuits::lookup::lookups::LookupPattern"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"kimchi/circuits/lookup/runtime_tables/struct.RuntimeTableSpec.html\" title=\"struct kimchi::circuits::lookup::runtime_tables::RuntimeTableSpec\">RuntimeTableSpec</a>","synthetic":false,"types":["kimchi::circuits::lookup::runtime_tables::RuntimeTableSpec"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"enum\" href=\"kimchi/circuits/lookup/tables/enum.GateLookupTable.html\" title=\"enum kimchi::circuits::lookup::tables::GateLookupTable\">GateLookupTable</a>","synthetic":false,"types":["kimchi::circuits::lookup::tables::GateLookupTable"]},{"text":"impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"kimchi/circuits/wires/struct.Wire.html\" title=\"struct kimchi::circuits::wires::Wire\">Wire</a>","synthetic":false,"types":["kimchi::circuits::wires::Wire"]},{"text":"impl&lt;'de, Field&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"kimchi/proof/struct.LookupEvaluations.html\" title=\"struct kimchi::proof::LookupEvaluations\">LookupEvaluations</a>&lt;Field&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;<a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;<a class=\"struct\" href=\"o1_utils/serialization/struct.SerdeAs.html\" title=\"struct o1_utils::serialization::SerdeAs\">SerdeAs</a>&gt;: <a class=\"trait\" href=\"https://docs.rs/serde_with/1.14.0/serde_with/de/trait.DeserializeAs.html\" title=\"trait serde_with::de::DeserializeAs\">DeserializeAs</a>&lt;'de, Field&gt;,&nbsp;</span>","synthetic":false,"types":["kimchi::proof::LookupEvaluations"]},{"text":"impl&lt;'de, Field&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"kimchi/proof/struct.ProofEvaluations.html\" title=\"struct kimchi::proof::ProofEvaluations\">ProofEvaluations</a>&lt;Field&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;<a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;<a class=\"struct\" href=\"o1_utils/serialization/struct.SerdeAs.html\" title=\"struct o1_utils::serialization::SerdeAs\">SerdeAs</a>&gt;: <a class=\"trait\" href=\"https://docs.rs/serde_with/1.14.0/serde_with/de/trait.DeserializeAs.html\" title=\"trait serde_with::de::DeserializeAs\">DeserializeAs</a>&lt;'de, Field&gt;,&nbsp;</span>","synthetic":false,"types":["kimchi::proof::ProofEvaluations"]},{"text":"impl&lt;'de, G:&nbsp;AffineCurve&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"kimchi/proof/struct.LookupCommitments.html\" title=\"struct kimchi::proof::LookupCommitments\">LookupCommitments</a>&lt;G&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;G: CanonicalDeserialize + CanonicalSerialize,&nbsp;</span>","synthetic":false,"types":["kimchi::proof::LookupCommitments"]},{"text":"impl&lt;'de, G:&nbsp;AffineCurve&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"kimchi/proof/struct.ProverCommitments.html\" title=\"struct kimchi::proof::ProverCommitments\">ProverCommitments</a>&lt;G&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;G: CanonicalDeserialize + CanonicalSerialize,&nbsp;</span>","synthetic":false,"types":["kimchi::proof::ProverCommitments"]},{"text":"impl&lt;'de, G:&nbsp;AffineCurve&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"kimchi/proof/struct.ProverProof.html\" title=\"struct kimchi::proof::ProverProof\">ProverProof</a>&lt;G&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;G: CanonicalDeserialize + CanonicalSerialize,&nbsp;</span>","synthetic":false,"types":["kimchi::proof::ProverProof"]},{"text":"impl&lt;'de, G&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"kimchi/proof/struct.RecursionChallenge.html\" title=\"struct kimchi::proof::RecursionChallenge\">RecursionChallenge</a>&lt;G&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;G: AffineCurve,<br>&nbsp;&nbsp;&nbsp;&nbsp;G: CanonicalDeserialize + CanonicalSerialize,&nbsp;</span>","synthetic":false,"types":["kimchi::proof::RecursionChallenge"]},{"text":"impl&lt;'de, G:&nbsp;<a class=\"trait\" href=\"kimchi/curve/trait.KimchiCurve.html\" title=\"trait kimchi::curve::KimchiCurve\">KimchiCurve</a>&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"kimchi/prover_index/struct.ProverIndex.html\" title=\"struct kimchi::prover_index::ProverIndex\">ProverIndex</a>&lt;G&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;<a class=\"struct\" href=\"kimchi/circuits/constraints/struct.ConstraintSystem.html\" title=\"struct kimchi::circuits::constraints::ConstraintSystem\">ConstraintSystem</a>&lt;G::ScalarField&gt;: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> + <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.DeserializeOwned.html\" title=\"trait serde::de::DeserializeOwned\">DeserializeOwned</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;G: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a>,&nbsp;</span>","synthetic":false,"types":["kimchi::prover_index::ProverIndex"]},{"text":"impl&lt;'de, G:&nbsp;<a class=\"trait\" href=\"commitment_dlog/commitment/trait.CommitmentCurve.html\" title=\"trait commitment_dlog::commitment::CommitmentCurve\">CommitmentCurve</a>&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"kimchi/verifier_index/struct.LookupVerifierIndex.html\" title=\"struct kimchi::verifier_index::LookupVerifierIndex\">LookupVerifierIndex</a>&lt;G&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;<a class=\"struct\" href=\"commitment_dlog/commitment/struct.PolyComm.html\" title=\"struct commitment_dlog::commitment::PolyComm\">PolyComm</a>&lt;G&gt;: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> + <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.DeserializeOwned.html\" title=\"trait serde::de::DeserializeOwned\">DeserializeOwned</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;<a class=\"struct\" href=\"commitment_dlog/commitment/struct.PolyComm.html\" title=\"struct commitment_dlog::commitment::PolyComm\">PolyComm</a>&lt;G&gt;: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> + <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.DeserializeOwned.html\" title=\"trait serde::de::DeserializeOwned\">DeserializeOwned</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;<a class=\"struct\" href=\"commitment_dlog/commitment/struct.PolyComm.html\" title=\"struct commitment_dlog::commitment::PolyComm\">PolyComm</a>&lt;G&gt;: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> + <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.DeserializeOwned.html\" title=\"trait serde::de::DeserializeOwned\">DeserializeOwned</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;<a class=\"struct\" href=\"commitment_dlog/commitment/struct.PolyComm.html\" title=\"struct commitment_dlog::commitment::PolyComm\">PolyComm</a>&lt;G&gt;: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> + <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.DeserializeOwned.html\" title=\"trait serde::de::DeserializeOwned\">DeserializeOwned</a>,&nbsp;</span>","synthetic":false,"types":["kimchi::verifier_index::LookupVerifierIndex"]},{"text":"impl&lt;'de, G:&nbsp;<a class=\"trait\" href=\"kimchi/curve/trait.KimchiCurve.html\" title=\"trait kimchi::curve::KimchiCurve\">KimchiCurve</a>&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"kimchi/verifier_index/struct.VerifierIndex.html\" title=\"struct kimchi::verifier_index::VerifierIndex\">VerifierIndex</a>&lt;G&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;<a class=\"struct\" href=\"commitment_dlog/commitment/struct.PolyComm.html\" title=\"struct commitment_dlog::commitment::PolyComm\">PolyComm</a>&lt;G&gt;: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> + <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.DeserializeOwned.html\" title=\"trait serde::de::DeserializeOwned\">DeserializeOwned</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;<a class=\"struct\" href=\"commitment_dlog/commitment/struct.PolyComm.html\" title=\"struct commitment_dlog::commitment::PolyComm\">PolyComm</a>&lt;G&gt;: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> + <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.DeserializeOwned.html\" title=\"trait serde::de::DeserializeOwned\">DeserializeOwned</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;<a class=\"struct\" href=\"commitment_dlog/commitment/struct.PolyComm.html\" title=\"struct commitment_dlog::commitment::PolyComm\">PolyComm</a>&lt;G&gt;: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> + <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.DeserializeOwned.html\" title=\"trait serde::de::DeserializeOwned\">DeserializeOwned</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;<a class=\"struct\" href=\"commitment_dlog/commitment/struct.PolyComm.html\" title=\"struct commitment_dlog::commitment::PolyComm\">PolyComm</a>&lt;G&gt;: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> + <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.DeserializeOwned.html\" title=\"trait serde::de::DeserializeOwned\">DeserializeOwned</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;<a class=\"struct\" href=\"commitment_dlog/commitment/struct.PolyComm.html\" title=\"struct commitment_dlog::commitment::PolyComm\">PolyComm</a>&lt;G&gt;: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> + <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.DeserializeOwned.html\" title=\"trait serde::de::DeserializeOwned\">DeserializeOwned</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;<a class=\"struct\" href=\"commitment_dlog/commitment/struct.PolyComm.html\" title=\"struct commitment_dlog::commitment::PolyComm\">PolyComm</a>&lt;G&gt;: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> + <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.DeserializeOwned.html\" title=\"trait serde::de::DeserializeOwned\">DeserializeOwned</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;<a class=\"struct\" href=\"commitment_dlog/commitment/struct.PolyComm.html\" title=\"struct commitment_dlog::commitment::PolyComm\">PolyComm</a>&lt;G&gt;: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> + <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.DeserializeOwned.html\" title=\"trait serde::de::DeserializeOwned\">DeserializeOwned</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;<a class=\"struct\" href=\"commitment_dlog/commitment/struct.PolyComm.html\" title=\"struct commitment_dlog::commitment::PolyComm\">PolyComm</a>&lt;G&gt;: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> + <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.DeserializeOwned.html\" title=\"trait serde::de::DeserializeOwned\">DeserializeOwned</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;<a class=\"struct\" href=\"commitment_dlog/commitment/struct.PolyComm.html\" title=\"struct commitment_dlog::commitment::PolyComm\">PolyComm</a>&lt;G&gt;: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> + <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.DeserializeOwned.html\" title=\"trait serde::de::DeserializeOwned\">DeserializeOwned</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;<a class=\"struct\" href=\"commitment_dlog/commitment/struct.PolyComm.html\" title=\"struct commitment_dlog::commitment::PolyComm\">PolyComm</a>&lt;G&gt;: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> + <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.DeserializeOwned.html\" title=\"trait serde::de::DeserializeOwned\">DeserializeOwned</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;<a class=\"struct\" href=\"commitment_dlog/commitment/struct.PolyComm.html\" title=\"struct commitment_dlog::commitment::PolyComm\">PolyComm</a>&lt;G&gt;: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> + <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.DeserializeOwned.html\" title=\"trait serde::de::DeserializeOwned\">DeserializeOwned</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;G: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;G::ScalarField: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a>,&nbsp;</span>","synthetic":false,"types":["kimchi::verifier_index::VerifierIndex"]}];
implementors["o1_utils"] = [{"text":"impl&lt;'de, F:&nbsp;Field, const N:&nbsp;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"o1_utils/foreign_field/struct.ForeignElement.html\" title=\"struct o1_utils::foreign_field::ForeignElement\">ForeignElement</a>&lt;F, N&gt;","synthetic":false,"types":["o1_utils::foreign_field::ForeignElement"]}];
implementors["oracle"] = [{"text":"impl&lt;'de, F:&nbsp;Field&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.137/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"oracle/poseidon/struct.ArithmeticSpongeParams.html\" title=\"struct oracle::poseidon::ArithmeticSpongeParams\">ArithmeticSpongeParams</a>&lt;F&gt;","synthetic":false,"types":["oracle::poseidon::ArithmeticSpongeParams"]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()