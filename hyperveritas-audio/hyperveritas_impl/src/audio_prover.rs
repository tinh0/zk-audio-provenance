#![allow(warnings)]

use ark_ec::pairing::Pairing;
use std::{ops::Deref, time::Instant};

use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::{Field, PrimeField, Zero};
use subroutines::{
    pcs::prelude::{Commitment, MultilinearKzgPCS, PolynomialCommitmentScheme},
    poly_iop::{
        prelude::{ProductCheck, SumCheck},
        PolyIOP,
    },
};

use arithmetic::{VPAuxInfo, VirtualPolynomial};
pub use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use std::sync::Arc;
use transcript::IOPTranscript;

use ark_bls12_381::Fr as F;
use ark_ff::One;
use ark_std::test_rng;

use super::helper::{vec_to_poly, matSparseMultVec, irredPolyTable};
use super::prover::range_checkProverIOP;

/// Prove audio trim (1D crop) transformation.
///
/// This function adapts the cropProveAffineIOP from 2D images to 1D audio samples.
/// It proves that a trimmed audio segment is correctly extracted from the original.
///
/// # Arguments
/// * `nv_orig` - Number of variables for original audio polynomial
/// * `nv_trim` - Number of variables for trimmed audio polynomial
/// * `orig_audio` - Original audio as MLE
/// * `start_sample` - Start sample index (inclusive)
/// * `end_sample` - End sample index (exclusive)
/// * `transcript` - IOP transcript for Fiat-Shamir
///
/// # Returns
/// Tuple of (SumCheckProof, VPAuxInfo)
pub fn trimProveAffineIOP<F: PrimeField>(
    nv_orig: usize,
    nv_trim: usize,
    orig_audio: Arc<DenseMultilinearExtension<F>>,
    start_sample: usize,
    end_sample: usize,
    transcript: &mut IOPTranscript<F>,
) -> (<PolyIOP<F> as SumCheck<F>>::SumCheckProof, VPAuxInfo<F>) {
    let trim_length = end_sample - start_sample;

    // Create 1D permutation: trimPerm[start_sample + i] -> i
    let mut trim_perm = Vec::new();
    for _ in 0..1 << nv_orig {
        trim_perm.push(Vec::new());
    }

    for i in 0..trim_length {
        let orig_idx = start_sample + i;
        if orig_idx < (1 << nv_orig) {
            trim_perm[orig_idx].push((i, F::one()));
        }
    }

    // Get Frievald randomness vector
    let frievald_rand_vec = transcript
        .get_and_append_challenge_vectors(b"frievald", 1 << nv_trim)
        .unwrap();

    // Compute permTimesR = sparse_mult(trimPerm, randVec)
    let perm_times_r = matSparseMultVec::<F>(1 << nv_orig, 1 << nv_trim, &trim_perm, &frievald_rand_vec);

    let perm_times_r_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(
        nv_orig,
        perm_times_r,
    ));

    // Build virtual polynomial: permTimesR * origAudio
    let mut i_perm = VirtualPolynomial::new_from_mle(&perm_times_r_poly, F::one());
    i_perm.mul_by_mle(orig_audio, F::one());

    // Run sumcheck
    let proof = <PolyIOP<F> as SumCheck<F>>::prove(&i_perm, transcript).unwrap();

    (proof, i_perm.aux_info)
}

/// Hash preimage IOP for audio (single channel version).
///
/// This is similar to the image version but handles a single audio channel.
pub fn audioHashPreimageIOP<F: PrimeField, E, PCS>(
    num_cols: usize,
    num_rows: usize,
    audio_evals: Vec<F>,
    max_val: u32,
    transcript: &mut IOPTranscript<E::ScalarField>,
    pcs_param: &PCS::ProverParam,
    ver_param: &PCS::VerifierParam,
) -> (
    VirtualPolynomial<F>,
    <PolyIOP<F> as SumCheck<F>>::SumCheckProof,
    VPAuxInfo<F>,
    <PolyIOP<E::ScalarField> as ProductCheck<E, PCS>>::ProductCheckProof,
    Arc<DenseMultilinearExtension<F>>,
    Arc<DenseMultilinearExtension<F>>,
    Arc<DenseMultilinearExtension<F>>,
    VPAuxInfo<F>,
)
where
    E: Pairing<ScalarField = F>,
    PCS: PolynomialCommitmentScheme<
        E,
        Polynomial = Arc<DenseMultilinearExtension<E::ScalarField>>,
        Point = Vec<F>,
        Evaluation = F,
    >,
{
    assert!(num_rows == 7, "num_rows must be exactly 7 (hash matrix has 128 = 2^7 rows)");

    use ark_std::rand::{SeedableRng, RngCore as R};
    use rand_chacha::ChaCha8Rng;

    // Initialize randomness matrix
    let mut matrix_a = Vec::new();
    for i in 0..128 {
        matrix_a.push(ChaCha8Rng::seed_from_u64(i));
    }

    // Create audio polynomial
    let audio_poly = vec_to_poly::<F>(audio_evals.clone()).0;

    // Get Frievald random vector
    let mut frievald_rand_vec = Vec::new();
    for _ in 0..(1 << num_rows) {
        let alpha = transcript.get_and_append_challenge(b"alpha").unwrap();
        frievald_rand_vec.push(alpha);
    }

    // Compute rT * A
    let mut rta = Vec::new();
    for _ in 0..(1 << num_cols) {
        let mut my_sum = F::zero();
        for j in 0..128 {
            my_sum += F::rand(&mut matrix_a[j]) * frievald_rand_vec[j];
        }
        rta.push(my_sum);
    }

    let (rta_poly, _) = vec_to_poly::<F>(rta);

    // Build virtual polynomial: rTA * audio
    let mut rhs = VirtualPolynomial::new_from_mle(&rta_poly, F::one());
    rhs.mul_by_mle(audio_poly.clone(), F::one());

    // Run sumcheck
    let proof = <PolyIOP<F> as SumCheck<F>>::prove(&rhs, transcript).unwrap();
    let poly_info = rhs.aux_info.clone();

    // Run range check on audio
    let (multset_proof, fx, gx, h, poly_info_prod) = range_checkProverIOP::<F, E, PCS>(
        num_cols,
        max_val,
        audio_poly.clone(),
        irredPolyTable[num_cols].try_into().unwrap(),
        irredPolyTable[num_cols + 1].try_into().unwrap(),
        transcript,
        pcs_param,
        ver_param,
    );

    (rhs, proof, poly_info, multset_proof, fx, gx, h, poly_info_prod)
}

/// Hash preimage IOP for stereo audio (two channels).
///
/// This handles both left and right channels.
pub fn stereoAudioHashPreimageIOP<F: PrimeField, E, PCS>(
    num_cols: usize,
    num_rows: usize,
    left_evals: Vec<F>,
    right_evals: Vec<F>,
    max_val: u32,
    transcript: &mut IOPTranscript<E::ScalarField>,
    pcs_param: &PCS::ProverParam,
    ver_param: &PCS::VerifierParam,
) -> (
    Vec<VirtualPolynomial<F>>,
    [<PolyIOP<F> as SumCheck<F>>::SumCheckProof; 2],
    [VPAuxInfo<F>; 2],
    Vec<<PolyIOP<E::ScalarField> as ProductCheck<E, PCS>>::ProductCheckProof>,
    Vec<Arc<DenseMultilinearExtension<F>>>,
    Vec<Arc<DenseMultilinearExtension<F>>>,
    Vec<Arc<DenseMultilinearExtension<F>>>,
    Vec<VPAuxInfo<F>>,
)
where
    E: Pairing<ScalarField = F>,
    PCS: PolynomialCommitmentScheme<
        E,
        Polynomial = Arc<DenseMultilinearExtension<E::ScalarField>>,
        Point = Vec<F>,
        Evaluation = F,
    >,
{
    assert!(num_rows == 7, "num_rows must be exactly 7 (hash matrix has 128 = 2^7 rows)");

    use ark_std::rand::{SeedableRng, RngCore as R};
    use rand_chacha::ChaCha8Rng;

    // Initialize randomness matrix
    let mut matrix_a = Vec::new();
    for i in 0..128 {
        matrix_a.push(ChaCha8Rng::seed_from_u64(i));
    }

    // Create audio polynomials
    let mut audio_polies: Vec<Arc<DenseMultilinearExtension<F>>> = Vec::new();
    audio_polies.push(vec_to_poly::<F>(left_evals.clone()).0);
    audio_polies.push(vec_to_poly::<F>(right_evals.clone()).0);

    // Get Frievald random vector
    let mut frievald_rand_vec = Vec::new();
    for _ in 0..(1 << num_rows) {
        let alpha = transcript.get_and_append_challenge(b"alpha").unwrap();
        frievald_rand_vec.push(alpha);
    }

    // Compute rT * A
    let mut rta = Vec::new();
    for _ in 0..(1 << num_cols) {
        let mut my_sum = F::zero();
        for j in 0..128 {
            my_sum += F::rand(&mut matrix_a[j]) * frievald_rand_vec[j];
        }
        rta.push(my_sum);
    }

    let (rta_poly, _) = vec_to_poly::<F>(rta);

    // Build virtual polynomials and run sumchecks
    let mut rhs_lr = Vec::new();
    for i in 0..2 {
        rhs_lr.push(VirtualPolynomial::new_from_mle(&rta_poly, F::one()));
        rhs_lr[i].mul_by_mle(audio_polies[i].clone(), F::one());
    }

    let proof_lr = [
        <PolyIOP<F> as SumCheck<F>>::prove(&rhs_lr[0], transcript).unwrap(),
        <PolyIOP<F> as SumCheck<F>>::prove(&rhs_lr[1], transcript).unwrap(),
    ];

    let poly_info_lr = [rhs_lr[0].aux_info.clone(), rhs_lr[1].aux_info.clone()];

    // Run range checks on both channels
    let (mut multset_proof_lr, mut fx_lr, mut gx_lr, mut h_lr, mut poly_info_prods) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());

    for i in 0..2 {
        let (multset_proof, fx, gx, h, poly_info_prod) = range_checkProverIOP::<F, E, PCS>(
            num_cols,
            max_val,
            audio_polies[i].clone(),
            irredPolyTable[num_cols].try_into().unwrap(),
            irredPolyTable[num_cols + 1].try_into().unwrap(),
            transcript,
            pcs_param,
            ver_param,
        );
        multset_proof_lr.push(multset_proof);
        fx_lr.push(fx);
        gx_lr.push(gx);
        h_lr.push(h);
        poly_info_prods.push(poly_info_prod);
    }

    (
        rhs_lr,
        proof_lr,
        poly_info_lr,
        multset_proof_lr,
        fx_lr,
        gx_lr,
        h_lr,
        poly_info_prods,
    )
}

pub fn main() {}
