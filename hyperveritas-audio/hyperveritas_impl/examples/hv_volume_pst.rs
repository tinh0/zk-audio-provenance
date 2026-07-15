#![allow(warnings)]
use std::ops::Add;
use ark_ec::pairing::Pairing;
use std::fmt::Debug;
use std::ops::Mul;
use ark_ff::MontBackend;
use ark_bls12_381::FrConfig;
use std::ops::AddAssign;

use core::num;
use std::{ops::Deref, primitive, str::FromStr, time::Instant};

use ark_bls12_381::{Bls12_381, Fq, Fr, G1Affine, G2Affine};
use ark_ff::{Field, Fp, Fp2, PrimeField, UniformRand, Zero};
use subroutines::{
    pcs::{
        self,
        prelude::{Commitment, MultilinearKzgPCS, PolynomialCommitmentScheme},
    },
    poly_iop::{
        prelude::{PermutationCheck, ProductCheck, SumCheck, ZeroCheck},
        PolyIOP,
    },
    BatchProof, MultilinearProverParam, PolyIOPErrors,
};

use arithmetic::{eq_eval, merge_polynomials, random_mle_list, VPAuxInfo, VirtualPolynomial};
pub use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use ark_std::{
    end_timer,
    rand::{self, RngCore},
    start_timer,
};
use proc_status::ProcStatus;
use std::{marker::PhantomData, sync::Arc};
use transcript::IOPTranscript;
use std::env;

use ark_bls12_381::Fr as F;
type PCS = MultilinearKzgPCS<Bls12_381>;
use ark_ff::One;
use ark_std::{rand::RngCore as R, test_rng};
use itertools::Itertools;
use hyperveritas_impl::{helper::*, audio::*, audio_prover::*, prover::*};

use rand::prelude::*;
use rand_chacha::ChaCha8Rng;

const irredPolyTable: &[u32] = &[
    0, 0, 7, 11, 19, 37, 67, 131, 285, 529, 1033, 2053, 4179, 8219, 16707, 32771, 69643, 131081,
    262273, 524327, 1048585, 2097157, 4194307, 8388641, 16777351, 33554441, 67108935,
];

fn hashPreimageIOPAudio<F: PrimeField, E, PCS>(
    numCols: usize,
    numRows: usize,
    audioEvals: Vec<F>,
    maxVal: u32,
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
    VPAuxInfo<F>
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
    let mut rng = test_rng();
    let mut matrixA = Vec::new();
    for i in 0..128 {
        matrixA.push(ChaCha8Rng::seed_from_u64(i));
    }

    let audioPoly = vec_to_poly::<F>(audioEvals.clone()).0;

    let mut frievaldRandVec = Vec::new();
    for _ in 0..(1 << numRows) {
        let alpha = transcript.get_and_append_challenge(b"alpha").unwrap();
        frievaldRandVec.push(alpha);
    }

    let mut rTA = Vec::new();
    for _ in 0..(1 << numCols) {
        let mut mySum = F::zero();
        for j in 0..128 {
            mySum += F::rand(&mut matrixA[j]) * frievaldRandVec[j];
        }
        rTA.push(mySum);
    }

    let (rTAPoly, _) = vec_to_poly::<F>(rTA.clone());

    let mut RHS = VirtualPolynomial::new_from_mle(&rTAPoly, F::one());
    RHS.mul_by_mle(audioPoly.clone(), F::one());

    let proof = <PolyIOP<F> as SumCheck<F>>::prove(&RHS, transcript).unwrap();
    let poly_info = RHS.aux_info.clone();

    let (multsetProof, fx, gx, h, poly_infoProd) = range_checkProverIOP::<F, E, PCS>(
        numCols,
        maxVal,
        audioPoly.clone(),
        irredPolyTable[numCols].try_into().unwrap(),
        irredPolyTable[numCols + 1].try_into().unwrap(),
        transcript,
        &pcs_param,
        &ver_param,
    );

    (RHS, proof, poly_info, multsetProof, fx, gx, h, poly_infoProd)
}

fn run_full_volume_pst(testSize: usize) {
    println!("\nstarting setup");

    let mut rng = test_rng();
    let numCols = testSize;
    let numRows = 7;
    let length = numCols + 1;

    let fileName = format!("audio/Audio{}.json", testSize);
    let srs = PCS::gen_srs_for_testing(&mut rng, length).unwrap();
    let (pcs_param, ver_param) = PCS::trim(&srs, None, Some(length)).unwrap();

    // Load audio
    let origAudio = load_audio(&fileName);
    let bitDepth = origAudio.bit_depth;
    let maxVal = get_audio_max_val(bitDepth);

    // Range check requires polynomial size > maxVal, so testSize >= ceil(log2(maxVal+1))
    let minSize = ((maxVal + 1) as f64).log2().ceil() as usize;
    if testSize < minSize {
        panic!(
            "Test size {} is too small for {}-bit audio (maxVal={}). Minimum size required: {}",
            testSize, bitDepth, maxVal, minSize
        );
    }

    let mut audioEvals = audio_to_field_vec::<F>(&origAudio.left, bitDepth);

    // Padding
    for _ in 0..(audioEvals.len().next_power_of_two() - audioEvals.len()) {
        audioEvals.push(F::zero());
    }

    // Hash computation
    let mut testDigest = Vec::new();
    let mut matrixA = Vec::new();
    for i in 0..128 {
        matrixA.push(ChaCha8Rng::seed_from_u64(i));
    }
    for i in 0..128 {
        let mut mySum = F::zero();
        for j in 0..(1 << numCols) {
            mySum += F::rand(&mut matrixA[i]) * audioEvals[j];
        }
        testDigest.push(mySum);
    }

    println!("setup done!\n");

    println!("starting prover");

    // Volume scaling parameters: 50% volume (numerator=1, denominator=2)
    let numerator: u64 = 1;
    let denominator: u64 = 2;

    let now0 = Instant::now();
    let origAudio = load_audio(&fileName);
    let origAudioPoly = vec_to_poly(audio_to_field_vec::<F>(&origAudio.left, bitDepth)).0;

    let origCom = PCS::commit(&pcs_param, &origAudioPoly).unwrap();

    let mut transcript =
        <PolyIOP<F> as ProductCheck<Bls12_381, MultilinearKzgPCS<Bls12_381>>>::init_transcript();

    transcript.append_serializable_element(b"audio(x)", &origCom);

    let (RHS, proof, poly_info_matMult, multsetProof, prod_x, frac_x, h, poly_infoProd) =
        hashPreimageIOPAudio::<F, Bls12_381, MultilinearKzgPCS<Bls12_381>>(
            numCols,
            numRows,
            audioEvals,
            maxVal,
            &mut transcript,
            &pcs_param,
            &ver_param,
        );

    // VOLUME SCALING TRANSFORMATION
    let volumeFileName = format!("audio/Volume{}.json", testSize);
    let volumeAudio = load_audio(&volumeFileName);

    let volumeAudioPoly = vec_to_poly(audio_to_field_vec::<F>(&volumeAudio.left, bitDepth)).0;

    // Compute volume error: num*original - denom*scaled + offset_adjustment should be in [0, denom)
    // Since scaled = floor(original * num / denom), error is the remainder
    // For signed audio with offset conversion, we need to adjust for the offset:
    //   error = num * original_f - denom * scaled_f + (denom - num) * offset
    let denom_f = F::from(denominator);
    let num_f = F::from(numerator);

    // Get the offset used for signed-to-unsigned conversion
    let offset: u64 = match bitDepth {
        8 => 0,      // 8-bit is already unsigned
        16 => 32768,
        24 => 8388608,
        _ => panic!("Unsupported bit depth"),
    };
    let offset_adjustment = (denom_f - num_f) * F::from(offset);

    let mut volumeError = Vec::new();
    for i in 0..(1 << numCols) {
        let origVal = if i < origAudioPoly.evaluations.len() {
            origAudioPoly.evaluations[i]
        } else {
            F::zero()
        };
        let scaledVal = if i < volumeAudioPoly.evaluations.len() {
            volumeAudioPoly.evaluations[i]
        } else {
            F::zero()
        };
        volumeError.push(num_f * origVal - denom_f * scaledVal + offset_adjustment);
    }

    let (volumeErrPoly, _) = vec_to_poly(volumeError);

    // Collect polynomials
    let mut polies = Vec::new();
    polies.push(origAudioPoly.clone());
    polies.push(h.clone());
    polies.push(prod_x.clone());
    polies.push(frac_x.clone());

    // Collect commitments
    let mut coms = Vec::new();
    coms.push(origCom);

    let hCom = PCS::commit(&pcs_param, &h).unwrap();
    coms.push(hCom);
    coms.push(multsetProof.prod_x_comm);
    coms.push(multsetProof.frac_comm);
    transcript.append_serializable_element(b"hCom(x)", &hCom);

    // Volume error commitment
    let volumeErrCom = PCS::commit(&pcs_param, &volumeErrPoly).unwrap();
    transcript.append_serializable_element(b"volumeErr(x)", &volumeErrCom);

    // Range check for volume error (maxVal = denominator - 1)
    let (multsetProofVol, fxVol, gxVol, hVol, auxVol) = range_checkProverIOP::<F, Bls12_381, MultilinearKzgPCS<Bls12_381>>(
        numCols,
        (denominator - 1) as u32,
        volumeErrPoly.clone(),
        irredPolyTable[numCols].try_into().unwrap(),
        irredPolyTable[numCols + 1].try_into().unwrap(),
        &mut transcript,
        &pcs_param,
        &ver_param,
    );

    polies.push(volumeErrPoly.clone());
    polies.push(hVol.clone());
    polies.push(fxVol.clone());
    polies.push(gxVol.clone());

    coms.push(volumeErrCom);
    let hVolCom = PCS::commit(&pcs_param, &hVol).unwrap();
    coms.push(hVolCom);
    coms.push(multsetProofVol.prod_x_comm);
    coms.push(multsetProofVol.frac_comm);

    transcript.append_serializable_element(b"hVolCom(x)", &hVolCom);

    // Build evaluation points
    let mut points = Vec::new();

    // Hash preimage point
    points.push(proof.point.clone());
    // 0 vector for h
    points.push(vec![F::zero(); numCols + 1]);
    // 1..10 vector for prod
    let mut final_query = vec![F::one(); numCols + 1];
    final_query[0] = F::zero();
    points.push(final_query);

    // Range check points for original audio
    let myRand = &multsetProof.zero_check_proof.point;
    let mut myRandSmall = Vec::new();
    for i in 0..myRand.len() - 1 {
        myRandSmall.push(myRand[i]);
    }
    points.push(myRandSmall.clone());

    let galoisRep = irredPolyTable[numCols + 1] - (1 << (numCols + 1));
    let (fiddle, zero, _startVal) = galoisifyPt::<F>((numCols + 1) as u32, galoisRep, myRand.clone());

    points.push(fiddle);
    points.push(zero);
    points.push(myRand.clone());

    let mut ptRand = Vec::new();
    ptRand.push(F::zero());
    for i in 0..myRand.len() - 1 {
        ptRand.push(myRand[i]);
    }
    points.push(ptRand.clone());
    ptRand[0] = F::one();
    points.push(ptRand.clone());

    // Transform point for volume
    let volumeTransformPt = transcript.get_and_append_challenge_vectors(b"alpha", numCols).unwrap();
    points.push(volumeTransformPt.clone());

    // Range check points for volume error
    let myRandVol = &multsetProofVol.zero_check_proof.point;
    let mut myRandSmallVol = Vec::new();
    for i in 0..myRandVol.len() - 1 {
        myRandSmallVol.push(myRandVol[i]);
    }
    points.push(myRandSmallVol.clone());

    let galoisRep = irredPolyTable[numCols + 1] - (1 << (numCols + 1));
    let (fiddleVol, zeroVol, _startValVol) = galoisifyPt::<F>((numCols + 1) as u32, galoisRep, myRandVol.clone());

    points.push(fiddleVol);
    points.push(zeroVol);
    points.push(myRandVol.clone());

    let mut ptRandVol = Vec::new();
    ptRandVol.push(F::zero());
    for i in 0..myRandVol.len() - 1 {
        ptRandVol.push(myRandVol[i]);
    }
    points.push(ptRandVol.clone());
    ptRandVol[0] = F::one();
    points.push(ptRandVol.clone());

    // Build evaluation lists
    let mut evalPols = Vec::new();
    let mut evalPoints: Vec<Vec<F>> = Vec::new();
    let mut evalVals = Vec::new();
    let mut evalComs = Vec::new();
    let mut evalPolsBig = Vec::new();
    let mut evalPointsBig: Vec<Vec<F>> = Vec::new();
    let mut evalValsBig = Vec::new();
    let mut evalComsBig = Vec::new();

    // Hash preimage opening
    evalPols.push(polies[0].clone());
    evalPoints.push(points[0].clone());
    evalVals.push(polies[0].evaluate(&points[0]).unwrap());
    evalComs.push(coms[0].clone());

    // Alpha_range for audio
    evalPols.push(polies[0].clone());
    evalPoints.push(points[3].clone());
    evalVals.push(polies[0].evaluate(&points[3]).unwrap());
    evalComs.push(coms[0].clone());

    // h(0) = 0
    evalPolsBig.push(polies[1].clone());
    evalPointsBig.push(points[1].clone());
    evalValsBig.push(F::zero());
    evalComsBig.push(coms[1].clone());

    // h at alpha_range
    evalPolsBig.push(polies[1].clone());
    evalPointsBig.push(points[6].clone());
    evalValsBig.push(polies[1].evaluate(&points[6]).unwrap());
    evalComsBig.push(coms[1].clone());

    // h at fiddle
    evalPolsBig.push(polies[1].clone());
    evalPointsBig.push(points[4].clone());
    evalValsBig.push(polies[1].evaluate(&points[4]).unwrap());
    evalComsBig.push(coms[1].clone());

    // h at zero
    evalPolsBig.push(polies[1].clone());
    evalPointsBig.push(points[5].clone());
    evalValsBig.push(polies[1].evaluate(&points[5]).unwrap());
    evalComsBig.push(coms[1].clone());

    // prod at 1..10
    evalPolsBig.push(polies[2].clone());
    evalPointsBig.push(points[2].clone());
    evalValsBig.push(F::one());
    evalComsBig.push(coms[2].clone());

    // prod at alpha_range
    evalPolsBig.push(polies[2].clone());
    evalPointsBig.push(points[6].clone());
    evalValsBig.push(polies[2].evaluate(&points[6]).unwrap());
    evalComsBig.push(coms[2].clone());

    // frac at alpha_range
    evalPolsBig.push(polies[3].clone());
    evalPointsBig.push(points[6].clone());
    evalValsBig.push(polies[3].evaluate(&points[6]).unwrap());
    evalComsBig.push(coms[3].clone());

    // prod at alpha_range||0
    evalPolsBig.push(polies[2].clone());
    evalPointsBig.push(points[7].clone());
    evalValsBig.push(polies[2].evaluate(&points[7]).unwrap());
    evalComsBig.push(coms[2].clone());

    // frac at alpha_range||0
    evalPolsBig.push(polies[3].clone());
    evalPointsBig.push(points[7].clone());
    evalValsBig.push(polies[3].evaluate(&points[7]).unwrap());
    evalComsBig.push(coms[3].clone());

    // prod at alpha_range||1
    evalPolsBig.push(polies[2].clone());
    evalPointsBig.push(points[8].clone());
    evalValsBig.push(polies[2].evaluate(&points[8]).unwrap());
    evalComsBig.push(coms[2].clone());

    // frac at alpha_range||1
    evalPolsBig.push(polies[3].clone());
    evalPointsBig.push(points[8].clone());
    evalValsBig.push(polies[3].evaluate(&points[8]).unwrap());
    evalComsBig.push(coms[3].clone());

    // Transform point for original audio
    evalPols.push(polies[0].clone());
    evalPoints.push(points[9].clone());
    evalVals.push(polies[0].evaluate(&points[9]).unwrap());
    evalComs.push(coms[0].clone());

    // Volume error at transform point
    let polIndex = 4; // volumeErrPoly
    evalPols.push(polies[polIndex].clone());
    evalPoints.push(points[9].clone());
    evalVals.push(polies[polIndex].evaluate(&points[9]).unwrap());
    evalComs.push(coms[polIndex].clone());

    // Volume error at alpha_range small point for range check monster value
    let polIndex = 4; // volumeErrPoly
    evalPols.push(polies[polIndex].clone());
    evalPoints.push(points[10].clone());
    evalVals.push(polies[polIndex].evaluate(&points[10]).unwrap());
    evalComs.push(coms[polIndex].clone());

    // Volume error range check
    let polIndex = 5; // hVol
    evalPolsBig.push(polies[polIndex].clone());
    evalPointsBig.push(points[1].clone()); // 0 vector
    evalValsBig.push(F::zero());
    evalComsBig.push(coms[polIndex].clone());

    // hVol at alpha_range for volume
    evalPolsBig.push(polies[polIndex].clone());
    evalPointsBig.push(points[13].clone());
    evalValsBig.push(polies[polIndex].evaluate(&points[13]).unwrap());
    evalComsBig.push(coms[polIndex].clone());

    // hVol at fiddle for volume
    evalPolsBig.push(polies[polIndex].clone());
    evalPointsBig.push(points[11].clone());
    evalValsBig.push(polies[polIndex].evaluate(&points[11]).unwrap());
    evalComsBig.push(coms[polIndex].clone());

    // hVol at zero for volume
    evalPolsBig.push(polies[polIndex].clone());
    evalPointsBig.push(points[12].clone());
    evalValsBig.push(polies[polIndex].evaluate(&points[12]).unwrap());
    evalComsBig.push(coms[polIndex].clone());

    // prod at 1..10 for volume
    let polIndex = 6; // fxVol (prod)
    evalPolsBig.push(polies[polIndex].clone());
    evalPointsBig.push(points[2].clone());
    evalValsBig.push(F::one());
    evalComsBig.push(coms[polIndex].clone());

    // prod at alpha_range for volume
    evalPolsBig.push(polies[polIndex].clone());
    evalPointsBig.push(points[13].clone());
    evalValsBig.push(polies[polIndex].evaluate(&points[13]).unwrap());
    evalComsBig.push(coms[polIndex].clone());

    // frac at alpha_range for volume
    let polIndex = 7; // gxVol (frac)
    evalPolsBig.push(polies[polIndex].clone());
    evalPointsBig.push(points[13].clone());
    evalValsBig.push(polies[polIndex].evaluate(&points[13]).unwrap());
    evalComsBig.push(coms[polIndex].clone());

    // prod at alpha_range||0 for volume
    let polIndex = 6;
    evalPolsBig.push(polies[polIndex].clone());
    evalPointsBig.push(points[14].clone());
    evalValsBig.push(polies[polIndex].evaluate(&points[14]).unwrap());
    evalComsBig.push(coms[polIndex].clone());

    // frac at alpha_range||0 for volume
    let polIndex = 7;
    evalPolsBig.push(polies[polIndex].clone());
    evalPointsBig.push(points[14].clone());
    evalValsBig.push(polies[polIndex].evaluate(&points[14]).unwrap());
    evalComsBig.push(coms[polIndex].clone());

    // prod at alpha_range||1 for volume
    let polIndex = 6;
    evalPolsBig.push(polies[polIndex].clone());
    evalPointsBig.push(points[15].clone());
    evalValsBig.push(polies[polIndex].evaluate(&points[15]).unwrap());
    evalComsBig.push(coms[polIndex].clone());

    // frac at alpha_range||1 for volume
    let polIndex = 7;
    evalPolsBig.push(polies[polIndex].clone());
    evalPointsBig.push(points[15].clone());
    evalValsBig.push(polies[polIndex].evaluate(&points[15]).unwrap());
    evalComsBig.push(coms[polIndex].clone());

    let openProofs = PCS::multi_open(&pcs_param, &evalPols, &evalPoints, &evalVals, &mut transcript).unwrap();
    let openProofsBig = PCS::multi_open(&pcs_param, &evalPolsBig, &evalPointsBig, &evalValsBig, &mut transcript).unwrap();

    let elapsed_time = now0.elapsed();
    println!("PROVER TIME: {:?} seconds\n", elapsed_time.as_millis() as f64 / 1000 as f64);

    // Compute proof size
    let mut total_bls_elems = 0;
    let mut total_256_elems = 0;
    let mut total_scalar_field_elems = 0;

    total_bls_elems += coms.len();
    total_256_elems += testDigest.len();
    total_256_elems += proof.point.len();
    for pf in proof.clone().proofs {
        total_256_elems += pf.evaluations.len();
    }
    // Original range check
    total_bls_elems += 2;
    let zero_pf = &multsetProof.zero_check_proof;
    total_256_elems += zero_pf.point.len();
    for pf in zero_pf.clone().proofs {
        total_256_elems += pf.evaluations.len();
    }
    // Volume range check
    total_bls_elems += 2;
    let zero_pf = &multsetProofVol.zero_check_proof;
    total_256_elems += zero_pf.point.len();
    for pf in zero_pf.clone().proofs {
        total_256_elems += pf.evaluations.len();
    }
    total_256_elems += evalVals.len();
    total_256_elems += evalValsBig.len();
    total_scalar_field_elems += openProofs.f_i_eval_at_point_i.len();
    total_bls_elems += openProofs.g_prime_proof.proofs.len();
    total_scalar_field_elems += openProofs.sum_check_proof.point.len();
    for p_msg in &openProofs.sum_check_proof.proofs {
        total_scalar_field_elems += p_msg.evaluations.len();
    }
    total_scalar_field_elems += openProofsBig.f_i_eval_at_point_i.len();
    total_bls_elems += openProofsBig.g_prime_proof.proofs.len();
    total_scalar_field_elems += openProofsBig.sum_check_proof.point.len();
    for p_msg in &openProofsBig.sum_check_proof.proofs {
        total_scalar_field_elems += p_msg.evaluations.len();
    }

    let total_bls_bytes = total_bls_elems * 48;
    let total_256_bytes = total_256_elems * 32;
    let total_scalar_bytes = total_scalar_field_elems * 32;
    let total_bytes = total_bls_bytes + total_256_bytes + total_scalar_bytes;

    println!("PROOF SIZE: {:?} bytes", total_bytes);

    // VERIFIER
    println!("\nstarting verifier");
    let now_ver = Instant::now();

    let volumeAudio = load_audio(&volumeFileName);
    let volumeAudioPoly = vec_to_poly(audio_to_field_vec::<F>(&volumeAudio.left, bitDepth)).0;

    // Initialize verifier transcript
    let mut verTranscript =
        <PolyIOP<F> as ProductCheck<Bls12_381, MultilinearKzgPCS<Bls12_381>>>::init_transcript();
    verTranscript.append_serializable_element(b"audio(x)", &coms[0]);

    let mut matrixA = Vec::new();
    for i in 0..128 {
        matrixA.push(ChaCha8Rng::seed_from_u64(i));
    }

    let mut frievaldRandVec = Vec::new();
    for _ in 0..(1 << numRows) {
        let alpha = verTranscript.get_and_append_challenge(b"alpha").unwrap();
        frievaldRandVec.push(alpha);
    }

    let mut rTA = Vec::new();
    for _ in 0..(1 << numCols) {
        let mut mySum = F::zero();
        for j in 0..128 {
            mySum += F::rand(&mut matrixA[j]) * frievaldRandVec[j];
        }
        rTA.push(mySum);
    }

    let mut expectedSumVal = F::zero();
    for j in 0..(1 << numRows) {
        expectedSumVal += frievaldRandVec[j] * testDigest[j];
    }

    let sumCheckForHash = <PolyIOP<F> as SumCheck<F>>::verify(expectedSumVal, &proof, &poly_info_matMult, &mut verTranscript).unwrap();

    let alpha1 = verTranscript.get_and_append_challenge(b"alpha").unwrap();
    let alpha2 = verTranscript.get_and_append_challenge(b"alpha").unwrap();
    let prodCheckSubclaim = <PolyIOP<F> as ProductCheck<Bls12_381, MultilinearKzgPCS<Bls12_381>>>::verify(&multsetProof, &poly_infoProd, &mut verTranscript).unwrap();

    verTranscript.append_serializable_element(b"hCom(x)", &hCom);
    verTranscript.append_serializable_element(b"volumeErr(x)", &volumeErrCom);

    let alpha1Vol = verTranscript.get_and_append_challenge(b"alpha").unwrap();
    let alpha2Vol = verTranscript.get_and_append_challenge(b"alpha").unwrap();
    let prodCheckSubclaimVol = <PolyIOP<F> as ProductCheck<Bls12_381, MultilinearKzgPCS<Bls12_381>>>::verify(&multsetProofVol, &auxVol, &mut verTranscript).unwrap();

    verTranscript.append_serializable_element(b"hVolCom(x)", &hVolCom);

    let volumeTransformPt = verTranscript.get_and_append_challenge_vectors(b"alpha", numCols).unwrap();

    // Batch verify
    PCS::batch_verify(&ver_param, &evalComs, &evalPoints, &openProofs, &mut verTranscript).unwrap();
    PCS::batch_verify(&ver_param, &evalComsBig, &evalPointsBig, &openProofsBig, &mut verTranscript).unwrap();

    let mut flag = true;
    let myZero = openProofs.f_i_eval_at_point_i[0] - openProofs.f_i_eval_at_point_i[0];
    let myOne = openProofs.f_i_eval_at_point_i[0] / openProofs.f_i_eval_at_point_i[0];

    // Verify volume scaling: num*original + (denom-num)*offset = denom*scaled + error
    let origAtPt = openProofs.f_i_eval_at_point_i[2]; // original at transform point
    let errAtPt = openProofs.f_i_eval_at_point_i[3]; // error at transform point

    let scaledAtPt = volumeAudioPoly.evaluate(&volumeTransformPt).unwrap();
    let denom_f = F::from(denominator);
    let num_f = F::from(numerator);

    let offset: u64 = match bitDepth {
        8 => 0,
        16 => 32768,
        24 => 8388608,
        _ => panic!("Unsupported bit depth"),
    };
    let offset_adjustment = (denom_f - num_f) * F::from(offset);

    let expectedLHS = num_f * origAtPt + offset_adjustment;
    let computedRHS = denom_f * scaledAtPt + errAtPt;
    flag = flag && (expectedLHS == computedRHS);

    // Verify hash preimage sumcheck final evaluation
    let (rTAPoly, _) = vec_to_poly::<F>(rTA.clone());
    flag = flag && sumCheckForHash.expected_evaluation == rTAPoly.evaluate(&sumCheckForHash.point).unwrap() * openProofs.f_i_eval_at_point_i[0];

    // FOR RANGE CHECK: h(0) = 0 for original audio
    flag = flag && (openProofsBig.f_i_eval_at_point_i[0] == myZero);
    // FOR PRODUCT CHECK: prod(1,..,1,0) = 1 for original audio
    flag = flag && (openProofsBig.f_i_eval_at_point_i[4] == myOne);

    // Build embedded table for original audio range check
    let primPolyForT = irredPolyTable[numCols] as u64;
    let mut embeddedTable: Vec<F> = vec![F::zero(); 1 << numCols];
    let mut plusOneTable: Vec<F> = vec![F::zero(); 1 << numCols];
    let galoisRepTable = primPolyForT - (1 << numCols);
    let size: u64 = 1 << numCols;
    let mut binaryString: u64 = 1;
    for i in 1..(maxVal as usize + 1) {
        embeddedTable[binaryString as usize] =
            F::from_le_bytes_mod_order(&transform_u32_to_array_of_u8(i as u32));
        binaryString <<= 1;
        if binaryString & size != 0 {
            binaryString ^= galoisRepTable;
        }
        binaryString = (size - 1) & binaryString;
        plusOneTable[binaryString as usize] =
            F::from_le_bytes_mod_order(&transform_u32_to_array_of_u8(i as u32));
    }
    let polyTable = DenseMultilinearExtension::from_evaluations_vec(numCols, embeddedTable);
    let polyPlusOneTable = DenseMultilinearExtension::from_evaluations_vec(numCols, plusOneTable);

    // Monster value for original audio range check
    {
        let myRand = &multsetProof.zero_check_proof.point;
        let galoisRepRange = irredPolyTable[numCols + 1] - (1 << (numCols + 1));
        let (_, _, startVal) = galoisifyPt::<F>((numCols + 1) as u32, galoisRepRange, myRand.clone());

        let mut myRandSmall = Vec::new();
        for j in 0..myRand.len() - 1 {
            myRandSmall.push(myRand[j]);
        }
        let lastVal = myRand[myRand.len() - 1];

        let audioAtAlphaSmall = openProofs.f_i_eval_at_point_i[1];
        let hAtAlphaRange = openProofsBig.f_i_eval_at_point_i[1];
        let hAtAlphaRangeFiddle = openProofsBig.f_i_eval_at_point_i[2];
        let hAtAlphaRange0 = openProofsBig.f_i_eval_at_point_i[3];
        let prodAtAlphaRange = openProofsBig.f_i_eval_at_point_i[5];
        let fracAtAlphaRange = openProofsBig.f_i_eval_at_point_i[6];
        let prodAtAlphaRange0 = openProofsBig.f_i_eval_at_point_i[7];
        let fracAtAlphaRange0 = openProofsBig.f_i_eval_at_point_i[8];
        let prodAtAlphaRange1 = openProofsBig.f_i_eval_at_point_i[9];
        let fracAtAlphaRange1 = openProofsBig.f_i_eval_at_point_i[10];

        let mut firstHalf = prodAtAlphaRange;
        let myAlpha = myRand[myRand.len() - 1];
        let vX0 = myAlpha * prodAtAlphaRange0 + (F::one() - myAlpha) * fracAtAlphaRange0;
        let vX1 = myAlpha * prodAtAlphaRange1 + (F::one() - myAlpha) * fracAtAlphaRange1;
        firstHalf += -vX0 * vX1;

        let mut f1 = alpha1 + ((F::one() - lastVal) * audioAtAlphaSmall + lastVal * polyTable.evaluate(&myRandSmall).unwrap());
        f1 += alpha2 * ((F::one() - lastVal) * audioAtAlphaSmall + lastVal * polyPlusOneTable.evaluate(&myRandSmall).unwrap());

        let f2 = alpha1 + hAtAlphaRange + alpha2 * (startVal * hAtAlphaRangeFiddle + (F::one() - startVal) * hAtAlphaRange0);
        let mut secondHalf = f2 * fracAtAlphaRange - f1;
        secondHalf = secondHalf * prodCheckSubclaim.alpha;

        let anticipatedVal = prodCheckSubclaim.zero_check_sub_claim.expected_evaluation;
        let finalVal = firstHalf + secondHalf;
        flag = flag && anticipatedVal == finalVal;
    }

    // Volume error range check verification
    // h(0) = 0 for volume error
    flag = flag && (openProofsBig.f_i_eval_at_point_i[11] == myZero);
    // prod(1,..,1,0) = 1 for volume error
    flag = flag && (openProofsBig.f_i_eval_at_point_i[15] == myOne);

    // Build table for volume error (maxVal = denominator - 1)
    let maxValVol: u32 = (denominator - 1) as u32;
    let mut embeddedTableVol: Vec<F> = vec![F::zero(); 1 << numCols];
    let mut plusOneTableVol: Vec<F> = vec![F::zero(); 1 << numCols];
    let mut binaryStringVol: u64 = 1;
    for i in 1..(maxValVol as usize + 1) {
        embeddedTableVol[binaryStringVol as usize] =
            F::from_le_bytes_mod_order(&transform_u32_to_array_of_u8(i as u32));
        binaryStringVol <<= 1;
        if binaryStringVol & size != 0 {
            binaryStringVol ^= galoisRepTable;
        }
        binaryStringVol = (size - 1) & binaryStringVol;
        plusOneTableVol[binaryStringVol as usize] =
            F::from_le_bytes_mod_order(&transform_u32_to_array_of_u8(i as u32));
    }
    let polyTableVol = DenseMultilinearExtension::from_evaluations_vec(numCols, embeddedTableVol);
    let polyPlusOneTableVol = DenseMultilinearExtension::from_evaluations_vec(numCols, plusOneTableVol);

    // Monster value for volume error range check
    {
        let myRand = &multsetProofVol.zero_check_proof.point;
        let galoisRepRange = irredPolyTable[numCols + 1] - (1 << (numCols + 1));
        let (_, _, startValVol) = galoisifyPt::<F>((numCols + 1) as u32, galoisRepRange, myRand.clone());

        let mut myRandSmall = Vec::new();
        for j in 0..myRand.len() - 1 {
            myRandSmall.push(myRand[j]);
        }
        let lastVal = myRand[myRand.len() - 1];

        let errAtAlphaSmall = openProofs.f_i_eval_at_point_i[4]; // volumeErr at alpha_range_small
        let hAtAlphaRange = openProofsBig.f_i_eval_at_point_i[12];
        let hAtAlphaRangeFiddle = openProofsBig.f_i_eval_at_point_i[13];
        let hAtAlphaRange0 = openProofsBig.f_i_eval_at_point_i[14];
        let prodAtAlphaRange = openProofsBig.f_i_eval_at_point_i[16];
        let fracAtAlphaRange = openProofsBig.f_i_eval_at_point_i[17];
        let prodAtAlphaRange0 = openProofsBig.f_i_eval_at_point_i[18];
        let fracAtAlphaRange0 = openProofsBig.f_i_eval_at_point_i[19];
        let prodAtAlphaRange1 = openProofsBig.f_i_eval_at_point_i[20];
        let fracAtAlphaRange1 = openProofsBig.f_i_eval_at_point_i[21];

        let mut firstHalf = prodAtAlphaRange;
        let myAlpha = myRand[myRand.len() - 1];
        let vX0 = myAlpha * prodAtAlphaRange0 + (F::one() - myAlpha) * fracAtAlphaRange0;
        let vX1 = myAlpha * prodAtAlphaRange1 + (F::one() - myAlpha) * fracAtAlphaRange1;
        firstHalf += -vX0 * vX1;

        let mut f1 = alpha1Vol + ((F::one() - lastVal) * errAtAlphaSmall + lastVal * polyTableVol.evaluate(&myRandSmall).unwrap());
        f1 += alpha2Vol * ((F::one() - lastVal) * errAtAlphaSmall + lastVal * polyPlusOneTableVol.evaluate(&myRandSmall).unwrap());

        let f2 = alpha1Vol + hAtAlphaRange + alpha2Vol * (startValVol * hAtAlphaRangeFiddle + (F::one() - startValVol) * hAtAlphaRange0);
        let mut secondHalf = f2 * fracAtAlphaRange - f1;
        secondHalf = secondHalf * prodCheckSubclaimVol.alpha;

        let anticipatedVal = prodCheckSubclaimVol.zero_check_sub_claim.expected_evaluation;
        let finalVal = firstHalf + secondHalf;
        flag = flag && anticipatedVal == finalVal;
    }

    println!("Verifier passed!: {:?}", flag);
    println!("verifier done!\n");

    let elapsed_ver = now_ver.elapsed();
    println!("VERIFIER TIME: {:?} seconds", elapsed_ver.as_millis() as f64 / 1000 as f64);
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let first_size = args[1].parse::<usize>().unwrap();
    let mut last_size = first_size;
    if args.len() == 3 {
        last_size = args[2].parse::<usize>().unwrap();
    }

    for i in first_size..last_size + 1 {
        println!("-----------------------------------------------------------------------");
        println!("Full System Volume Scaling (50%), HyperVerITAS PST. Size: 2^{:?}\n", i);
        let _res = run_full_volume_pst(i);
        println!("-----------------------------------------------------------------------");
    }
}
