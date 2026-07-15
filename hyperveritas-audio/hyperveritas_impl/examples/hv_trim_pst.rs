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

    let now = Instant::now();
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
        irredPolyTable[numCols+1].try_into().unwrap(),
        transcript,
        &pcs_param,
        &ver_param,
    );

    (RHS, proof, poly_info, multsetProof, fx, gx, h, poly_infoProd)
}

fn run_full_trim_pst(testSize: usize) {
    println!("\nstarting setup");

    let mut rng = test_rng();
    let numCols = testSize;
    let trimNumCols = testSize - 1;
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

    // Implement padding
    for _ in 0..(audioEvals.len().next_power_of_two() - audioEvals.len()) {
        audioEvals.push(F::zero());
    }

    // Hash computation (simulating camera/device hash)
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

    let now0 = Instant::now();
    let origAudio = load_audio(&fileName);
    let origAudioPoly = vec_to_poly(audio_to_field_vec::<F>(&origAudio.left, bitDepth)).0;

    let now2 = Instant::now();
    let origCom = PCS::commit(&pcs_param, &origAudioPoly).unwrap();
    let elapsed_time = now2.elapsed();

    let mut transcript =
        <PolyIOP<F> as ProductCheck<Bls12_381, MultilinearKzgPCS<Bls12_381>>>::init_transcript();
    let mut transcriptVerifier =
        <PolyIOP<F> as ProductCheck<Bls12_381, MultilinearKzgPCS<Bls12_381>>>::init_transcript();

    transcript.append_serializable_element(b"audio(x)", &origCom);
    transcriptVerifier.append_serializable_element(b"audio(x)", &origCom);

    // Time the IOP
    let now: Instant = Instant::now();
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
    let elapsed_time = now.elapsed();

    // TRIM TRANSFORMATION
    let now: Instant = Instant::now();

    let trimFileName = format!("audio/Trim{}.json", testSize);
    let trimAudio = load_audio(&trimFileName);

    let trimAudioPoly = vec_to_poly(audio_to_field_vec::<F>(&trimAudio.left, bitDepth)).0;

    // Trim parameters: first half of the audio
    let startSample = 0;
    let endSample = trimAudio.num_samples;

    let (transProof, poly_infoTrans) = trimProveAffineIOP::<F>(
        numCols,
        trimNumCols,
        origAudioPoly.clone(),
        startSample,
        endSample,
        &mut transcript,
    );

    let elapsed_time = now.elapsed();

    let mut polies = Vec::new();
    polies.push(origAudioPoly.clone());
    polies.push(h.clone());
    polies.push(prod_x.clone());
    polies.push(frac_x.clone());

    let mut coms = Vec::new();
    coms.push(origCom);

    let hCom = PCS::commit(&pcs_param, &h).unwrap();
    coms.push(hCom);
    coms.push(multsetProof.prod_x_comm);
    coms.push(multsetProof.frac_comm);
    transcript.append_serializable_element(b"hCom(x)", &hCom);

    let nowOpens = Instant::now();

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

    // Range check points
    let myRand = &multsetProof.zero_check_proof.point;
    let mut myRandSmall = Vec::new();
    for i in 0..myRand.len() - 1 {
        myRandSmall.push(myRand[i]);
    }
    points.push(myRandSmall.clone());

    let galoisRep = irredPolyTable[numCols + 1] - (1 << (numCols + 1));
    let (fiddle, zero, startVal) = galoisifyPt::<F>((numCols + 1) as u32, galoisRep, myRand.clone());

    points.push(fiddle);
    points.push(zero.clone());
    points.push(myRand.clone());

    let mut ptRand = Vec::new();
    ptRand.push(F::zero());
    for i in 0..myRand.len() - 1 {
        ptRand.push(myRand[i]);
    }
    points.push(ptRand.clone());
    ptRand[0] = F::one();
    points.push(ptRand.clone());

    // Transform point
    points.push(transProof.point.clone());

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

    // Transform point for audio
    evalPols.push(polies[0].clone());
    evalPoints.push(points[9].clone());
    evalVals.push(polies[0].evaluate(&points[9]).unwrap());
    evalComs.push(coms[0].clone());

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
    total_bls_elems += 2; // frac and prod commits
    let zero_pf = &multsetProof.zero_check_proof;
    total_256_elems += zero_pf.point.len();
    for pf in zero_pf.clone().proofs {
        total_256_elems += pf.evaluations.len();
    }
    total_256_elems += transProof.point.len();
    for pf in transProof.clone().proofs {
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

    let trimAudio = load_audio(&trimFileName);
    let trimAudioPoly = vec_to_poly(audio_to_field_vec::<F>(&trimAudio.left, bitDepth)).0;

    // Initialize verifier transcript
    let mut verTranscript =
        <PolyIOP<F> as ProductCheck<Bls12_381, MultilinearKzgPCS<Bls12_381>>>::init_transcript();
    verTranscript.append_serializable_element(b"audio(x)", &coms[0]);

    // Initialize randomness
    let mut matrixA = Vec::new();
    for i in 0..128 {
        matrixA.push(ChaCha8Rng::seed_from_u64(i));
    }

    // Collapse hash matrix
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

    // Expected sum value
    let mut expectedSumVal = F::zero();
    for j in 0..(1 << numRows) {
        expectedSumVal += frievaldRandVec[j] * testDigest[j];
    }

    // Verify sumcheck for hash
    let sumCheckForHash = <PolyIOP<F> as SumCheck<F>>::verify(expectedSumVal, &proof, &poly_info_matMult, &mut verTranscript).unwrap();

    // Range check verification
    let alpha1 = verTranscript.get_and_append_challenge(b"alpha").unwrap();
    let alpha2 = verTranscript.get_and_append_challenge(b"alpha").unwrap();
    let prodCheckSubclaim = <PolyIOP<F> as ProductCheck<Bls12_381, MultilinearKzgPCS<Bls12_381>>>::verify(&multsetProof, &poly_infoProd, &mut verTranscript).unwrap();

    // Verify transformation sumcheck
    // Note: frievald challenges obtained, then sumcheck verified, then hCom appended (matching prover order)
    let frievaldRandVecTrim = verTranscript.get_and_append_challenge_vectors(b"frievald", 1 << trimNumCols).unwrap();

    let mut expectedSumValTrim = F::zero();
    for j in 0..(1 << trimNumCols) {
        if j < trimAudioPoly.evaluations.len() {
            expectedSumValTrim += frievaldRandVecTrim[j] * trimAudioPoly.evaluations[j];
        }
    }

    let sumCheckForTrans = <PolyIOP<F> as SumCheck<F>>::verify(expectedSumValTrim, &transProof, &poly_infoTrans, &mut verTranscript).unwrap();

    // Append hCom after sumcheck verification (matching prover order)
    verTranscript.append_serializable_element(b"hCom(x)", &hCom);

    // Batch verify openings
    PCS::batch_verify(&ver_param, &evalComs, &evalPoints, &openProofs, &mut verTranscript).unwrap();
    PCS::batch_verify(&ver_param, &evalComsBig, &evalPointsBig, &openProofsBig, &mut verTranscript).unwrap();

    // Verify relationships
    let mut flag = true;
    let myZero = openProofs.f_i_eval_at_point_i[1] - openProofs.f_i_eval_at_point_i[1];
    let myOne = openProofs.f_i_eval_at_point_i[0] / openProofs.f_i_eval_at_point_i[0];

    // h(0) = 0
    flag = flag && (openProofsBig.f_i_eval_at_point_i[0] == myZero);
    // prod(1,..,1,0) = 1
    flag = flag && (openProofsBig.f_i_eval_at_point_i[4] == myOne);

    // Verify range check relationship
    let (rTAPoly, _) = vec_to_poly::<F>(rTA.clone());
    flag = flag && sumCheckForHash.expected_evaluation == rTAPoly.evaluate(&sumCheckForHash.point).unwrap() * openProofs.f_i_eval_at_point_i[0];

    // Verify transform
    let trimLength = endSample - startSample;
    let mut trimPerm = Vec::new();
    for _ in 0..(1 << numCols) {
        trimPerm.push(Vec::new());
    }
    for i in 0..trimLength {
        let origIdx = startSample + i;
        if origIdx < (1 << numCols) {
            trimPerm[origIdx].push((i, F::one()));
        }
    }
    let permTimesR: Vec<F> = matSparseMultVec::<F>(1 << numCols, 1 << trimNumCols, &trimPerm, &frievaldRandVecTrim);
    let (permTimesRPoly, _) = vec_to_poly::<F>(permTimesR.clone());
    flag = flag && sumCheckForTrans.expected_evaluation == permTimesRPoly.evaluate(&sumCheckForTrans.point).unwrap() * openProofs.f_i_eval_at_point_i[2];

    // Verify range check zero-check sub-claim (monster value)
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

    // prod(x) - v(x,0)*v(x,1)
    let mut firstHalf = prodAtAlphaRange;
    let myAlpha = myRand[myRand.len() - 1];
    let vX0 = myAlpha * prodAtAlphaRange0 + (F::one() - myAlpha) * fracAtAlphaRange0;
    let vX1 = myAlpha * prodAtAlphaRange1 + (F::one() - myAlpha) * fracAtAlphaRange1;
    firstHalf += -vX0 * vX1;

    // alpha0 + merge(I,T)(X) + alpha1 merge(I,T_{+1})(X)
    let mut f1 = alpha1 + ((F::one() - lastVal) * audioAtAlphaSmall + lastVal * polyTable.evaluate(&myRandSmall).unwrap());
    f1 += alpha2 * ((F::one() - lastVal) * audioAtAlphaSmall + lastVal * polyPlusOneTable.evaluate(&myRandSmall).unwrap());
    // alpha0 + h(X) + alpha1 h_{+1}(X)
    let f2 = alpha1 + hAtAlphaRange + alpha2 * (startVal * hAtAlphaRangeFiddle + (F::one() - startVal) * hAtAlphaRange0);
    let mut secondHalf = f2 * fracAtAlphaRange - f1;
    secondHalf = secondHalf * prodCheckSubclaim.alpha;

    let anticipatedVal = prodCheckSubclaim.zero_check_sub_claim.expected_evaluation;
    let finalVal = firstHalf + secondHalf;
    flag = flag && anticipatedVal == finalVal;

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
        println!("Full System Trim, HyperVerITAS PST. Size: 2^{:?}\n", i);
        let _res = run_full_trim_pst(i);
        println!("-----------------------------------------------------------------------");
    }
}
