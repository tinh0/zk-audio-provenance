#![allow(warnings)]

mod iop_brakedown;
use iop_brakedown::*;

use core::num;
use proc_status::ProcStatus;
use arithmetic::bit_decompose;
use transcript::IOPTranscript;
use std::{marker::PhantomData, sync::Arc, ops::{Range, Deref}, primitive, str::FromStr, time::Instant, env, array, iter};
use std::fs;
use std::path::Path;

use ark_ec::pairing::prepare_g1;
use ark_std::{rand::{RngCore as R, rngs::{OsRng, StdRng}, CryptoRng, RngCore, SeedableRng}, test_rng, };

use rand_chacha::ChaCha8Rng;

use hyperveritas_impl::{types::*, helper::*, audio::*};

use plonkish_backend::{
    pcs::{
        Evaluation, PolynomialCommitmentScheme,
        multilinear::{MultilinearBrakedown, MultilinearBrakedownCommitment, additive::{batch_open_one, batch_verify_one},},
    },
    poly::{
        Polynomial,
        multilinear::{rotation_eval, MultilinearPolynomial}
    },
    piop::sum_check::{
        evaluate, SumCheck, VirtualPolynomial,
        classic::{ClassicSumCheck, ClassicSumCheckProver, EvaluationsProver},
    },
    util::{
        Itertools,
        hash::Blake2s,
        new_fields::Mersenne127 as F,
        code::{Brakedown, BrakedownSpec3, BrakedownSpec6},
        expression::{CommonPolynomial, Expression, Query, Rotation},
        arithmetic::{BatchInvert, BooleanHypercube, Field as myField},
        transcript::{Blake2sTranscript, FiatShamirTranscript, FieldTranscript, FieldTranscriptRead, FieldTranscriptWrite, InMemoryTranscript, TranscriptWrite},
    },
};


type Pcs = MultilinearBrakedown<F, Blake2s, BrakedownSpec6>;
type VT = FiatShamirTranscript<Blake2s, std::io::Cursor<Vec<u8>>>;


const irredPolyTable: &[u32] = &[
    0, 0, 7, 11, 19, 37, 67, 131, 285, 529, 1033, 2053, 4179, 8219, 16707, 32771, 69643, 131081,
    262273, 524327, 1048585, 2097157, 4194307, 8388641, 16777351, 33554441, 67108935,
];

/// Convert audio samples to field elements for Brakedown (Mersenne127 field)
fn audio_to_brakedown_field(samples: &[i32], bit_depth: u8) -> Vec<F> {
    let offset: i64 = match bit_depth {
        8 => 0,
        16 => 32768,
        24 => 8388608,
        _ => panic!("Unsupported bit depth: {}", bit_depth),
    };
    samples.iter()
        .map(|&s| F::from((s as i64 + offset) as u64))
        .collect()
}

/// Get offset for signed-to-unsigned conversion
fn get_offset(bit_depth: u8) -> u64 {
    match bit_depth {
        8 => 0,
        16 => 32768,
        24 => 8388608,
        _ => panic!("Unsupported bit depth: {}", bit_depth),
    }
}

/// Get max value for audio bit depth
fn get_max_val(bit_depth: u8) -> u64 {
    match bit_depth {
        8 => 255,
        16 => 65535,
        24 => 16777215,
        _ => panic!("Unsupported bit depth: {}", bit_depth),
    }
}

fn fp(label: &str, v: &[F]) {
    if v.is_empty() {
        println!("{} len=0", label);
        return;
    }
    let last = v[v.len() - 1];
    let second = if v.len() > 1 { v[1] } else { v[0] };
    println!("{} len={} 0={:?} 1={:?} last={:?}", label, v.len(), v[0], second, last);
}

fn dbg_fp<T: core::fmt::Debug>(label: &str, x: &T) {
    let s = format!("{:?}", x);
    let head = &s[..s.len().min(120)];
    let tail = if s.len() > 120 { &s[s.len()-120..] } else { "" };
    println!("{} debug_len={} head=`{}` tail=`{}`", label, s.len(), head, tail);
}

pub fn eq_eval(x: &[F], y: &[F]) -> F {
    let mut res = F::ONE;
    for (&xi, &yi) in x.iter().zip(y.iter()) {
        let xi_yi = xi * yi;
        res *= xi_yi + xi_yi - xi - yi + F::ONE;
    }
    return(res)
}

/// Build range check evaluation points for a given random point.
/// Returns 6 points: [alpha_range, fiddle, zero_pt, alpha_range_dup, alpha_range||0, alpha_range||1]
fn build_range_pts(numCols: usize, myRand: &Vec<F>) -> Vec<Vec<F>> {
    let mut pts = Vec::new();
    let galoisRep = irredPolyTable[numCols + 1] - (1 << (numCols+1));
    let (fiddle, zero, _startVal) = galoisifyPt((numCols+1) as u32, galoisRep, myRand.clone());

    pts.push(myRand.clone());        // alpha_range
    pts.push(fiddle);                 // fiddle
    pts.push(zero);                   // zero_pt
    pts.push(myRand.clone());         // alpha_range (dup for prod/frac)

    let mut ptRand = Vec::new();
    ptRand.push(F::ZERO);
    for i in 0..myRand.len()-1 {
        ptRand.push(myRand[i]);
    }
    pts.push(ptRand.clone());         // alpha_range||0
    ptRand[0] = F::ONE;
    pts.push(ptRand);                 // alpha_range||1

    pts
}

fn makePtsFullVolume(numCols: usize, hashPt: Vec<F>, origRangePt: Vec<F>, errRangePt: Vec<F>, transformPt: Vec<F>) -> Vec<Vec<F>> {
    let mut points = Vec::new();

    // [0] Hash sumcheck point (pad to numCols+1)
    let mut origPt = hashPt.clone();
    origPt.push(F::ZERO);
    points.push(origPt);

    // [1] Zero vector (for h(0) = 0)
    points.push(vec![F::ZERO; numCols+1]);

    // [2] [0,1,1,...,1] vector (for prod(1..1,0) = 1)
    let mut final_query = vec![F::ONE; numCols+1];
    final_query[0] = F::ZERO;
    points.push(final_query);

    // [3-8] Original audio range check points
    let orig_pts = build_range_pts(numCols, &origRangePt);
    for p in orig_pts { points.push(p); }

    // [9] Transform point (pad to numCols+1)
    let mut transPt = transformPt.clone();
    transPt.push(F::ZERO);
    points.push(transPt);

    // [10-15] Error range check points
    let err_pts = build_range_pts(numCols, &errRangePt);
    for p in err_pts { points.push(p); }

    points
}

fn setup(input_size: usize) -> (<Pcs as PolynomialCommitmentScheme<F>>::ProverParam, <Pcs as PolynomialCommitmentScheme<F>>::VerifierParam, Vec<F>) {
    println!("\nstarting setup");
    let mut rng = test_rng();

    let poly_vars = input_size + 1;

    // param setup
    let (pp, vp) = {
        let poly_size = 1 << (poly_vars);
        let param = Pcs::setup(poly_size, 4, &mut rng).unwrap();
        Pcs::trim(&param, poly_size, 4).unwrap()
    };

    // load audio for given input size
    let fileName = format!("audio/Audio{}.json", input_size);
    let origAudio = load_audio(&fileName);
    let bitDepth = origAudio.bit_depth;

    let audioEvals = audio_to_brakedown_field(&origAudio.left, bitDepth);

    // creating the hash for the audio
    let mut matrixA = Vec::new();
    for i in 0..128 {
        matrixA.push(ChaCha8Rng::seed_from_u64(i));
    }

    let mut digest = Vec::new();
    for i in 0..128 {
        let mut mySum = F::ZERO;
        for j in 0..(1 << input_size) {
            if j < audioEvals.len() {
                mySum += F::random(&mut matrixA[i]) * audioEvals[j];
            }
        }
        digest.push(mySum);
    }

    println!("setup done!\n");
    return (pp, vp, digest)
}

fn verify_from_bytes(
    vp: <MultilinearBrakedown<F, Blake2s, BrakedownSpec6> as PolynomialCommitmentScheme<F>>::VerifierParam,
    numRows: usize,
    numCols: usize,
    cameraHash: Vec<F>,
    proof_bytes: &[u8],
    input_size: usize,
) -> bool {
    println!("\nstarting verifier");

    let mut commits = Vec::new();

    // Volume scaling parameters
    let numerator: u64 = 1;
    let denominator: u64 = 2;
    let num_f = F::from(numerator);
    let denom_f = F::from(denominator);

    // Load volume audio for verification
    let volumeFileName = format!("audio/Volume{}.json", input_size);
    let volumeAudio = load_audio(&volumeFileName);
    let bitDepth = volumeAudio.bit_depth;
    let maxVal = get_max_val(bitDepth);
    let offset = get_offset(bitDepth);
    let offset_adjustment = (denom_f - num_f) * F::from(offset);
    let errMaxVal: u64 = denominator - 1;

    let volumeEvals = audio_to_brakedown_field(&volumeAudio.left, bitDepth);

    println!("PROOF SIZE: {:?} bytes", proof_bytes.len());

    let mut ver_transcript = Blake2sTranscript::from_proof((), proof_bytes);

    // Read audio commitment
    commits.append(&mut Pcs::read_commitments(&vp, 1, &mut ver_transcript).unwrap());

    // ========== HASH PREIMAGE VERIFICATION ==========
    let frievaldRandVecrTA = <VT as FieldTranscript<F>>::squeeze_challenges(&mut ver_transcript, 1 << numRows);
    let challenges: Vec<F> = vec![<VT as FieldTranscript<F>>::squeeze_challenge(&mut ver_transcript)];
    let rand_vector = <VT as FieldTranscript<F>>::squeeze_challenges(&mut ver_transcript, numCols);

    let mut mySumVal = F::ZERO;
    for j in 0..1 << numRows {
        mySumVal += frievaldRandVecrTA[j] * cameraHash[j];
    }
    let verResCameraHash = ClassicSumCheck::<EvaluationsProver<F>>::verify(&(), numCols, 2, mySumVal, &mut ver_transcript).unwrap();
    fp("VERIFIER hash r*", &verResCameraHash.1);
    let hashPt = verResCameraHash.clone().1;

    // ========== ORIGINAL RANGE CHECK VERIFICATION ==========
    commits.append(&mut Pcs::read_commitments(&vp, 1, &mut ver_transcript).unwrap());
    let alpha1 = <VT as FieldTranscript<F>>::squeeze_challenge(&mut ver_transcript);
    let alpha2 = <VT as FieldTranscript<F>>::squeeze_challenge(&mut ver_transcript);
    commits.append(&mut Pcs::read_commitments(&vp, 2, &mut ver_transcript).unwrap());

    let beta = <VT as FieldTranscript<F>>::squeeze_challenge(&mut ver_transcript);
    let challenges_range: Vec<F> = vec![<VT as FieldTranscript<F>>::squeeze_challenge(&mut ver_transcript)];
    let rand_vector_range = <VT as FieldTranscript<F>>::squeeze_challenges(&mut ver_transcript, numCols+1);

    let verResRange = ClassicSumCheck::<EvaluationsProver<F>>::verify(&(), numCols+1, 3, F::ZERO, &mut ver_transcript).unwrap();
    let origRangePt = verResRange.1.clone();

    // ========== ERROR RANGE CHECK VERIFICATION ==========
    // Read error commitment
    commits.append(&mut Pcs::read_commitments(&vp, 1, &mut ver_transcript).unwrap());
    // Read hErr commitment
    commits.append(&mut Pcs::read_commitments(&vp, 1, &mut ver_transcript).unwrap());
    let alpha1Err = <VT as FieldTranscript<F>>::squeeze_challenge(&mut ver_transcript);
    let alpha2Err = <VT as FieldTranscript<F>>::squeeze_challenge(&mut ver_transcript);
    // Read fracErr + prodErr commitments
    commits.append(&mut Pcs::read_commitments(&vp, 2, &mut ver_transcript).unwrap());

    let betaErr = <VT as FieldTranscript<F>>::squeeze_challenge(&mut ver_transcript);
    let challenges_err_range: Vec<F> = vec![<VT as FieldTranscript<F>>::squeeze_challenge(&mut ver_transcript)];
    let rand_vector_err_range = <VT as FieldTranscript<F>>::squeeze_challenges(&mut ver_transcript, numCols+1);

    let verResErrRange = ClassicSumCheck::<EvaluationsProver<F>>::verify(&(), numCols+1, 3, F::ZERO, &mut ver_transcript).unwrap();
    let errRangePt = verResErrRange.1.clone();

    // Squeeze transform point
    let transformPt: Vec<F> = <VT as FieldTranscript<F>>::squeeze_challenges(&mut ver_transcript, numCols);

    // Build evaluation points
    let points = makePtsFullVolume(numCols, hashPt.clone(), origRangePt.clone(), errRangePt.clone(), transformPt.clone());

    // commits layout: [0]=audio, [1]=h, [2]=frac, [3]=prod, [4]=err, [5]=hErr, [6]=fracErr, [7]=prodErr

    // Build placeholder eval vecs (values will be overwritten from transcript)
    let hevals_vec: Vec<Evaluation<F>> = (0..4).map(|j| Evaluation::new(j, j, F::ZERO)).collect();
    let fracevals_vec: Vec<Evaluation<F>> = (0..3).map(|j| Evaluation::new(j, j, F::ZERO)).collect();
    let prodevals_vec: Vec<Evaluation<F>> = (0..4).map(|j| Evaluation::new(j, j, F::ZERO)).collect();
    let audioevals_vec: Vec<Evaluation<F>> = (0..3).map(|j| Evaluation::new(j, j, F::ZERO)).collect();
    let errevals_vec: Vec<Evaluation<F>> = (0..2).map(|j| Evaluation::new(j, j, F::ZERO)).collect();
    let hErrevals_vec: Vec<Evaluation<F>> = (0..4).map(|j| Evaluation::new(j, j, F::ZERO)).collect();
    let fracErrevals_vec: Vec<Evaluation<F>> = (0..3).map(|j| Evaluation::new(j, j, F::ZERO)).collect();
    let prodErrevals_vec: Vec<Evaluation<F>> = (0..4).map(|j| Evaluation::new(j, j, F::ZERO)).collect();

    // ========== READ AND VERIFY PCS OPENINGS ==========
    // --- Original h ---
    let hpoints_0 = vec![points[1].clone(), points[3].clone(), points[4].clone(), points[5].clone()];
    let h_evals: Vec<F> = ver_transcript.read_field_elements(hevals_vec.len()).unwrap();
    let mut hevals2 = Vec::new();
    for j in 0..hevals_vec.len() {
        let mut newEval = hevals_vec[j].clone();
        newEval.value = h_evals[j];
        hevals2.push(newEval);
    }
    println!("VERIFY PCS: h");
    batch_verify_one::<F, Pcs>(&vp, numCols+1, commits[1].clone(), &hpoints_0, &hevals2, &mut ver_transcript).unwrap();

    // --- Original frac ---
    let fracpoints_0 = vec![points[6].clone(), points[7].clone(), points[8].clone()];
    let frac_evals: Vec<F> = ver_transcript.read_field_elements(fracevals_vec.len()).unwrap();
    let mut fracevals2 = Vec::new();
    for j in 0..fracevals_vec.len() {
        let mut newEval = fracevals_vec[j].clone();
        newEval.value = frac_evals[j];
        fracevals2.push(newEval);
    }
    println!("VERIFY PCS: frac");
    batch_verify_one::<F, Pcs>(&vp, numCols+1, commits[2].clone(), &fracpoints_0, &fracevals2, &mut ver_transcript).unwrap();

    // --- Original prod ---
    let prodpoints_0 = vec![points[2].clone(), points[6].clone(), points[7].clone(), points[8].clone()];
    let prod_evals: Vec<F> = ver_transcript.read_field_elements(prodevals_vec.len()).unwrap();
    let mut prodevals2 = Vec::new();
    for j in 0..prodevals_vec.len() {
        let mut newEval = prodevals_vec[j].clone();
        newEval.value = prod_evals[j];
        prodevals2.push(newEval);
    }
    println!("VERIFY PCS: prod");
    batch_verify_one::<F, Pcs>(&vp, numCols+1, commits[3].clone(), &prodpoints_0, &prodevals2, &mut ver_transcript).unwrap();

    // --- Audio ---
    let mut smallPt = points[3].clone();
    smallPt[numCols] = F::ZERO;
    let audiopoints_0 = vec![points[0].clone(), smallPt.clone(), points[9].clone()];
    let audio_evals: Vec<F> = ver_transcript.read_field_elements(audioevals_vec.len()).unwrap();
    let mut audioevals2 = Vec::new();
    for j in 0..audioevals_vec.len() {
        let mut newEval = audioevals_vec[j].clone();
        newEval.value = audio_evals[j];
        audioevals2.push(newEval);
    }
    println!("VERIFY PCS: audio");
    batch_verify_one::<F, Pcs>(&vp, numCols+1, commits[0].clone(), &audiopoints_0, &audioevals2, &mut ver_transcript).unwrap();

    // --- Error ---
    let mut errSmallPt = points[10].clone();
    errSmallPt[numCols] = F::ZERO;
    let errpoints_0 = vec![points[9].clone(), errSmallPt.clone()];
    let err_evals: Vec<F> = ver_transcript.read_field_elements(errevals_vec.len()).unwrap();
    let mut errevals2 = Vec::new();
    for j in 0..errevals_vec.len() {
        let mut newEval = errevals_vec[j].clone();
        newEval.value = err_evals[j];
        errevals2.push(newEval);
    }
    println!("VERIFY PCS: error");
    batch_verify_one::<F, Pcs>(&vp, numCols+1, commits[4].clone(), &errpoints_0, &errevals2, &mut ver_transcript).unwrap();

    // --- Error h ---
    let hErrpoints_0 = vec![points[1].clone(), points[10].clone(), points[11].clone(), points[12].clone()];
    let hErr_evals: Vec<F> = ver_transcript.read_field_elements(hErrevals_vec.len()).unwrap();
    let mut hErrevals2 = Vec::new();
    for j in 0..hErrevals_vec.len() {
        let mut newEval = hErrevals_vec[j].clone();
        newEval.value = hErr_evals[j];
        hErrevals2.push(newEval);
    }
    println!("VERIFY PCS: hErr");
    batch_verify_one::<F, Pcs>(&vp, numCols+1, commits[5].clone(), &hErrpoints_0, &hErrevals2, &mut ver_transcript).unwrap();

    // --- Error frac ---
    let fracErrpoints_0 = vec![points[13].clone(), points[14].clone(), points[15].clone()];
    let fracErr_evals: Vec<F> = ver_transcript.read_field_elements(fracErrevals_vec.len()).unwrap();
    let mut fracErrevals2 = Vec::new();
    for j in 0..fracErrevals_vec.len() {
        let mut newEval = fracErrevals_vec[j].clone();
        newEval.value = fracErr_evals[j];
        fracErrevals2.push(newEval);
    }
    println!("VERIFY PCS: fracErr");
    batch_verify_one::<F, Pcs>(&vp, numCols+1, commits[6].clone(), &fracErrpoints_0, &fracErrevals2, &mut ver_transcript).unwrap();

    // --- Error prod ---
    let prodErrpoints_0 = vec![points[2].clone(), points[13].clone(), points[14].clone(), points[15].clone()];
    let prodErr_evals: Vec<F> = ver_transcript.read_field_elements(prodErrevals_vec.len()).unwrap();
    let mut prodErrevals2 = Vec::new();
    for j in 0..prodErrevals_vec.len() {
        let mut newEval = prodErrevals_vec[j].clone();
        newEval.value = prodErr_evals[j];
        prodErrevals2.push(newEval);
    }
    println!("VERIFY PCS: prodErr");
    batch_verify_one::<F, Pcs>(&vp, numCols+1, commits[7].clone(), &prodErrpoints_0, &prodErrevals2, &mut ver_transcript).unwrap();

    // ========== VERIFY RELATIONSHIPS ==========
    let mut success = true;

    // --- Hash preimage binding ---
    let mut matrixA = Vec::new();
    for i in 0..128 {
        matrixA.push(ChaCha8Rng::seed_from_u64(i));
    }
    let mut rTA = Vec::new();
    for _ in 0..(1 << numCols) {
        let mut mySum = F::ZERO;
        for j in 0..128 {
            mySum += F::random(&mut matrixA[j]) * frievaldRandVecrTA[j];
        }
        rTA.push(mySum);
    }
    let rTAPoly = MultilinearPolynomial::<F>::new(rTA.clone());

    let mut rTApt = Vec::new();
    for i in 0..points[0].len()-1 {
        rTApt.push(verResCameraHash.1[i]);
    }

    let LHS = rTAPoly.evaluate(&rTApt);
    let RHS = audio_evals[0];
    success = success && (verResCameraHash.0 == LHS * RHS);

    // --- Volume transformation check (SOUND) ---
    // Verify: num * orig(alpha) + offset_adjustment == denom * volume(alpha) + error(alpha)
    let origAtPt = audio_evals[2]; // audio at transform point (PCS-opened)
    let errAtPt = err_evals[0];    // error at transform point (PCS-opened)

    // Verifier locally evaluates the public volume audio at the transform point
    let volumeAudioPoly = MultilinearPolynomial::new(volumeEvals.clone());
    let volumeAtPt = volumeAudioPoly.evaluate(&transformPt);

    let expectedLHS = num_f * origAtPt + offset_adjustment;
    let computedRHS = denom_f * volumeAtPt + errAtPt;
    success = success && (expectedLHS == computedRHS);

    // --- Original range check verification ---
    // h(0) = 0
    success = success && (h_evals[0] == F::ZERO);

    // Build embedded tables for original range check
    let primPolyForT = irredPolyTable[numCols] as u64;
    let mut embeddedTable: Vec<F> = vec![F::ZERO; 1 << numCols];
    let mut plusOneTable: Vec<F> = vec![F::ZERO; 1 << numCols];
    let galoisRep = primPolyForT - (1 << numCols);
    let size = 1 << numCols;
    let mut binaryString: u64 = 1;
    for i in 1..(maxVal as usize + 1) {
        embeddedTable[binaryString as usize] = F::from(i as u64);
        binaryString <<= 1;
        if binaryString & size != 0 {
            binaryString ^= galoisRep;
        }
        binaryString = (size - 1) & binaryString;
        plusOneTable[binaryString as usize] = F::from(i as u64);
    }
    let polyTable = MultilinearPolynomial::new(embeddedTable.clone());
    let polyPlusOneTable = MultilinearPolynomial::new(plusOneTable.clone());

    // Monster value for original audio range check
    {
        let myRand = &points[3];
        let galoisRepRange = irredPolyTable[numCols + 1] - (1 << (numCols + 1));
        let (_, _, startVal) = galoisifyPt((numCols+1) as u32, galoisRepRange, myRand.clone());

        let mut myRandSmall = Vec::new();
        for i in 0..myRand.len()-1 {
            myRandSmall.push(myRand[i]);
        }
        let lastVal = myRand[myRand.len()-1];
        let audioAtAlphaSmall = audio_evals[1];
        let hAtAlphaRange = h_evals[1];
        let hAtAlphaRangeFiddle = h_evals[2];
        let hAtAlphaRange0 = h_evals[3];
        let prodAtAlphaRange = prod_evals[1];
        let fracAtAlphaRange = frac_evals[0];
        let prodAtAlphaRange0 = prod_evals[2];
        let fracAtAlphaRange0 = frac_evals[1];
        let prodAtAlphaRange1 = prod_evals[3];
        let fracAtAlphaRange1 = frac_evals[2];

        let mut firstHalf = prodAtAlphaRange;
        let myAlpha = myRand[myRand.len()-1];
        let vX0 = myAlpha * prodAtAlphaRange0 + (F::ONE - myAlpha) * fracAtAlphaRange0;
        let vX1 = myAlpha * prodAtAlphaRange1 + (F::ONE - myAlpha) * fracAtAlphaRange1;
        firstHalf += -vX0 * vX1;

        let mut f1 = alpha1 + ((F::ONE - lastVal) * audioAtAlphaSmall + lastVal * polyTable.evaluate(&myRandSmall));
        f1 += alpha2 * ((F::ONE - lastVal) * audioAtAlphaSmall + lastVal * polyPlusOneTable.evaluate(&myRandSmall));

        let f2 = alpha1 + hAtAlphaRange + alpha2 * (startVal * hAtAlphaRangeFiddle + (F::ONE - startVal) * hAtAlphaRange0);
        let mut secondHalf = f2 * fracAtAlphaRange - f1;
        secondHalf = secondHalf * beta;

        let anticipatedVal = verResRange.0;
        let finalVal = firstHalf + secondHalf;
        let extra = eq_eval(&myRand, &rand_vector_range);
        success = success && (anticipatedVal == finalVal * extra);
    }

    // --- Error range check verification ---
    // h(0) = 0
    success = success && (hErr_evals[0] == F::ZERO);

    // Build embedded tables for error range check (maxVal = errMaxVal)
    let mut embeddedTableErr: Vec<F> = vec![F::ZERO; 1 << numCols];
    let mut plusOneTableErr: Vec<F> = vec![F::ZERO; 1 << numCols];
    let mut binaryStringErr: u64 = 1;
    for i in 1..(errMaxVal as usize + 1) {
        embeddedTableErr[binaryStringErr as usize] = F::from(i as u64);
        binaryStringErr <<= 1;
        if binaryStringErr & size != 0 {
            binaryStringErr ^= galoisRep;
        }
        binaryStringErr = (size - 1) & binaryStringErr;
        plusOneTableErr[binaryStringErr as usize] = F::from(i as u64);
    }
    let polyTableErr = MultilinearPolynomial::new(embeddedTableErr);
    let polyPlusOneTableErr = MultilinearPolynomial::new(plusOneTableErr);

    // Monster value for error range check
    {
        let myRand = &points[10];
        let galoisRepRange = irredPolyTable[numCols + 1] - (1 << (numCols + 1));
        let (_, _, startValErr) = galoisifyPt((numCols+1) as u32, galoisRepRange, myRand.clone());

        let mut myRandSmall = Vec::new();
        for i in 0..myRand.len()-1 {
            myRandSmall.push(myRand[i]);
        }
        let lastVal = myRand[myRand.len()-1];
        let errAtAlphaSmall = err_evals[1];
        let hAtAlphaRange = hErr_evals[1];
        let hAtAlphaRangeFiddle = hErr_evals[2];
        let hAtAlphaRange0 = hErr_evals[3];
        let prodAtAlphaRange = prodErr_evals[1];
        let fracAtAlphaRange = fracErr_evals[0];
        let prodAtAlphaRange0 = prodErr_evals[2];
        let fracAtAlphaRange0 = fracErr_evals[1];
        let prodAtAlphaRange1 = prodErr_evals[3];
        let fracAtAlphaRange1 = fracErr_evals[2];

        let mut firstHalf = prodAtAlphaRange;
        let myAlpha = myRand[myRand.len()-1];
        let vX0 = myAlpha * prodAtAlphaRange0 + (F::ONE - myAlpha) * fracAtAlphaRange0;
        let vX1 = myAlpha * prodAtAlphaRange1 + (F::ONE - myAlpha) * fracAtAlphaRange1;
        firstHalf += -vX0 * vX1;

        let mut f1 = alpha1Err + ((F::ONE - lastVal) * errAtAlphaSmall + lastVal * polyTableErr.evaluate(&myRandSmall));
        f1 += alpha2Err * ((F::ONE - lastVal) * errAtAlphaSmall + lastVal * polyPlusOneTableErr.evaluate(&myRandSmall));

        let f2 = alpha1Err + hAtAlphaRange + alpha2Err * (startValErr * hAtAlphaRangeFiddle + (F::ONE - startValErr) * hAtAlphaRange0);
        let mut secondHalf = f2 * fracAtAlphaRange - f1;
        secondHalf = secondHalf * betaErr;

        let anticipatedVal = verResErrRange.0;
        let finalVal = firstHalf + secondHalf;
        let extra = eq_eval(&myRand, &rand_vector_err_range);
        success = success && (anticipatedVal == finalVal * extra);
    }

    println!("Verifier passed!: {:?}", success);
    println!("verifier done!\n");
    return success;
}

fn run_verifier_only(input_size: usize, input_dir: &str) {
    let numCols = input_size;
    let numRows = 7;

    // Re-derive verifier params and camera hash (setup is deterministic)
    let (_pp, vp, digest) = setup(input_size);

    // Load proof bytes from disk
    let in_path = Path::new(input_dir);
    let proof_bytes = fs::read(in_path.join("proof.bin"))
        .expect("Failed to read proof.bin");

    // Load public inputs
    let public_json: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(in_path.join("public_inputs.json"))
            .expect("Failed to read public_inputs.json")
    ).unwrap();

    let loaded_input_size = public_json["input_size"].as_u64().unwrap() as usize;
    let loaded_numRows = public_json["numRows"].as_u64().unwrap() as usize;
    let loaded_numCols = public_json["numCols"].as_u64().unwrap() as usize;

    println!("Loaded proof: {} bytes", proof_bytes.len());
    println!("Public inputs: input_size={}, numRows={}, numCols={}", loaded_input_size, loaded_numRows, loaded_numCols);

    // Run verifier
    let verifier_start = Instant::now();

    let success = verify_from_bytes(
        vp, numRows, numCols,
        digest, &proof_bytes, input_size,
    );

    let elapsed_verifier = verifier_start.elapsed();
    println!("VERIFIER TIME: {:?} seconds", elapsed_verifier.as_millis() as f64 / 1000 as f64);
    println!("VERIFIED: {:?}", success);

    if !success {
        std::process::exit(1);
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage: hv_volume_brakedown_verify <size> <input_dir>");
        std::process::exit(1);
    }

    let input_size = args[1].parse::<usize>().unwrap();
    let input_dir = &args[2];

    println!("-----------------------------------------------------------------------");
    println!("Verifier Only - Volume, HyperVerITAS Brakedown 127. Size: 2^{:?}\n", input_size);
    run_verifier_only(input_size, input_dir);
    println!("-----------------------------------------------------------------------");
}
