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

fn hashPreimageProveAudio(
    pp: <MultilinearBrakedown<F, Blake2s, BrakedownSpec6> as PolynomialCommitmentScheme<F>>::ProverParam,
    numCols: usize,
    numRows: usize,
    audioEvals: Vec<F>,
    audioEvalsInt: Vec<usize>,
    maxVal: u64,
    transcript: &mut (impl TranscriptWrite<<MultilinearBrakedown<F, Blake2s, BrakedownSpec6> as PolynomialCommitmentScheme<F>>::CommitmentChunk, F> + InMemoryTranscript),
) -> (
    Vec<MultilinearBrakedownCommitment<F, Blake2s>>,
    Vec<F>,
    Vec<F>,
    MultilinearPolynomial<F>,
    [Vec<F>;1],
    Vec<MultilinearBrakedownCommitment<F, Blake2s>>,
    Vec<MultilinearPolynomial<F>>,
    Vec<F>,
) {
    let mut rng = test_rng();

    let mut matrixA = Vec::new();
    for i in 0..128 {
        matrixA.push(ChaCha8Rng::seed_from_u64(i));
    }

    // Create audio polynomial with padding
    let mut padded = audioEvals.clone();
    padded.append(&mut vec![F::ZERO; 1 << numCols]);
    let audioPoly = MultilinearPolynomial::new(padded);

    let audioCom = Pcs::batch_commit_and_write(&pp, &[audioPoly.clone()], transcript);
    let audioPolySmall = MultilinearPolynomial::<F>::new(audioEvals.clone());

    // Get Frievald random vec
    let frievaldRandVec = transcript.squeeze_challenges(1 << numRows);

    // Make rT*A
    let mut rTA = Vec::new();
    for _ in 0..(1 << numCols) {
        let mut mySum = F::ZERO;
        for j in 0..128 {
            mySum += F::random(&mut matrixA[j]) * frievaldRandVec[j];
        }
        rTA.push(mySum);
    }

    let rTAPoly = MultilinearPolynomial::<F>::new(rTA.clone());

    // Run the sumcheck on rTA * audio
    let poly_0 = Expression::<F>::Polynomial(Query::new(0, Rotation::cur()));
    let poly_1 = Expression::<F>::Polynomial(Query::new(1, Rotation::cur()));

    let prod = poly_0.clone() * poly_1;

    let polys = vec![rTAPoly.clone(), audioPolySmall.clone()];

    let challenges = vec![transcript.squeeze_challenge()];
    let rand_vector = transcript.squeeze_challenges(numCols);
    let ys = [rand_vector.clone()];

    let mut my_sum = F::ZERO;
    let rta_evals = rTAPoly.evals();
    let audio_evals = audioPolySmall.evals();
    for i in 0..rta_evals.len() {
        my_sum += rta_evals[i] * audio_evals[i];
    }

    let proof_mm =
        <ClassicSumCheck<EvaluationsProver<F>>>::prove(&(), numCols, VirtualPolynomial::new(&prod, &polys, &challenges, &ys), my_sum, transcript).unwrap();

    // Run range check on audio
    let mut hTable = vec![0usize; (maxVal + 2) as usize];
    for j in 0..audioEvalsInt.len() {
        if audioEvalsInt[j] <= maxVal as usize {
            hTable[audioEvalsInt[j]] += 1;
        }
    }

    let (exp_out, poly_out, chall_out, ys_out, com_out) = range_checkProverIOP(
        pp.clone(),
        numCols,
        maxVal,
        hTable,
        audioPolySmall.clone(),
        irredPolyTable[numCols].try_into().unwrap(),
        irredPolyTable[numCols+1].try_into().unwrap(),
        transcript,
        0,
    );

    let proof_range =
        <ClassicSumCheck<EvaluationsProver<F>>>::prove(&(), numCols+1, VirtualPolynomial::new(&exp_out.clone(), &poly_out.clone(), &chall_out.clone(), &[ys_out.clone()]), F::ZERO, transcript).unwrap();

    return (audioCom.unwrap(), proof_mm.0, proof_range.0, audioPoly, ys, com_out, poly_out, ys_out);
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

fn prove(pp: <Pcs as PolynomialCommitmentScheme<F>>::ProverParam, input_size: usize, numRows: usize, numCols: usize)
 -> (impl (TranscriptWrite<<Pcs as PolynomialCommitmentScheme<F>>::CommitmentChunk, F>) + InMemoryTranscript)
{
    println!("starting prover");
    let length = input_size + 1;

    // Volume scaling parameters: 50% volume (numerator=1, denominator=2)
    let numerator: u64 = 1;
    let denominator: u64 = 2;
    let num_f = F::from(numerator);
    let denom_f = F::from(denominator);

    // create a new transcript
    let mut transcript = Blake2sTranscript::new(());

    // prover loads audio
    let fileName = format!("audio/Audio{}.json", input_size);
    let origAudio = load_audio(&fileName);
    let bitDepth = origAudio.bit_depth;
    let maxVal = get_max_val(bitDepth);
    let offset = get_offset(bitDepth);
    let offset_adjustment = (denom_f - num_f) * F::from(offset);

    let audioEvals = audio_to_brakedown_field(&origAudio.left, bitDepth);

    // Get integer representation for histogram
    let audioEvalsInt: Vec<usize> = origAudio.left.iter()
        .map(|&s| (s as i64 + offset as i64) as usize)
        .collect();

    // Do the hash preimage proof
    let (audioCom, mmChall, rangeChall, audioPoly, audioYs, com_outs, poly_outs, ys_outs) =
        hashPreimageProveAudio(
            pp.clone(),
            numCols,
            numRows,
            audioEvals.clone(),
            audioEvalsInt.clone(),
            maxVal,
            &mut transcript,
        );

    fp("PROVER mmChall", &mmChall);
    fp("PROVER rangeChall", &rangeChall);
    let mut Polies = Vec::new();

    Polies.push(audioPoly.clone());

    // h, frac, prod from range check
    Polies.push(poly_outs[6].clone()); // h
    Polies.push(poly_outs[0].clone()); // frac
    Polies.push(poly_outs[1].clone()); // prod

    let mut PolyComs = audioCom.clone();
    PolyComs.push(com_outs[2].clone()); // h
    PolyComs.push(com_outs[0].clone()); // frac
    PolyComs.push(com_outs[1].clone()); // prod

    // ========== VOLUME ERROR POLYNOMIAL ==========
    // Load volume audio
    let volumeFileName = format!("audio/Volume{}.json", input_size);
    let volumeAudio = load_audio(&volumeFileName);
    let volumeEvals = audio_to_brakedown_field(&volumeAudio.left, bitDepth);

    // Compute error: error[i] = num * orig[i] - denom * volume[i] + offset_adjustment
    let mut volumeError = Vec::new();
    for i in 0..(1 << numCols) {
        let origVal = if i < audioEvals.len() { audioEvals[i] } else { F::ZERO };
        let volVal = if i < volumeEvals.len() { volumeEvals[i] } else { F::ZERO };
        volumeError.push(num_f * origVal - denom_f * volVal + offset_adjustment);
    }

    // Pad error polynomial to numCols+1 vars
    let mut paddedError = volumeError.clone();
    paddedError.append(&mut vec![F::ZERO; 1 << numCols]);
    let errPoly = MultilinearPolynomial::new(paddedError);
    let errPolySmall = MultilinearPolynomial::new(volumeError.clone());

    // Commit error polynomial
    let errCom = Pcs::batch_commit_and_write(&pp, &[errPoly.clone()], &mut transcript).unwrap();

    // Build error histogram for range check
    let errMaxVal: u64 = denominator - 1;
    let mut hTableErr = vec![0usize; (errMaxVal + 2) as usize];
    for i in 0..audioEvalsInt.len().min(1 << numCols) {
        let orig_uint = audioEvalsInt[i] as u64;
        let vol_uint = (volumeAudio.left[i] as i64 + offset as i64) as u64;
        let err_int = (numerator * orig_uint + (denominator - numerator) * offset - denominator * vol_uint) as usize;
        hTableErr[err_int] += 1;
    }
    // Pad zeros for remaining entries
    let paddingZeros = (1 << numCols) - audioEvalsInt.len().min(1 << numCols);
    if offset == 0 {
        hTableErr[0] += paddingZeros;
    } else {
        let padErrVal = ((denominator - numerator) * offset) as usize;
        if padErrVal <= errMaxVal as usize {
            hTableErr[padErrVal] += paddingZeros;
        }
    }

    // Run range check on error polynomial
    let (exp_out_err, poly_out_err, chall_out_err, ys_out_err, com_out_err) = range_checkProverIOP(
        pp.clone(),
        numCols,
        errMaxVal,
        hTableErr,
        errPolySmall.clone(),
        irredPolyTable[numCols].try_into().unwrap(),
        irredPolyTable[numCols+1].try_into().unwrap(),
        &mut transcript,
        0,
    );

    let proof_err_range =
        <ClassicSumCheck<EvaluationsProver<F>>>::prove(&(), numCols+1, VirtualPolynomial::new(&exp_out_err, &poly_out_err, &chall_out_err, &[ys_out_err.clone()]), F::ZERO, &mut transcript).unwrap();
    fp("PROVER errRangeChall", &proof_err_range.0);

    // Add error polynomials and commitments
    Polies.push(errPoly.clone());             // [4] error
    Polies.push(poly_out_err[6].clone());     // [5] hErr
    Polies.push(poly_out_err[0].clone());     // [6] fracErr
    Polies.push(poly_out_err[1].clone());     // [7] prodErr

    PolyComs.append(&mut errCom.clone());     // [4] errCom
    PolyComs.push(com_out_err[2].clone());    // [5] hErrCom
    PolyComs.push(com_out_err[0].clone());    // [6] fracErrCom
    PolyComs.push(com_out_err[1].clone());    // [7] prodErrCom

    // Squeeze random transform point
    let transformPt: Vec<F> = transcript.squeeze_challenges(numCols);

    // Build evaluation points
    let polynomials = Polies;
    let coms = PolyComs;
    let points = makePtsFullVolume(numCols, mmChall.clone(), rangeChall.clone(), proof_err_range.0.clone(), transformPt.clone());

    // ========== BUILD EVALUATION SETS ==========

    // --- Original h evaluations (4 points) ---
    let hInd = 1;
    let mut hcom_0: Vec<&_> = (0..4).map(|_| &coms[hInd]).collect();
    let mut hpoly_0: Vec<&_> = (0..4).map(|_| &polynomials[hInd]).collect();
    let hpoints_0 = vec![points[1].clone(), points[3].clone(), points[4].clone(), points[5].clone()];
    let mut hevals_0 = Vec::new();
    hevals_0.push(Evaluation::new(0, 0, F::ZERO));
    hevals_0.push(Evaluation::new(1, 1, hpoly_0[1].evaluate(&hpoints_0[1])));
    hevals_0.push(Evaluation::new(2, 2, hpoly_0[2].evaluate(&hpoints_0[2])));
    hevals_0.push(Evaluation::new(3, 3, hpoly_0[3].evaluate(&hpoints_0[3])));

    // --- Original frac evaluations (3 points) ---
    let fracInd = 2;
    let mut fraccom_0: Vec<&_> = (0..3).map(|_| &coms[fracInd]).collect();
    let mut fracpoly_0: Vec<&_> = (0..3).map(|_| &polynomials[fracInd]).collect();
    let fracpoints_0 = vec![points[6].clone(), points[7].clone(), points[8].clone()];
    let mut fracevals_0 = Vec::new();
    fracevals_0.push(Evaluation::new(0, 0, fracpoly_0[0].evaluate(&fracpoints_0[0])));
    fracevals_0.push(Evaluation::new(1, 1, fracpoly_0[1].evaluate(&fracpoints_0[1])));
    fracevals_0.push(Evaluation::new(2, 2, fracpoly_0[2].evaluate(&fracpoints_0[2])));

    // --- Original prod evaluations (4 points) ---
    let prodInd = 3;
    let mut prodcom_0: Vec<&_> = (0..4).map(|_| &coms[prodInd]).collect();
    let mut prodpoly_0: Vec<&_> = (0..4).map(|_| &polynomials[prodInd]).collect();
    let prodpoints_0 = vec![points[2].clone(), points[6].clone(), points[7].clone(), points[8].clone()];
    let mut prodevals_0 = Vec::new();
    prodevals_0.push(Evaluation::new(0, 0, prodpoly_0[0].evaluate(&prodpoints_0[0])));
    prodevals_0.push(Evaluation::new(1, 1, prodpoly_0[1].evaluate(&prodpoints_0[1])));
    prodevals_0.push(Evaluation::new(2, 2, prodpoly_0[2].evaluate(&prodpoints_0[2])));
    prodevals_0.push(Evaluation::new(3, 3, prodpoly_0[3].evaluate(&prodpoints_0[3])));

    // --- Audio evaluations (3 points: hash, range_small, transform) ---
    let audioInd = 0;
    let mut audiocom_0: Vec<&_> = (0..3).map(|_| &coms[audioInd]).collect();
    let mut audiopoly_0: Vec<&_> = (0..3).map(|_| &polynomials[audioInd]).collect();
    let mut smallPt = points[3].clone();
    smallPt[numCols] = F::ZERO;
    let audiopoints_0 = vec![points[0].clone(), smallPt.clone(), points[9].clone()];
    let mut audioevals_0 = Vec::new();
    audioevals_0.push(Evaluation::new(0, 0, audiopoly_0[0].evaluate(&audiopoints_0[0])));
    audioevals_0.push(Evaluation::new(1, 1, audiopoly_0[1].evaluate(&audiopoints_0[1])));
    audioevals_0.push(Evaluation::new(2, 2, audiopoly_0[2].evaluate(&audiopoints_0[2])));

    // --- Error evaluations (2 points: transform, err_range_small) ---
    let errInd = 4;
    let mut errcom_0: Vec<&_> = (0..2).map(|_| &coms[errInd]).collect();
    let mut errpoly_0: Vec<&_> = (0..2).map(|_| &polynomials[errInd]).collect();
    let mut errSmallPt = points[10].clone();
    errSmallPt[numCols] = F::ZERO;
    let errpoints_0 = vec![points[9].clone(), errSmallPt.clone()];
    let mut errevals_0 = Vec::new();
    errevals_0.push(Evaluation::new(0, 0, errpoly_0[0].evaluate(&errpoints_0[0])));
    errevals_0.push(Evaluation::new(1, 1, errpoly_0[1].evaluate(&errpoints_0[1])));

    // --- Error h evaluations (4 points) ---
    let hErrInd = 5;
    let mut hErrcom_0: Vec<&_> = (0..4).map(|_| &coms[hErrInd]).collect();
    let mut hErrpoly_0: Vec<&_> = (0..4).map(|_| &polynomials[hErrInd]).collect();
    let hErrpoints_0 = vec![points[1].clone(), points[10].clone(), points[11].clone(), points[12].clone()];
    let mut hErrevals_0 = Vec::new();
    hErrevals_0.push(Evaluation::new(0, 0, F::ZERO));
    hErrevals_0.push(Evaluation::new(1, 1, hErrpoly_0[1].evaluate(&hErrpoints_0[1])));
    hErrevals_0.push(Evaluation::new(2, 2, hErrpoly_0[2].evaluate(&hErrpoints_0[2])));
    hErrevals_0.push(Evaluation::new(3, 3, hErrpoly_0[3].evaluate(&hErrpoints_0[3])));

    // --- Error frac evaluations (3 points) ---
    let fracErrInd = 6;
    let mut fracErrcom_0: Vec<&_> = (0..3).map(|_| &coms[fracErrInd]).collect();
    let mut fracErrpoly_0: Vec<&_> = (0..3).map(|_| &polynomials[fracErrInd]).collect();
    let fracErrpoints_0 = vec![points[13].clone(), points[14].clone(), points[15].clone()];
    let mut fracErrevals_0 = Vec::new();
    fracErrevals_0.push(Evaluation::new(0, 0, fracErrpoly_0[0].evaluate(&fracErrpoints_0[0])));
    fracErrevals_0.push(Evaluation::new(1, 1, fracErrpoly_0[1].evaluate(&fracErrpoints_0[1])));
    fracErrevals_0.push(Evaluation::new(2, 2, fracErrpoly_0[2].evaluate(&fracErrpoints_0[2])));

    // --- Error prod evaluations (4 points) ---
    let prodErrInd = 7;
    let mut prodErrcom_0: Vec<&_> = (0..4).map(|_| &coms[prodErrInd]).collect();
    let mut prodErrpoly_0: Vec<&_> = (0..4).map(|_| &polynomials[prodErrInd]).collect();
    let prodErrpoints_0 = vec![points[2].clone(), points[13].clone(), points[14].clone(), points[15].clone()];
    let mut prodErrevals_0 = Vec::new();
    prodErrevals_0.push(Evaluation::new(0, 0, prodErrpoly_0[0].evaluate(&prodErrpoints_0[0])));
    prodErrevals_0.push(Evaluation::new(1, 1, prodErrpoly_0[1].evaluate(&prodErrpoints_0[1])));
    prodErrevals_0.push(Evaluation::new(2, 2, prodErrpoly_0[2].evaluate(&prodErrpoints_0[2])));
    prodErrevals_0.push(Evaluation::new(3, 3, prodErrpoly_0[3].evaluate(&prodErrpoints_0[3])));

    // ========== WRITE EVALUATIONS AND BATCH OPEN ==========
    // Original h
    transcript.write_field_elements(hevals_0.iter().map(Evaluation::value)).unwrap();
    batch_open_one::<F, Pcs>(&pp, length, hpoly_0, hcom_0, &hpoints_0, &hevals_0, &mut transcript).unwrap();

    // Original frac
    transcript.write_field_elements(fracevals_0.iter().map(Evaluation::value)).unwrap();
    batch_open_one::<F, Pcs>(&pp, length, fracpoly_0, fraccom_0, &fracpoints_0, &fracevals_0, &mut transcript).unwrap();

    // Original prod
    transcript.write_field_elements(prodevals_0.iter().map(Evaluation::value)).unwrap();
    batch_open_one::<F, Pcs>(&pp, length, prodpoly_0, prodcom_0, &prodpoints_0, &prodevals_0, &mut transcript).unwrap();

    // Audio
    transcript.write_field_elements(audioevals_0.iter().map(Evaluation::value)).unwrap();
    batch_open_one::<F, Pcs>(&pp, length, audiopoly_0, audiocom_0, &audiopoints_0, &audioevals_0, &mut transcript).unwrap();

    // Error
    transcript.write_field_elements(errevals_0.iter().map(Evaluation::value)).unwrap();
    batch_open_one::<F, Pcs>(&pp, length, errpoly_0, errcom_0, &errpoints_0, &errevals_0, &mut transcript).unwrap();

    // Error h
    transcript.write_field_elements(hErrevals_0.iter().map(Evaluation::value)).unwrap();
    batch_open_one::<F, Pcs>(&pp, length, hErrpoly_0, hErrcom_0, &hErrpoints_0, &hErrevals_0, &mut transcript).unwrap();

    // Error frac
    transcript.write_field_elements(fracErrevals_0.iter().map(Evaluation::value)).unwrap();
    batch_open_one::<F, Pcs>(&pp, length, fracErrpoly_0, fracErrcom_0, &fracErrpoints_0, &fracErrevals_0, &mut transcript).unwrap();

    // Error prod
    transcript.write_field_elements(prodErrevals_0.iter().map(Evaluation::value)).unwrap();
    batch_open_one::<F, Pcs>(&pp, length, prodErrpoly_0, prodErrcom_0, &prodErrpoints_0, &prodErrevals_0, &mut transcript).unwrap();

    println!("prover done!");

    return transcript;
}

fn run_prover_only(input_size: usize, output_dir: &str) {
    let numCols = input_size;
    let numRows = 7;
    let length = numCols + 1;

    // setup: get prover and verifier parameters, audio hash (digest)
    let (pp, _vp, digest) = setup(input_size);

    // now we begin proving
    let prover_start = Instant::now();

    let transcript = prove(pp, input_size, numRows, numCols);

    let elapsed_prover = prover_start.elapsed();
    println!("PROVER TIME: {:?} seconds", elapsed_prover.as_millis() as f64 / 1000 as f64);

    // Serialize proof transcript to bytes
    let trans_pf = transcript.into_proof();
    println!("PROOF SIZE: {:?} bytes", trans_pf.len());

    // Write proof bytes to disk
    let out_path = Path::new(output_dir);
    fs::create_dir_all(out_path).expect("Failed to create output directory");

    fs::write(out_path.join("proof.bin"), &trans_pf)
        .expect("Failed to write proof.bin");

    // Write public inputs as JSON
    let public_inputs = serde_json::json!({
        "input_size": input_size,
        "numRows": numRows,
        "numCols": numCols,
        "numerator": 1,
        "denominator": 2,
    });
    fs::write(
        out_path.join("public_inputs.json"),
        serde_json::to_string_pretty(&public_inputs).unwrap(),
    ).expect("Failed to write public_inputs.json");

    // Write camera hash (digest) -- this is the public attestation the "camera" / recording device would sign
    fs::write(
        out_path.join("camera_hash.json"),
        serde_json::to_string(&digest).unwrap(),
    ).expect("Failed to write camera_hash.json");

    println!("Proof artifacts written to: {}", output_dir);
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage: hv_volume_brakedown_prove <size> <output_dir>");
        std::process::exit(1);
    }

    let input_size = args[1].parse::<usize>().unwrap();
    let output_dir = &args[2];

    println!("-----------------------------------------------------------------------");
    println!("Prover Only - Volume, HyperVerITAS Brakedown 127. Size: 2^{:?}\n", input_size);
    run_prover_only(input_size, output_dir);
    println!("-----------------------------------------------------------------------");
}
