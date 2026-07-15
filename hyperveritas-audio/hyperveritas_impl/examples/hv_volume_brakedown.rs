#![allow(warnings)]

mod iop_brakedown;
use iop_brakedown::*;

use core::num;
use proc_status::ProcStatus;
use arithmetic::bit_decompose;
use transcript::IOPTranscript;
use std::{marker::PhantomData, sync::Arc, ops::{Range, Deref}, primitive, str::FromStr, time::Instant, env, array, iter};

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
 -> (Vec<Vec<Evaluation<F>>>, Vec<Vec<Evaluation<F>>>, Vec<Vec<Evaluation<F>>>, Vec<Vec<Evaluation<F>>>,
     Vec<Vec<Evaluation<F>>>, Vec<Vec<Evaluation<F>>>, Vec<Vec<Evaluation<F>>>, Vec<Vec<Evaluation<F>>>,
     (impl (TranscriptWrite<<Pcs as PolynomialCommitmentScheme<F>>::CommitmentChunk, F>) + InMemoryTranscript))
{
    println!("starting prover");
    let length = input_size + 1;

    // Benchmark harness: 50% volume (matches upstream default; same scale
    // used by all four baselines for direct comparison).
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
    // Padded entries have error = num*0 - denom*0 + offset_adj = offset_adj
    // But padded audio is 0 and padded volume is 0, so error = offset_adj
    // For 8-bit (offset=0): error = 0. For signed: error = (denom-num)*offset
    // Since we pad with zeros on both sides, the error for padded entries is offset_adjustment
    // which for 8-bit is 0. For signed audio, we need to handle this.
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
    // Following the crop brakedown pattern: separate vectors per polynomial group

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

    let mut hevals_vec = vec![hevals_0];

    // --- Original frac evaluations (3 points) ---
    let fracInd = 2;
    let mut fraccom_0: Vec<&_> = (0..3).map(|_| &coms[fracInd]).collect();
    let mut fracpoly_0: Vec<&_> = (0..3).map(|_| &polynomials[fracInd]).collect();
    let fracpoints_0 = vec![points[6].clone(), points[7].clone(), points[8].clone()];
    let mut fracevals_0 = Vec::new();
    fracevals_0.push(Evaluation::new(0, 0, fracpoly_0[0].evaluate(&fracpoints_0[0])));
    fracevals_0.push(Evaluation::new(1, 1, fracpoly_0[1].evaluate(&fracpoints_0[1])));
    fracevals_0.push(Evaluation::new(2, 2, fracpoly_0[2].evaluate(&fracpoints_0[2])));

    let mut fracevals_vec = vec![fracevals_0];

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

    let mut prodevals_vec = vec![prodevals_0];

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

    let mut audioevals_vec = vec![audioevals_0];

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

    let mut errevals_vec = vec![errevals_0];

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

    let mut hErrevals_vec = vec![hErrevals_0];

    // --- Error frac evaluations (3 points) ---
    let fracErrInd = 6;
    let mut fracErrcom_0: Vec<&_> = (0..3).map(|_| &coms[fracErrInd]).collect();
    let mut fracErrpoly_0: Vec<&_> = (0..3).map(|_| &polynomials[fracErrInd]).collect();
    let fracErrpoints_0 = vec![points[13].clone(), points[14].clone(), points[15].clone()];
    let mut fracErrevals_0 = Vec::new();
    fracErrevals_0.push(Evaluation::new(0, 0, fracErrpoly_0[0].evaluate(&fracErrpoints_0[0])));
    fracErrevals_0.push(Evaluation::new(1, 1, fracErrpoly_0[1].evaluate(&fracErrpoints_0[1])));
    fracErrevals_0.push(Evaluation::new(2, 2, fracErrpoly_0[2].evaluate(&fracErrpoints_0[2])));

    let mut fracErrevals_vec = vec![fracErrevals_0];

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

    let mut prodErrevals_vec = vec![prodErrevals_0];

    // ========== WRITE EVALUATIONS AND BATCH OPEN ==========
    // Original h
    transcript.write_field_elements(hevals_vec[0].iter().map(Evaluation::value)).unwrap();
    batch_open_one::<F, Pcs>(&pp, length, hpoly_0, hcom_0, &hpoints_0, &hevals_vec[0], &mut transcript).unwrap();

    // Original frac
    transcript.write_field_elements(fracevals_vec[0].iter().map(Evaluation::value)).unwrap();
    batch_open_one::<F, Pcs>(&pp, length, fracpoly_0, fraccom_0, &fracpoints_0, &fracevals_vec[0], &mut transcript).unwrap();

    // Original prod
    transcript.write_field_elements(prodevals_vec[0].iter().map(Evaluation::value)).unwrap();
    batch_open_one::<F, Pcs>(&pp, length, prodpoly_0, prodcom_0, &prodpoints_0, &prodevals_vec[0], &mut transcript).unwrap();

    // Audio
    transcript.write_field_elements(audioevals_vec[0].iter().map(Evaluation::value)).unwrap();
    batch_open_one::<F, Pcs>(&pp, length, audiopoly_0, audiocom_0, &audiopoints_0, &audioevals_vec[0], &mut transcript).unwrap();

    // Error
    transcript.write_field_elements(errevals_vec[0].iter().map(Evaluation::value)).unwrap();
    batch_open_one::<F, Pcs>(&pp, length, errpoly_0, errcom_0, &errpoints_0, &errevals_vec[0], &mut transcript).unwrap();

    // Error h
    transcript.write_field_elements(hErrevals_vec[0].iter().map(Evaluation::value)).unwrap();
    batch_open_one::<F, Pcs>(&pp, length, hErrpoly_0, hErrcom_0, &hErrpoints_0, &hErrevals_vec[0], &mut transcript).unwrap();

    // Error frac
    transcript.write_field_elements(fracErrevals_vec[0].iter().map(Evaluation::value)).unwrap();
    batch_open_one::<F, Pcs>(&pp, length, fracErrpoly_0, fracErrcom_0, &fracErrpoints_0, &fracErrevals_vec[0], &mut transcript).unwrap();

    // Error prod
    transcript.write_field_elements(prodErrevals_vec[0].iter().map(Evaluation::value)).unwrap();
    batch_open_one::<F, Pcs>(&pp, length, prodErrpoly_0, prodErrcom_0, &prodErrpoints_0, &prodErrevals_vec[0], &mut transcript).unwrap();

    println!("prover done!");

    return (hevals_vec, fracevals_vec, prodevals_vec, audioevals_vec, errevals_vec, hErrevals_vec, fracErrevals_vec, prodErrevals_vec, transcript);
}

fn verify(
    vp: <MultilinearBrakedown<F, Blake2s, BrakedownSpec6> as PolynomialCommitmentScheme<F>>::VerifierParam,
    numRows: usize,
    numCols: usize,
    hevals_vec: Vec<Vec<Evaluation<F>>>,
    fracevals_vec: Vec<Vec<Evaluation<F>>>,
    prodevals_vec: Vec<Vec<Evaluation<F>>>,
    audioevals_vec: Vec<Vec<Evaluation<F>>>,
    errevals_vec: Vec<Vec<Evaluation<F>>>,
    hErrevals_vec: Vec<Vec<Evaluation<F>>>,
    fracErrevals_vec: Vec<Vec<Evaluation<F>>>,
    prodErrevals_vec: Vec<Vec<Evaluation<F>>>,
    cameraHash: Vec<F>,
    transcript: (impl (TranscriptWrite<<MultilinearBrakedown<F, Blake2s, BrakedownSpec6> as PolynomialCommitmentScheme<F>>::CommitmentChunk, F>) + InMemoryTranscript),
    input_size: usize,
) {
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

    let trans_pf = transcript.into_proof();

    println!("PROOF SIZE: {:?} bytes", trans_pf.len());

    let mut ver_transcript = Blake2sTranscript::from_proof((), trans_pf.as_slice());

    // Read audio commitment
    commits.append(&mut Pcs::read_commitments(&vp, 1, &mut ver_transcript).unwrap());

    // ========== HASH PREIMAGE VERIFICATION (unchanged) ==========
    let frievaldRandVecrTA = <VT as FieldTranscript<F>>::squeeze_challenges(&mut ver_transcript, 1 << numRows);
    let challenges: Vec<F> = vec![<VT as FieldTranscript<F>>::squeeze_challenge(&mut ver_transcript)];
    let rand_vector = <VT as FieldTranscript<F>>::squeeze_challenges(&mut ver_transcript, numCols);

    let mut mySumVal = F::ZERO;
    for j in 0..1 << numRows {
        mySumVal += frievaldRandVecrTA[j] * cameraHash[j];
    }
    let verResCameraHash = ClassicSumCheck::<EvaluationsProver<F>>::verify(&(), numCols, 2, mySumVal, &mut ver_transcript).unwrap();
    let hashPt = verResCameraHash.clone().1;

    // ========== ORIGINAL RANGE CHECK VERIFICATION (unchanged) ==========
    commits.append(&mut Pcs::read_commitments(&vp, 1, &mut ver_transcript).unwrap());
    let alpha1 = <VT as FieldTranscript<F>>::squeeze_challenge(&mut ver_transcript);
    let alpha2 = <VT as FieldTranscript<F>>::squeeze_challenge(&mut ver_transcript);
    commits.append(&mut Pcs::read_commitments(&vp, 2, &mut ver_transcript).unwrap());

    let beta = <VT as FieldTranscript<F>>::squeeze_challenge(&mut ver_transcript);
    let challenges_range: Vec<F> = vec![<VT as FieldTranscript<F>>::squeeze_challenge(&mut ver_transcript)];
    let rand_vector_range = <VT as FieldTranscript<F>>::squeeze_challenges(&mut ver_transcript, numCols+1);

    let verResRange = ClassicSumCheck::<EvaluationsProver<F>>::verify(&(), numCols+1, 3, F::ZERO, &mut ver_transcript).unwrap();
    let origRangePt = verResRange.1.clone();

    // ========== ERROR RANGE CHECK VERIFICATION (NEW) ==========
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

    // ========== READ AND VERIFY PCS OPENINGS ==========
    // --- Original h ---
    let hpoints_0 = vec![points[1].clone(), points[3].clone(), points[4].clone(), points[5].clone()];
    let h_evals: Vec<F> = ver_transcript.read_field_elements(hevals_vec[0].len()).unwrap();
    let mut hevals2 = Vec::new();
    for j in 0..hevals_vec[0].len() {
        let mut newEval = hevals_vec[0][j].clone();
        newEval.value = h_evals[j];
        hevals2.push(newEval);
    }
    batch_verify_one::<F, Pcs>(&vp, numCols+1, commits[1].clone(), &hpoints_0, &hevals2, &mut ver_transcript).unwrap();

    // --- Original frac ---
    let fracpoints_0 = vec![points[6].clone(), points[7].clone(), points[8].clone()];
    let frac_evals: Vec<F> = ver_transcript.read_field_elements(fracevals_vec[0].len()).unwrap();
    let mut fracevals2 = Vec::new();
    for j in 0..fracevals_vec[0].len() {
        let mut newEval = fracevals_vec[0][j].clone();
        newEval.value = frac_evals[j];
        fracevals2.push(newEval);
    }
    batch_verify_one::<F, Pcs>(&vp, numCols+1, commits[2].clone(), &fracpoints_0, &fracevals2, &mut ver_transcript).unwrap();

    // --- Original prod ---
    let prodpoints_0 = vec![points[2].clone(), points[6].clone(), points[7].clone(), points[8].clone()];
    let prod_evals: Vec<F> = ver_transcript.read_field_elements(prodevals_vec[0].len()).unwrap();
    let mut prodevals2 = Vec::new();
    for j in 0..prodevals_vec[0].len() {
        let mut newEval = prodevals_vec[0][j].clone();
        newEval.value = prod_evals[j];
        prodevals2.push(newEval);
    }
    batch_verify_one::<F, Pcs>(&vp, numCols+1, commits[3].clone(), &prodpoints_0, &prodevals2, &mut ver_transcript).unwrap();

    // --- Audio ---
    let mut smallPt = points[3].clone();
    smallPt[numCols] = F::ZERO;
    let audiopoints_0 = vec![points[0].clone(), smallPt.clone(), points[9].clone()];
    let audio_evals: Vec<F> = ver_transcript.read_field_elements(audioevals_vec[0].len()).unwrap();
    let mut audioevals2 = Vec::new();
    for j in 0..audioevals_vec[0].len() {
        let mut newEval = audioevals_vec[0][j].clone();
        newEval.value = audio_evals[j];
        audioevals2.push(newEval);
    }
    batch_verify_one::<F, Pcs>(&vp, numCols+1, commits[0].clone(), &audiopoints_0, &audioevals2, &mut ver_transcript).unwrap();

    // --- Error ---
    let mut errSmallPt = points[10].clone();
    errSmallPt[numCols] = F::ZERO;
    let errpoints_0 = vec![points[9].clone(), errSmallPt.clone()];
    let err_evals: Vec<F> = ver_transcript.read_field_elements(errevals_vec[0].len()).unwrap();
    let mut errevals2 = Vec::new();
    for j in 0..errevals_vec[0].len() {
        let mut newEval = errevals_vec[0][j].clone();
        newEval.value = err_evals[j];
        errevals2.push(newEval);
    }
    batch_verify_one::<F, Pcs>(&vp, numCols+1, commits[4].clone(), &errpoints_0, &errevals2, &mut ver_transcript).unwrap();

    // --- Error h ---
    let hErrpoints_0 = vec![points[1].clone(), points[10].clone(), points[11].clone(), points[12].clone()];
    let hErr_evals: Vec<F> = ver_transcript.read_field_elements(hErrevals_vec[0].len()).unwrap();
    let mut hErrevals2 = Vec::new();
    for j in 0..hErrevals_vec[0].len() {
        let mut newEval = hErrevals_vec[0][j].clone();
        newEval.value = hErr_evals[j];
        hErrevals2.push(newEval);
    }
    batch_verify_one::<F, Pcs>(&vp, numCols+1, commits[5].clone(), &hErrpoints_0, &hErrevals2, &mut ver_transcript).unwrap();

    // --- Error frac ---
    let fracErrpoints_0 = vec![points[13].clone(), points[14].clone(), points[15].clone()];
    let fracErr_evals: Vec<F> = ver_transcript.read_field_elements(fracErrevals_vec[0].len()).unwrap();
    let mut fracErrevals2 = Vec::new();
    for j in 0..fracErrevals_vec[0].len() {
        let mut newEval = fracErrevals_vec[0][j].clone();
        newEval.value = fracErr_evals[j];
        fracErrevals2.push(newEval);
    }
    batch_verify_one::<F, Pcs>(&vp, numCols+1, commits[6].clone(), &fracErrpoints_0, &fracErrevals2, &mut ver_transcript).unwrap();

    // --- Error prod ---
    let prodErrpoints_0 = vec![points[2].clone(), points[13].clone(), points[14].clone(), points[15].clone()];
    let prodErr_evals: Vec<F> = ver_transcript.read_field_elements(prodErrevals_vec[0].len()).unwrap();
    let mut prodErrevals2 = Vec::new();
    for j in 0..prodErrevals_vec[0].len() {
        let mut newEval = prodErrevals_vec[0][j].clone();
        newEval.value = prodErr_evals[j];
        prodErrevals2.push(newEval);
    }
    batch_verify_one::<F, Pcs>(&vp, numCols+1, commits[7].clone(), &prodErrpoints_0, &prodErrevals2, &mut ver_transcript).unwrap();

    // ========== VERIFY RELATIONSHIPS ==========
    let mut success = true;

    // --- Hash preimage binding (unchanged) ---
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
}

fn run_whole_system_volume_brake(input_size: usize) {
    let numCols = input_size;
    let numRows = 7;
    let length = numCols + 1;

    // setup
    let (pp, vp, digest) = setup(input_size);

    // prove
    let prover_start = Instant::now();
    let (hevals_vec, fracevals_vec, prodevals_vec, audioevals_vec, errevals_vec, hErrevals_vec, fracErrevals_vec, prodErrevals_vec, transcript) = prove(pp, input_size, numRows, numCols);
    let elapsed_prover = prover_start.elapsed();
    println!("PROVER TIME: {:?} seconds", elapsed_prover.as_millis() as f64 / 1000.0);

    // verify
    let verifier_start = Instant::now();
    verify(vp, numRows, numCols, hevals_vec, fracevals_vec, prodevals_vec, audioevals_vec, errevals_vec, hErrevals_vec, fracErrevals_vec, prodErrevals_vec, digest, transcript, input_size);
    let elapsed_verifier = verifier_start.elapsed();
    println!("VERIFIER TIME: {:?} seconds", elapsed_verifier.as_millis() as f64 / 1000.0);
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let first_size = args[1].parse::<usize>().unwrap();
    let mut last_size = first_size;
    if args.len() == 3 {
        last_size = args[2].parse::<usize>().unwrap();
    }

    for i in first_size..last_size+1 {
        println!("-----------------------------------------------------------------------");
        println!("Full System Volume, HyperVerITAS Brakedown 127. Size: 2^{:?}\n", i);
        let _res = run_whole_system_volume_brake(i);
        println!("-----------------------------------------------------------------------");
    }
}
