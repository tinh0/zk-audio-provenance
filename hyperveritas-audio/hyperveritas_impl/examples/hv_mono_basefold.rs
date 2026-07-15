#![allow(warnings)]

mod iop_basefold;
use iop_basefold::*;

use core::num;
use proc_status::ProcStatus;
use arithmetic::bit_decompose;
use transcript::IOPTranscript;
use std::{marker::PhantomData, sync::Arc, ops::{Range, Deref}, primitive, str::FromStr, time::Instant, env, array, iter};

use ark_ec::pairing::prepare_g1;
use ark_std::{rand::{RngCore as R, rngs::{OsRng, StdRng}, CryptoRng, RngCore, SeedableRng}, test_rng};

use rand_chacha::ChaCha8Rng;

use hyperveritas_impl::{types::*, helper::*, audio::*};

use plonkish_backend::{
    pcs::{
        Evaluation, PolynomialCommitmentScheme,
        univariate::{Fri, FriProverParams, FriVerifierParams},
        multilinear::{Basefold, BasefoldCommitment, BasefoldParams, BasefoldProverParams, BasefoldVerifierParams, BasefoldExtParams, Type1Polynomial, Type2Polynomial},
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
        expression::{CommonPolynomial, Expression, Query, Rotation},
        arithmetic::{BatchInvert, BooleanHypercube, Field as myField},
        transcript::{Blake2sTranscript, FiatShamirTranscript, FieldTranscript, FieldTranscriptRead, FieldTranscriptWrite, InMemoryTranscript, TranscriptWrite},
    },
};


type Pcs = Basefold<F, Blake2s, Twenty>;
type VT = FiatShamirTranscript<Blake2s, std::io::Cursor<Vec<u8>>>;


const irredPolyTable: &[u32] = &[
    0, 0, 7, 11, 19, 37, 67, 131, 285, 529, 1033, 2053, 4179, 8219, 16707, 32771, 69643, 131081,
    262273, 524327, 1048585, 2097157, 4194307, 8388641, 16777351, 33554441, 67108935,
];

fn audio_to_basefold_field(samples: &[i32], bit_depth: u8) -> Vec<F> {
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

fn get_offset(bit_depth: u8) -> u64 {
    match bit_depth {
        8 => 0,
        16 => 32768,
        24 => 8388608,
        _ => panic!("Unsupported bit depth: {}", bit_depth),
    }
}

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

fn makePtsFullMono(numCols: usize, hashPt: Vec<F>, origRangePt: Vec<F>, errRangePt: Vec<F>, transformPt: Vec<F>) -> Vec<Vec<F>> {
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

    // [3-8] Original audio range check points (left channel)
    let orig_pts = build_range_pts(numCols, &origRangePt);
    for p in orig_pts { points.push(p); }

    // [9] Transform point (pad to numCols+1)
    let mut transPt = transformPt.clone();
    transPt.push(F::ZERO);
    points.push(transPt);

    // [10-15] Error range check points
    let err_pts = build_range_pts(numCols, &errRangePt);
    for p in err_pts { points.push(p); }

    // [16] Left small point (orig range with last=0)
    let mut smallPt = points[3].clone();
    smallPt[numCols] = F::ZERO;
    points.push(smallPt);

    // [17] Error small point (err range with last=0)
    let mut errSmallPt = points[10].clone();
    errSmallPt[numCols] = F::ZERO;
    points.push(errSmallPt);

    points
}

fn hashPreimageProveStereoAudio(
    pp: <Pcs as PolynomialCommitmentScheme<F>>::ProverParam,
    numCols: usize,
    numRows: usize,
    leftEvals: Vec<F>,
    rightEvals: Vec<F>,
    leftEvalsInt: Vec<usize>,
    maxVal: u64,
    transcript: &mut (impl TranscriptWrite<<Pcs as PolynomialCommitmentScheme<F>>::CommitmentChunk, F> + InMemoryTranscript),
) -> (
    Vec<BasefoldCommitment<F, Blake2s>>,
    Vec<F>,
    Vec<F>,
    MultilinearPolynomial<F>,
    MultilinearPolynomial<F>,
    [Vec<F>;1],
    Vec<BasefoldCommitment<F, Blake2s>>,
    Vec<MultilinearPolynomial<F>>,
    Vec<F>,
) {
    let mut rng = test_rng();

    let mut matrixA = Vec::new();
    for i in 0..128 {
        matrixA.push(ChaCha8Rng::seed_from_u64(i));
    }

    // Create audio polynomials with padding
    let mut paddedLeft = leftEvals.clone();
    paddedLeft.append(&mut vec![F::ZERO; 1 << numCols]);
    let leftPoly = MultilinearPolynomial::new(paddedLeft);

    let mut paddedRight = rightEvals.clone();
    paddedRight.append(&mut vec![F::ZERO; 1 << numCols]);
    let rightPoly = MultilinearPolynomial::new(paddedRight);

    let audioCom = Pcs::batch_commit_and_write(&pp, &[leftPoly.clone(), rightPoly.clone()], transcript);
    let leftPolySmall = MultilinearPolynomial::<F>::new(leftEvals.clone());
    let rightPolySmall = MultilinearPolynomial::<F>::new(rightEvals.clone());

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

    // Run the sumcheck on rTA * (left + alpha_stereo * right)
    let poly_0 = Expression::<F>::Polynomial(Query::new(0, Rotation::cur()));
    let poly_1 = Expression::<F>::Polynomial(Query::new(1, Rotation::cur()));
    let poly_2 = Expression::<F>::Polynomial(Query::new(2, Rotation::cur()));

    let alpha_stereo = transcript.squeeze_challenge();

    let prod = poly_0.clone() * poly_1 + Expression::Constant(alpha_stereo) * poly_0.clone() * poly_2;

    let polys = vec![rTAPoly.clone(), leftPolySmall.clone(), rightPolySmall.clone()];

    let challenges = vec![transcript.squeeze_challenge()];
    let rand_vector = transcript.squeeze_challenges(numCols);
    let ys = [rand_vector.clone()];

    let mut my_sum_left = F::ZERO;
    let mut my_sum_right = F::ZERO;
    let rta_evals = rTAPoly.evals();
    let left_evals = leftPolySmall.evals();
    let right_evals = rightPolySmall.evals();
    for i in 0..rta_evals.len() {
        my_sum_left += rta_evals[i] * left_evals[i];
        my_sum_right += rta_evals[i] * right_evals[i];
    }

    let my_sum = my_sum_left + alpha_stereo * my_sum_right;

    let proof_mm =
        <ClassicSumCheck<EvaluationsProver<F>>>::prove(&(), numCols, VirtualPolynomial::new(&prod, &polys, &challenges, &ys), my_sum, transcript).unwrap();

    // Run range check on left channel
    let mut hTable = vec![0usize; (maxVal + 2) as usize];
    for j in 0..leftEvalsInt.len() {
        if leftEvalsInt[j] <= maxVal as usize {
            hTable[leftEvalsInt[j]] += 1;
        }
    }

    let (exp_out, poly_out, chall_out, ys_out, com_out) = range_checkProverIOP(
        pp.clone(),
        numCols,
        maxVal,
        hTable,
        leftPolySmall.clone(),
        irredPolyTable[numCols].try_into().unwrap(),
        irredPolyTable[numCols+1].try_into().unwrap(),
        transcript,
        0,
    );

    let proof_range =
        <ClassicSumCheck<EvaluationsProver<F>>>::prove(&(), numCols+1, VirtualPolynomial::new(&exp_out.clone(), &poly_out.clone(), &chall_out.clone(), &[ys_out.clone()]), F::ZERO, transcript).unwrap();

    return (audioCom.unwrap(), proof_mm.0, proof_range.0, leftPoly, rightPoly, ys, com_out, poly_out, ys_out);
}

fn setup(input_size: usize) -> (<Pcs as PolynomialCommitmentScheme<F>>::ProverParam, <Pcs as PolynomialCommitmentScheme<F>>::VerifierParam, Vec<Vec<F>>) {
    println!("\nstarting setup");
    let mut rng = test_rng();

    let poly_vars = input_size + 1;

    // param setup
    let (pp, vp) = {
        let poly_size = 1 << (poly_vars);
        let param = Pcs::setup(poly_size, 4, &mut rng).unwrap();
        Pcs::trim(&param, poly_size, 4).unwrap()
    };

    // load stereo audio for given input size
    let fileName = format!("audio/StereoAudio{}.json", input_size);
    let stereoAudio = load_audio(&fileName);
    let bitDepth = stereoAudio.bit_depth;

    let leftEvals = audio_to_basefold_field(&stereoAudio.left, bitDepth);
    let rightEvals = audio_to_basefold_field(stereoAudio.right.as_ref().unwrap(), bitDepth);

    // creating separate hashes for left and right channels
    let mut matrixA = Vec::new();
    for i in 0..128 {
        matrixA.push(ChaCha8Rng::seed_from_u64(i));
    }

    let mut digestLeft = Vec::new();
    for i in 0..128 {
        let mut mySum = F::ZERO;
        for j in 0..(1 << input_size) {
            if j < leftEvals.len() {
                mySum += F::random(&mut matrixA[i]) * leftEvals[j];
            }
        }
        digestLeft.push(mySum);
    }

    let mut matrixA = Vec::new();
    for i in 0..128 {
        matrixA.push(ChaCha8Rng::seed_from_u64(i));
    }

    let mut digestRight = Vec::new();
    for i in 0..128 {
        let mut mySum = F::ZERO;
        for j in 0..(1 << input_size) {
            if j < rightEvals.len() {
                mySum += F::random(&mut matrixA[i]) * rightEvals[j];
            }
        }
        digestRight.push(mySum);
    }

    let mut digestStereo = Vec::new();
    digestStereo.push(digestLeft);
    digestStereo.push(digestRight);

    println!("setup done!\n");
    return (pp, vp, digestStereo)
}

fn prove(pp: <Pcs as PolynomialCommitmentScheme<F>>::ProverParam, input_size: usize, numRows: usize, numCols: usize)
 -> (Vec<Evaluation<F>>, (impl (TranscriptWrite<<Pcs as PolynomialCommitmentScheme<F>>::CommitmentChunk, F>) + InMemoryTranscript))
{
    println!("starting prover");
    let length = input_size + 1;

    // create a new transcript
    let mut transcript = Blake2sTranscript::new(());

    // prover loads stereo audio
    let fileName = format!("audio/StereoAudio{}.json", input_size);
    let stereoAudio = load_audio(&fileName);
    let bitDepth = stereoAudio.bit_depth;
    let maxVal = get_max_val(bitDepth);
    let offset = get_offset(bitDepth);

    let leftEvals = audio_to_basefold_field(&stereoAudio.left, bitDepth);
    let rightEvals = audio_to_basefold_field(stereoAudio.right.as_ref().unwrap(), bitDepth);

    // Get integer representation for histogram
    let leftEvalsInt: Vec<usize> = stereoAudio.left.iter()
        .map(|&s| (s as i64 + offset as i64) as usize)
        .collect();

    // Do the hash preimage proof
    let (audioCom, mmChall, rangeChall, leftPoly, rightPoly, audioYs, com_outs, poly_outs, ys_outs) =
        hashPreimageProveStereoAudio(
            pp.clone(),
            numCols,
            numRows,
            leftEvals.clone(),
            rightEvals.clone(),
            leftEvalsInt.clone(),
            maxVal,
            &mut transcript,
        );

    let mut Polies = Vec::new();

    Polies.push(leftPoly.clone());  // [0] left channel
    Polies.push(rightPoly.clone()); // [1] right channel

    // h, frac, prod from range check
    Polies.push(poly_outs[6].clone()); // [2] h
    Polies.push(poly_outs[0].clone()); // [3] frac
    Polies.push(poly_outs[1].clone()); // [4] prod

    let mut PolyComs = audioCom.clone();
    PolyComs.push(com_outs[2].clone()); // [2] h
    PolyComs.push(com_outs[0].clone()); // [3] frac
    PolyComs.push(com_outs[1].clone()); // [4] prod

    // ========== MONO ERROR POLYNOMIAL ==========
    // Load mono audio
    let monoFileName = format!("audio/Mono{}.json", input_size);
    let monoAudio = load_audio(&monoFileName);
    let monoEvals = audio_to_basefold_field(&monoAudio.left, bitDepth);

    // Compute error: error[i] = left[i] + right[i] - 2 * mono[i]
    let two = F::from(2u64);
    let mut monoError = Vec::new();
    for i in 0..(1 << numCols) {
        let leftVal = if i < leftEvals.len() { leftEvals[i] } else { F::ZERO };
        let rightVal = if i < rightEvals.len() { rightEvals[i] } else { F::ZERO };
        let monoVal = if i < monoEvals.len() { monoEvals[i] } else { F::ZERO };
        monoError.push(leftVal + rightVal - two * monoVal);
    }

    // Pad error polynomial to numCols+1 vars
    let mut paddedError = monoError.clone();
    paddedError.append(&mut vec![F::ZERO; 1 << numCols]);
    let errPoly = MultilinearPolynomial::new(paddedError);
    let errPolySmall = MultilinearPolynomial::new(monoError.clone());

    // Commit error polynomial
    let errCom = Pcs::batch_commit_and_write(&pp, &[errPoly.clone()], &mut transcript).unwrap();

    // Build error histogram for range check
    let errMaxVal: u64 = 1; // mono error is in [0, 1]
    let mut hTableErr = vec![0usize; (errMaxVal + 2) as usize];
    for i in 0..(1 << numCols) {
        let leftVal = if i < leftEvals.len() { leftEvals[i] } else { F::ZERO };
        let rightVal = if i < rightEvals.len() { rightEvals[i] } else { F::ZERO };
        let monoVal = if i < monoEvals.len() { monoEvals[i] } else { F::ZERO };
        let errVal = leftVal + rightVal - two * monoVal;
        // Error should be 0 or 1
        if errVal == F::ZERO {
            hTableErr[0] += 1;
        } else if errVal == F::ONE {
            hTableErr[1] += 1;
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
    Polies.push(errPoly.clone());             // [5] error
    Polies.push(poly_out_err[6].clone());     // [6] hErr
    Polies.push(poly_out_err[0].clone());     // [7] fracErr
    Polies.push(poly_out_err[1].clone());     // [8] prodErr

    PolyComs.append(&mut errCom.clone());     // [5] errCom
    PolyComs.push(com_out_err[2].clone());    // [6] hErrCom
    PolyComs.push(com_out_err[0].clone());    // [7] fracErrCom
    PolyComs.push(com_out_err[1].clone());    // [8] prodErrCom

    // Squeeze random transform point
    let transformPt: Vec<F> = transcript.squeeze_challenges(numCols);

    // Build evaluation points
    let polynomials = Polies;
    let coms = PolyComs;
    let points = makePtsFullMono(numCols, mmChall.clone(), rangeChall.clone(), proof_err_range.0.clone(), transformPt.clone());

    // ========== BUILD EVALUATIONS ==========
    let mut evals = Vec::new();

    // --- Original h evaluations (poly=2) at points [1,3,4,5] ---
    evals.push(Evaluation::new(2, 1, F::ZERO));
    evals.push(Evaluation::new(2, 3, polynomials[2].evaluate(&points[3])));
    evals.push(Evaluation::new(2, 4, polynomials[2].evaluate(&points[4])));
    evals.push(Evaluation::new(2, 5, polynomials[2].evaluate(&points[5])));

    // --- Original frac evaluations (poly=3) at points [6,7,8] ---
    evals.push(Evaluation::new(3, 6, polynomials[3].evaluate(&points[6])));
    evals.push(Evaluation::new(3, 7, polynomials[3].evaluate(&points[7])));
    evals.push(Evaluation::new(3, 8, polynomials[3].evaluate(&points[8])));

    // --- Original prod evaluations (poly=4) at points [2,6,7,8] ---
    evals.push(Evaluation::new(4, 2, polynomials[4].evaluate(&points[2])));
    evals.push(Evaluation::new(4, 6, polynomials[4].evaluate(&points[6])));
    evals.push(Evaluation::new(4, 7, polynomials[4].evaluate(&points[7])));
    evals.push(Evaluation::new(4, 8, polynomials[4].evaluate(&points[8])));

    // --- Left channel evaluations (poly=0) at points [0,16,9] ---
    evals.push(Evaluation::new(0, 0, polynomials[0].evaluate(&points[0])));
    evals.push(Evaluation::new(0, 16, polynomials[0].evaluate(&points[16])));
    evals.push(Evaluation::new(0, 9, polynomials[0].evaluate(&points[9])));

    // --- Right channel evaluations (poly=1) at points [0,9] ---
    evals.push(Evaluation::new(1, 0, polynomials[1].evaluate(&points[0])));
    evals.push(Evaluation::new(1, 9, polynomials[1].evaluate(&points[9])));

    // --- Error evaluations (poly=5) at points [9,17] ---
    evals.push(Evaluation::new(5, 9, polynomials[5].evaluate(&points[9])));
    evals.push(Evaluation::new(5, 17, polynomials[5].evaluate(&points[17])));

    // --- Error h evaluations (poly=6) at points [1,10,11,12] ---
    evals.push(Evaluation::new(6, 1, F::ZERO));
    evals.push(Evaluation::new(6, 10, polynomials[6].evaluate(&points[10])));
    evals.push(Evaluation::new(6, 11, polynomials[6].evaluate(&points[11])));
    evals.push(Evaluation::new(6, 12, polynomials[6].evaluate(&points[12])));

    // --- Error frac evaluations (poly=7) at points [13,14,15] ---
    evals.push(Evaluation::new(7, 13, polynomials[7].evaluate(&points[13])));
    evals.push(Evaluation::new(7, 14, polynomials[7].evaluate(&points[14])));
    evals.push(Evaluation::new(7, 15, polynomials[7].evaluate(&points[15])));

    // --- Error prod evaluations (poly=8) at points [2,13,14,15] ---
    evals.push(Evaluation::new(8, 2, polynomials[8].evaluate(&points[2])));
    evals.push(Evaluation::new(8, 13, polynomials[8].evaluate(&points[13])));
    evals.push(Evaluation::new(8, 14, polynomials[8].evaluate(&points[14])));
    evals.push(Evaluation::new(8, 15, polynomials[8].evaluate(&points[15])));

    // Write evals to transcript and batch open
    transcript.write_field_elements(evals.iter().map(Evaluation::value)).unwrap();

    Pcs::batch_open(
        &pp,
        &polynomials,
        &coms,
        &points,
        &evals,
        &mut transcript,
    ).unwrap();

    println!("prover done!");

    return (evals, transcript)
}

fn verify(
    vp: <Pcs as PolynomialCommitmentScheme<F>>::VerifierParam,
    numRows: usize,
    numCols: usize,
    evals: Vec<Evaluation<F>>,
    cameraHashStereo: Vec<Vec<F>>,
    transcript: (impl (TranscriptWrite<<Pcs as PolynomialCommitmentScheme<F>>::CommitmentChunk, F>) + InMemoryTranscript),
    input_size: usize,
) {
    println!("\nstarting verifier");

    let mut commits = Vec::new();

    // Load mono audio for verification
    let monoFileName = format!("audio/Mono{}.json", input_size);
    let monoAudio = load_audio(&monoFileName);
    let bitDepth = monoAudio.bit_depth;
    let maxVal = get_max_val(bitDepth);
    let offset = get_offset(bitDepth);
    let errMaxVal: u64 = 1;

    let monoEvals = audio_to_basefold_field(&monoAudio.left, bitDepth);

    let trans_pf = transcript.into_proof();

    println!("PROOF SIZE: {:?} bytes", trans_pf.len());

    let mut ver_transcript = Blake2sTranscript::from_proof((), trans_pf.as_slice());

    // Read stereo audio commitments (left and right)
    commits.append(&mut Pcs::read_commitments(&vp, 2, &mut ver_transcript).unwrap());

    // ========== HASH PREIMAGE VERIFICATION ==========
    let frievaldRandVecrTA = <VT as FieldTranscript<F>>::squeeze_challenges(&mut ver_transcript, 1 << numRows);

    // Squeeze alpha for batching stereo channels
    let alpha_stereo = <VT as FieldTranscript<F>>::squeeze_challenge(&mut ver_transcript);

    let challenges: Vec<F> = vec![<VT as FieldTranscript<F>>::squeeze_challenge(&mut ver_transcript)];
    let rand_vector = <VT as FieldTranscript<F>>::squeeze_challenges(&mut ver_transcript, numCols);

    let mut mySumLeft = F::ZERO;
    let mut mySumRight = F::ZERO;
    for j in 0..1 << numRows {
        mySumLeft += frievaldRandVecrTA[j] * cameraHashStereo[0][j];
        mySumRight += frievaldRandVecrTA[j] * cameraHashStereo[1][j];
    }
    let mySumVal = mySumLeft + alpha_stereo * mySumRight;
    let verResCameraHash = ClassicSumCheck::<EvaluationsProver<F>>::verify(&(), numCols, 2, mySumVal, &mut ver_transcript).unwrap();
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
    let points = makePtsFullMono(numCols, hashPt.clone(), origRangePt.clone(), errRangePt.clone(), transformPt.clone());

    // commits layout: [0]=left, [1]=right, [2]=h, [3]=frac, [4]=prod, [5]=err, [6]=hErr, [7]=fracErr, [8]=prodErr

    // ========== READ AND VERIFY PCS OPENINGS ==========
    let evals2: Vec<F> = ver_transcript.read_field_elements(evals.len()).unwrap();
    let mut my_evals = Vec::new();
    for i in 0..evals.len() {
        let mut newEval = evals[i].clone();
        newEval.value = evals2[i];
        my_evals.push(newEval);
    }

    Pcs::batch_verify(
        &vp,
        &commits,
        &points,
        &my_evals,
        &mut ver_transcript,
    ).unwrap();

    // ========== VERIFY RELATIONSHIPS ==========
    let mut success = true;

    // Extract evaluation values by index:
    // [0-3]: h evals (zero, range, fiddle, zero_pt)
    // [4-6]: frac evals (range, ||0, ||1)
    // [7-10]: prod evals (final, range, ||0, ||1)
    // [11-13]: left evals (hash, small, transform)
    // [14-15]: right evals (hash, transform)
    // [16-17]: err evals (transform, small)
    // [18-21]: hErr evals (zero, range, fiddle, zero_pt)
    // [22-24]: fracErr evals (range, ||0, ||1)
    // [25-28]: prodErr evals (final, range, ||0, ||1)

    let h_evals = &evals2[0..4];
    let frac_evals = &evals2[4..7];
    let prod_evals = &evals2[7..11];
    let left_evals = &evals2[11..14];
    let right_evals = &evals2[14..16];
    let err_evals = &evals2[16..18];
    let hErr_evals = &evals2[18..22];
    let fracErr_evals = &evals2[22..25];
    let prodErr_evals = &evals2[25..29];

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
    let RHS = left_evals[0] + alpha_stereo * right_evals[0];
    success = success && (verResCameraHash.0 == LHS * RHS);

    // --- Mono transformation check ---
    // Verify: left(alpha) + right(alpha) == 2 * mono(alpha) + error(alpha)
    let leftAtPt = left_evals[2]; // left at transform point
    let rightAtPt = right_evals[1]; // right at transform point
    let errAtPt = err_evals[0];    // error at transform point

    // Verifier locally evaluates the public mono audio at the transform point
    let monoAudioPoly = MultilinearPolynomial::new(monoEvals.clone());
    let monoAtPt = monoAudioPoly.evaluate(&transformPt);

    let two = F::from(2u64);
    let expectedLHS = leftAtPt + rightAtPt;
    let computedRHS = two * monoAtPt + errAtPt;
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
        let leftAtAlphaSmall = left_evals[1];
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

        let mut f1 = alpha1 + ((F::ONE - lastVal) * leftAtAlphaSmall + lastVal * polyTable.evaluate(&myRandSmall));
        f1 += alpha2 * ((F::ONE - lastVal) * leftAtAlphaSmall + lastVal * polyPlusOneTable.evaluate(&myRandSmall));

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

    // Build embedded tables for error range check (maxVal = errMaxVal = 1)
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

fn run_whole_system_mono_basefold(input_size: usize) {
    let numCols = input_size;
    let numRows = 7;
    let length = numCols + 1;

    // setup
    let (pp, vp, digest) = setup(input_size);

    // prove
    let prover_start = Instant::now();
    let (evals, transcript) = prove(pp, input_size, numRows, numCols);
    let elapsed_prover = prover_start.elapsed();
    println!("PROVER TIME: {:?} seconds", elapsed_prover.as_millis() as f64 / 1000.0);

    // verify
    let verifier_start = Instant::now();
    verify(vp, numRows, numCols, evals, digest, transcript, input_size);
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
        println!("Full System Mono, HyperVerITAS Basefold. Size: 2^{:?}\n", i);
        let _res = run_whole_system_mono_basefold(i);
        println!("-----------------------------------------------------------------------");
    }
}
