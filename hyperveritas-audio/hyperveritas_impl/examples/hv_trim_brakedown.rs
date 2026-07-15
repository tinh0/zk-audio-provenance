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

pub fn matSparseMultVecBrakedown(
    numRows: usize,
    numCols: usize,
    sprseRep: &[Vec<(usize, F)>],
    r: &[F],
) -> Vec<F> {
    let mut Ar = Vec::new();
    for i in 0..numRows {
        let mut mySum = F::ZERO;
        for j in 0..sprseRep[i].len() {
            mySum += sprseRep[i][j].1 * r[sprseRep[i][j].0];
        }
        Ar.push(mySum);
    }
    return Ar;
}

fn makePtsFullTrim(numCols: usize, vals: Vec<Vec<F>>) -> Vec<Vec<F>> {
    let mut points = Vec::new();

    // Original sumcheck point
    let mut origPt: Vec<F> = vals[0].clone();
    origPt.push(F::ZERO);
    points.push(origPt.clone());

    // 0 vector, used for h
    let pt0: Vec<F> = vec![F::ZERO; numCols+1];
    points.push(pt0.clone());

    // 1..10 vector, used for prod
    let mut final_query = vec![F::ONE; numCols+1];
    final_query[0] = F::ZERO;
    points.push(final_query);

    // Eval for range check
    let myRand = vals[1].clone();
    points.push(myRand.clone());

    // point 1 for h_{+1}
    let galoisRep = irredPolyTable[numCols + 1] - (1 << (numCols+1));
    let (fiddle, zero, startVal) = galoisifyPt((numCols+1) as u32, galoisRep, myRand.clone());

    points.push(fiddle);
    // point 2 for h_{+1}
    points.push(zero);

    // Rand point used for prod and frac polies
    points.push(myRand.clone());

    // Randpoint but last is 0
    let mut ptRand = Vec::new();
    ptRand.push(F::ZERO);
    for i in 0..myRand.clone().len()-1 {
        ptRand.push(myRand[i]);
    }
    points.push(ptRand.clone());
    // Randpoint but last is 1
    ptRand[0] = F::ONE;
    points.push(ptRand.clone());

    // Transform point (pad to numCols + 1)
    let mut transPt: Vec<F> = vals[2].clone();
    transPt.push(F::ZERO);
    points.push(transPt.clone());

    return points;
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

pub fn affineTrimProve(
    pp: <MultilinearBrakedown<F, Blake2s, BrakedownSpec6> as PolynomialCommitmentScheme<F>>::ProverParam,
    nvOrig: usize,
    nvTrim: usize,
    origAudio: MultilinearPolynomial<F>,
    trimmedAudio: MultilinearPolynomial<F>,
    startSample: usize,
    endSample: usize,
    transcript: &mut (impl TranscriptWrite<<MultilinearBrakedown<F, Blake2s, BrakedownSpec6> as PolynomialCommitmentScheme<F>>::CommitmentChunk, F> + InMemoryTranscript),
) -> (Vec<MultilinearPolynomial<F>>, [Vec<F>; 1], (Vec<F>, Vec<F>), F)
{
    let trimLength = endSample - startSample;

    // Create 1D permutation for trim
    let mut trimPerm = Vec::new();
    for _ in 0..1 << nvOrig {
        trimPerm.push(Vec::new());
    }
    for i in 0..trimLength {
        let origIdx = startSample + i;
        if origIdx < (1 << nvOrig) {
            trimPerm[origIdx].push((i, F::ONE));
        }
    }

    let frievaldRandVec = transcript.squeeze_challenges(1 << nvTrim);

    let permTimesR = matSparseMultVecBrakedown(1 << nvOrig, 1 << nvTrim, &trimPerm, &frievaldRandVec);

    let permTimesRPoly = MultilinearPolynomial::new(permTimesR.clone());

    let perm_poly = Expression::<F>::Polynomial(Query::new(0, Rotation::cur()));
    let audio_poly = Expression::<F>::Polynomial(Query::new(1, Rotation::cur()));

    let polys = vec![permTimesRPoly.clone(), origAudio.clone()];

    let juicer = perm_poly * audio_poly;

    let challenges = vec![transcript.squeeze_challenge()];
    let rand_vector = transcript.squeeze_challenges(nvOrig);

    let ys = [rand_vector.clone()];

    let mut my_sum = F::ZERO;
    for i in 0..1 << nvOrig {
        my_sum += polys[0].evals()[i] * polys[1].evals()[i];
    }

    let proof_trim = <ClassicSumCheck<EvaluationsProver<F>>>::prove(&(), nvOrig, VirtualPolynomial::new(&juicer.clone(), &polys.clone(), &challenges.clone(), &ys.clone()), my_sum, transcript).unwrap();

    return (polys.clone(), ys.clone(), proof_trim, my_sum)
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

fn prove(pp: <Pcs as PolynomialCommitmentScheme<F>>::ProverParam, input_size: usize, numRows: usize, numCols: usize, nvTrim: usize)
 -> (usize, usize,
     Vec<Vec<Evaluation<F>>>, Vec<Vec<Evaluation<F>>>, Vec<Vec<Evaluation<F>>>, Vec<Vec<Evaluation<F>>>,
     (impl (TranscriptWrite<<Pcs as PolynomialCommitmentScheme<F>>::CommitmentChunk, F>) + InMemoryTranscript))
{
    println!("starting prover");
    let length = input_size + 1;

    // create a new transcript
    let mut transcript = Blake2sTranscript::new(());

    // prover loads audio
    let fileName = format!("audio/Audio{}.json", input_size);
    let origAudio = load_audio(&fileName);
    let bitDepth = origAudio.bit_depth;
    let maxVal = get_max_val(bitDepth);

    let audioEvals = audio_to_brakedown_field(&origAudio.left, bitDepth);

    // Get integer representation for histogram
    let offset: i64 = match bitDepth {
        8 => 0,
        16 => 32768,
        24 => 8388608,
        _ => panic!("Unsupported bit depth"),
    };
    let audioEvalsInt: Vec<usize> = origAudio.left.iter()
        .map(|&s| (s as i64 + offset) as usize)
        .collect();

    // Do the hash preimage proof
    let (audioCom, mmChall, rangeChall, audioPoly, audioYs, com_outs, poly_outs, ys_outs) =
        hashPreimageProveAudio(
            pp.clone(),
            numCols,
            numRows,
            audioEvals.clone(),
            audioEvalsInt,
            maxVal,
            &mut transcript,
        );

    let mut Polies = Vec::new();

    Polies.push(audioPoly.clone()); // already exactly the committed polynomial

    // h, frac, prod from range check
    Polies.push(poly_outs[6].clone()); // h
    Polies.push(poly_outs[0].clone()); // frac
    Polies.push(poly_outs[1].clone()); // prod

    let mut PolyComs = audioCom.clone();
    PolyComs.push(com_outs[2].clone()); // h
    PolyComs.push(com_outs[0].clone()); // frac
    PolyComs.push(com_outs[1].clone()); // prod

    // Load trimmed audio
    let trimFileName = format!("audio/Trim{}.json", input_size);
    let trimAudio = load_audio(&trimFileName);

    let origAudioPoly = MultilinearPolynomial::new(audioEvals.clone());
    let trimAudioPoly = MultilinearPolynomial::new(audio_to_brakedown_field(&trimAudio.left, bitDepth));

    let startSample = 0;
    let endSample = trimAudio.num_samples;

    let (trim_polys, ys_trim, proof_trim, trim_sum) = affineTrimProve(
        pp.clone(),
        numCols,
        nvTrim,
        origAudioPoly,
        trimAudioPoly,
        startSample,
        endSample,
        &mut transcript
    );

    let mut polynomials = Polies;
    let mut coms = PolyComs;
    let mut my_alphas = Vec::new();
    my_alphas.push(mmChall.clone());
    my_alphas.push(rangeChall.clone());
    my_alphas.push(proof_trim.0.clone());
    let points = makePtsFullTrim(numCols, my_alphas.clone());

    let mut hcoms_vec = Vec::new();
    let mut hpolys_vec = Vec::new();
    let mut hpoints_vec = Vec::new();
    let mut hevals_vec = Vec::new();

    let mut fraccoms_vec = Vec::new();
    let mut fracpolys_vec = Vec::new();
    let mut fracpoints_vec = Vec::new();
    let mut fracevals_vec = Vec::new();

    let mut prodcoms_vec = Vec::new();
    let mut prodpolys_vec = Vec::new();
    let mut prodpoints_vec = Vec::new();
    let mut prodevals_vec = Vec::new();

    let mut audiocoms_vec = Vec::new();
    let mut audiopolys_vec = Vec::new();
    let mut audiopoints_vec = Vec::new();
    let mut audioevals_vec = Vec::new();

    // H evaluations
    let hInd = 1;
    let mut hcom_0 = Vec::new();
    hcom_0.push(&coms[hInd]);
    hcom_0.push(&coms[hInd]);
    hcom_0.push(&coms[hInd]);
    hcom_0.push(&coms[hInd]);

    let mut hpoly_0 = Vec::new();
    hpoly_0.push(&polynomials[hInd]);
    hpoly_0.push(&polynomials[hInd]);
    hpoly_0.push(&polynomials[hInd]);
    hpoly_0.push(&polynomials[hInd]);

    let mut hpoints_0 = Vec::new();
    hpoints_0.push(points[1].clone()); // 0 vector
    hpoints_0.push(points[3].clone()); // range check point
    hpoints_0.push(points[4].clone()); // fiddle
    hpoints_0.push(points[5].clone()); // zero

    let mut hevals_0 = Vec::new();
    hevals_0.push(Evaluation::new(0, 0, F::ZERO));
    hevals_0.push(Evaluation::new(1, 1, hpoly_0[1].evaluate(&hpoints_0[1])));
    hevals_0.push(Evaluation::new(2, 2, hpoly_0[2].evaluate(&hpoints_0[2])));
    hevals_0.push(Evaluation::new(3, 3, hpoly_0[3].evaluate(&hpoints_0[3])));

    hcoms_vec.push(hcom_0);
    hpolys_vec.push(hpoly_0);
    hpoints_vec.push(hpoints_0);
    hevals_vec.push(hevals_0);

    // Frac evaluations
    let fracInd = 2;
    let mut fraccom_0 = Vec::new();
    fraccom_0.push(&coms[fracInd]);
    fraccom_0.push(&coms[fracInd]);
    fraccom_0.push(&coms[fracInd]);

    let mut fracpoly_0 = Vec::new();
    fracpoly_0.push(&polynomials[fracInd]);
    fracpoly_0.push(&polynomials[fracInd]);
    fracpoly_0.push(&polynomials[fracInd]);

    let mut fracpoints_0 = Vec::new();
    fracpoints_0.push(points[6].clone());
    fracpoints_0.push(points[7].clone());
    fracpoints_0.push(points[8].clone());

    let mut fracevals_0 = Vec::new();
    fracevals_0.push(Evaluation::new(0, 0, fracpoly_0[0].evaluate(&fracpoints_0[0])));
    fracevals_0.push(Evaluation::new(1, 1, fracpoly_0[1].evaluate(&fracpoints_0[1])));
    fracevals_0.push(Evaluation::new(2, 2, fracpoly_0[2].evaluate(&fracpoints_0[2])));

    fraccoms_vec.push(fraccom_0);
    fracpolys_vec.push(fracpoly_0);
    fracpoints_vec.push(fracpoints_0);
    fracevals_vec.push(fracevals_0);

    // Prod evaluations
    let prodInd = 3;
    let mut prodcom_0 = Vec::new();
    prodcom_0.push(&coms[prodInd]);
    prodcom_0.push(&coms[prodInd]);
    prodcom_0.push(&coms[prodInd]);
    prodcom_0.push(&coms[prodInd]);

    let mut prodpoly_0 = Vec::new();
    prodpoly_0.push(&polynomials[prodInd]);
    prodpoly_0.push(&polynomials[prodInd]);
    prodpoly_0.push(&polynomials[prodInd]);
    prodpoly_0.push(&polynomials[prodInd]);

    let mut prodpoints_0 = Vec::new();
    prodpoints_0.push(points[2].clone());
    prodpoints_0.push(points[6].clone());
    prodpoints_0.push(points[7].clone());
    prodpoints_0.push(points[8].clone());

    let mut prodevals_0 = Vec::new();
prodevals_0.push(Evaluation::new(
    0,
    0,
    prodpoly_0[0].evaluate(&prodpoints_0[0]),
));
    prodevals_0.push(Evaluation::new(1, 1, prodpoly_0[1].evaluate(&prodpoints_0[1])));
    prodevals_0.push(Evaluation::new(2, 2, prodpoly_0[2].evaluate(&prodpoints_0[2])));
    prodevals_0.push(Evaluation::new(3, 3, prodpoly_0[3].evaluate(&prodpoints_0[3])));

    prodcoms_vec.push(prodcom_0);
    prodpolys_vec.push(prodpoly_0);
    prodpoints_vec.push(prodpoints_0);
    prodevals_vec.push(prodevals_0);

    // Audio evaluations
    let audioInd = 0;
    let mut audiocom_0 = Vec::new();
    audiocom_0.push(&coms[audioInd]);
    audiocom_0.push(&coms[audioInd]);
    audiocom_0.push(&coms[audioInd]);

    let mut audiopoly_0 = Vec::new();
    audiopoly_0.push(&polynomials[audioInd]);
    audiopoly_0.push(&polynomials[audioInd]);
    audiopoly_0.push(&polynomials[audioInd]);

    // Small point for range check
    let mut smallPt = points[3].clone();
    smallPt[numCols] = F::ZERO;

    let mut audiopoints_0 = Vec::new();
    audiopoints_0.push(points[0].clone()); // hash preimage point
    audiopoints_0.push(smallPt.clone());   // range check small point
    audiopoints_0.push(points[9].clone()); // transform point

    let mut audioevals_0 = Vec::new();
    audioevals_0.push(Evaluation::new(0, 0, audiopoly_0[0].evaluate(&audiopoints_0[0])));
    audioevals_0.push(Evaluation::new(1, 1, audiopoly_0[1].evaluate(&audiopoints_0[1])));
    audioevals_0.push(Evaluation::new(2, 2, audiopoly_0[2].evaluate(&audiopoints_0[2])));

    audiocoms_vec.push(audiocom_0);
    audiopolys_vec.push(audiopoly_0);
    audiopoints_vec.push(audiopoints_0);
    audioevals_vec.push(audioevals_0);

    // Write evaluations and batch open
    transcript.write_field_elements(hevals_vec[0].iter().map(Evaluation::value)).unwrap();

    batch_open_one::<F, Pcs>(
        &pp,
        length,
        hpolys_vec[0].clone(),
        hcoms_vec[0].clone(),
        &hpoints_vec[0],
        &hevals_vec[0],
        &mut transcript,
    ).unwrap();

    transcript.write_field_elements(fracevals_vec[0].iter().map(Evaluation::value)).unwrap();
    batch_open_one::<F, Pcs>(
        &pp,
        length,
        fracpolys_vec[0].clone(),
        fraccoms_vec[0].clone(),
        &fracpoints_vec[0],
        &fracevals_vec[0],
        &mut transcript,
    ).unwrap();

    transcript.write_field_elements(prodevals_vec[0].iter().map(Evaluation::value)).unwrap();
    batch_open_one::<F, Pcs>(
        &pp,
        length,
        prodpolys_vec[0].clone(),
        prodcoms_vec[0].clone(),
        &prodpoints_vec[0],
        &prodevals_vec[0],
        &mut transcript,
    ).unwrap();

    transcript.write_field_elements(audioevals_vec[0].iter().map(Evaluation::value)).unwrap();
    batch_open_one::<F, Pcs>(
        &pp,
        length,
        audiopolys_vec[0].clone(),
        audiocoms_vec[0].clone(),
        &audiopoints_vec[0],
        &audioevals_vec[0],
        &mut transcript,
    ).unwrap();

    println!("prover done!");

    return (startSample, endSample, hevals_vec, fracevals_vec, prodevals_vec, audioevals_vec, transcript);
}

fn verify(
    vp: <MultilinearBrakedown<F, Blake2s, BrakedownSpec6> as PolynomialCommitmentScheme<F>>::VerifierParam,
    numRows: usize,
    numCols: usize,
    nvTrim: usize,
    startSample: usize,
    endSample: usize,
    hevals_vec: Vec<Vec<Evaluation<F>>>,
    fracevals_vec: Vec<Vec<Evaluation<F>>>,
    prodevals_vec: Vec<Vec<Evaluation<F>>>,
    audioevals_vec: Vec<Vec<Evaluation<F>>>,
    cameraHash: Vec<F>,
    transcript: (impl (TranscriptWrite<<MultilinearBrakedown<F, Blake2s, BrakedownSpec6> as PolynomialCommitmentScheme<F>>::CommitmentChunk, F>) + InMemoryTranscript),
    input_size: usize,
) {
    println!("\nstarting verifier");
    let trimLength = endSample - startSample;

    let mut commits = Vec::new();
    let mut my_alphas = Vec::new();

    // Load trim audio for verification
    let trimFileName = format!("audio/Trim{}.json", input_size);
    let trimAudio = load_audio(&trimFileName);
    let bitDepth = trimAudio.bit_depth;
    let maxVal = get_max_val(bitDepth);

    let trimEvals = audio_to_brakedown_field(&trimAudio.left, bitDepth);

    let trans_pf = transcript.into_proof();

    println!("PROOF SIZE: {:?} bytes", trans_pf.len());

    let mut ver_transcript = Blake2sTranscript::from_proof((), trans_pf.as_slice());

    // Read audio commitment
    commits.append(&mut Pcs::read_commitments(&vp, 1, &mut ver_transcript).unwrap());

    // Squeeze RTA Challenge (Frievald)
    let frievaldRandVecrTA = <VT as FieldTranscript<F>>::squeeze_challenges(&mut ver_transcript, 1 << numRows);

    // Squeeze challenges for sumcheck
    let challenges: Vec<F> = vec![<VT as FieldTranscript<F>>::squeeze_challenge(&mut ver_transcript)];
    // Squeeze rand_vec for sumcheck
    let rand_vector = <VT as FieldTranscript<F>>::squeeze_challenges(&mut ver_transcript, numCols);

    // Verify sumcheck for hash preimage
    let mut mySumVal = F::ZERO;
    for j in 0..1 << numRows {
        mySumVal += frievaldRandVecrTA[j] * cameraHash[j];
    }
    let verResCameraHash = ClassicSumCheck::<EvaluationsProver<F>>::verify(&(), numCols, 2, mySumVal, &mut ver_transcript).unwrap();
    my_alphas.push(verResCameraHash.clone().1);

    // Range check verification
    // Append h table com
    commits.append(&mut Pcs::read_commitments(&vp, 1, &mut ver_transcript).unwrap());
    // Get alpha for the multset check
    let alpha1 = <VT as FieldTranscript<F>>::squeeze_challenge(&mut ver_transcript);
    let alpha2 = <VT as FieldTranscript<F>>::squeeze_challenge(&mut ver_transcript);
    // Append frac then prod coms
    commits.append(&mut Pcs::read_commitments(&vp, 2, &mut ver_transcript).unwrap());


    // Squeeze beta
    let beta = <VT as FieldTranscript<F>>::squeeze_challenge(&mut ver_transcript);

    // Squeeze challenges and rand_vector for sumcheck
    let challenges_range: Vec<F> = vec![<VT as FieldTranscript<F>>::squeeze_challenge(&mut ver_transcript)];
    let rand_vector_range = <VT as FieldTranscript<F>>::squeeze_challenges(&mut ver_transcript, numCols+1);

    // Verify range sumcheck
    let verResRange = ClassicSumCheck::<EvaluationsProver<F>>::verify(&(), numCols+1, 3, F::ZERO, &mut ver_transcript).unwrap();
    my_alphas.push(verResRange.1.clone());

    // Squeeze Frievald for trim
    let frievaldTrim = <VT as FieldTranscript<F>>::squeeze_challenges(&mut ver_transcript, 1 << nvTrim);
    // Challenges and randVec for trim sumcheck
    let challenges_trim: Vec<F> = vec![<VT as FieldTranscript<F>>::squeeze_challenge(&mut ver_transcript)];
    let rand_vector_trim = <VT as FieldTranscript<F>>::squeeze_challenges(&mut ver_transcript, numCols);

    // Calculate sum for trim sumcheck
    let mut mySumTrim = F::ZERO;
    for j in 0..(1 << nvTrim) {
        if j < trimEvals.len() {
            mySumTrim += frievaldTrim[j] * trimEvals[j];
        }
    }

    // Verify trim sumcheck
    let verResTrim = ClassicSumCheck::<EvaluationsProver<F>>::verify(&(), numCols, 2, mySumTrim, &mut ver_transcript).unwrap();
    my_alphas.push(verResTrim.1);

    let points = makePtsFullTrim(numCols, my_alphas.clone());

    // Read and verify h evaluations
    let mut hpoints_0 = Vec::new();
    hpoints_0.push(points[1].clone());
    hpoints_0.push(points[3].clone());
    hpoints_0.push(points[4].clone());
    hpoints_0.push(points[5].clone());

    let h_evals: Vec<F> = ver_transcript.read_field_elements(hevals_vec[0].len()).unwrap();
    let mut hevals2 = Vec::new();
    for j in 0..hevals_vec[0].len() {
        let mut newEval = hevals_vec[0][j].clone();
        newEval.value = h_evals[j];
        hevals2.push(newEval);
    }
    batch_verify_one::<F, Pcs>(
        &vp,
        numCols+1,
        commits[1].clone(),
        &hpoints_0,
        &hevals2,
        &mut ver_transcript,
    ).unwrap();

    // Read and verify frac evaluations
    let mut fracpoints_0 = Vec::new();
    fracpoints_0.push(points[6].clone());
    fracpoints_0.push(points[7].clone());
    fracpoints_0.push(points[8].clone());

    let frac_evals: Vec<F> = ver_transcript.read_field_elements(fracevals_vec[0].len()).unwrap();
    let mut fracevals2 = Vec::new();
    for j in 0..fracevals_vec[0].len() {
        let mut newEval = fracevals_vec[0][j].clone();
        newEval.value = frac_evals[j];
        fracevals2.push(newEval);
    }

    batch_verify_one::<F, Pcs>(
        &vp,
        numCols+1,
        commits[2].clone(),
        &fracpoints_0,
        &fracevals2,
        &mut ver_transcript,
    ).unwrap();

    // Read and verify prod evaluations
    let mut prodpoints_0 = Vec::new();
    prodpoints_0.push(points[2].clone());
    prodpoints_0.push(points[6].clone());
    prodpoints_0.push(points[7].clone());
    prodpoints_0.push(points[8].clone());

    let prod_evals: Vec<F> = ver_transcript.read_field_elements(prodevals_vec[0].len()).unwrap();
    let mut prodevals2 = Vec::new();
    for j in 0..prodevals_vec[0].len() {
        let mut newEval = prodevals_vec[0][j].clone();
        newEval.value = prod_evals[j];
        prodevals2.push(newEval);
    }

    batch_verify_one::<F, Pcs>(
        &vp,
        numCols+1,
        commits[3].clone(),
        &prodpoints_0,
        &prodevals2,
        &mut ver_transcript,
    ).unwrap();

    // Read and verify audio evaluations
    let mut smallPt = points[3].clone();
    smallPt[numCols] = F::ZERO;

    let mut audiopoints_0 = Vec::new();
    audiopoints_0.push(points[0].clone());
    audiopoints_0.push(smallPt.clone());
    audiopoints_0.push(points[9].clone());

    let audio_evals: Vec<F> = ver_transcript.read_field_elements(audioevals_vec[0].len()).unwrap();
    let mut audioevals2 = Vec::new();
    for j in 0..audioevals_vec[0].len() {
        let mut newEval = audioevals_vec[0][j].clone();
        newEval.value = audio_evals[j];
        audioevals2.push(newEval);
    }

    batch_verify_one::<F, Pcs>(
        &vp,
        numCols+1,
        commits[0].clone(),
        &audiopoints_0,
        &audioevals2,
        &mut ver_transcript,
    ).unwrap();

    // Verify relationships
    let mut success = true;

    // Compute rTA
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

    // Verify trim transformation
    let mut trimPerm = Vec::new();
    for _ in 0..1 << numCols {
        trimPerm.push(Vec::new());
    }
    for i in 0..trimLength {
        let origIdx = startSample + i;
        if origIdx < (1 << numCols) {
            trimPerm[origIdx].push((i, F::ONE));
        }
    }
    let permTimesR = matSparseMultVecBrakedown(1 << numCols, 1 << nvTrim, &trimPerm, &frievaldTrim);
    let permTimesRPoly = MultilinearPolynomial::new(permTimesR.clone());

    let mut transPoint = Vec::new();
    for i in 0..numCols {
        transPoint.push(points[9][i]);
    }
    let LHS_trim = permTimesRPoly.evaluate(&transPoint);
    let RHS_trim = audio_evals[2];
    success = success && (verResTrim.0 == LHS_trim * RHS_trim);

    // Verify h(0) = 0 and prod(1..0) = 1
    success = success && (h_evals[0] == F::ZERO);

    // Verify range check
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

    let myRand = &points[3];
    let startVal = myRand[0];
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

    // prod(x) - v(x,0)v(x,1)
    let mut firstHalf = prodAtAlphaRange;
    let myAlpha = myRand[myRand.len()-1];
    let vX0 = myAlpha * prodAtAlphaRange0 + (F::ONE - myAlpha) * fracAtAlphaRange0;
    let vX1 = myAlpha * prodAtAlphaRange1 + (F::ONE - myAlpha) * fracAtAlphaRange1;
    firstHalf += -vX0 * vX1;

    // f1 and f2
    let mut f1 = alpha1 + ((F::ONE - lastVal) * audioAtAlphaSmall + lastVal * polyTable.evaluate(&myRandSmall));
    f1 += alpha2 * ((F::ONE - lastVal) * audioAtAlphaSmall + lastVal * polyPlusOneTable.evaluate(&myRandSmall));

    let mut f2 = alpha1 + hAtAlphaRange + alpha2 * (startVal * hAtAlphaRangeFiddle + (F::ONE - startVal) * hAtAlphaRange0);
    let mut secondHalf = (f2 * fracAtAlphaRange - f1);
    secondHalf = secondHalf * beta;

    let anticipatedVal = verResRange.0;
    let finalVal = firstHalf + secondHalf;

    let extra = eq_eval(&myRand, &rand_vector_range);
    success = success && (anticipatedVal == finalVal * extra);

    println!("Verifier passed!: {:?}", success);
    println!("verifier done!\n");
}

fn run_whole_system_trim_brake(input_size: usize) {
    let numCols = input_size;
    let nvTrim = input_size - 1;
    let numRows = 7;
    let length = numCols + 1;

    // setup
    let (pp, vp, digest) = setup(input_size);

    // prove
    let prover_start = Instant::now();
    let (startSample, endSample, hevals_vec, fracevals_vec, prodevals_vec, audioevals_vec, transcript) = prove(pp, input_size, numRows, numCols, nvTrim);
    let elapsed_prover = prover_start.elapsed();
    println!("PROVER TIME: {:?} seconds", elapsed_prover.as_millis() as f64 / 1000.0);

    // verify
    let verifier_start = Instant::now();
    verify(vp, numRows, numCols, nvTrim, startSample, endSample, hevals_vec, fracevals_vec, prodevals_vec, audioevals_vec, digest, transcript, input_size);
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
        println!("Full System Trim, HyperVerITAS Brakedown 127. Size: 2^{:?}\n", i);
        let _res = run_whole_system_trim_brake(i);
        println!("-----------------------------------------------------------------------");
    }
}
