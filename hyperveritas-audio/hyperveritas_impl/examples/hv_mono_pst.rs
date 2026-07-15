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

fn hashPreimageIOPStereo<F: PrimeField, E, PCS>(
    numCols: usize,
    numRows: usize,
    LREvals: [Vec<F>; 2],
    maxVal: u32,
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
    Vec<VPAuxInfo<F>>
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

    let mut audioPolies: Vec<Arc<DenseMultilinearExtension<F>>> = Vec::new();
    audioPolies.push(vec_to_poly::<F>(LREvals[0].clone()).0);
    audioPolies.push(vec_to_poly::<F>(LREvals[1].clone()).0);

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

    let (rTAPoly, _) = vec_to_poly::<F>(rTA);

    let mut RHS_LR = Vec::new();
    for i in 0..2 {
        RHS_LR.push(VirtualPolynomial::new_from_mle(&rTAPoly, F::one()));
        RHS_LR[i].mul_by_mle(audioPolies[i].clone(), F::one());
    }

    let proofLR = [
        <PolyIOP<F> as SumCheck<F>>::prove(&RHS_LR[0], transcript).unwrap(),
        <PolyIOP<F> as SumCheck<F>>::prove(&RHS_LR[1], transcript).unwrap(),
    ];

    let poly_infoLR = [RHS_LR[0].aux_info.clone(), RHS_LR[1].aux_info.clone()];

    let (mut multsetProofLR, mut fxLR, mut gxLR, mut hLR, mut poly_infoProds) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());

    for i in 0..2 {
        let (multsetProof, fx, gx, h, poly_infoProd) = range_checkProverIOP::<F, E, PCS>(
            numCols,
            maxVal,
            audioPolies[i].clone(),
            irredPolyTable[numCols].try_into().unwrap(),
            irredPolyTable[numCols + 1].try_into().unwrap(),
            transcript,
            &pcs_param,
            &ver_param,
        );
        multsetProofLR.push(multsetProof);
        fxLR.push(fx);
        gxLR.push(gx);
        hLR.push(h);
        poly_infoProds.push(poly_infoProd);
    }

    (RHS_LR, proofLR, poly_infoLR, multsetProofLR, fxLR, gxLR, hLR, poly_infoProds)
}

fn run_full_mono_pst(testSize: usize) {
    println!("\nstarting setup");

    let mut rng = test_rng();
    let numCols = testSize;
    let numRows = 7;
    let length = numCols + 1;

    let fileName = format!("audio/StereoAudio{}.json", testSize);
    let srs = PCS::gen_srs_for_testing(&mut rng, length).unwrap();
    let (pcs_param, ver_param) = PCS::trim(&srs, None, Some(length)).unwrap();

    // Load stereo audio
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

    assert!(origAudio.num_channels == 2, "Expected stereo audio");

    let mut leftEvals = audio_to_field_vec::<F>(&origAudio.left, bitDepth);
    let mut rightEvals = audio_to_field_vec::<F>(origAudio.right.as_ref().unwrap(), bitDepth);

    // Padding
    for _ in 0..(leftEvals.len().next_power_of_two() - leftEvals.len()) {
        leftEvals.push(F::zero());
        rightEvals.push(F::zero());
    }

    // Hash computation for both channels
    let mut testDigestLR = Vec::new();
    for k in 0..2 {
        let mut matrixA = Vec::new();
        for i in 0..128 {
            matrixA.push(ChaCha8Rng::seed_from_u64(i));
        }
        let evals = if k == 0 { &leftEvals } else { &rightEvals };
        let mut testDigest = Vec::new();
        for i in 0..128 {
            let mut mySum = F::zero();
            for j in 0..(1 << numCols) {
                mySum += F::rand(&mut matrixA[i]) * evals[j];
            }
            testDigest.push(mySum);
        }
        testDigestLR.push(testDigest);
    }

    println!("setup done!\n");

    println!("starting prover");

    let now0 = Instant::now();
    let origAudio = load_audio(&fileName);
    let leftPoly = vec_to_poly(audio_to_field_vec::<F>(&origAudio.left, bitDepth)).0;
    let rightPoly = vec_to_poly(audio_to_field_vec::<F>(origAudio.right.as_ref().unwrap(), bitDepth)).0;

    let leftCom = PCS::commit(&pcs_param, &leftPoly).unwrap();
    let rightCom = PCS::commit(&pcs_param, &rightPoly).unwrap();

    let mut transcript =
        <PolyIOP<F> as ProductCheck<Bls12_381, MultilinearKzgPCS<Bls12_381>>>::init_transcript();

    transcript.append_serializable_element(b"left(x)", &leftCom);
    transcript.append_serializable_element(b"right(x)", &rightCom);

    let LREvals = [leftEvals, rightEvals];

    let (RHS_LR, proofLR, poly_info_matMult, multsetProofLR, prod_xLR, frac_xLR, hLR, poly_infoProds) =
        hashPreimageIOPStereo::<F, Bls12_381, MultilinearKzgPCS<Bls12_381>>(
            numCols,
            numRows,
            LREvals,
            maxVal,
            &mut transcript,
            &pcs_param,
            &ver_param,
        );

    // MONO MIX TRANSFORMATION
    let monoFileName = format!("audio/Mono{}.json", testSize);
    let monoAudio = load_audio(&monoFileName);

    let monoPoly = vec_to_poly(audio_to_field_vec::<F>(&monoAudio.left, bitDepth)).0;

    // Compute mono mix error: left + right - 2*mono should be in [0, 1]
    // Since mono = floor((left + right) / 2), we have:
    // - error = 0 when (left + right) is even
    // - error = 1 when (left + right) is odd
    let two = F::one() + F::one();
    let mut monoError = Vec::new();
    for i in 0..(1 << numCols) {
        let monoVal = if i < monoPoly.evaluations.len() {
            monoPoly.evaluations[i]
        } else {
            F::zero()
        };
        let leftVal = if i < leftPoly.evaluations.len() {
            leftPoly.evaluations[i]
        } else {
            F::zero()
        };
        let rightVal = if i < rightPoly.evaluations.len() {
            rightPoly.evaluations[i]
        } else {
            F::zero()
        };
        monoError.push(leftVal + rightVal - two * monoVal);
    }

    let (monoErrPoly, _) = vec_to_poly(monoError);

    // Collect polynomials
    let mut polies = Vec::new();
    polies.push(leftPoly.clone());
    polies.push(rightPoly.clone());
    for i in 0..2 {
        polies.push(hLR[i].clone());
        polies.push(prod_xLR[i].clone());
        polies.push(frac_xLR[i].clone());
    }

    // Collect commitments
    let mut coms = Vec::new();
    coms.push(leftCom);
    coms.push(rightCom);

    let mut hComs = Vec::new();
    for i in 0..2 {
        let hCom = PCS::commit(&pcs_param, &hLR[i]).unwrap();
        hComs.push(hCom);
        transcript.append_serializable_element(b"hCom(x)", &hCom);
    }

    for i in 0..2 {
        coms.push(hComs[i]);
        coms.push(multsetProofLR[i].prod_x_comm);
        coms.push(multsetProofLR[i].frac_comm);
    }

    // Mono error commitment
    let monoErrCom = PCS::commit(&pcs_param, &monoErrPoly).unwrap();
    transcript.append_serializable_element(b"monoErr(x)", &monoErrCom);

    // Range check for mono error (maxVal = 1)
    let (multsetProofMono, fxMono, gxMono, hMono, auxMono) = range_checkProverIOP::<F, Bls12_381, MultilinearKzgPCS<Bls12_381>>(
        numCols,
        1, // maxVal = 1 for mono mix error
        monoErrPoly.clone(),
        irredPolyTable[numCols].try_into().unwrap(),
        irredPolyTable[numCols + 1].try_into().unwrap(),
        &mut transcript,
        &pcs_param,
        &ver_param,
    );

    polies.push(monoErrPoly.clone());
    polies.push(hMono.clone());
    polies.push(fxMono.clone());
    polies.push(gxMono.clone());

    coms.push(monoErrCom);
    let hMonoCom = PCS::commit(&pcs_param, &hMono).unwrap();
    coms.push(hMonoCom);
    coms.push(multsetProofMono.prod_x_comm);
    coms.push(multsetProofMono.frac_comm);

    transcript.append_serializable_element(b"hMonoCom(x)", &hMonoCom);

    // Build evaluation points
    let mut points = Vec::new();

    // Hash preimage points for L and R
    for i in 0..2 {
        points.push(proofLR[i].point.clone());
    }
    // 0 vector for h
    points.push(vec![F::zero(); numCols + 1]);
    // 1..10 vector for prod
    let mut final_query = vec![F::one(); numCols + 1];
    final_query[0] = F::zero();
    points.push(final_query);

    // Range check points for L and R
    for i in 0..2 {
        let myRand = &multsetProofLR[i].zero_check_proof.point;
        let mut myRandSmall = Vec::new();
        for j in 0..myRand.len() - 1 {
            myRandSmall.push(myRand[j]);
        }
        points.push(myRandSmall.clone());

        let galoisRep = irredPolyTable[numCols + 1] - (1 << (numCols + 1));
        let (fiddle, zero, _startVal) = galoisifyPt::<F>((numCols + 1) as u32, galoisRep, myRand.clone());
        points.push(fiddle);
        points.push(zero);
        points.push(myRand.clone());

        let mut ptRand = Vec::new();
        ptRand.push(F::zero());
        for j in 0..myRand.len() - 1 {
            ptRand.push(myRand[j]);
        }
        points.push(ptRand.clone());
        ptRand[0] = F::one();
        points.push(ptRand);
    }

    // Transformation point for mono
    let monoTransformPt = transcript.get_and_append_challenge_vectors(b"alpha", numCols).unwrap();
    points.push(monoTransformPt.clone());

    // Range check points for mono error
    let myRand = &multsetProofMono.zero_check_proof.point;
    let mut myRandSmall = Vec::new();
    for j in 0..myRand.len() - 1 {
        myRandSmall.push(myRand[j]);
    }
    points.push(myRandSmall.clone());

    let galoisRep = irredPolyTable[numCols + 1] - (1 << (numCols + 1));
    let (fiddle, zero, _startVal) = galoisifyPt::<F>((numCols + 1) as u32, galoisRep, myRand.clone());
    points.push(fiddle);
    points.push(zero);
    points.push(myRand.clone());

    let mut ptRand = Vec::new();
    ptRand.push(F::zero());
    for j in 0..myRand.len() - 1 {
        ptRand.push(myRand[j]);
    }
    points.push(ptRand.clone());
    ptRand[0] = F::one();
    points.push(ptRand);

    // Build evaluation lists
    let mut evalPols = Vec::new();
    let mut evalPoints: Vec<Vec<F>> = Vec::new();
    let mut evalVals = Vec::new();
    let mut evalComs = Vec::new();
    let mut evalPolsBig = Vec::new();
    let mut evalPointsBig: Vec<Vec<F>> = Vec::new();
    let mut evalValsBig = Vec::new();
    let mut evalComsBig = Vec::new();

    // Hash and range check for L and R
    for i in 0..2 {
        // Hash preimage
        evalPols.push(polies[i].clone());
        evalPoints.push(points[i].clone());
        evalVals.push(polies[i].evaluate(&points[i]).unwrap());
        evalComs.push(coms[i].clone());

        // Alpha_range for channel
        let polIndex = i;
        let ptIndex = 4 + 6 * i;
        evalPols.push(polies[polIndex].clone());
        evalPoints.push(points[ptIndex].clone());
        evalVals.push(polies[polIndex].evaluate(&points[ptIndex]).unwrap());
        evalComs.push(coms[polIndex].clone());

        // h(0) = 0
        let polIndex = 2 + 3 * i;
        evalPolsBig.push(polies[polIndex].clone());
        evalPointsBig.push(points[2].clone());
        evalValsBig.push(F::zero());
        evalComsBig.push(coms[polIndex].clone());

        // h at alpha_range
        let ptIndex = 7 + 6 * i;
        evalPolsBig.push(polies[polIndex].clone());
        evalPointsBig.push(points[ptIndex].clone());
        evalValsBig.push(polies[polIndex].evaluate(&points[ptIndex]).unwrap());
        evalComsBig.push(coms[polIndex].clone());

        // h at fiddle
        let ptIndex = 5 + 6 * i;
        evalPolsBig.push(polies[polIndex].clone());
        evalPointsBig.push(points[ptIndex].clone());
        evalValsBig.push(polies[polIndex].evaluate(&points[ptIndex]).unwrap());
        evalComsBig.push(coms[polIndex].clone());

        // h at zero
        let ptIndex = 6 + 6 * i;
        evalPolsBig.push(polies[polIndex].clone());
        evalPointsBig.push(points[ptIndex].clone());
        evalValsBig.push(polies[polIndex].evaluate(&points[ptIndex]).unwrap());
        evalComsBig.push(coms[polIndex].clone());

        // prod at 1..10
        let polIndex = 3 + 3 * i;
        evalPolsBig.push(polies[polIndex].clone());
        evalPointsBig.push(points[3].clone());
        evalValsBig.push(F::one());
        evalComsBig.push(coms[polIndex].clone());

        // prod at alpha_range
        let ptIndex = 7 + 6 * i;
        evalPolsBig.push(polies[polIndex].clone());
        evalPointsBig.push(points[ptIndex].clone());
        evalValsBig.push(polies[polIndex].evaluate(&points[ptIndex]).unwrap());
        evalComsBig.push(coms[polIndex].clone());

        // frac at alpha_range
        let polIndex = 4 + 3 * i;
        evalPolsBig.push(polies[polIndex].clone());
        evalPointsBig.push(points[ptIndex].clone());
        evalValsBig.push(polies[polIndex].evaluate(&points[ptIndex]).unwrap());
        evalComsBig.push(coms[polIndex].clone());

        // prod at alpha_range||0
        let polIndex = 3 + 3 * i;
        let ptIndex = 8 + 6 * i;
        evalPolsBig.push(polies[polIndex].clone());
        evalPointsBig.push(points[ptIndex].clone());
        evalValsBig.push(polies[polIndex].evaluate(&points[ptIndex]).unwrap());
        evalComsBig.push(coms[polIndex].clone());

        // frac at alpha_range||0
        let polIndex = 4 + 3 * i;
        evalPolsBig.push(polies[polIndex].clone());
        evalPointsBig.push(points[ptIndex].clone());
        evalValsBig.push(polies[polIndex].evaluate(&points[ptIndex]).unwrap());
        evalComsBig.push(coms[polIndex].clone());

        // prod at alpha_range||1
        let polIndex = 3 + 3 * i;
        let ptIndex = 9 + 6 * i;
        evalPolsBig.push(polies[polIndex].clone());
        evalPointsBig.push(points[ptIndex].clone());
        evalValsBig.push(polies[polIndex].evaluate(&points[ptIndex]).unwrap());
        evalComsBig.push(coms[polIndex].clone());

        // frac at alpha_range||1
        let polIndex = 4 + 3 * i;
        evalPolsBig.push(polies[polIndex].clone());
        evalPointsBig.push(points[ptIndex].clone());
        evalValsBig.push(polies[polIndex].evaluate(&points[ptIndex]).unwrap());
        evalComsBig.push(coms[polIndex].clone());

        // Transform point for L/R
        evalPols.push(polies[i].clone());
        evalPoints.push(points[16].clone()); // monoTransformPt
        evalVals.push(polies[i].evaluate(&points[16]).unwrap());
        evalComs.push(coms[i].clone());
    }

    // Mono error at transform point
    let polIndex = 8; // monoErrPoly
    evalPols.push(polies[polIndex].clone());
    evalPoints.push(points[16].clone());
    evalVals.push(polies[polIndex].evaluate(&points[16]).unwrap());
    evalComs.push(coms[polIndex].clone());

    // Mono error at alpha_range small point for range check monster value
    let polIndex = 8; // monoErrPoly
    evalPols.push(polies[polIndex].clone());
    evalPoints.push(points[17].clone());
    evalVals.push(polies[polIndex].evaluate(&points[17]).unwrap());
    evalComs.push(coms[polIndex].clone());

    // Mono error range check
    let polIndex = 9; // hMono
    evalPolsBig.push(polies[polIndex].clone());
    evalPointsBig.push(points[2].clone()); // 0 vector
    evalValsBig.push(F::zero());
    evalComsBig.push(coms[polIndex].clone());

    // h at alpha_range for mono
    evalPolsBig.push(polies[polIndex].clone());
    evalPointsBig.push(points[20].clone());
    evalValsBig.push(polies[polIndex].evaluate(&points[20]).unwrap());
    evalComsBig.push(coms[polIndex].clone());

    // h at fiddle for mono
    evalPolsBig.push(polies[polIndex].clone());
    evalPointsBig.push(points[18].clone());
    evalValsBig.push(polies[polIndex].evaluate(&points[18]).unwrap());
    evalComsBig.push(coms[polIndex].clone());

    // h at zero for mono
    evalPolsBig.push(polies[polIndex].clone());
    evalPointsBig.push(points[19].clone());
    evalValsBig.push(polies[polIndex].evaluate(&points[19]).unwrap());
    evalComsBig.push(coms[polIndex].clone());

    // prod at 1..10 for mono
    let polIndex = 10; // fxMono (prod)
    evalPolsBig.push(polies[polIndex].clone());
    evalPointsBig.push(points[3].clone());
    evalValsBig.push(F::one());
    evalComsBig.push(coms[polIndex].clone());

    // prod at alpha_range for mono
    evalPolsBig.push(polies[polIndex].clone());
    evalPointsBig.push(points[20].clone());
    evalValsBig.push(polies[polIndex].evaluate(&points[20]).unwrap());
    evalComsBig.push(coms[polIndex].clone());

    // frac at alpha_range for mono
    let polIndex = 11; // gxMono (frac)
    evalPolsBig.push(polies[polIndex].clone());
    evalPointsBig.push(points[20].clone());
    evalValsBig.push(polies[polIndex].evaluate(&points[20]).unwrap());
    evalComsBig.push(coms[polIndex].clone());

    // prod at alpha_range||0 for mono
    let polIndex = 10;
    evalPolsBig.push(polies[polIndex].clone());
    evalPointsBig.push(points[21].clone());
    evalValsBig.push(polies[polIndex].evaluate(&points[21]).unwrap());
    evalComsBig.push(coms[polIndex].clone());

    // frac at alpha_range||0 for mono
    let polIndex = 11;
    evalPolsBig.push(polies[polIndex].clone());
    evalPointsBig.push(points[21].clone());
    evalValsBig.push(polies[polIndex].evaluate(&points[21]).unwrap());
    evalComsBig.push(coms[polIndex].clone());

    // prod at alpha_range||1 for mono
    let polIndex = 10;
    evalPolsBig.push(polies[polIndex].clone());
    evalPointsBig.push(points[22].clone());
    evalValsBig.push(polies[polIndex].evaluate(&points[22]).unwrap());
    evalComsBig.push(coms[polIndex].clone());

    // frac at alpha_range||1 for mono
    let polIndex = 11;
    evalPolsBig.push(polies[polIndex].clone());
    evalPointsBig.push(points[22].clone());
    evalValsBig.push(polies[polIndex].evaluate(&points[22]).unwrap());
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
    total_bls_elems += hComs.len();
    for digest in &testDigestLR {
        total_256_elems += digest.len();
    }
    for i in 0..2 {
        total_256_elems += proofLR[i].point.len();
        for pf in proofLR[i].clone().proofs {
            total_256_elems += pf.evaluations.len();
        }
        total_bls_elems += 2;
        let zero_pf = &multsetProofLR[i].zero_check_proof;
        total_256_elems += zero_pf.point.len();
        for pf in zero_pf.clone().proofs {
            total_256_elems += pf.evaluations.len();
        }
    }
    // Mono range check
    total_bls_elems += 2;
    let zero_pf = &multsetProofMono.zero_check_proof;
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

    let monoAudio = load_audio(&monoFileName);
    let monoPoly = vec_to_poly(audio_to_field_vec::<F>(&monoAudio.left, bitDepth)).0;

    // Initialize verifier transcript
    let mut verTranscript =
        <PolyIOP<F> as ProductCheck<Bls12_381, MultilinearKzgPCS<Bls12_381>>>::init_transcript();
    verTranscript.append_serializable_element(b"left(x)", &coms[0]);
    verTranscript.append_serializable_element(b"right(x)", &coms[1]);

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

    let mut expectedSumVal = [F::zero(), F::zero()];
    for i in 0..2 {
        for j in 0..(1 << numRows) {
            expectedSumVal[i] += frievaldRandVec[j] * testDigestLR[i][j];
        }
    }

    let mut sumCheckForHash = Vec::new();
    for i in 0..2 {
        sumCheckForHash.push(<PolyIOP<F> as SumCheck<F>>::verify(expectedSumVal[i], &proofLR[i], &poly_info_matMult[i], &mut verTranscript).unwrap());
    }

    let mut alpha1 = Vec::new();
    let mut alpha2 = Vec::new();
    let mut prodCheckSubclaims = Vec::new();
    for i in 0..2 {
        alpha1.push(verTranscript.get_and_append_challenge(b"alpha").unwrap());
        alpha2.push(verTranscript.get_and_append_challenge(b"alpha").unwrap());
        prodCheckSubclaims.push(<PolyIOP<F> as ProductCheck<Bls12_381, MultilinearKzgPCS<Bls12_381>>>::verify(&multsetProofLR[i], &poly_infoProds[i], &mut verTranscript).unwrap());
    }

    for i in 0..2 {
        verTranscript.append_serializable_element(b"hCom(x)", &hComs[i]);
    }

    verTranscript.append_serializable_element(b"monoErr(x)", &monoErrCom);

    let alpha1Mono = verTranscript.get_and_append_challenge(b"alpha").unwrap();
    let alpha2Mono = verTranscript.get_and_append_challenge(b"alpha").unwrap();
    let prodCheckSubclaimMono = <PolyIOP<F> as ProductCheck<Bls12_381, MultilinearKzgPCS<Bls12_381>>>::verify(&multsetProofMono, &auxMono, &mut verTranscript).unwrap();

    verTranscript.append_serializable_element(b"hMonoCom(x)", &hMonoCom);

    let monoTransformPt = verTranscript.get_and_append_challenge_vectors(b"alpha", numCols).unwrap();

    // Batch verify
    PCS::batch_verify(&ver_param, &evalComs, &evalPoints, &openProofs, &mut verTranscript).unwrap();
    PCS::batch_verify(&ver_param, &evalComsBig, &evalPointsBig, &openProofsBig, &mut verTranscript).unwrap();

    let mut flag = true;
    let myZero = openProofs.f_i_eval_at_point_i[0] - openProofs.f_i_eval_at_point_i[0];
    let myOne = openProofs.f_i_eval_at_point_i[0] / openProofs.f_i_eval_at_point_i[0];

    // Verify mono mix: left + right = 2*mono + error
    let leftAtPt = openProofs.f_i_eval_at_point_i[2]; // L at transform point
    let rightAtPt = openProofs.f_i_eval_at_point_i[5]; // R at transform point
    let errAtPt = openProofs.f_i_eval_at_point_i[6]; // err at transform point

    let monoAtPt = monoPoly.evaluate(&monoTransformPt).unwrap();
    let two = F::one() + F::one();
    let expectedLHS = leftAtPt + rightAtPt;
    let computedRHS = two * monoAtPt + errAtPt;
    flag = flag && (expectedLHS == computedRHS);

    // Verify hash preimage sumcheck final evaluations for L and R
    let (rTAPoly, _) = vec_to_poly::<F>(rTA.clone());
    for i in 0..2 {
        flag = flag && sumCheckForHash[i].expected_evaluation == rTAPoly.evaluate(&sumCheckForHash[i].point).unwrap() * openProofs.f_i_eval_at_point_i[i * 3];
    }

    // FOR RANGE CHECK: h(0) = 0 for L, R range checks
    for i in 0..2 {
        flag = flag && (openProofsBig.f_i_eval_at_point_i[11 * i] == myZero);
    }

    // FOR PRODUCT CHECK: prod(1,..,1,0) = 1 for L, R range checks
    for i in 0..2 {
        flag = flag && (openProofsBig.f_i_eval_at_point_i[4 + 11 * i] == myOne);
    }

    // Build embedded table for range check verification
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

    // Monster value for L and R range checks
    let mut startVals = Vec::new();
    for i in 0..2 {
        let myRand = &multsetProofLR[i].zero_check_proof.point;
        let galoisRepRange = irredPolyTable[numCols + 1] - (1 << (numCols + 1));
        let (_, _, startVal) = galoisifyPt::<F>((numCols + 1) as u32, galoisRepRange, myRand.clone());
        startVals.push(startVal);

        let mut myRandSmall = Vec::new();
        for j in 0..myRand.len() - 1 {
            myRandSmall.push(myRand[j]);
        }
        let lastVal = myRand[myRand.len() - 1];

        let audioAtAlphaSmall = openProofs.f_i_eval_at_point_i[1 + i * 3];
        let hAtAlphaRange = openProofsBig.f_i_eval_at_point_i[1 + 11 * i];
        let hAtAlphaRangeFiddle = openProofsBig.f_i_eval_at_point_i[2 + 11 * i];
        let hAtAlphaRange0 = openProofsBig.f_i_eval_at_point_i[3 + 11 * i];
        let prodAtAlphaRange = openProofsBig.f_i_eval_at_point_i[5 + 11 * i];
        let fracAtAlphaRange = openProofsBig.f_i_eval_at_point_i[6 + 11 * i];
        let prodAtAlphaRange0 = openProofsBig.f_i_eval_at_point_i[7 + 11 * i];
        let fracAtAlphaRange0 = openProofsBig.f_i_eval_at_point_i[8 + 11 * i];
        let prodAtAlphaRange1 = openProofsBig.f_i_eval_at_point_i[9 + 11 * i];
        let fracAtAlphaRange1 = openProofsBig.f_i_eval_at_point_i[10 + 11 * i];

        let mut firstHalf = prodAtAlphaRange;
        let myAlpha = myRand[myRand.len() - 1];
        let vX0 = myAlpha * prodAtAlphaRange0 + (F::one() - myAlpha) * fracAtAlphaRange0;
        let vX1 = myAlpha * prodAtAlphaRange1 + (F::one() - myAlpha) * fracAtAlphaRange1;
        firstHalf += -vX0 * vX1;

        let mut f1 = alpha1[i] + ((F::one() - lastVal) * audioAtAlphaSmall + lastVal * polyTable.evaluate(&myRandSmall).unwrap());
        f1 += alpha2[i] * ((F::one() - lastVal) * audioAtAlphaSmall + lastVal * polyPlusOneTable.evaluate(&myRandSmall).unwrap());

        let f2 = alpha1[i] + hAtAlphaRange + alpha2[i] * (startVals[i] * hAtAlphaRangeFiddle + (F::one() - startVals[i]) * hAtAlphaRange0);
        let mut secondHalf = f2 * fracAtAlphaRange - f1;
        secondHalf = secondHalf * prodCheckSubclaims[i].alpha;

        let anticipatedVal = prodCheckSubclaims[i].zero_check_sub_claim.expected_evaluation;
        let finalVal = firstHalf + secondHalf;
        flag = flag && anticipatedVal == finalVal;
    }

    // Mono error range check verification
    // h(0) = 0 for mono error
    flag = flag && (openProofsBig.f_i_eval_at_point_i[22] == myZero);
    // prod(1,..,1,0) = 1 for mono error
    flag = flag && (openProofsBig.f_i_eval_at_point_i[26] == myOne);

    // Build table for mono error (maxVal = 1)
    let maxValMono: u32 = 1;
    let mut embeddedTableMono: Vec<F> = vec![F::zero(); 1 << numCols];
    let mut plusOneTableMono: Vec<F> = vec![F::zero(); 1 << numCols];
    let mut binaryStringMono: u64 = 1;
    for i in 1..(maxValMono as usize + 1) {
        embeddedTableMono[binaryStringMono as usize] =
            F::from_le_bytes_mod_order(&transform_u32_to_array_of_u8(i as u32));
        binaryStringMono <<= 1;
        if binaryStringMono & size != 0 {
            binaryStringMono ^= galoisRepTable;
        }
        binaryStringMono = (size - 1) & binaryStringMono;
        plusOneTableMono[binaryStringMono as usize] =
            F::from_le_bytes_mod_order(&transform_u32_to_array_of_u8(i as u32));
    }
    let polyTableMono = DenseMultilinearExtension::from_evaluations_vec(numCols, embeddedTableMono);
    let polyPlusOneTableMono = DenseMultilinearExtension::from_evaluations_vec(numCols, plusOneTableMono);

    // Monster value for mono error range check
    {
        let myRand = &multsetProofMono.zero_check_proof.point;
        let galoisRepRange = irredPolyTable[numCols + 1] - (1 << (numCols + 1));
        let (_, _, startValMono) = galoisifyPt::<F>((numCols + 1) as u32, galoisRepRange, myRand.clone());

        let mut myRandSmall = Vec::new();
        for j in 0..myRand.len() - 1 {
            myRandSmall.push(myRand[j]);
        }
        let lastVal = myRand[myRand.len() - 1];

        let errAtAlphaSmall = openProofs.f_i_eval_at_point_i[7]; // monoErr at alpha_range_small
        let hAtAlphaRange = openProofsBig.f_i_eval_at_point_i[23];
        let hAtAlphaRangeFiddle = openProofsBig.f_i_eval_at_point_i[24];
        let hAtAlphaRange0 = openProofsBig.f_i_eval_at_point_i[25];
        let prodAtAlphaRange = openProofsBig.f_i_eval_at_point_i[27];
        let fracAtAlphaRange = openProofsBig.f_i_eval_at_point_i[28];
        let prodAtAlphaRange0 = openProofsBig.f_i_eval_at_point_i[29];
        let fracAtAlphaRange0 = openProofsBig.f_i_eval_at_point_i[30];
        let prodAtAlphaRange1 = openProofsBig.f_i_eval_at_point_i[31];
        let fracAtAlphaRange1 = openProofsBig.f_i_eval_at_point_i[32];

        let mut firstHalf = prodAtAlphaRange;
        let myAlpha = myRand[myRand.len() - 1];
        let vX0 = myAlpha * prodAtAlphaRange0 + (F::one() - myAlpha) * fracAtAlphaRange0;
        let vX1 = myAlpha * prodAtAlphaRange1 + (F::one() - myAlpha) * fracAtAlphaRange1;
        firstHalf += -vX0 * vX1;

        let mut f1 = alpha1Mono + ((F::one() - lastVal) * errAtAlphaSmall + lastVal * polyTableMono.evaluate(&myRandSmall).unwrap());
        f1 += alpha2Mono * ((F::one() - lastVal) * errAtAlphaSmall + lastVal * polyPlusOneTableMono.evaluate(&myRandSmall).unwrap());

        let f2 = alpha1Mono + hAtAlphaRange + alpha2Mono * (startValMono * hAtAlphaRangeFiddle + (F::one() - startValMono) * hAtAlphaRange0);
        let mut secondHalf = f2 * fracAtAlphaRange - f1;
        secondHalf = secondHalf * prodCheckSubclaimMono.alpha;

        let anticipatedVal = prodCheckSubclaimMono.zero_check_sub_claim.expected_evaluation;
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
        println!("Full System Mono Mix, HyperVerITAS PST. Size: 2^{:?}\n", i);
        let _res = run_full_mono_pst(i);
        println!("-----------------------------------------------------------------------");
    }
}
