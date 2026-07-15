#![allow(warnings)]

use ark_std::{rand::{RngCore, SeedableRng}, test_rng};
use rand_chacha::ChaCha8Rng;

use hyperveritas_impl::{helper::*, image::Image};

use plonkish_backend::{
    pcs::{
        Evaluation, PolynomialCommitmentScheme,
        multilinear::{MultilinearBrakedown, MultilinearBrakedownCommitment, additive::batch_verify_one},
    },
    poly::{
        Polynomial,
        multilinear::MultilinearPolynomial,
    },
    piop::sum_check::{
        SumCheck,
        classic::{ClassicSumCheck, EvaluationsProver},
    },
    util::{
        hash::Blake2s,
        new_fields::Mersenne127 as F,
        code::BrakedownSpec6,
        arithmetic::Field as myField,
        transcript::{Blake2sTranscript, FiatShamirTranscript, FieldTranscript, FieldTranscriptRead, InMemoryTranscript},
    },
};

use crate::helpers::*;

type Pcs = MultilinearBrakedown<F, Blake2s, BrakedownSpec6>;
type VT = FiatShamirTranscript<Blake2s, std::io::Cursor<Vec<u8>>>;

/// Compute the camera hash (digestRGB) from an original image.
/// This is what the "camera" would compute and sign.
pub fn compute_camera_hash(input_size: usize, orig_img: &Image) -> Vec<Vec<F>> {
    let rgb_evals = [
        fieldVec::<F>(&orig_img.R.iter().map(|&x| x as u64).collect::<Vec<_>>()),
        fieldVec::<F>(&orig_img.G.iter().map(|&x| x as u64).collect::<Vec<_>>()),
        fieldVec::<F>(&orig_img.B.iter().map(|&x| x as u64).collect::<Vec<_>>()),
    ];

    let mut digest_rgb = Vec::new();
    for k in 0..3 {
        let mut matrix_a = Vec::new();
        for i in 0..128 {
            matrix_a.push(ChaCha8Rng::seed_from_u64(i));
        }

        let mut digest = Vec::new();
        for i in 0..128 {
            let mut my_sum = F::ZERO;
            for j in 0..(1 << input_size) {
                my_sum += F::random(&mut matrix_a[i]) * rgb_evals[k][j];
            }
            digest.push(my_sum);
        }
        digest_rgb.push(digest);
    }

    digest_rgb
}

/// Run PCS parameter setup only (no camera hash).
/// The camera hash is now a public input, not recomputed by the verifier.
pub fn setup_params(input_size: usize) -> (
    <Pcs as PolynomialCommitmentScheme<F>>::ProverParam,
    <Pcs as PolynomialCommitmentScheme<F>>::VerifierParam,
) {
    let mut rng = test_rng();
    let poly_vars = input_size + 1;

    let poly_size = 1 << poly_vars;
    let param = Pcs::setup(poly_size, 4, &mut rng).unwrap();
    Pcs::trim(&param, poly_size, 4).unwrap()
}

/// Verify a crop proof from serialized bytes.
///
/// The camera hash (digestRGB) is now received as a public input,
/// not recomputed from the original image.
pub fn verify_from_bytes(
    vp: <Pcs as PolynomialCommitmentScheme<F>>::VerifierParam,
    num_rows: usize,
    num_cols: usize,
    nv_crop: usize,
    orig_width: usize,
    orig_height: usize,
    start_x: usize,
    start_y: usize,
    end_x: usize,
    end_y: usize,
    camera_hash: Vec<Vec<F>>,
    proof_bytes: &[u8],
    crop_img: &Image,
) -> bool {
    let width = end_x - start_x;
    let height = end_y - start_y;

    // Build eval vec structures
    let mut hevals_vec: Vec<Vec<Evaluation<F>>> = Vec::new();
    let mut fracevals_vec: Vec<Vec<Evaluation<F>>> = Vec::new();
    let mut prodevals_vec: Vec<Vec<Evaluation<F>>> = Vec::new();
    let mut imgevals_vec: Vec<Vec<Evaluation<F>>> = Vec::new();
    for _ch in 0..3 {
        let mut hevals_0 = Vec::new();
        for j in 0..4 { hevals_0.push(Evaluation::new(j, j, F::ZERO)); }
        hevals_vec.push(hevals_0);

        let mut fracevals_0 = Vec::new();
        for j in 0..3 { fracevals_0.push(Evaluation::new(j, j, F::ZERO)); }
        fracevals_vec.push(fracevals_0);

        let mut prodevals_0 = Vec::new();
        for j in 0..4 { prodevals_0.push(Evaluation::new(j, j, F::ZERO)); }
        prodevals_vec.push(prodevals_0);

        let mut imgevals_0 = Vec::new();
        for j in 0..3 { imgevals_0.push(Evaluation::new(j, j, F::ZERO)); }
        imgevals_vec.push(imgevals_0);
    }

    // Load crop image data from struct instead of file
    let mut commits = Vec::new();
    let mut my_alphas = Vec::new();

    let rgb_evals_crop = [
        fieldVec::<F>(&crop_img.R.iter().map(|&x| x as u64).collect::<Vec<_>>()),
        fieldVec::<F>(&crop_img.G.iter().map(|&x| x as u64).collect::<Vec<_>>()),
        fieldVec::<F>(&crop_img.B.iter().map(|&x| x as u64).collect::<Vec<_>>()),
    ];

    // Load proof from bytes
    let mut ver_transcript = Blake2sTranscript::from_proof((), proof_bytes);

    // Append image coms
    commits.append(&mut Pcs::read_commitments(&vp, 3, &mut ver_transcript).unwrap());

    // Squeeze RTA Challenge(Frievald)
    let frievald_rand_vec_rta = <VT as FieldTranscript<F>>::squeeze_challenges(&mut ver_transcript, 1 << num_rows);

    // Squeeze batching sumcheck vals, alpha1, alpha2
    let alpha_1_hash = <VT as FieldTranscript<F>>::squeeze_challenge(&mut ver_transcript);
    let alpha_2_hash = <VT as FieldTranscript<F>>::squeeze_challenge(&mut ver_transcript);

    // Squeeze challenges for sumcheck
    let _challenges: Vec<F> = vec![<VT as FieldTranscript<F>>::squeeze_challenge(&mut ver_transcript)];
    // Squeeze rand_vec for sumcheck
    let _rand_vector = <VT as FieldTranscript<F>>::squeeze_challenges(&mut ver_transcript, num_cols);

    // Verify sumcheck
    let mut my_sum_vals = [F::ZERO, F::ZERO, F::ZERO];
    for i in 0..3 {
        for j in 0..1 << num_rows {
            my_sum_vals[i] += frievald_rand_vec_rta[j] * camera_hash[i][j];
        }
    }
    let my_sum = my_sum_vals[0] + alpha_1_hash * my_sum_vals[1] + alpha_2_hash * my_sum_vals[2];
    let ver_res_camera_hash = match ClassicSumCheck::<EvaluationsProver<F>>::verify(&(), num_cols, 2, my_sum, &mut ver_transcript) {
        Ok(v) => v,
        Err(_) => return false,
    };
    my_alphas.push(ver_res_camera_hash.clone().1);

    // Done with camera hash part; moving on to range check
    let mut alpha1 = Vec::new();
    let mut alpha2 = Vec::new();
    let mut ver_res_range_rgb = Vec::new();
    let mut betas = Vec::new();
    let mut maybe_challenge_vecs = Vec::new();
    for i in 0..3 {
        // Append h table com
        commits.append(&mut Pcs::read_commitments(&vp, 1, &mut ver_transcript).unwrap());
        // Get alpha for the multset check
        alpha1.push(<VT as FieldTranscript<F>>::squeeze_challenge(&mut ver_transcript));
        alpha2.push(<VT as FieldTranscript<F>>::squeeze_challenge(&mut ver_transcript));
        // Append frac then prod coms
        commits.append(&mut Pcs::read_commitments(&vp, 2, &mut ver_transcript).unwrap());
        // Squeeze beta
        betas.push(<VT as FieldTranscript<F>>::squeeze_challenge(&mut ver_transcript));

        // Squeeze challenges and rand_vector for sumcheck
        let _challenges: Vec<F> = vec![<VT as FieldTranscript<F>>::squeeze_challenge(&mut ver_transcript)];
        let rand_vector = <VT as FieldTranscript<F>>::squeeze_challenges(&mut ver_transcript, num_cols + 1);
        // Prove the range sumcheck
        ver_res_range_rgb.push(match ClassicSumCheck::<EvaluationsProver<F>>::verify(&(), num_cols + 1, 3, F::ZERO, &mut ver_transcript) {
            Ok(v) => v,
            Err(_) => return false,
        });
        my_alphas.push(ver_res_range_rgb[i].1.clone());
        maybe_challenge_vecs.push(rand_vector);
    }

    // Squeeze Frievald Verifier
    let frievald_crop = <VT as FieldTranscript<F>>::squeeze_challenges(&mut ver_transcript, 1 << nv_crop);
    // Get alphas for batching sumcheck
    let alpha_1_trans = <VT as FieldTranscript<F>>::squeeze_challenge(&mut ver_transcript);
    let alpha_2_trans = <VT as FieldTranscript<F>>::squeeze_challenge(&mut ver_transcript);
    // Challenges and randVec for sumcheck
    let _challenges: Vec<F> = vec![<VT as FieldTranscript<F>>::squeeze_challenge(&mut ver_transcript)];
    let _rand_vector = <VT as FieldTranscript<F>>::squeeze_challenges(&mut ver_transcript, num_cols);
    // Calculate sum for sumcheck
    let mut my_sum_vals = [F::ZERO, F::ZERO, F::ZERO];
    for j in 0..(1 << nv_crop) {
        my_sum_vals[0] += frievald_crop[j] * rgb_evals_crop[0][j];
        my_sum_vals[1] += frievald_crop[j] * rgb_evals_crop[1][j];
        my_sum_vals[2] += frievald_crop[j] * rgb_evals_crop[2][j];
    }
    let my_sum = my_sum_vals[0] + alpha_1_trans * my_sum_vals[1] + alpha_2_trans * my_sum_vals[2];
    // Verify sumcheck
    let ver_res_img_transform = match ClassicSumCheck::<EvaluationsProver<F>>::verify(&(), num_cols, 2, my_sum, &mut ver_transcript) {
        Ok(v) => v,
        Err(_) => return false,
    };
    my_alphas.push(ver_res_img_transform.1);

    let points = make_pts_full_crop(num_cols, my_alphas.clone());

    let mut hpoints_vec = Vec::new();
    let mut hevals_vec2 = Vec::new();

    let mut fracpoints_vec = Vec::new();
    let mut fracevals_vec2 = Vec::new();

    let mut prodpoints_vec = Vec::new();
    let mut prodevals_vec2 = Vec::new();

    let mut imgpoints_vec = Vec::new();
    let mut imgevals_vec2 = Vec::new();

    let length = num_cols + 1;

    for i in 0..3 {
        let img_chnl_ind = i;
        let prod_ind = 5 + i * 3;
        let frac_ind = 4 + i * 3;
        let h_ind = 3 + i * 3;

        // MAKE H
        let mut hpoints_0 = Vec::new();
        hpoints_0.push(points[1].clone());
        hpoints_0.push(points[3 + i * 6].clone());
        hpoints_0.push(points[4 + i * 6].clone());
        hpoints_0.push(points[5 + i * 6].clone());

        hpoints_vec.push(hpoints_0.clone());

        let h_evals: Vec<F> = ver_transcript.read_field_elements(hevals_vec[i].len()).unwrap();
        let mut hevals2 = Vec::new();

        for j in 0..hevals_vec[i].len() {
            let mut new_eval = hevals_vec[i][j].clone();
            new_eval.value = h_evals[j];
            hevals2.push(new_eval);
        }

        hevals_vec2.push(h_evals.clone());

        match batch_verify_one::<F, Pcs>(
            &vp,
            length,
            commits[h_ind].clone(),
            &hpoints_0,
            &hevals2,
            &mut ver_transcript,
        ) {
            Ok(_) => {},
            Err(_) => return false,
        };

        // make FRAC
        let mut fracpoints_0 = Vec::new();
        fracpoints_0.push(points[6 + i * 6].clone());
        fracpoints_0.push(points[7 + i * 6].clone());
        fracpoints_0.push(points[8 + i * 6].clone());

        fracpoints_vec.push(fracpoints_0.clone());

        let frac_evals: Vec<F> = ver_transcript.read_field_elements(fracevals_vec[i].len()).unwrap();
        let mut fracevals2 = Vec::new();

        for j in 0..fracevals_vec[i].len() {
            let mut new_eval = fracevals_vec[i][j].clone();
            new_eval.value = frac_evals[j];
            fracevals2.push(new_eval);
        }

        fracevals_vec2.push(frac_evals.clone());

        match batch_verify_one::<F, Pcs>(
            &vp,
            length,
            commits[frac_ind].clone(),
            &fracpoints_0,
            &fracevals2,
            &mut ver_transcript,
        ) {
            Ok(_) => {},
            Err(_) => return false,
        };

        // make PROD
        let mut prodpoints_0 = Vec::new();
        prodpoints_0.push(points[2].clone());
        prodpoints_0.push(points[6 + i * 6].clone());
        prodpoints_0.push(points[7 + i * 6].clone());
        prodpoints_0.push(points[8 + i * 6].clone());

        prodpoints_vec.push(prodpoints_0.clone());

        let prod_evals: Vec<F> = ver_transcript.read_field_elements(prodevals_vec[i].len()).unwrap();
        let mut prodevals2 = Vec::new();

        for j in 0..prodevals_vec[i].len() {
            let mut new_eval = prodevals_vec[i][j].clone();
            new_eval.value = prod_evals[j];
            prodevals2.push(new_eval);
        }

        prodevals_vec2.push(prod_evals.clone());

        match batch_verify_one::<F, Pcs>(
            &vp,
            length,
            commits[prod_ind].clone(),
            &prodpoints_0,
            &prodevals2,
            &mut ver_transcript,
        ) {
            Ok(_) => {},
            Err(_) => return false,
        };

        // make IMG
        let mut imgpoints_0 = Vec::new();
        imgpoints_0.push(points[0].clone());
        imgpoints_0.push(points[points.len() - 3 + i].clone());
        imgpoints_0.push(points[21].clone());

        imgpoints_vec.push(imgpoints_0.clone());

        let img_evals: Vec<F> = ver_transcript.read_field_elements(imgevals_vec[i].len()).unwrap();
        let mut imgevals2 = Vec::new();

        for j in 0..imgevals_vec[i].len() {
            let mut new_eval = imgevals_vec[i][j].clone();
            new_eval.value = img_evals[j];
            imgevals2.push(new_eval);
        }

        imgevals_vec2.push(img_evals.clone());

        match batch_verify_one::<F, Pcs>(
            &vp,
            length,
            commits[img_chnl_ind].clone(),
            &imgpoints_0,
            &imgevals2,
            &mut ver_transcript,
        ) {
            Ok(_) => {},
            Err(_) => return false,
        };
    }

    // We have done all the opening proofs. Now it's JUST point equality.

    // We compute rTA
    let mut matrix_a = Vec::new();
    for i in 0..128 {
        matrix_a.push(ChaCha8Rng::seed_from_u64(i));
    }
    let mut rta = Vec::new();
    for i in 0..(1 << num_cols) {
        let mut my_sum = F::ZERO;
        for j in 0..128 {
            my_sum += F::random(&mut matrix_a[j]) * frievald_rand_vec_rta[j];
        }
        rta.push(my_sum);
    }
    let rta_poly = MultilinearPolynomial::<F>::new(rta.clone());

    let mut rta_pt = Vec::new();
    for i in 0..points[0].len() - 1 {
        rta_pt.push(ver_res_camera_hash.1[i]);
    }

    let lhs = rta_poly.evaluate(&rta_pt);
    let rhs = imgevals_vec2[0][0] + alpha_1_hash * imgevals_vec2[1][0] + alpha_2_hash * imgevals_vec2[2][0];
    let mut success = true;
    success = success && (ver_res_camera_hash.0 == lhs * rhs);

    // Verify image transformation
    let mut crop_perm = Vec::new();
    for _i in 0..1 << num_cols {
        let row = Vec::new();
        crop_perm.push(row);
    }
    let mut counter = 0;
    let mut init_val = orig_width * start_y + start_x;
    for _i in 0..height {
        for _j in 0..width {
            crop_perm[init_val].push((counter, F::ONE));
            counter += 1;
            init_val += 1;
        }
        init_val += orig_width - width;
    }
    let perm_times_r = mat_sparse_mult_vec(1 << num_cols, 1 << nv_crop, &crop_perm, &frievald_crop);
    let perm_times_r_poly = MultilinearPolynomial::new(perm_times_r.clone());
    let mut trans_point = Vec::new();
    for i in 0..points[21].len() - 1 {
        trans_point.push(points[21][i]);
    }
    let lhs = perm_times_r_poly.evaluate(&trans_point);
    let rhs = imgevals_vec2[0][2] + alpha_1_trans * imgevals_vec2[1][2] + alpha_2_trans * imgevals_vec2[2][2];
    success = success && (ver_res_img_transform.0 == lhs * rhs);

    // Verify h and v are done correctly in range check
    for i in 0..3 {
        success = success && (hevals_vec2[i][0] == F::ZERO);
        success = success && (prodevals_vec2[i][0] == F::ONE);
    }

    // Verify the range check
    let prim_poly_for_t = IRRED_POLY_TABLE[num_cols] as u64;
    let mut embedded_table: Vec<F> = vec![F::ZERO; 1 << num_cols];
    let mut plus_one_table: Vec<F> = vec![F::ZERO; 1 << num_cols];
    let galois_rep = prim_poly_for_t - (1 << num_cols);
    let size = 1u64 << num_cols;
    let mut binary_string: u64 = 1;
    for i in 1..(256usize + 1) {
        embedded_table[binary_string as usize] = F::from(i as u64);
        binary_string <<= 1;
        if binary_string & size != 0 {
            binary_string ^= galois_rep;
        }
        binary_string = (size - 1) & binary_string;
        plus_one_table[binary_string as usize] = F::from(i as u64);
    }
    let poly_table = MultilinearPolynomial::new(embedded_table.clone());
    let poly_plus_one_table = MultilinearPolynomial::new(plus_one_table.clone());

    for i in 0..3 {
        let my_rand = &points[3 + i * 6];
        let start_val = my_rand[0];
        let mut my_rand_small = Vec::new();
        for k in 0..my_rand.len() - 1 {
            my_rand_small.push(my_rand[k]);
        }
        let _last_val = my_rand[my_rand.len() - 1];
        let img_at_alpha_small = imgevals_vec2[i][1];
        let h_at_alpha_range = hevals_vec2[i][1];
        let h_at_alpha_range_fiddle = hevals_vec2[i][2];
        let h_at_alpha_range_0 = hevals_vec2[i][3];
        let prod_at_alpha_range = prodevals_vec2[i][1];
        let frac_at_alpha_range = fracevals_vec2[i][0];
        let prod_at_alpha_range_0 = prodevals_vec2[i][2];
        let frac_at_alpha_range_0 = fracevals_vec2[i][1];
        let prod_at_alpha_range_1 = prodevals_vec2[i][3];
        let frac_at_alpha_range_1 = fracevals_vec2[i][2];

        // We first compute prod(x) - v(x,0)v(x,1)
        let mut first_half = prod_at_alpha_range;
        let my_alpha = my_rand[my_rand.len() - 1];
        let v_x0 = my_alpha * prod_at_alpha_range_0 + (F::ONE - my_alpha) * frac_at_alpha_range_0;
        let v_x1 = my_alpha * prod_at_alpha_range_1 + (F::ONE - my_alpha) * frac_at_alpha_range_1;
        first_half += -v_x0 * v_x1;

        // alpha0 + merge(I,T)(X) + alpha1 merge(I,T_{+1})(X)
        let last_val = my_rand[my_rand.len() - 1];
        let mut f1 = alpha1[i] + ((F::ONE - last_val) * img_at_alpha_small + last_val * poly_table.evaluate(&my_rand_small));
        f1 += alpha2[i] * ((F::ONE - last_val) * img_at_alpha_small + last_val * poly_plus_one_table.evaluate(&my_rand_small));
        // alpha0 + h(X) + alpha1 h_{+1}(X)
        let f2 = alpha1[i] + h_at_alpha_range + alpha2[i] * (start_val * h_at_alpha_range_fiddle + (F::ONE - start_val) * h_at_alpha_range_0);
        let mut second_half = f2 * frac_at_alpha_range - f1;
        second_half = second_half * betas[i];

        let anticipated_val = ver_res_range_rgb[i].0;

        let final_val = first_half + second_half;

        let extra = eq_eval(my_rand, &maybe_challenge_vecs[i]);

        // gates(alpha) = finalVAL
        // anticipatedVal = gates(alpha)*eq_thingy(alpha)
        success = success && (anticipated_val == final_val * extra);
    }

    success
}
