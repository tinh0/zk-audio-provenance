#![allow(warnings)]

use plonkish_backend::util::{
    new_fields::Mersenne127 as F,
    arithmetic::Field as myField,
};

pub const IRRED_POLY_TABLE: &[u32] = &[
    0, 0, 7, 11, 19, 37, 67, 131, 285, 529, 1033, 2053, 4179, 8219, 16707, 32771, 69643, 131081,
    262273, 524327, 1048585, 2097157, 4194307, 8388641, 16777351, 33554441, 67108935,
];

pub fn eq_eval(x: &[F], y: &[F]) -> F {
    let mut res = F::ONE;
    for (&xi, &yi) in x.iter().zip(y.iter()) {
        let xi_yi = xi * yi;
        res *= xi_yi + xi_yi - xi - yi + F::ONE;
    }
    res
}

pub fn mat_sparse_mult_vec(
    num_rows: usize,
    _num_cols: usize,
    sprse_rep: &[Vec<(usize, F)>],
    r: &[F],
) -> Vec<F> {
    let mut result = Vec::new();
    for i in 0..num_rows {
        let mut my_sum = F::ZERO;
        for j in 0..sprse_rep[i].len() {
            my_sum += sprse_rep[i][j].1 * r[sprse_rep[i][j].0];
        }
        result.push(my_sum);
    }
    result
}

pub fn make_pts_full_crop(num_cols: usize, vals: Vec<Vec<F>>) -> Vec<Vec<F>> {
    let mut points = Vec::new();

    let mut orig_pt: Vec<F> = vals[0].clone();
    orig_pt.push(F::ZERO);
    points.push(orig_pt.clone());

    // 0 vector, used for h
    let pt0: Vec<F> = vec![F::ZERO; num_cols + 1];
    points.push(pt0.clone());
    // 1..10 vector, used for prod
    let mut final_query = vec![F::ONE; num_cols + 1];
    final_query[0] = F::ZERO;
    points.push(final_query);
    // Eval for range for image
    for i in 0..3 {
        let my_rand = vals[1 + i].clone();

        points.push(my_rand.clone());

        // point 1 for h_{+1}
        let galois_rep = IRRED_POLY_TABLE[num_cols + 1] - (1 << (num_cols + 1));
        let (fiddle, zero, _start_val) = galoisify_pt((num_cols + 1) as u32, galois_rep, my_rand.clone());

        points.push(fiddle);
        // point 2 for h_{+1}
        points.push(zero);

        //Rand point used for prod and frac polies
        points.push(my_rand.clone());

        // Randpoint but last is 0
        let mut pt_rand = Vec::new();
        pt_rand.push(F::ZERO);
        for k in 0..my_rand.len() - 1 {
            pt_rand.push(my_rand[k]);
        }
        points.push(pt_rand.clone());
        // Randpoint but last is 1
        pt_rand[0] = F::ONE;
        points.push(pt_rand.clone());
    }
    // zero can be at beginning or end depending on little endian or big endian
    let mut little_juicer = vals[4].clone();
    little_juicer.push(F::ZERO);
    points.push(little_juicer.clone());
    for j in 0..3 {
        let mut small_pt = points[3 + j * 6].clone();
        small_pt[num_cols] = F::ZERO;
        points.push(small_pt);
    }
    points
}

pub fn galoisify_pt(nv: u32, galois_rep: u32, pt: Vec<F>) -> (Vec<F>, Vec<F>, F) {
    let mut my_indexes = Vec::new();
    let mut galois_rep_temp = galois_rep;

    for i in 0..nv + 1 {
        if galois_rep_temp >= (2u32).pow((nv - i).try_into().unwrap()) {
            galois_rep_temp -= (2u32).pow((nv - i).try_into().unwrap());
            my_indexes.push(nv - i);
        }
    }

    let mut fiddled_pt = Vec::new();
    let mut zero_pt = Vec::new();

    for i in 1..nv {
        zero_pt.push(pt[i as usize]);
        if my_indexes.contains(&i) {
            fiddled_pt.push(F::ONE - pt[i as usize]);
        } else {
            fiddled_pt.push(pt[i as usize]);
        }
    }
    zero_pt.push(F::ZERO);
    fiddled_pt.push(F::ONE);
    let start_index = pt[0];

    (fiddled_pt, zero_pt, start_index)
}
