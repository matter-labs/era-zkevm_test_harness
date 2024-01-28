//! Implementation based on https://github.com/ethereum/consensus-specs/blob/86fb82b221474cc89387fa6436806507b3849d88/specs/deneb/polynomial-commitments.md
use crate::boojum::blake2::Digest;
use crate::boojum::pairing::bls12_381::fq::Fq;
use crate::boojum::pairing::bls12_381::fq12::Fq12;
use crate::boojum::pairing::bls12_381::fr::{Fr, FrRepr};
use crate::boojum::pairing::bls12_381::Bls12;
use crate::boojum::pairing::bls12_381::{G1Affine, G1Compressed, G2Affine, G2Compressed, G1, G2};
use crate::boojum::pairing::ff::{Field, PrimeField};
use crate::boojum::pairing::Engine;
use crate::boojum::pairing::{CurveAffine, CurveProjective, EncodedPoint};
use crate::sha2::Sha256;
use rayon::prelude::*;
use serde::Serialize;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct TrustedSetup {
    g1_lagrange: Vec<String>,
}

const BLS_MODULUS: [u64; 4] = [
    0xffffffff00000001,
    0x53bda402fffe5bfe,
    0x3339d80809a1d805,
    0x73eda753299d7d48,
];
const FIELD_ELEMENTS_PER_BLOB: usize = 4096;
const SETUP_JSON: &str = "src/kzg/trusted_setup.json";

// reverse bit order of given number assuming an order of 4096
fn bit_reverse_4096(n: u64) -> u64 {
    n.reverse_bits() >> 52
}

fn bit_reverse_array<T: Clone>(input: &mut [T]) {
    (0..input.len()).for_each(|i| {
        let ri = bit_reverse_4096(i as u64) as usize;
        if i < ri {
            input.swap(ri, i);
        }
    });
}

fn hex_to_bytes(hex_string: &str) -> Vec<u8> {
    (0..hex_string.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_string[i..i + 2], 16).unwrap())
        .collect::<Vec<u8>>()
}

lazy_static::lazy_static! {
    static ref ROOTS_OF_UNITY: [Fr; FIELD_ELEMENTS_PER_BLOB] = {
        // 39033254847818212395286706435128746857159659164139250548781411570340225835782
        // 2^12 root of unity for BLS12-381
        let base_root = Fr::from_repr(FrRepr([
            0xe206da11a5d36306,
            0x0ad1347b378fbf96,
            0xfc3e8acfe0f8245f,
            0x564c0a11a0f704f4,
        ])).unwrap();
        let mut roots = [Fr::one(); FIELD_ELEMENTS_PER_BLOB];
        roots[1] = base_root;
        (2..4096).for_each(|i| {
            let prev_root = roots[i-1];
            roots[i] = base_root;
            roots[i].mul_assign(&prev_root);
        });

        roots
    };
    static ref ROOTS_OF_UNITY_BRP: [Fr; FIELD_ELEMENTS_PER_BLOB] = {
        let mut reversed_roots = ROOTS_OF_UNITY.clone();
        bit_reverse_array(&mut reversed_roots);
        reversed_roots
    };
    static ref SETUP_G2_1: G2 = {
        let point = "b5bfd7dd8cdeb128843bc287230af38926187075cbfbefa81009a2ce615ac53d2914e5870cb452d2afaaab24f3499f72185cbfee53492714734429b7b38608e23926c911cceceac9a36851477ba4c60b087041de621000edc98edada20c1def2";
        let bytes = hex_to_bytes(point);
        let mut point = G2Compressed::empty();
        let v = point.as_mut();
        v.copy_from_slice(bytes.as_slice());
        point.into_affine().unwrap().into_projective()
    };
    // Bit-reversed Lagrange bases of the eip4844 setup ceremony
    static ref LAGRANGE_SETUP_BRP: [G1Affine; FIELD_ELEMENTS_PER_BLOB] = {
        let setup: TrustedSetup = serde_json::from_slice(&std::fs::read(SETUP_JSON).unwrap()).unwrap();
        let mut base_setup: Vec<G1> = setup.g1_lagrange.iter().map(|hex| {
            let bytes = hex_to_bytes(&hex[2..]);
            let mut point = G1Compressed::empty();
            let v = point.as_mut();
            v.copy_from_slice(bytes.as_slice());
            point.into_affine().unwrap().into_projective()
        }).collect::<Vec<G1>>();

        // radix-2 ifft
        // we break up the powers into smallest chunks and then compose them together with the
        // cooley-tukey algorithm. the roots need to be inverted, and all results need to be
        // divided by 2^12.
        let roots = ROOTS_OF_UNITY
            .into_iter()
            .take(FIELD_ELEMENTS_PER_BLOB / 2)
            .map(|r| if r != Fr::one() { r.inverse().unwrap() } else { r })
            .collect::<Vec<Fr>>();

        // we bit-reverse the powers to perform the IFFT in-place
        bit_reverse_array(&mut base_setup);

        // then, we chunk the powers in order to compute the DFTs and combine them
        let mut split = 1;
        while split < base_setup.len() {
            base_setup.chunks_mut(split * 2).for_each(|chunk| {
                let (low, high) = chunk.split_at_mut(split);
                low.iter_mut()
                    .zip(high)
                    .zip(roots.iter().step_by(FIELD_ELEMENTS_PER_BLOB / (split * 2)))
                    .for_each(|((low, high), root)| {
                        high.mul_assign(*root);
                        let mut neg = low.clone();
                        neg.sub_assign(high);
                        low.add_assign(high);
                        *high = neg;
                    });
            });

            split *= 2;
        }


        // lastly, we need to divide all the results by 2^12
        let domain_inv = Fr::from_repr(FrRepr([FIELD_ELEMENTS_PER_BLOB as u64, 0, 0, 0]))
            .unwrap()
            .inverse()
            .unwrap();
        let mut lagrange_bases = base_setup
            .iter_mut()
            .map(|power| {
                power.mul_assign(domain_inv);
                power.into_affine()
            })
            .collect::<Vec<G1Affine>>();

        // we re-run the brp since the blobs are interpreted as evaluation form polys in brp
        bit_reverse_array(&mut lagrange_bases);
        let mut lagrange_bases_arr = [G1Affine::zero(); FIELD_ELEMENTS_PER_BLOB];
        lagrange_bases_arr.copy_from_slice(&lagrange_bases);
        lagrange_bases_arr
    };
}

/// Computes a KZG commitment to a EIP4844 blob.
pub fn compute_commitment(blob: &[Fr]) -> G1Affine {
    assert!(blob.len() <= FIELD_ELEMENTS_PER_BLOB);
    multiscalar_mul(&LAGRANGE_SETUP_BRP.as_slice(), blob)
}

// XXX: this could be sped up but im not sure if its necessary due to always having 4096 elements
/// Performs a naive MSM and compute a polynomial commitment.
pub fn multiscalar_mul(points: &[G1Affine], scalars: &[Fr]) -> G1Affine {
    assert!(scalars.len() <= points.len());
    scalars
        .par_iter()
        .zip(points)
        .fold(
            || G1::zero(),
            |mut acc, (scalar, point)| {
                acc.add_assign(&point.mul(*scalar));
                acc
            },
        )
        .reduce(
            || G1::zero(),
            |mut a: G1, b: G1| {
                a.add_assign(&b);
                a
            },
        )
        .into_affine()
}

/// Computes a KZG opening proof for the given blob and evaluation point.
pub fn compute_proof(blob: &[Fr], z: &Fr) -> (G1Affine, Fr) {
    let y = eval_poly(blob, z);
    let shifted_poly = blob
        .into_iter()
        .map(|el| {
            let mut el = el.clone();
            el.sub_assign(&y);
            el
        })
        .collect::<Vec<Fr>>();
    let denom_poly = ROOTS_OF_UNITY_BRP
        .into_iter()
        .map(|mut el| {
            el.sub_assign(&z);
            el
        })
        .collect::<Vec<Fr>>();
    let quotient_poly = shifted_poly
        .iter()
        .zip(denom_poly.iter())
        .enumerate()
        .map(|(i, (shifted, denom))| {
            if denom.is_zero() {
                compute_quotient_eval(&ROOTS_OF_UNITY_BRP[i], blob, &y)
            } else {
                let mut res = shifted.clone();
                res.mul_assign(&denom.inverse().unwrap());
                res
            }
        })
        .collect::<Vec<Fr>>();

    (
        multiscalar_mul(&LAGRANGE_SETUP_BRP.to_vec(), &quotient_poly),
        y,
    )
}

/// Verifies a KZG commitment and proof for a given evaluation point and evaluation result.
pub fn verify_kzg_proof(commitment: &G1Affine, z: &Fr, y: &Fr, proof: &G1Affine) -> bool {
    let mut t = G2Affine::one().into_projective();
    t.mul_assign(*z);
    let mut x_minus_z = SETUP_G2_1.clone();
    x_minus_z.sub_assign(&t);

    let mut p_minus_y = commitment.into_projective();
    let mut t = G1Affine::one().into_projective();
    t.mul_assign(*y);
    p_minus_y.sub_assign(&t);

    let mut g2_neg = G2Affine::one().into_projective();
    g2_neg.negate();

    let mut p1 = Bls12::pairing(p_minus_y, g2_neg);
    p1.mul_assign(&Bls12::pairing(*proof, x_minus_z));
    p1 == Fq12::one()
}

/// Computes a KZG opening proof for the given polynomial with a deterministic challenge point.
pub fn compute_proof_poly(blob: &[Fr], commitment: &G1Affine) -> G1Affine {
    let z = compute_challenge(blob, commitment);
    compute_proof(blob, &z).0
}

/// Verifies a KZG commitment and opening proof for a given polynomial with a deterministic
/// challenge point.
pub fn verify_proof_poly(blob: &[Fr], commitment: &G1Affine, proof: &G1Affine) -> bool {
    let challenge = compute_challenge(&blob, commitment);
    let y = eval_poly(blob, &challenge);
    verify_kzg_proof(commitment, &challenge, &y, proof)
}

fn compute_quotient_eval(z: &Fr, poly: &[Fr], y: &Fr) -> Fr {
    ROOTS_OF_UNITY_BRP
        .iter()
        .zip(poly.iter())
        .fold(Fr::zero(), |mut acc, (root, p)| {
            if *root == *z {
                acc
            } else {
                let mut p = p.clone();
                let mut z_1 = z.clone();
                let mut z_2 = z.clone();
                p.sub_assign(&y);
                p.mul_assign(&root);
                z_1.sub_assign(&root);
                z_2.mul_assign(&z_1);
                p.mul_assign(&z_2.inverse().unwrap());
                acc.add_assign(&p);
                acc
            }
        })
}

// barycentric eval
fn eval_poly(blob: &[Fr], z: &Fr) -> Fr {
    assert!(blob.len() <= FIELD_ELEMENTS_PER_BLOB);
    let inverse_width = Fr::from_repr(FrRepr([blob.len() as u64, 0, 0, 0]))
        .unwrap()
        .inverse()
        .unwrap();
    let mut res = {
        if let Some(idx) = ROOTS_OF_UNITY_BRP.iter().position(|r| r == z) {
            blob[idx]
        } else {
            blob.iter()
                .zip(ROOTS_OF_UNITY_BRP.iter())
                .fold(Fr::zero(), |mut acc, (el, root)| {
                    let mut el = el.clone();
                    el.mul_assign(&root);
                    let mut z_1 = z.clone();
                    z_1.sub_assign(&root);
                    el.mul_assign(&z_1.inverse().unwrap());
                    acc.add_assign(&el);
                    acc
                })
        }
    };

    let mut z_1 = z.clone();
    z_1 = z_1.pow([blob.len() as u64]);
    z_1.sub_assign(&Fr::one());
    res.mul_assign(&z_1);
    res.mul_assign(&inverse_width);
    res
}

fn compute_challenge(blob: &[Fr], commitment: &G1Affine) -> Fr {
    let mut data = String::from("FSBLOBVERIFY_V1_").into_bytes();
    let degree_separator: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0];
    data.extend(&degree_separator);
    let blob_bytes = blob
        .iter()
        .flat_map(|el| {
            el.into_repr()
                .0
                .iter()
                .rev()
                .flat_map(|v| v.to_be_bytes())
                .collect::<Vec<u8>>()
        })
        .collect::<Vec<u8>>();
    data.extend(&blob_bytes);
    data.extend(commitment.into_compressed().as_ref());

    let mut result = [0u8; 32];
    let digest = Sha256::digest(data);
    result.copy_from_slice(&digest);

    // reduce to fit within bls scalar field
    let mut repr = u8_repr_to_u64_repr(result);
    while repr_greater_than(repr, BLS_MODULUS) != std::cmp::Ordering::Less {
        repr = reduce(repr, BLS_MODULUS);
    }

    Fr::from_repr(FrRepr(repr)).unwrap()
}

fn u8_repr_to_u64_repr(bytes: [u8; 32]) -> [u64; 4] {
    let mut ret = [0u64; 4];
    for i in 0..ret.len() {
        let mut repr = [0u8; 8];
        let end = 32 - (8 * i);
        let beg = 32 - (8 * (i + 1));
        repr.copy_from_slice(&bytes[beg..end]);
        ret[i] = u64::from_be_bytes(repr);
    }

    ret
}

fn repr_greater_than(repr: [u64; 4], modulus: [u64; 4]) -> std::cmp::Ordering {
    for (r, m) in repr.into_iter().zip(modulus).rev() {
        if r > m {
            return std::cmp::Ordering::Greater;
        } else if m > r {
            return std::cmp::Ordering::Less;
        }
    }

    std::cmp::Ordering::Equal
}

fn reduce(repr: [u64; 4], modulus: [u64; 4]) -> [u64; 4] {
    let mut res = [0u64; 4];

    let (v, borrow) = repr[0].borrowing_sub(modulus[0], false);
    res[0] = v;
    let (v, borrow) = repr[1].borrowing_sub(modulus[1], borrow);
    res[1] = v;
    let (v, borrow) = repr[2].borrowing_sub(modulus[2], borrow);
    res[2] = v;
    // we only call reduce if repr is greater than modulus so we dont need the last borrow value
    let (v, _) = repr[3].borrowing_sub(modulus[3], borrow);
    res[3] = v;
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rand;

    #[test]
    fn test_commit_verify() {
        let mut rng = rand::thread_rng();
        let mut blob = [Fr::zero(); FIELD_ELEMENTS_PER_BLOB];
        blob.iter_mut().for_each(|v| *v = Fr::rand(&mut rng));

        let commitment = compute_commitment(&blob);
        let z = Fr::rand(&mut rng);
        let (proof, y) = compute_proof(&blob, &z);
        assert!(verify_kzg_proof(&commitment, &z, &y, &proof));
    }

    #[test]
    fn test_commit_verify_random_challenge() {
        let mut rng = rand::thread_rng();
        let mut blob = [Fr::zero(); FIELD_ELEMENTS_PER_BLOB];
        blob.iter_mut().for_each(|v| *v = Fr::rand(&mut rng));

        let commitment = compute_commitment(&blob);
        let proof = compute_proof_poly(&blob, &commitment);
        assert!(verify_proof_poly(&blob, &commitment, &proof));
    }
}
