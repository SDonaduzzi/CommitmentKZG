use ark_ff::{AdditiveGroup, Field, UniformRand, Zero};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Projective};
use ark_ec::{pairing::Pairing, PrimeGroup};
use rand::thread_rng;

pub struct PublicParams {
    pub g1: Vec<G1Projective>,
    pub g2: Vec<G2Projective>,
}

pub fn setup_phase(max_degree: usize) -> PublicParams {
    let mut rng = thread_rng();
    let tau: Fr = Fr::rand(&mut rng);

    //G1 public parameters
    let g1: G1Projective = G1Projective::generator();

    let mut powers_of_tau: Vec<G1Projective> = Vec::with_capacity(max_degree + 1);
    let mut current_power = Fr::ONE;

    //Creating public marameters (g, g^tau, g^tau^2, ..., g^tau^k)
    for _ in 0..=max_degree {
        let point = g1 * current_power;
        powers_of_tau.push(point);
        current_power *= tau;
    }

    //G2 public parameters
    let g2: G2Projective = G2Projective::generator();

    let mut powers_of_tau2: Vec<G2Projective> = Vec::with_capacity(max_degree + 1);
    let mut current_power2 = Fr::ONE;

    for _ in 0..=max_degree {
        let point2 = g2 * current_power2;
        powers_of_tau2.push(point2);
        current_power2 *= tau;
    }

    println!("Public parameters G1: {:?},\nPublic parameters G2: {:?}", powers_of_tau, powers_of_tau2);

    let public_params = PublicParams
    {
        g1: powers_of_tau,
        g2: powers_of_tau2,
    };

    public_params
}

pub fn create_polynomial(max_degree: usize) -> DensePolynomial<Fr> {
    let mut coefficients: Vec<Fr> = Vec::with_capacity(max_degree + 1);
    let rng = thread_rng();
    for i in 0..=max_degree {
        let coeff = Fr::from((i + 2) as u64);
        //let coeff = Fr::rand(&mut rng); for random coefficients
        //println!("coefficients: {:?}", coeff);
        coefficients.push(coeff);
    }

    let polynomial = DensePolynomial::from_coefficients_vec(coefficients);
    polynomial
}

pub fn commitment_phase(public_parameters: &Vec<G1Projective>, polynomial: &DensePolynomial<Fr>, max_degree: usize) -> G1Projective {
    let mut commitment = G1Projective::ZERO;
    //Committing the polynomial (a1*pp1 + a2*pp2 ... + an*ppn)
    for i in 0..=max_degree {
        let scalar_mul = public_parameters[i] * polynomial.coeffs[i];
        commitment += scalar_mul;
    }
    println!("Commitment: {:?}", commitment);
    commitment
}

pub fn prove_multi_evaluations(public_parameters: &Vec<G1Projective>, polynomial: &DensePolynomial<Fr>, zs: &[Fr]) -> (Vec<Fr>, Vec<G1Projective>) {
    let mut evaluations = Vec::new();
    let mut proofs = Vec::new();

    //calculating multi evaluations
    for &z in zs {
        //Evaluating P(z)
        let y = polynomial.evaluate(&z);
        evaluations.push(y);

        //Calculating Q(x) = (P(x)-y)/(x-z)
        let dividend = polynomial.clone() - DensePolynomial::from_coefficients_vec(vec![y]);
        let divisor = DensePolynomial::from_coefficients_vec(vec![-z, Fr::ONE]);

        if divisor.is_zero() {
            println!("Error: divisor is zero when calculating Q(x)");
            proofs.push(G1Projective::ZERO);
        } else {
            let qx = dividend / divisor;
            //Committing Q(x)
            let mut proof = G1Projective::ZERO;
            for i in 0..qx.coeffs.len() {
                let scalar_mul = public_parameters[i] * qx.coeffs[i];
                proof += scalar_mul;
            }
            proofs.push(proof);
        }
    }

    (evaluations, proofs)
}

pub fn verify_multi_evaluations(commitment: G1Projective, proofs: Vec<G1Projective>, zs: &[Fr], ys: &[Fr], public_parameters2: &Vec<G2Projective>,) -> bool {
    let g2 = public_parameters2[0];
    let g2_tau = public_parameters2[1];

    for ((&z, &y), proof) in zs.iter().zip(ys.iter()).zip(proofs.iter()) {
        let g2_tau_z = g2_tau - g2 * z;
        let gy = G1Projective::generator() * y;
        let commitment_y = commitment - gy;

        //Pairing e(π,[t−a]2​)=e(c−[b]1​,h)
        let pairing_1 = Bls12_381::pairing(*proof, g2_tau_z);
        let pairing_2 = Bls12_381::pairing(commitment_y, g2);

        if pairing_1 != pairing_2 {
            return false;
        }
    }

    true
}