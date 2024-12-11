use ark_ff::{AdditiveGroup, Field, UniformRand, Zero};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Projective};
use ark_std::test_rng;
use ark_ec::{pairing::Pairing, PrimeGroup};
use rand::thread_rng;
use std::io;

struct PublicParams {
    g1: Vec<G1Projective>,
    g2: Vec<G2Projective>,
}

fn setup_phase(max_degree: usize) -> PublicParams
{
    let mut rng = thread_rng();
    let tau: Fr = Fr::rand(&mut rng);

    //G1 public parameters
    let g1: G1Projective = G1Projective::generator();

    let mut powers_of_tau: Vec<G1Projective> = Vec::with_capacity(max_degree + 1);
    let mut current_power = Fr::ONE;

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

fn create_polynomial(max_degree: usize) -> DensePolynomial<Fr>
{
    let mut coefficients: Vec<Fr> = Vec::with_capacity(max_degree + 1);

    for i in 0..=max_degree {
        let coeff = Fr::from((i + 2) as u64);
        coefficients.push(coeff);
    }

    let polynomial = DensePolynomial::from_coefficients_vec(coefficients);
    polynomial
}

fn commitment_phase(public_parameters: &Vec<G1Projective>, polynomial: &DensePolynomial<Fr>, max_degree: usize) -> G1Projective
{
    let mut commitment = G1Projective::ZERO;
    for i in 0..=max_degree {
        let scalar_mul = public_parameters[i] * polynomial.coeffs[i];
        commitment += scalar_mul;
    }
    println!("Commitment: {:?}", commitment);
    commitment
}

fn prove_an_evaluation(public_parameters: &Vec<G1Projective>, polynomial: &DensePolynomial<Fr>, z: Fr) -> (Fr, G1Projective) {
    let y = polynomial.evaluate(&z);
    println!("Evaluating polynomial at z = {:?}: P(z) = {:?}", z, y);
 
    let dividend = polynomial.clone() - DensePolynomial::from_coefficients_vec(vec![y]);
    let divisor = DensePolynomial::from_coefficients_vec(vec![-z, Fr::ONE]);

    //Check if divisor is not 0
    if divisor.is_zero() {
        println!("Error: divisor is zero when calculating Q(x)");
        return (y, G1Projective::ZERO);
    }

    //Calculating Q(x)
    let qx = dividend / divisor;
    println!("Q(x): {:?}", qx);

    //Committing proof
    let mut proof = G1Projective::ZERO;
    for i in 0..qx.coeffs.len() {
        let scalar_mul = public_parameters[i] * qx.coeffs[i];
        proof += scalar_mul;
    }
    println!("Committed proof: {:?}", proof);

    (y, proof)
}

fn verify_evaluation(commitment: G1Projective, proof: G1Projective, z: Fr, y: Fr, public_parameters2: &Vec<G2Projective>) -> bool {
   let g2 = public_parameters2[0];
   let g2_tau = public_parameters2[1];

   let g2_tau_z = g2_tau - g2 * z;

   let gy = G1Projective::generator() * y;
   let commitment_y = commitment - gy;

   let pairing_1 = Bls12_381::pairing(proof, g2_tau_z);
   let pairing_2 = Bls12_381::pairing(commitment_y, g2);

   pairing_1 == pairing_2
}

fn main() {
    let mut rng = thread_rng();

    println!("Insert the max degree value for the polynomial:");
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let max_degree: usize = input.trim().parse().expect("Error, insert a numeric value \n");
    if max_degree == 0 {
        panic!("The degree must be greater than 0.");
    }
    if max_degree > 1_000_000 {
        panic!("Degree too large to handle.");
    }

    let polynomial = create_polynomial(max_degree);
    let public_parameters = setup_phase(max_degree);

    let commitment = commitment_phase(&public_parameters.g1, &polynomial, max_degree);

    let z = Fr::rand(&mut rng);

    let (y, proof) = prove_an_evaluation(&public_parameters.g1, &polynomial, z);

    let verification = verify_evaluation(commitment, proof, z, y, &public_parameters.g2);

    if verification
    {
        println!("The evaluation is correct");
    } else {
        println!("The evaluation is NOT correct");
    }

}