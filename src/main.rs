mod functions; //Imports functions.rs file
use functions::*;
use std::io;
use rand::thread_rng;
use ark_bls12_381::Fr;
use ark_ff::UniformRand;

fn main() {
    let mut rng = thread_rng();

    //Ask for the max degree
    println!("Insert the max degree value for the polynomial:");
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let max_degree: usize = input.trim().parse().expect("Error, insert a numeric value \n");

    //Check max degree
    if max_degree == 0 {
        panic!("The degree must be greater than 0.");
    }
    if max_degree > 1_000_000 {
        panic!("Degree too large to handle.");
    }

    //Creating polynomial
    let polynomial = create_polynomial(max_degree);

    //Setup phase
    let public_parameters = setup_phase(max_degree);

    //Commitment phase
    let commitment = commitment_phase(&public_parameters.g1, &polynomial, max_degree);

    //Prove multi evaluations phase
    let zs: Vec<Fr> = (0..3).map(|_| Fr::rand(&mut rng)).collect();
    let (ys, proofs) = prove_multi_evaluations(&public_parameters.g1, &polynomial, &zs);

    //Verify multi evaluations phase
    let verification = verify_multi_evaluations(commitment, proofs, &zs, &ys, &public_parameters.g2);

    if verification {
        println!("All evaluations are correct");
    } else {
        println!("Some evaluations are NOT correct");
    }
}
