//use rust_symcrypt;
use rustls_symcrypt::hash::*;
use rustls::crypto::hash::Hash;

fn main() {
    // let sha256_instance = SHA256;
    // let res = sha256_instance.algorithm();
    // println!("{:?}", res);

    // let len = sha256_instance.output_len();
    // println!("{:?}", len);

    // let data = hex::decode("641ec2cf711e").unwrap();
    // let expected: &str = "cfdbd6c9acf9842ce04e8e6a0421838f858559cf22d2ea8a38bd07d5e4692233";


    // let result = sha256_instance.hash(&data); // this also works, instead of what i had below.
    // //println!("{:?}", result);
    // assert_eq!(hex::encode(result), expected);



    // let new_instance = SHA256::start(&SHA256); // this is creating a new sha256 context or sha 256 "state"

    println!("Hello, world!");

}
