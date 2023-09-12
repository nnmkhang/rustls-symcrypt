use rustls_symcrypt::hash::*;
use rustls::crypto::hash::Hash;

fn main() {
    let sha256_instance = Sha256;
    let res = sha256_instance.algorithm();
    println!("{:?}", res);

    let len = sha256_instance.output_len();
    println!("{:?}", len);

    let data = hex::decode("641ec2cf711e").unwrap();
    let expected: &str = "cfdbd6c9acf9842ce04e8e6a0421838f858559cf22d2ea8a38bd07d5e4692233";


    let result = sha256_instance.hash(&data); 
    assert_eq!(hex::encode(result), expected);

    let mut new_instance = sha256_instance.start(); 
    new_instance.update(&data);

    let fork_result = new_instance.fork_finish();
    assert_eq!(hex::encode(fork_result), expected);

    let finish_result = new_instance.finish();
    assert_eq!(hex::encode(finish_result), expected);

    println!("Hello, world!");

}
