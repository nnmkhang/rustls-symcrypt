/// TEMP FILE FOR TESTING

use rustls_symcrypt::hash::*;
use rustls_symcrypt::hmac::*;
use rustls::crypto::hmac::Hmac;

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




    // hmac testing 

    let sha256_hmac = HmacSha256;
    println!("{:?}", sha256_hmac.hash_output_len());
    let p_key = hex::decode("0a71d5cf99849bc13d73832dcd864244").unwrap();
    let data4 = hex::decode("17f1ee0c6767a1f3f04bb3c1b7a4e0d4f0e59e5963c1a3bf1540a76b25136baef425faf488722e3e331c77d26fbbd8300df532498f50c5ecd243f481f09348f964ddb8056f6e2886bb5b2f453fcf1de5629f3d166324570bf849792d35e3f711b041b1a7e30494b5d1316484ed85b8da37094627a8e66003d079bfd8beaa80dc").unwrap();
    let data1 = hex::decode("17f1ee0c6767a1f3f04bb3").unwrap();
    let data2 = hex::decode("c1b7a4e0d4f0e59e5963c1a3bf1540a76b25136baef425faf488722e3e331c77d26fbbd8300df532498f50c5ecd243f481f09348f964ddb8056f6e2886bb5b2f453fcf1de5629f3d166324570bf849792d35e3f711b041b1a7e30494b5d1316484ed85b8da37094627a8e66003d079bfd8beaa80").unwrap();
    let data3 = hex::decode("dc").unwrap();
    let expected = "2a0f542090b51b84465cd93e5ddeeaa14ca51162f48047835d2df845fb488af4";

    let sha256_hmac_state = sha256_hmac.with_key(&p_key);

    let result = sha256_hmac_state.sign_concat(&data1, &[&data2], &data3);
    assert_eq!(hex::encode(result), expected);
    
    println!("{:?}", sha256_hmac_state.tag_len());

    let result2 = sha256_hmac_state.sign(&[&data4]);
    assert_eq!(hex::encode(result2), expected);

}
