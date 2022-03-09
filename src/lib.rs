extern crate base64;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use bls_signatures::{
    self as bls,
    Serialize,
};
use std::io::Cursor;
use regex::Regex;

const SIGNATURE_SIZE: usize = 96;
const PUBLIC_KEY_SIZE: usize = 48;

#[no_mangle]
pub unsafe extern "C" fn hello(to: *const c_char) -> *mut c_char {
    let c_str = CStr::from_ptr(to);
    let recipient = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => "you",
    };

    CString::new(format!("Hello from Rust: {}", recipient))
        .unwrap()
        .into_raw()
}

#[no_mangle]
pub unsafe extern "C" fn hello_release(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    CString::from_raw(s);
}

#[no_mangle]
pub unsafe extern "C" fn cksign(num: *const c_char) -> *mut c_char {
    let c_str = CStr::from_ptr(num);
    let c_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => ""
    };
    if c_str == "" {
        return CString::new("").unwrap().into_raw()
    }

    let arr: Vec<&str> = c_str.split(" ").collect();
    if arr.len() != 2 {
        return CString::new("").unwrap().into_raw()
    }
    let ck_str = arr[0];
    let msg_str = arr[1];
    
    let ck_arr = match base64::decode(ck_str) {
        Ok(v) => v,
        Err(_) => return CString::new("").unwrap().into_raw(),
    };
    if ck_arr.len() != 32 {
        return CString::new("").unwrap().into_raw()
    }
    let msg_arr = match base64::decode(msg_str) {
        Ok(v) => v,
        Err(_) => return CString::new("").unwrap().into_raw(),
    };

    let sig = match sign(&ck_arr, &msg_arr) {
        Ok(v) => v,
        Err(_) => vec![]
    };
    if sig.len() == 0 {
        return CString::new("").unwrap().into_raw()
    };
    let sig = base64::encode(&sig);

    CString::new(sig).unwrap().into_raw()
}


#[no_mangle]
pub unsafe extern "C" fn pkgen(s: *const c_char) -> *mut c_char {
    let c_str = CStr::from_ptr(s);
    let c_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => ""
    };
    if c_str == "" {
        return CString::new("").unwrap().into_raw()
    }
    //let str_arr: Vec<&str> = c_str.split(",").collect();
    let str_arr = match base64::decode(c_str) {
        Ok(v) => v,
        Err(_) => return CString::new("").unwrap().into_raw(),
    };

    if str_arr.len() != 32 {
        return CString::new("").unwrap().into_raw()
    }

    let pk = match private_key_public_key(&str_arr) {
        Ok(v) => v,
        Err(_) => vec![]
    };
    if pk.len() == 0 {
        return CString::new("").unwrap().into_raw()
    };
    //let pk: Vec<String> = pk.iter().map(|x|x.to_string()).collect();
    let pk = base64::encode(&pk);

    CString::new(pk).unwrap().into_raw()
}

#[no_mangle]
pub unsafe extern "C" fn ckgen(num: *const c_char) -> *mut c_char {
    let numstr = CStr::from_ptr(num);
    let numstr = match numstr.to_str() {
        Ok(s) => s,
        Err(_) => ""
    };
    let ck = match private_key_from_seed(numstr) {
        Ok(v) => v,
        Err(_) => vec![]
    };
    // let ck: Vec<String> = ck.iter().map(|x| x.to_string()).collect();
    // if ck.len() == 0 {
    //     return CString::new("").unwrap().into_raw()
    // }
    // let ck = ck.join(",");
    let ck = base64::encode(&ck);
    CString::new(ck).unwrap().into_raw()
}

pub fn private_key_from_seed(num: &str) -> Result<Vec<u8>, String> {
    let re = Regex::new(r"^\d+$").unwrap();
    if !re.is_match(num) {
        return Err("expected input to be string of number".to_owned())
    }
    let k = bls::PrivateKey::from_string(num).unwrap();

    Ok(k.as_bytes())
}

pub fn private_key_public_key(b: &[u8]) -> Result<Vec<u8>, String> {
    do_private_key_public_key(b)
}

fn do_private_key_public_key(b: &[u8]) -> Result<Vec<u8>, String> {
    let pub_key = private_key_from_bytes(b).map(|pk| pk.public_key())?;

    let mut pub_key_bytes = [0; PUBLIC_KEY_SIZE];
    write_bytes(pub_key, &mut pub_key_bytes[..])?;

    Ok(pub_key_bytes[..].to_owned())
}

pub fn sign(private_key: &[u8], msg: &[u8]) -> Result<Vec<u8>, String> {
    do_sign(private_key, msg)
}
fn do_sign(private_key: &[u8], msg: &[u8]) -> Result<Vec<u8>, String> {
    let signature = private_key_from_bytes(private_key).map(|pk| pk.sign(msg))?;
    let mut sign_bytes = [0; SIGNATURE_SIZE];
    write_bytes(signature, &mut sign_bytes)?;

    Ok((&sign_bytes[..]).to_owned())
}

fn private_key_from_bytes(raw: &[u8]) -> Result<bls::PrivateKey, String> {
    bls::PrivateKey::from_bytes(raw).map_err(|e| format!("invalid private key bytes: {:?}", e))
}

fn write_bytes<S: Serialize>(ser: S, buf: &mut [u8]) -> Result<(), String> {
    let mut dest = Cursor::new(buf);
    ser.write_bytes(&mut dest)
        .map_err(|e| format!("write to bytes buffer: {:?}", e))
}

#[cfg(target_os = "android")]
mod android;


#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn it_works() {
        let expected = vec![87, 169, 152, 133, 46, 146, 13, 126, 172, 165, 31, 212, 53, 138, 68, 74, 58, 127, 235, 14, 166, 4, 107, 245, 199, 14, 6, 52, 75, 237, 227, 94];
        let expected_pubkey = vec![135, 122, 210, 235, 207, 189, 146, 109, 175, 113, 92, 66, 70, 90, 223, 67, 97, 41, 238, 129, 2, 31, 88, 66, 66, 85, 174, 103, 156, 87, 193, 19, 148, 130, 86, 78, 235, 145, 208, 245, 160, 128, 182, 64, 161, 72, 139, 147];
        let expected_sig = vec![142, 49, 213, 84, 215, 246, 31, 30, 38, 177, 196, 208, 104, 12, 141, 184, 22, 145, 121, 204, 192, 61, 204, 157, 205, 120, 88, 135, 44, 100, 92, 121, 151, 194, 205, 178, 123, 17, 181, 140, 237, 43, 89, 241, 175, 3, 150, 98, 17, 78, 139, 64, 203, 26, 84, 99, 219, 193, 97, 76, 120, 34, 8, 5, 84, 136, 196, 249, 57, 114, 228, 159, 113, 138, 121, 151, 130, 79, 122, 170, 62, 111, 198, 205, 255, 131, 61, 109, 207, 34, 32, 48, 121, 188, 142, 234];
        let s = format!("{:?}", expected);
        let l = s.len() - 1;
        assert_eq!(s[1..l], "87, 169, 152, 133, 46, 146, 13, 126, 172, 165, 31, 212, 53, 138, 68, 74, 58, 127, 235, 14, 166, 4, 107, 245, 199, 14, 6, 52, 75, 237, 227, 94".to_owned());
        let ck = private_key_from_seed("93892345875220621086177621514716840165145141117139133851571162414145201818610233518212926161511341681582081892142441308824718710715149251217861711602365847115732527").unwrap();
        assert_eq!(ck, expected);
        let mm: Vec<String> = expected.iter().map(|x| x.to_string()).collect();
        assert_eq!(mm.join(","), "87,169,152,133,46,146,13,126,172,165,31,212,53,138,68,74,58,127,235,14,166,4,107,245,199,14,6,52,75,237,227,94");
        let pubkey = private_key_public_key(&ck).unwrap();
        assert_eq!(pubkey, expected_pubkey);
        let msg = "this is a message".as_bytes();
        assert_eq!(&[116, 104, 105, 115, 32, 105, 115, 32, 97, 32, 109, 101, 115, 115, 97, 103, 101], msg);
        let sig = sign(&ck, msg).unwrap();
        assert_eq!(sig, expected_sig);

        let expected = vec![189, 88, 17, 47, 18, 228, 12, 158, 48, 115, 174, 7, 50, 122, 190, 21, 116, 136, 81, 157, 17, 8, 118, 235, 150, 61, 190, 169, 99, 163, 4, 18];
        let expected_pubkey = vec![141, 138, 112, 167, 221, 204, 28, 0, 68, 120, 87, 235, 112, 57, 212, 163, 161, 233, 139, 71, 170, 18, 236, 192, 69, 17, 213, 132, 52, 112, 126, 68, 132, 119, 217, 97, 155, 205, 4, 83, 116, 160, 249, 18, 54, 240, 241, 110];
        let expected_sig = vec![131, 241, 95, 212, 156, 181, 179, 237, 154, 218, 118, 90, 90, 201, 178, 248, 209, 31, 233, 88, 22, 143, 26, 111, 130, 211, 254, 160, 34, 23, 230, 44, 252, 39, 197, 8, 187, 198, 186, 30, 243, 78, 221, 114, 202, 155, 248, 21, 10, 208, 75, 25, 86, 240, 78, 212, 189, 232, 84, 190, 163, 253, 112, 250, 249, 177, 174, 254, 15, 198, 81, 69, 29, 72, 86, 108, 14, 2, 204, 246, 229, 129, 25, 236, 139, 114, 175, 16, 90, 221, 162, 160, 108, 219, 165, 227];
        let ck = private_key_from_seed("3920719821373211138135206736995243204711509321097422731182236239109116231206197207106180160201722225538951916823619178521471121227156838760767428721010720171184161").unwrap();
        assert_eq!(ck, expected);
        let pubkey = private_key_public_key(&ck).unwrap();
        assert_eq!(pubkey, expected_pubkey);
        let msg = "this is a message".as_bytes();
        
        let sig = sign(&ck, msg).unwrap();
        assert_eq!(sig, expected_sig);

        let str = "1,2,3";
        let str_arr: Vec<&str> = str.split(",").collect();
        let str_arr: Vec<u8> = str_arr.iter().map(|x| x.parse::<u8>().unwrap()).collect();
        assert_eq!(str_arr, &[1, 2, 3]);

        let bytes = base64::decode("aGVsbG8gd29ybGQ=").unwrap();
        assert_eq!(bytes, vec![104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100]);

        let base64str = base64::encode(&vec![104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100]);
        assert_eq!(base64str, "aGVsbG8gd29ybGQ=");
    }
}
