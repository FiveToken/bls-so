#![cfg(target_os = "android")]
#![allow(non_snake_case)]

use crate::*;
use jni::objects::{JClass, JString};
use jni::sys::jstring;
use jni::JNIEnv;
use std::ffi::CString;

#[allow(clippy::similar_names)]
#[no_mangle]
pub extern "system" fn Java_io_forcewallet_wtools_WtoolsKt_cksign (
  env: JNIEnv,
  _: JClass,
  input: JString,
) -> jstring {
    let java_str = env.get_string(input).expect("Couldn't get Java string!");
    let java_str_ptr = java_str.as_ptr();

    let result = unsafe { cksign(java_str_ptr) };
    let result_ptr = unsafe { CString::from_raw(result) };
    let result_ptr = result_ptr.to_str().unwrap();
    let output = env
    .new_string(result_ptr)
    .expect("Couldn't create a Java string!");
    output.into_inner()
}

#[allow(clippy::similar_names)]
#[no_mangle]
pub extern "system" fn Java_io_forcewallet_wtools_WtoolsKt_pkgen (
  env: JNIEnv,
  _: JClass,
  input: JString,
) -> jstring {
    let java_str = env.get_string(input).expect("Couldn't get Java string!");
    let java_str_ptr = java_str.as_ptr();

    let result = unsafe { pkgen(java_str_ptr) };
    let result_ptr = unsafe { CString::from_raw(result) };
    let result_ptr = result_ptr.to_str().unwrap();
    let output = env
    .new_string(result_ptr)
    .expect("Couldn't create a Java string!");
    output.into_inner()
}

#[allow(clippy::similar_names)]
#[no_mangle]
pub extern "system" fn Java_io_forcewallet_wtools_WtoolsKt_ckgen (
  env: JNIEnv,
  _: JClass,
  input: JString,
) -> jstring {
    let java_str = env.get_string(input).expect("Couldn't get Java string!");
    let java_str_ptr = java_str.as_ptr();

    let result = unsafe { ckgen(java_str_ptr) };
    let result_ptr = unsafe { CString::from_raw(result) };
    let result_ptr = result_ptr.to_str().unwrap();
    let output = env
    .new_string(result_ptr)
    .expect("Couldn't create a Java string!");
    output.into_inner()
}

