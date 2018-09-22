#![cfg_attr(feature = "clippy", feature(plugin))]
#![cfg_attr(feature = "clippy", plugin(clippy))]

extern crate base64;
extern crate sodiumoxide;

pub mod crypto;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
