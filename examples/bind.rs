extern crate ldap;

use ldap::Ldap;

pub fn main() {
    let addr = "127.0.0.1:389".parse().unwrap();

    let mut ldap = Ldap::connect(&addr);

    let res = ldap.simple_bind("cn=admin, dc=example, dc=org".to_string(), "admin".to_string()).unwrap();

    if res {
        println!("Bind succeeded!");
    } else {
        println!("Bind failed! :(");
    }
}
