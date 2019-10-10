use std::io;
use asnom::structures::OctetString;
use asnom::common::TagClass::*;
use asnom::structures::{Tag, Integer, Sequence, ASNTag};
use std::prelude::v1::String;

use ldap::Ldap;

impl Ldap {
    pub fn simple_bind(&mut self, dn: String, pw: String) ->io::Result<bool> {
        let req = Tag::Sequence(Sequence {
            id: 0,
            class: Application,
            inner: vec![
                   Tag::Integer(Integer {
                       inner: 3,
                       .. Default::default()
                   }),
                   Tag::OctetString(OctetString {
                       inner: dn.into_bytes(),
                       .. Default::default()
                   }),
                   Tag::OctetString(OctetString {
                       id: 0,
                       class: Context,
                       inner: pw.into_bytes(),
                   })
            ],
        });

        let mut dde = self.send(req).unwrap();
        let result = self.data_decode(&mut dde);
        let is_ok = match result {
            Some(tag) => {
                println!("xxxx");
                let i = tag.expect_constructed().unwrap();
                if i[0] == Tag::Integer(Integer {
                    id: 10,
                    class: Universal,
                    inner: 0
                    }).into_structure() {
                        Ok(true)
                    }
                    else {
                         Ok(false)
                    }
            },
            None => Ok(false),
        };

        is_ok
    }
}
