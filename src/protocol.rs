use std::prelude::v1::*;
use mio::net::TcpStream;
use std::io::Result;
use std::io::{Write, Read};

use asnom::structures::{Tag, Sequence, Integer};
use asnom::structures::ASNTag;
use asnom::write;
use asnom::common;
use asnom::IResult;
use asnom::structure::StructureTag;
use asnom::parse::Parser;
use asnom::ConsumerState;
use asnom::Move;
use asnom::Input;
use asnom::Consumer;
use asnom::parse::parse_uint;

pub struct Protocol;

impl Protocol {
    pub fn data_encode(&mut self, message: Tag, into: &mut Vec<u8>) -> Result<()> {
        let outtag = Tag::Sequence(Sequence {
            inner: vec![
                Tag::Integer(Integer {
                    inner: 0 as i64,
                    .. Default::default()
                }),
                message,
            ],
            .. Default::default()
        });

        let outstruct = outtag.into_structure();
        try!(write::encode_into(into, outstruct));
        Ok(())
    }

    pub fn data_decode(&self, buf: &mut Vec<u8>) -> Option<StructureTag> {
        let mut parser = Parser::new();
        let rev_buf = buf.as_slice();
        match parser.handle(Input::Element(rev_buf)) {
            &ConsumerState::Done(amt, ref tag) => {
                match amt {
                    Move::Consume(amt) => {
                        let tag = tag.clone();
                        if let Some(mut tags) = tag.match_id(16u64).and_then(|x| x.expect_constructed()) {
                            let protoop = tags.pop().unwrap();
                            let msgid: Vec<u8> = tags.pop().unwrap()
                                        .match_class(common::TagClass::Universal)
                                        .and_then(|x| x.match_id(2u64))
                                        .and_then(|x| x.expect_primitive()).unwrap();
                            if let IResult::Done(_, id) = parse_uint(msgid.as_slice()) {
                                return match protoop.id {
                                    // SearchResultEntry
                                    4 => {
                                        None
                                    },
                                    // SearchResultDone
                                    5 => {
                                        None
                                    },
                                    // Any other Message
                                    _ => {
                                        Some(protoop)
                                    },
                                }
                            }
                        }

                        return None;
                    },
                    Move::Seek(_) => None,
                    Move::Await(_) => None
                }
            },
            &ConsumerState::Continue(_) => None,
            &ConsumerState::Error(_e) => None,
        }
    }
}