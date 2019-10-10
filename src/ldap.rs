use std::net::SocketAddr;
use std::prelude::v1::*;
use std::net::TcpStream;
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

pub struct Ldap {
    sock: TcpStream
}

impl Ldap {
    pub fn connect(addr: &SocketAddr) -> Self {
        let socket = TcpStream::connect(&addr);
        Ldap { 
            sock: socket.unwrap()
        }
    }

    pub fn send(&mut self, req: Tag) -> std::io::Result<Vec<u8>> {

        println!("req {:?}", &req);
        let mut into: Vec<u8> = Vec::new();
        self.data_encode(req, &mut into).unwrap();

        println!("{:?}", into);
        let write_len = self.sock.write(&into).unwrap();
        println!("write len {}", write_len);
        self.sock.flush()?;
        
        let mut buf = [0; 100];
        let size = self.sock.read(&mut buf).unwrap();
        println!("rev size {} buf {}{}{}{}{}{}{}{}{}{}", size, buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9]);

        Ok(buf.to_vec())
    }

    pub fn data_encode(&mut self, message: Tag, into: &mut Vec<u8>) -> Result<()> {

        println!("encode {:?}", &message);
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
        println!("{:?}", into);
        Ok(())
    }

    pub fn data_decode(&self, buf: &mut Vec<u8>) -> Option<StructureTag> {
        let mut parser = Parser::new();
        let rev_buf = buf.as_slice();
        //println!("decode {} {}{}{}{}{}", rev_buf.len(), rev_buf[0], rev_buf[1], rev_buf[2], rev_buf[3], rev_buf[4],);
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
                                        println!("protoop {:?}", protoop);
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
