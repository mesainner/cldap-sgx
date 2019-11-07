use std::prelude::v1::*;
use mio::{Events, Poll, Token};
use mio::net::TcpStream;
use std::time::Duration;
use std::io::{Write, Read};

use asnom::structures::Tag;
use asnom::structure::StructureTag;

use tls::*;
use webpki::DNSNameRef;

use protocol::Protocol;

pub struct Ldap {
    tcp_sock: TcpStream
}

impl Ldap {
        pub fn connect( addr: &str) -> Self {
            let sock_addr = addr.parse().unwrap();
            Ldap {
                tcp_sock: TcpStream::connect(&sock_addr).unwrap()
            }
        }

    pub fn send(&mut self, req: Tag) -> std::io::Result<Vec<u8>> {

        let mut ret_buf = [0; 10000];
        let mut into: Vec<u8> = Vec::new();
        Protocol.data_encode(req, &mut into);

        let write_len = self.tcp_sock.write(&into);
        self.tcp_sock.flush()?;

        let mut poll = Poll::new().unwrap();
        poll.register(&self.tcp_sock, Token(1), mio::Ready::readable() , mio::PollOpt::level() | mio::PollOpt::oneshot());
        let mut events = Events::with_capacity(128);

        poll.poll(&mut events, Some(Duration::from_secs(30)));
        for event in &events {
            if event.token() == Token(1) {
                self.tcp_sock.read(&mut ret_buf) ;
            }            
        } 

        Ok(ret_buf.to_vec())
    }
}

struct LdapTls {
    tls_sock: TlsClient
}

impl LdapTls {
    pub fn connect_tls( addr: &str, cert: &str) -> Self {
        let sock_addr = addr.parse().unwrap();
        let socket = TcpStream::connect(&sock_addr).unwrap();
        let config = make_config(cert);

        let domain = addr.split(':').next().expect("hostname");
        println!("domain: {:?}", &domain);
        let dns_name = webpki::DNSNameRef::try_from_ascii_str(domain).unwrap();

        LdapTls { 
            tls_sock: TlsClient::new(socket, dns_name, config)
        }
    }
}
