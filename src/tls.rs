// Copyright (C) 2017-2019 Baidu, Inc. All Rights Reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
//  * Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//    distribution.
//  * Neither the name of Baidu, Inc., nor the names of its
//    contributors may be used to endorse or promote products derived
//    from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use std::collections;
use std::untrusted::fs;
use std::net::SocketAddr;
use std::str;
use std::io;
use std::string::String;
use std::vec::Vec;
use std::io::{Read, Write, BufReader};
use std::sync::{Arc, SgxMutex};
use rustls::Session;
use mio::net::TcpStream;

//#[macro_use]
//extern crate log;

const CLIENT: mio::Token = mio::Token(0);

/// This encapsulates the TCP-level connection, some connection
/// state, and the underlying TLS-level session.
pub struct TlsClient {
    socket: TcpStream,
    closing: bool,
    clean_closure: bool,
    tls_session: rustls::ClientSession,
}

impl TlsClient {
    pub fn ready(&mut self,
             poll: &mut mio::Poll,
             ev: &mio::event::Event) -> bool {
        assert_eq!(ev.token(), CLIENT);

        if ev.readiness().is_readable() {
            self.do_read();
        }

        if ev.readiness().is_writable() {
            self.do_write();
        }

        if self.is_closed() {
            println!("Connection closed");
            return false;
        }

        self.reregister(poll);
        true
    }
}

/// We implement `io::Write` and pass through to the TLS session
impl io::Write for TlsClient {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.tls_session.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tls_session.flush()
    }
}

impl io::Read for TlsClient {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.tls_session.read(bytes)
    }
}

impl TlsClient {
    pub fn new(sock: TcpStream, hostname: webpki::DNSNameRef, cfg: Arc<rustls::ClientConfig>) -> TlsClient {
        TlsClient {
            socket: sock,
            closing: false,
            clean_closure: false,
            tls_session: rustls::ClientSession::new(&cfg, hostname),
        }
    }

    pub fn read_source_to_end(&mut self, rd: &mut dyn io::Read) -> io::Result<usize> {
        let mut buf = Vec::new();
        let len = rd.read_to_end(&mut buf)?;
        self.tls_session.write_all(&buf).unwrap();
        Ok(len)
    }

    /// We're ready to do a read.
    pub fn do_read(&mut self) {
        // Read TLS data.  This fails if the underlying TCP connection
        // is broken.
        let rc = self.tls_session.read_tls(&mut self.socket);
        if rc.is_err() {
            println!("TLS read error: {:?}", rc);
            self.closing = true;
            return;
        }

        // If we're ready but there's no data: EOF.
        if rc.unwrap() == 0 {
            println!("EOF");
            self.closing = true;
            self.clean_closure = true;
            return;
        }

        // Reading some TLS data might have yielded new TLS
        // messages to process.  Errors from this indicate
        // TLS protocol problems and are fatal.
        let processed = self.tls_session.process_new_packets();
        if processed.is_err() {
            println!("TLS error: {:?}", processed.unwrap_err());
            self.closing = true;
            return;
        }

        // Having read some TLS data, and processed any new messages,
        // we might have new plaintext as a result.
        //
        // Read it and then write it to stdout.
        let mut plaintext = Vec::new();
        let rc = self.tls_session.read_to_end(&mut plaintext);
        if !plaintext.is_empty() {
            io::stdout().write_all(&plaintext).unwrap();
        }

        // If that fails, the peer might have started a clean TLS-level
        // session closure.
        if rc.is_err() {
            let err = rc.unwrap_err();
            println!("Plaintext read error: {:?}", err);
            self.clean_closure = err.kind() == io::ErrorKind::ConnectionAborted;
            self.closing = true;
            return;
        }
    }

    pub fn do_write(&mut self) {
        self.tls_session.write_tls(&mut self.socket).unwrap();
    }

    pub fn register(&self, poll: &mut mio::Poll) {
        poll.register(&self.socket,
                      CLIENT,
                      self.ready_interest(),
                      mio::PollOpt::level() | mio::PollOpt::oneshot())
            .unwrap();
    }

    pub fn reregister(&self, poll: &mut mio::Poll) {
        poll.reregister(&self.socket,
                        CLIENT,
                        self.ready_interest(),
                        mio::PollOpt::level() | mio::PollOpt::oneshot())
            .unwrap();
    }

    // Use wants_read/wants_write to register for different mio-level
    // IO readiness events.
    pub fn ready_interest(&self) -> mio::Ready {
        let rd = self.tls_session.wants_read();
        let wr = self.tls_session.wants_write();

        if rd && wr {
            mio::Ready::readable() | mio::Ready::writable()
        } else if wr {
            mio::Ready::writable()
        } else {
            mio::Ready::readable()
        }
    }

    pub fn is_closed(&self) -> bool {
        self.closing
    }
}

/// This is an example cache for client session data.
/// It optionally dumps cached data to a file, but otherwise
/// is just in-memory.
///
/// Note that the contents of such a file are extremely sensitive.
/// Don't write this stuff to disk in production code.
struct PersistCache {
    cache: SgxMutex<collections::HashMap<Vec<u8>, Vec<u8>>>,
    filename: Option<String>,
}

impl PersistCache {
    /// Make a new cache.  If filename is Some, load the cache
    /// from it and flush changes back to that file.
    fn new(filename: &Option<String>) -> PersistCache {
        let cache = PersistCache {
            cache: SgxMutex::new(collections::HashMap::new()),
            filename: filename.clone(),
        };
        if cache.filename.is_some() {
            cache.load();
        }
        cache
    }

    /// If we have a filename, save the cache contents to it.
    fn save(&self) {
        use rustls::internal::msgs::codec::Codec;
        use rustls::internal::msgs::base::PayloadU16;

        if self.filename.is_none() {
            return;
        }

        let mut file = fs::File::create(self.filename.as_ref().unwrap())
            .expect("cannot open cache file");

        for (key, val) in self.cache.lock().unwrap().iter() {
            let mut item = Vec::new();
            let key_pl = PayloadU16::new(key.clone());
            let val_pl = PayloadU16::new(val.clone());
            key_pl.encode(&mut item);
            val_pl.encode(&mut item);
            file.write_all(&item).unwrap();
        }
    }

    /// We have a filename, so replace the cache contents from it.
    fn load(&self) {
        use rustls::internal::msgs::codec::{Codec, Reader};
        use rustls::internal::msgs::base::PayloadU16;

        let mut file = match fs::File::open(self.filename.as_ref().unwrap()) {
            Ok(f) => f,
            Err(_) => return,
        };
        let mut data = Vec::new();
        file.read_to_end(&mut data).unwrap();

        let mut cache = self.cache.lock()
            .unwrap();
        cache.clear();
        let mut rd = Reader::init(&data);

        while rd.any_left() {
            let key_pl = PayloadU16::read(&mut rd).unwrap();
            let val_pl = PayloadU16::read(&mut rd).unwrap();
            cache.insert(key_pl.0, val_pl.0);
        }
    }
}

impl rustls::StoresClientSessions for PersistCache {
    /// put: insert into in-memory cache, and perhaps persist to disk.
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        self.cache.lock()
            .unwrap()
            .insert(key, value);
        self.save();
        true
    }

    /// get: from in-memory cache
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.cache.lock()
            .unwrap()
            .get(key).cloned()
    }
}

/// Build a `ClientConfig` from our arguments
pub fn make_config(cert: &str) -> Arc<rustls::ClientConfig> {
    let mut config = rustls::ClientConfig::new();

    let certfile = fs::File::open(cert).expect("Cannot open CA file");
    let mut reader = BufReader::new(certfile);
    config.root_store
        .add_pem_file(&mut reader)
        .unwrap();

    let cache = Option::None;
    let persist = Arc::new(PersistCache::new(&cache));
    config.set_persistence(persist);

    Arc::new(config)
}

// TODO: um, well, it turns out that openssl s_client/s_server
// that we use for testing doesn't do ipv6.  So we can't actually
// test ipv6 and hence kill this.
pub fn lookup_ipv4(host: &str, port: u16) -> SocketAddr {
    use std::net::ToSocketAddrs;

    let addrs = (host, port).to_socket_addrs().unwrap();
    for addr in addrs {
        if let SocketAddr::V4(_) = addr {
            return addr;
        }
    }

    unreachable!("Cannot lookup address");
}
