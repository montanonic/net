//! Rustic interface into the winsock2 API.
use std::default::Default;
use std::ffi::{CStr, CString};
use std::fmt::{self, Formatter};
use std::marker;
use std::mem::MaybeUninit;
use std::{mem, ptr};
use winapi::ctypes::c_int;
use winapi::shared::ws2def::{
    ADDRINFOA, AF_INET, AF_INET6, AI_PASSIVE, IPPROTO_ICMP, IPPROTO_IP, PADDRINFOA, SOCK_RAW,
};
use winapi::um::winsock2::{
    self, WSACleanup, WSAGetLastError, WSAStartup, INVALID_SOCKET, SOCKET, WSADATA, WSAEACCES,
};
use winapi::um::ws2tcpip;

use crate::utils;
use socket::Socket;
use winsock_service::WinsockService;

/// WSA = Windows Sockets API.
pub fn initialize_winsock() {
    // First we start the service.
    let mut service = WinsockService::new();
    service.start();

    // Then we create a socket.
    let socket = Socket::create();

    // Get address info for it:
    let mut addr_info = socket::get_addr_info("localhost", "", &socket);

    for info in addr_info.iter_mut() {
        info;
    }
}

mod socket {
    //! After you're done with a socket, closesocket should be called. If a
    //! socket fails to create though, this does not need to happen: the API
    //! here reflects that, with the struct panic-ing if it fails to create
    //! without worry (it need not run any cleanup itself). Instead the Winsock
    //! Service cleanup should be called in case of error, but because we panic
    //! here in case of error, the stack will unwind, and thus the pre-existing
    //! winsock service will run its drop impl which triggers cleanup.
    //!
    //! Note that the fact that we create a socket after starting the service is
    //! *not* enforced by the internal API of this module. Its public API should
    //! ensure that users never need to worry about this, ideally exposing a
    //! "higher-level" struct that allows for easy creation of the socket, with
    //! all service details handled in the background.
    use super::*;

    pub struct Socket {
        handle: SOCKET,
        address_family: c_int,
        r#type: c_int,
        protocol: c_int,
    }

    impl Socket {
        /// Creates a Raw Socket over IPv4 and via the ICMP protocol.
        pub fn create() -> Self {
            let address_family = AF_INET; // IPv4
            let socket_type = SOCK_RAW;
            let protocol = IPPROTO_ICMP as i32;

            match unsafe { winsock2::socket(address_family, socket_type, protocol) } {
                INVALID_SOCKET => {
                    let err_code = unsafe { WSAGetLastError() };
                    let err_msg = match err_code {
                        WSAEACCES => "Permission denied. \
                    An attempt was made to access a socket in a way forbidden \
                    by its access permissions. An example is using a broadcast \
                    address for sendto without broadcast permission being set \
                    using setsockopt(SO_BROADCAST)."
                            .into(),
                        code => format!("socket failed to create, error code: {}", code),
                    };
                    panic!(err_msg);
                }
                handle => Self {
                    handle,
                    address_family,
                    r#type: socket_type,
                    protocol,
                },
            }
        }

        pub fn get_handle(&self) -> SOCKET {
            self.handle
        }
    }

    impl Drop for Socket {
        fn drop(&mut self) {
            let code = unsafe { winsock2::closesocket(self.handle) };
            println!("socketclose code: {}", code);
        }
    }

    #[derive(Debug)]
    pub struct AddrInfo(PADDRINFOA);

    // impl fmt::Debug for AddrInfo {
    //     fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    //         let s = self.0;
    //         f.debug_struct("AddrInfo")
    //             .field("ai_flags", &s.ai_flags)
    //             .field("ai_family", &s.ai_family)
    //             .field("ai_socktype", &s.ai_socktype)
    //             .field("ai_protocol", &s.ai_protocol)
    //             .field("ai_addrlen", &s.ai_addrlen)
    //             .field("ai_canonname", &s.ai_canonname)
    //             .field("ai_addr", &s.ai_addr)
    //             .field("ai_next", &s.ai_next)
    //     }
    // }

    impl AddrInfo {}

    impl Drop for AddrInfo {
        fn drop(&mut self) {
            unsafe { ws2tcpip::freeaddrinfo(self.0) };
            println!("Addr Info list was freed");
        }
    }

    impl FFIListMut<ADDRINFOA> for AddrInfo {
        fn next_ptr(&mut self) -> PADDRINFOA {
            self.0
        }
    }

    impl FFIListMut<ADDRINFOA> for ADDRINFOA {
        fn next_ptr(&mut self) -> PADDRINFOA {
            self.ai_next
        }
    }

    /// See
    /// https://docs.microsoft.com/en-us/windows/win32/api/ws2tcpip/nf-ws2tcpip-getaddrinfo
    ///
    /// host_name may be:
    ///
    /// * empty: all registered addresses on the local computer are returned
    /// * equal to localhost: all loopback addresses on the local computer are
    ///   returned
    /// * a computer name: all permanent addresses for the computer that can be
    ///   used as a source address are returned
    ///
    /// service_or_port: "A service name is a string alias for a port number.
    /// For example, “http” is an alias for port 80 defined by the Internet
    /// Engineering Task Force (IETF) as the default port used by web servers
    /// for the HTTP protocol."
    pub fn get_addr_info(host_name: &str, service_or_port: &str, socket: &Socket) -> AddrInfo {
        // "For the Internet protocol, the numeric host address string is a
        // dotted-decimal IPv4 address or an IPv6 hex address."
        let host_name = CString::new(host_name).unwrap();
        let service_or_port = CString::new(service_or_port).unwrap();
        let hints = {
            let mut h: ADDRINFOA = unsafe { mem::zeroed() };
            // AI_PASSIVE = The socket address will be used in a call to the
            // bind function.
            h.ai_flags = AI_PASSIVE;
            h.ai_family = socket.address_family;
            h.ai_socktype = socket.r#type;
            h.ai_protocol = socket.protocol;
            h
        };
        let mut result: PADDRINFOA = ptr::null_mut();

        let code = unsafe {
            ws2tcpip::getaddrinfo(
                host_name.as_ptr(),
                service_or_port.as_ptr(),
                &hints,
                &mut result,
            )
        };

        // API example code shows running WSACleanup and nothing else in the
        // case of error here. Thus, panicking is sufficient as it will Drop
        // code that does as much.
        if code != 0 {
            panic!(format!(
                "getting address info failed with code: {}. Last winsock error code: {}",
                code,
                unsafe { WSAGetLastError() }
            ));
        }

        AddrInfo(result)
    }
}

mod winsock_service {
    use super::*;
    /// "All processes (applications or DLLs) that call Winsock functions must
    /// initialize the use of the Windows Sockets DLL before making other Winsock
    /// functions calls. This also makes certain that Winsock is supported on the
    /// system."
    /// https://docs.microsoft.com/en-us/windows/win32/winsock/initializing-winsock
    ///
    /// This struct manages the data for doing exactly this. When it is dropped, the
    /// winsock service is terminated via WSACleanup.
    pub struct WinsockService {
        has_started: bool,
    }

    impl WinsockService {
        pub fn new() -> Self {
            Self { has_started: false }
        }

        pub fn start(&mut self) {
            // We set this flag first so that our drop will get called if
            // wsa_startup panics, because wsa_startup can panic *after* the
            // underlying service starts.
            //
            // An alternative implementation could just have start return a new
            // struct, but this is a very minor improvement for such a simple
            // API at the moment.
            self.has_started = true;
            wsa_startup();
        }
    }

    impl Drop for WinsockService {
        fn drop(&mut self) {
            if self.has_started {
                let code = unsafe { WSACleanup() };
                println!("WSACleanup code: {}", code);
            }
        }
    }

    /// Remember to WSACleanup afterwards!
    fn wsa_startup() {
        // See https://en.wikipedia.org/wiki/Winsock#Specifications for a list of
        // versions.
        //
        // The version of the Windows Sockets specification that the Ws2_32.dll
        // expects the caller to use. The high-order byte specifies the minor
        // version number; the low-order byte specifies the major version number.
        //
        // The latest version is 2.2, and we'll use that.
        let version = utils::two_u8_to_u16(2, 2);

        // When WSAStartup is called it will populate this WSAData struct with
        // information about the current running winsock service. Since it
        // initializes it for us, we only need to provide it the empty structure to
        // populate.
        let mut wsa_data = MaybeUninit::uninit();

        let startup_code = unsafe { WSAStartup(version, wsa_data.as_mut_ptr()) };
        // This allows wsa_data to actually be dropped (and for its fields to be
        // accessed).
        let wsa_data: WSADATA = unsafe { wsa_data.assume_init() };

        if startup_code != 0 {
            panic!(format!(
                "WSAStartup failed with error code {:?}",
                startup_code
            ));
        } else if wsa_data.wVersion != version {
            panic!(
                "Winsock version didn't match ours! \
            This isn't necessarily an issue, but it's worth knowing. \
            If this comes up and doesn't make sense, feel empowered \
            to remove the panic."
            );
        }
        // The service has successfully started.
    }
}

/// Foreign structures which function as lists, specifically via mutable
/// pointers. All you need to do is provide an accessor to wherever the list
/// pointer is in your struct (through the next_ptr method)!
///
/// The iterator interface is not zero-cost, as we both return a custom struct
/// that implements the iterator interface, and also use dyn Trait throughout.
/// It would be cheapest to manually create iterator interfaces specific to your
/// struct's semantics. I only mention this for edification, the cost is so
/// monumentally low all other things considered as to be irrelevant, and is IMO
/// absolutely worth paying for in these cases.
trait FFIListMut<T> {
    fn next_ptr(&mut self) -> *mut T;
    fn iter_mut(&mut self) -> FFIListMutIter<T> {
        FFIListMutIter {
            ptr: self.next_ptr(),
            phantom: marker::PhantomData,
        }
    }
}

struct FFIListMutIter<'a, T> {
    ptr: *mut T,
    phantom: marker::PhantomData<&'a mut T>,
}

impl<'a, T: FFIListMut<T>> Iterator for FFIListMutIter<'a, T> {
    type Item = &'a mut T;

    fn next(&mut self) -> Option<Self::Item> {
        let current_ptr = self.ptr;
        unsafe {
            // Ensure that the pointer is not null before accessing.
            if current_ptr != ptr::null_mut() {
                // Move the pointer in the iterator forward so that we advance,
                // and return a mutable reference to the current structure.
                self.ptr = (*current_ptr).next_ptr();
                Some(&mut *current_ptr)
            } else {
                None
            }
        }
    }
}
