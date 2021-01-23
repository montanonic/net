//! Rustic interface into the winsock2 API.
use std::default::Default;
use std::mem::MaybeUninit;
use std::ptr;
use winapi::shared::ws2def::{AF_INET, IPPROTO_ICMP, IPPROTO_IP, SOCK_RAW};
use winapi::um::winsock2::{
    self, closesocket, socket, WSACleanup, WSAGetLastError, WSAStartup, INVALID_SOCKET, SOCKET,
    WSADATA, WSAEACCES,
};

use crate::utils;
use socket::Socket;
use winsock_service::WinsockService;

/// To initialize a winsock, we'll need to provide details of what our
/// implementation does. This is handled by the WSADATA data structure. WSA =
/// Windows Sockets API.
pub fn initialize_winsock() {
    // First we start the service.
    let mut service = WinsockService::new();
    service.start();
    // Then we create a socket.
    let socket = Socket::create();

    dbg!(socket.get_handle());
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

    pub struct Socket(SOCKET);

    impl Socket {
        pub fn create() -> Self {
            Self(make_socket())
        }

        pub fn get_handle(&self) -> SOCKET {
            self.0
        }
    }

    impl Drop for Socket {
        fn drop(&mut self) {
            let code = unsafe { closesocket(self.0) };
            println!("socketclose code: {}", code);
        }
    }

    /// Creates a Raw Socket over IPv4 and via the ICMP protocol.
    fn make_socket() -> SOCKET {
        let address_family = AF_INET; // IPv4
        let socket_type = SOCK_RAW;
        let protocol = IPPROTO_ICMP as i32;

        match unsafe { socket(address_family, socket_type, protocol) } {
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
            valid => valid,
        }
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
