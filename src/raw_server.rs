//! https://docs.microsoft.com/en-us/windows/win32/winsock/about-clients-and-servers/
//!
//! The following steps are implemented here to construct our server: Initialize
//! Winsock. Create a socket. Bind the socket. Listen on the socket for a
//! client. Accept a connection from a client. Receive and send data.
//! Disconnect.
//!
//! This module's main export is a raw server which handles requests to a raw socket.
