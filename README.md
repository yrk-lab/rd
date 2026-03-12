# README #

*Rd* is a remote desktop client for Plan 9 operating system
implementing RDP, the Microsoft's Remote Desktop Protocol.

It does not support pre-RDP5 protocol versions and requires the server
to support an equivalent of *STARTTLS* (Windows XP SP2/2003 and up).
The X.509 certs presented by servers are checked with `okThumbprint`
against the list kept in `/sys/lib/tls/rdp` file.

![Screenshot](https://repository-images.githubusercontent.com/1048642731/0b819f74-9069-4ece-b70a-1f88e288a6a9)
