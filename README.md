# Pedersen DKG in Go
Simulate a Pedersen DKG (for a Boneh-Lynn Shacham group signature scheme) protocol round in your computer, using goroutines as DKG participants.
This is far from perfect ; see at the top of `dkg.go`.

## How to run
First, you need to build and install https://github.com/herumi/bls (and all its dependencies).
This project does not currently have a "install" target in the Makefile, so you can't just "make install". You need to put all the necessary libraries yourself in the right place, as well as their headers.
Respectively, this means `/usr/local/lib` and `/usr/local/include/`.

Once this has been done, copy the `ffi/go/bls` folder aside `dkg.go`.
You may now `go run dkg.go`. If you wish to set the threshold and total participant count, `go run dkg.go T C`, where T is threshold and C the total.
