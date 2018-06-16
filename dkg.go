package main

// This is a basic implementation of Pedersen's DKG protocol
// Goroutines are used to simulate the members taking part in the DKG
// Communication of shares should be encrypted so that no-one except their recipient can read it. It's done here using Golang's official reimplementation of NaCl's crypto_box ; but the public key exchange phase is obviously not secure and would be vulnerable to a MiTM attack. Remember, the point of this is only to be a demo.

// There is currently no implementation of a complaint mechanism.

// BTW, this is the first time I write Go code, so this is likely not very beautiful and / or optimised
// I'm also passing everything by value, not by reference, so it's not memory efficient
// Function, methods, variable, structs, etc naming may not be very go-ish, nor consistent for that matter

// At any rate, Pedersen's DKG protocol is known to be vulnerable (Gennaro, Jarecki, Krawczyk, and Rabin's "Secure Distributed Key Generation for Discrete-Log Based Cryptosystems"). Thankfully, they also provide a safer alternative.
// Therefore, you'd likely be better off implementing *their* DKG protocol.

import (
	"io"
	"os"
	"strconv"
	"time"
	"crypto/rand"
	"./bls"
	"golang.org/x/crypto/nacl/box"
	"github.com/satori/go.uuid"
	"github.com/dustin/go-broadcast"
)
// ======== the next four functions are the core of this file, they wrap the required cryptographic functions from BLS ===========
// I mostly borrowed them from http://github.com/dfinity/dkg and translated them from JS to Go
/**
 * generates a members contribution to the DKG
 * @param {[]uuid.UUID} idVec - an array of UUID (identifying the participants)
 * @param {int} threshold - the threshold number of members needed to sign on a message to
 * @param {bool} nullSecret - whether we're recreating a new random secret to be shared, or using a null secret (which is useful to update shares for all the DKG's participants, without changing the secret)
 * produce the groups signature
 * @returns {tuple} a tuple containing, in this order :
 * 1. the vVec (verification vector) which is an array of public keys, containing a `threshold` number of elements
 * 2. the `contributionMap` which is maps a share of the secret key to the UUID of the member it's destined to
 * 3. the eventual error
 */
func GenerateContribution(uuidVec []uuid.UUID, threshold int, nullSecret bool) (vVec []bls.PublicKey, contributionMap map[uuid.UUID]bls.SecretKey, err error) {
	contributionMap = make(map[uuid.UUID]bls.SecretKey, len(uuidVec))
	
	var sec bls.SecretKey
	if !nullSecret {
		sec.SetByCSPRNG()
	}
	secVec := sec.GetMasterSecretKey(threshold)
	vVec = bls.GetMasterPublicKey(secVec)
	
	// derive a `shareCount` number of shares
	for i := 0; i < len(uuidVec); i++ {
		var contrib bls.SecretKey
		id := hashedID(uuidVec[i])
		err = contrib.Set(secVec, &id)
		if err != nil {
			return nil, nil, err
		}
		contributionMap[uuidVec[i]] = contrib
	}
	
	return vVec, contributionMap, nil
}

/**
 * Adds two verification vectors together to produce a single verification vector
 * @param {[]bls.PublicKey} lhs - the first vector to add (represented as an array of public keys)
 * @param {[]bls.PublicKey} rhs - the second
 * @returns {[]bls.PublicKey} the vector resulting from the addition
 */
func AddVectors(lhs []bls.PublicKey, rhs []bls.PublicKey) (fpk []bls.PublicKey) {
	if (len(lhs) != len(rhs)) {
		panic("Inconsistent public vector length !")
	}
	
	fpk = make([]bls.PublicKey, len(lhs)) //everything's 0 in there
	for i := range lhs {
		fpk[i] = lhs[i]
		fpk[i].Add(&rhs[i])
	}
	return fpk
}

/**
 * Adds two secret key contributions together to produce a single secret key
 * @param {bls.SecretKey} lhs - the first secret key to add
 * @param {bls.SecretKey} rhs - the second
 * @returns {bls.SecretKey} the result from the addition
 */
func AddContributions(lhs bls.SecretKey, rhs bls.SecretKey) (fsk bls.SecretKey) {
	fsk = lhs
	fsk.Add(&rhs)
	return fsk
}

/**
 * Verifies a contribution share
 * @param {uuid.UUID} uuid - the UUID identifying the participant verifying the contribution
 * @param {bls.SecretKey} contribution - the secret key contribution
 * @param {[]bls.PublicKey} verifVec - an array of pointers to public keys which is
 * the verification vector of the sender of the contribution
 * @returns {Boolean, error} - whether it passed the verification, and the eventual error (a failed verification is NOT an error)
 */
func VerifyContributionShare(uuid uuid.UUID, contribution bls.SecretKey, verifVec []bls.PublicKey) (bool, error) {
	var pk1, pk2 bls.PublicKey
	id := hashedID(uuid)
	err := pk1.Set(verifVec, &id)
	
	if (err != nil) {
		return false, err
	}
	
	pk2 = *contribution.GetPublicKey()

	return pk2.IsEqual(&pk1), nil
}

// ===== Converting a UUID (used in this impl. to identify participants) to a byte array usable by herumi's BLS lib =====
func hashedID(uuid uuid.UUID) bls.ID { //yes, bls.ID is just a struct wrapping a byte array
	var id bls.ID
    id.SetLittleEndian(uuid.Bytes())
    return id
}

// ============== NaCl Wrapper ==============
func sealMsg(msg []byte, peerPublicKey, playerSecretKey [32]byte) []byte {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
    	panic(err)
	}
	
	// This encrypts msg and appends the result to the nonce.
	encrypted := box.Seal(nonce[:], msg[:], &nonce, &peerPublicKey, &playerSecretKey)
	return encrypted
}

func openMsg(encrypted []byte, senderPublicKey, playerSecretKey [32]byte) []byte {
	var decryptNonce [24]byte
	copy(decryptNonce[:], encrypted[:24])
	decrypted, ok := box.Open(nil, encrypted[24:], &decryptNonce, &senderPublicKey, &playerSecretKey)
	if !ok {
    	panic("decryption error")
	}
	return decrypted
}

// ====== the structs representing broadcast messages between participants =======
type Broadcast struct {
	sender uuid.UUID
}
type Announce struct {
	Broadcast
	publicKey [32]byte
}
type VerifVectorAndShareContribsBroadcast struct {
	Broadcast
	vector []bls.PublicKey
	encryptedShareContributions map[uuid.UUID][]byte // this should be securely transmitted to the target, so that no-one else can read it – but this requires a trust anchor. For simplicity, we just seal the share using the public key broadcasted beforehand. It's up to you to ensure the share contributions' secrecy – if someone can get hold of n contributions, one share is not secret anymore. If he can get more, then potentially more shares are published.
}
type SigningResultBroadcast struct {
	Broadcast
	sign bls.Sign
}

// ====== the structs representing a Player (a participant in the DKG) =======
type Player struct {
	channel chan interface{}
	reporter chan int
	transmitter broadcast.Broadcaster
	broadcastsInAdvance []interface{} //required because broadcast.Broadcaster makes no guarantee about the receiving order
	peerIDsMapKeys map[uuid.UUID][32]byte
	secretKey [32]byte
	
    id uuid.UUID
    secretKeyShare bls.SecretKey
    verificationVector []bls.PublicKey
}

// making a player ready to partake in the DKG
func (player *Player) init(b broadcast.Broadcaster, playerCount int, reporter chan int) {
	player.reporter = reporter
	
	id, err := uuid.NewV4()
	if err != nil {
		panic(err)
	}
	player.id = id
	
	player.channel = make(chan interface{}, playerCount)
	b.Register(player.channel)
	player.transmitter = b
	
	player.peerIDsMapKeys = make(map[uuid.UUID][32]byte)
} 

// the main routine of a player – ruling the announce phase, and the share exchange phase
func (player *Player) routine(threshold int) {
	player.announce()
	println("closing announce round with", len(player.peerIDsMapKeys), "peers")
	
	player.createAndShareContributions(threshold)
	player.receiveContributions()
	player.reporter <- 1
}

func (player *Player) announce() {
	pKey, sKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
    	panic(err)
	}
	player.secretKey = *sKey

	player.transmitter.Submit(Announce{Broadcast{player.id}, *pKey})
	
	loopsWaited := 0
	for {
		select {
		case raw := <- player.channel:
			loopsWaited = 0
			announce, ok := raw.(Announce)
			if (!ok) {
				cast, isVerVec := raw.(VerifVectorAndShareContribsBroadcast)
				if (isVerVec) {
					if (player.broadcastsInAdvance == nil) {
						player.broadcastsInAdvance = make([]interface{}, 1)
					}
					player.broadcastsInAdvance = append(player.broadcastsInAdvance, cast) // sometimes, the goroutines run un-concurrently enough that some players are already sending their contributions and verif vectors, while others are still processing the announces. And I'm not sure go-broadcast makes any guarantee about the receiving order of broadcasts (I tried various broadcasting libs), so keeping that just to be sure
					break
				}
				panic("Unknown broadcast !")
			}
			player.peerIDsMapKeys[announce.sender] = announce.publicKey
			if (len(player.peerIDsMapKeys) == cap(player.channel)) {
				return
			}
		default:
			if (loopsWaited >= 50) {
				panic("Timeout!")
			}
			time.Sleep(100 * time.Millisecond)
			loopsWaited += 1
		}
	}
}

// the method that creates the share contributions for every DKG participant (=players), encrypts them, and sends them
func 	(player *Player) createAndShareContributions(threshold int) {
	peersIDs := make([]uuid.UUID, len(player.peerIDsMapKeys))
	index := 0
	for uuid, _ := range player.peerIDsMapKeys {
		peersIDs[index] = uuid
		index += 1
	}
	
	player.verificationVector = make([]bls.PublicKey, 0, threshold)
	verVec, shareContribMap, err := GenerateContribution(peersIDs, threshold, false)
	if (err != nil) { panic(err) }
	encryptedShareContribs := make(map[uuid.UUID][]byte)
	
	player.verificationVector = verVec
	player.secretKeyShare = shareContribMap[player.id]
	
	for uuid, shareContrib := range shareContribMap { 
		encryptedShareContribs[uuid] = sealMsg(shareContrib.GetLittleEndian(), player.peerIDsMapKeys[uuid], player.secretKey)
	}
	
	player.transmitter.Submit(VerifVectorAndShareContribsBroadcast{Broadcast{player.id}, verVec, encryptedShareContribs})
}

// method that receives the sent contributions, and processes them (decryption, verification against the verif vector and storage)
func (player *Player) receiveContributions() {
	loopsWaited := 0
	vectorsAdded := 0
	
	for i := range player.broadcastsInAdvance { //recast to myself everything I may have received somewhat too early, I'll handle it later
		println("AHOY", len(player.broadcastsInAdvance))
		player.channel <- player.broadcastsInAdvance[i]
	}
	received := make([]uuid.UUID, 0)
	for {
		select {
		case raw := <- player.channel:
			loopsWaited = 0
			cast, isVerVec := raw.(VerifVectorAndShareContribsBroadcast)
			if (isVerVec) {
				if (cast.sender != player.id) { //don't take into account twice the same vector and share (mine)
					if (vectorsAdded >= len(player.peerIDsMapKeys)) {
						panic("Trying to add extra vector and share !")
					}
					
					msg := openMsg(cast.encryptedShareContributions[player.id],  player.peerIDsMapKeys[cast.sender], player.secretKey)
					var share bls.SecretKey
					share.SetLittleEndian(msg)
					
					isValid, err := VerifyContributionShare(player.id, share, cast.vector)
					if (err != nil) { panic(err) }
					if (!isValid) {
						panic("should file a complaint : was dealt an invalid share")
					}
					
					player.verificationVector = AddVectors(player.verificationVector, cast.vector)
					vectorsAdded += 1
					received = append(received, cast.sender)
					
					player.secretKeyShare = AddContributions(player.secretKeyShare, share)
				} else {
					vectorsAdded += 1
				}
				
				if (vectorsAdded == len(player.peerIDsMapKeys)) {
					println("Verification vector and share reconstructed", len(player.channel), vectorsAdded, player.id.String())
					return
				}
				break;
			} 
			panic("Unknown broadcast !")
		default:
			if (loopsWaited >= 200) {
				panic("Timeout for verification vector sharing !")
			}
			time.Sleep(100 * time.Millisecond)
			loopsWaited += 1
		}
	}
}

// finally, the method which signs a test message, broadcasts it, and receives other's signatures to build the group signature of said message
func (player *Player) groupSigningRoutine() {
	println("Signing !")
	msg := "Hello everybody, everybody hello"
	sign := player.secretKeyShare.Sign(msg)
	signatures := make(map[uuid.UUID]bls.Sign)
	player.transmitter.Submit(SigningResultBroadcast{Broadcast{player.id}, *sign})
	
	loopsWaited := 0
	for {
		select {
		case raw := <- player.channel:
			loopsWaited = 0
			cast, ok := raw.(SigningResultBroadcast)
			if (!ok) {
				panic("Unknown broadcast !")
			}
			if (cast.sender == player.id) { 
				break
			}
			
			signatures[cast.sender] = cast.sign
			
			if (len(signatures) == cap(player.channel) -1) {
				var sign bls.Sign
				var signVec []bls.Sign
				var idVec []bls.ID
				
				for uid, sig := range signatures {
					signVec = append(signVec, sig)
					idVec = append(idVec, hashedID(uid))
				}
				
				sign.Recover(signVec, idVec)
				
				result := "failed"
				if (sign.Verify(&player.verificationVector[0], msg)) {
					result = "passed"
				}
				println("done, test", result, "group signature is", sign.GetHexString())
				player.reporter <- 1
				return
			}
		default:
			if (loopsWaited >= 50) {
				panic("Timeout!")
			}
			time.Sleep(100 * time.Millisecond)
			loopsWaited += 1
		}
	}
}

func main() {
	argsWithoutProg := os.Args[1:]
	
	var playerCount int
	var quorum int //this is the threshold for the Boneh-Lynn-Shacham aggregate sig scheme
	
	if (0 < len(argsWithoutProg)) {
		_quorum, err := strconv.ParseInt(argsWithoutProg[0], 0, 0)
		if (err != nil) { panic(err) }
		quorum = int(_quorum)
		
		if (1 < len(argsWithoutProg)) {
			_playerCount, err := strconv.ParseInt(argsWithoutProg[1], 0, 0)
			if (err != nil) { panic(err) }
			playerCount = int(_playerCount)
		} else {
			println("Cannot set BLS threshold without setting total participant count")
			os.Exit(78) // 78 is EX_CONFIG (configuration error)
		}
	} else {
		playerCount = 7
		quorum = 4
	}
	
	if (playerCount <= quorum) {
		println("This scheme won't work !")
	}
	if (quorum < 2) {
		println("This scheme won't work at all !")
		os.Exit(78) // 78 is EX_CONFIG (configuration error)
	}
	
	group := broadcast.NewBroadcaster(playerCount*playerCount)
	
	count := 0
	reporter := make(chan int)
	
	bls.Init(bls.CurveFp254BNb)
	
	players := make([]Player, playerCount)
	
	for i := 0; i < playerCount; i++ { //two loops because we have to ensure everyone's ready to receive before sending
		players[i].init(group, playerCount, reporter)
	}
	
	for i := 0; i < playerCount; i++ {
		go players[i].routine(quorum)
	}
	
	readyForNext := false
	for {
		select {
		case c := <-reporter:
			count = count + c
			if (count >= playerCount) {
				readyForNext = true
				break
			}
		}
		if readyForNext { 
			break
		}
	}
	
	count = 0
	readyForNext = false
	for i := 0; i < playerCount; i++ {
		go players[i].groupSigningRoutine()
	}
	
	for {
		select {
		case c := <-reporter:
			count = count + c
			if (count >= playerCount) {
				readyForNext = true
				break
			}
		}
		if readyForNext { 
			break
		}
	}
}
