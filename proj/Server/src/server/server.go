package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"dh_go"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"strings"
)

var dh *dh_go.DH

var userKey *rsa.PublicKey

type RegisterRequest struct {
	Username     string `json:"username"`
	HashedPasswd string `json:"hashedPasswd"`
	PublicKey    string `json:"publicKey"`
}

type RegisterResponse struct {
	Status string `json:"status"`
}

type LoginRequest struct {
	Signature        string `json:"Signature"`
	Hmac             string `json:"hmac"`
	EncryptedContent []byte `json:"encryptedContent"`
}

type LoginResponse struct {
<<<<<<< HEAD
	DHServerKey      string `json:"dhServerKey"`
	Iv               []byte `json:"iv"`
	EncryptedContent []byte `json:"encryptedContent"`
}

type SubmitRequest struct {
	VulnDescription string `json:"vulnDescription"`
	Fingerprint     string `json:"fingerprint"`
}

type SubmitResponse struct {
	Status string `json:"status"`
}

type ScoreResponse struct {
	ScoreList string `json:"scoreList"`
=======
    Signature  string `json:"Signature"`
    Hmac  string `json:"hmac"`
    DHServerKey  string `json:"dhServerKey"`
    // includes non encypted iv (16 bytes) + ks from diffie-hellman () + sessionId (16 bytes)
    EncryptedContent  []byte `json:"encryptedContent"` 
}

type SubmitRequest struct {
    Signature  string `json:"Signature"`
    Hmac  string `json:"hmac"`
    VulnDescription  string `json:"vulnDescription"`
    Fingerprint  string `json:"fingerprint"`
}

type SubmitResponse struct {
    Signature  string `json:"Signature"`
    Hmac  string `json:"hmac"`
    Status  string `json:"status"`
}

type ScoreResponse struct {
    Signature  string `json:"Signature"`
    Hmac  string `json:"hmac"`
    ScoreList  string `json:"scoreList"`
>>>>>>> 3ea98d04f88169b80dce034f6d8929408b18941e
}

func GenerateRandomNumber(length int) *big.Int {
	randInteger, err := rand.Int(rand.Reader, big.NewInt(int64(length)))
	if err != nil {
		log.Fatal(err)
	}
	return randInteger
}

<<<<<<< HEAD
func LoadPrivKeyFromFile(filename string) *rsa.PrivateKey {
	keyString, _ := ioutil.ReadFile(filename)
	block, _ := pem.Decode([]byte(keyString))
	parseResult, _ := x509.ParsePKCS8PrivateKey(block.Bytes)
	privKey := parseResult.(*rsa.PrivateKey)
	return privKey
=======
func LoadPrivKeyFromFile(filename string) *rsa.PrivateKey { 
    keyString, _ := ioutil.ReadFile(filename)
    block, _ := pem.Decode([]byte(keyString))
    parseResult, _ := x509.ParsePKCS8PrivateKey(block.Bytes)
    privKey := parseResult.(*rsa.PrivateKey)
    return privKey
>>>>>>> 3ea98d04f88169b80dce034f6d8929408b18941e
}

func LoadPubKeyFromFile(filename string) *rsa.PublicKey {
	keyString, _ := ioutil.ReadFile(filename)
	block, _ := pem.Decode([]byte(keyString))
	var cert *x509.Certificate
	cert, _ = x509.ParseCertificate(block.Bytes)
	pubKey := cert.PublicKey.(*rsa.PublicKey)
	return pubKey
}

/*func LoadClientPubKeyFromDatabase(username string) *rsa.PublicKey {
    // obtain keytext from database

    parseResult, _ := x509.ParsePKCS8PrivateKey(block.Bytes)
    publicKey := parseResult.(*rsa.PublicKey)
}*/

func LoadClientPubKeyFromDatabase(block []byte) *rsa.PublicKey {
	publicPem, _ := pem.Decode(block)
	if publicPem == nil {
		log.Fatal("Client's public key is not in pem format")
	}
	parseResult, parseErr := x509.ParsePKIXPublicKey(publicPem.Bytes)
	if parseErr != nil {
		log.Fatal(parseErr)
	}
	publicKey := parseResult.(*rsa.PublicKey)

	return publicKey
}

func DecryptWithPrivateKey(encryptedMessage []byte, privKey *rsa.PrivateKey) string {
<<<<<<< HEAD
	log.Println("DecryptWithPrivateKey")
	hash := sha256.New()
	log.Println("hash done")
	/*
		    publicKey := LoadPubKeyFromFile("../../ssl/server_tls.crt")

		    log.Println("after getting public key")

		    content := "as,f4bf9f7fcbedaba0392f108c59d8f4a38b3838efb64877380171b54475c2ade8,43605213990907437119360750126973250176164454042249042287736004320420075268620"
		    encryptedContent, err := rsa.EncryptOAEP(hash, rand.Reader, publicKey, []byte(content), nil)
		    if err != nil {
				log.Fatal(err)
		    }*/
	//plainText, err := rsa.DecryptPKCS1v15(rand.Reader, privKey, encryptedMessage)
	plainText, err := rsa.DecryptOAEP(hash, rand.Reader, privKey, encryptedMessage, nil)
	//plainText, err := rsa.DecryptOAEP(hash, rand.Reader, privKey, encryptedContent, nil)
=======
    hash := sha256.New()
    log.Println("hash done")

    plainText, err := rsa.DecryptOAEP(hash, rand.Reader, privKey, encryptedMessage, nil)
>>>>>>> 3ea98d04f88169b80dce034f6d8929408b18941e
	if err != nil {
		log.Fatal(err)
	}
	return string(plainText)
}

// using symmetric key generated (size = 256 bits)
<<<<<<< HEAD
func EncryptWithDHKey(message string) ([]byte, []byte) {
	//cipher, err := aes.NewCipher(dh.Sh_secret.Bytes())
	keyBlock, err := aes.NewCipher(dh.Sh_secret.Bytes())
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("keyBlock %v", keyBlock)

	log.Printf("block len %v", aes.BlockSize)

	log.Printf("message %v", string(message))
	log.Printf("message len %v", len(message))

	// message padding to match block size
	paddedMessage := PKCS5Padding([]byte(message), aes.BlockSize)
	log.Printf("paddedMessage %v", string(paddedMessage))
	log.Printf("paddedMessage len %v", len(paddedMessage))
=======
func EncryptWithDHKey(message string) []byte {
    //cipher, err := aes.NewCipher(dh.Sh_secret.Bytes())
    keyBlock, err := aes.NewCipher(dh.Sh_secret.Bytes())
    if err != nil {
		log.Fatal(err)
    }
    
    // message padding to match block size
    paddedMessage := PKCS5Padding([]byte(message), aes.BlockSize)
>>>>>>> 3ea98d04f88169b80dce034f6d8929408b18941e

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext
<<<<<<< HEAD
	buffer := make([]byte, aes.BlockSize+len(message)+1)
	log.Printf("buffer after make %v", buffer)
	iv := buffer[:aes.BlockSize]
	log.Printf("iv %v", iv)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		log.Fatal(err)
	}
	log.Printf("buffer after io %v", buffer)

	log.Printf("buffer after %v", buffer)
	log.Printf("buffer len after %v", len(buffer))

	mode := cipher.NewCBCEncrypter(keyBlock, iv)
	mode.CryptBlocks(buffer[aes.BlockSize:], []byte(paddedMessage))

	log.Printf("buffer after cryptblocks %v", buffer)
	log.Printf("buffer len after cryptblocks %v", len(buffer))

	log.Printf("message in bytes %v", []byte(paddedMessage))

	//return hex.EncodeToString(buffer), iv
	return buffer, iv
}

func PKCS5Padding(message []byte, blockSize int) []byte {
	if len(message)%aes.BlockSize != 0 {
		padding := blockSize - len(message)%blockSize
		padtext := bytes.Repeat([]byte{byte(padding)}, padding)
		return append(message, padtext...)
	}
	return message
=======
    buffer := make([]byte, aes.BlockSize + len(paddedMessage))
    log.Printf("buffer after make %v", buffer);
    iv := buffer[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		log.Fatal(err)
    }
    
    mode := cipher.NewCBCEncrypter(keyBlock, iv)
    mode.CryptBlocks(buffer[aes.BlockSize:], []byte(paddedMessage))

    return buffer
}

func PKCS5Padding(message []byte, blockSize int) []byte {
    padding := blockSize - len(message)%blockSize
    padtext := bytes.Repeat([]byte{byte(padding)}, padding)
    return append(message, padtext...)
>>>>>>> 3ea98d04f88169b80dce034f6d8929408b18941e
}

//func VerifyClientSignature(username string, hashedPasswd []byte, hmac []byte, signature []byte) {
func VerifyClientSignature(hashedPasswd []byte, hmac []byte, signature []byte) {
<<<<<<< HEAD
	// load client's public key from database and parse into key

	//publicKey := LoadClientPubKeyFromDatabase(username)

	log.Printf("hmac %v", string(hmac))
	//encodedExpectedHmac := hex.EncodeToString(hmac);
	//log.Printf("encodedExpectedHmac %v", encodedExpectedHmac);
	newhash := crypto.SHA256
	pssh := newhash.New()
	pssh.Write(hmac)
	hashedHmac := pssh.Sum(nil)
	log.Printf("hashedhmac %v", hashedHmac[:])
	//verifyErr := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashedHmac[:], signature)
	log.Printf("userkey %v", userKey)
	verifyErr := rsa.VerifyPSS(userKey, newhash, hashedHmac, signature, nil)
	if verifyErr != nil {
		log.Fatal(verifyErr)
	}
	log.Printf("Message signature verified!")
=======
    // load client's public key from database and parse into key

    //publicKey := LoadClientPubKeyFromDatabase(username)

    log.Printf("hmac %v", string(hmac));
    //encodedExpectedHmac := hex.EncodeToString(hmac);
    //log.Printf("encodedExpectedHmac %v", encodedExpectedHmac);
    newhash := crypto.SHA256
    pssh := newhash.New()
    pssh.Write(hmac)
    hashedHmac := pssh.Sum(nil)
    log.Printf("hashedhmac %v", hashedHmac[:]);
    //verifyErr := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashedHmac[:], signature)
    verifyErr := rsa.VerifyPSS(userKey, newhash, hashedHmac, signature, nil)
    if verifyErr != nil {
        log.Fatal(verifyErr)
    }
    log.Printf("Message signature verified!")
>>>>>>> 3ea98d04f88169b80dce034f6d8929408b18941e
}

func CheckMessageIntegrity(messageHmac []byte, encryptedMessage []byte, hashedPasswd []byte) {
	// does the hmac of the encrypted message content received to check if the hmac's the same in the signature
	hasherHmac := hmac.New(sha256.New, hashedPasswd)
	hasherHmac.Write(encryptedMessage)
	expectedHmac := hasherHmac.Sum(nil)
	encodedExpectedHmac := hex.EncodeToString(expectedHmac)

	integrityChecks := hmac.Equal(messageHmac, []byte(encodedExpectedHmac))
	if integrityChecks == false {
		log.Fatal("Integrity violated!")
	}
	log.Printf("Message integrity checked!")
}

func registerHandler(w http.ResponseWriter, r *http.Request) {

	var userRequest RegisterRequest
	json.NewDecoder(r.Body).Decode(&userRequest)

	decodedPublicKey, err := base64.StdEncoding.DecodeString(userRequest.PublicKey)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("userkey %v", string(decodedPublicKey))
	userKey = LoadClientPubKeyFromDatabase(decodedPublicKey)

	log.Printf("register request from: %v", userRequest.Username)

	// TODO falta aqui a parte da base de dados: guardar user data
	// CHANGE DATABASE TO KEEP USER PUBLIC KEY????
	//addUser(userRequest.Username, userRequest.HashedPasswd, userRequest.PublicKey)

<<<<<<< HEAD
	//fmt.Fprintf(w, "Request body: %+v", ur.Username)
	fmt.Fprintf(w, "Register")
=======
    //fmt.Fprintf(w, "Request body: %+v", ur.Username)
    fmt.Fprintf(w, "")
>>>>>>> 3ea98d04f88169b80dce034f6d8929408b18941e
}

func loginHandler(w http.ResponseWriter, r *http.Request) {

	var userRequest LoginRequest
	json.NewDecoder(r.Body).Decode(&userRequest)

	//signatureBytes := []byte(userRequest.Signature)

	hmacBytes := []byte(userRequest.Hmac)

	log.Println("AAAAAAAAAAAAAAAA")
	priv_key := LoadPrivKeyFromFile("../../ssl/server.key")
	log.Printf("Private key @ login: %v", priv_key)
	decryptedContent := DecryptWithPrivateKey(userRequest.EncryptedContent, priv_key)

<<<<<<< HEAD
	fields := strings.Split(decryptedContent, ",")
	//username := fields[0]
	hashedPasswd := fields[1]
	hashedPasswdBytes := []byte(hashedPasswd)
	Kc := fields[2]
	log.Printf(Kc)
	log.Printf("login request from: %v", fields[0])
=======
    decryptedContent := DecryptWithPrivateKey(userRequest.EncryptedContent, LoadPrivKeyFromFile("../../ssl/server.key"))
    
    fields := strings.Split(decryptedContent, ",")
    //username := fields[0]
    hashedPasswd := fields[1]
    hashedPasswdBytes := []byte(hashedPasswd)
    Kc := fields[2]
>>>>>>> 3ea98d04f88169b80dce034f6d8929408b18941e

	CheckMessageIntegrity(hmacBytes, userRequest.EncryptedContent, hashedPasswdBytes)
	//VerifyClientSignature(username, []byte(hashedPasswd),userRequest.Hmac, userRequest.Signature)
	//VerifyClientSignature(hashedPasswdBytes, hmacBytes, signatureBytes)

	dh.GenSecret()
	dh.CalcPublic()
	dh.CalcSahredSecret(Kc)

<<<<<<< HEAD
	w.Header().Set("Content-Type", "application/json")

	sessionId := GenerateRandomNumber(8)

	content := dh.Public.Text(10) + "," + sessionId.Text(10)
	log.Printf("content %v ", content)

	// block size is always 128 bits (16 bytes), so iv size is 128 bits (16 bytes)
	encryptedContent, iv := EncryptWithDHKey(content)
	log.Printf("encryptedContent %v ", content)

	response := LoginResponse{
		DHServerKey:      dh.Public.Text(10),
		Iv:               iv,
		EncryptedContent: encryptedContent}
	json.NewEncoder(w).Encode(response)

	fmt.Fprintf(w, "Login")
=======
    log.Printf("k: %v", dh.Sh_secret)

    w.Header().Set("Content-Type", "application/json")

    sessionId := GenerateRandomNumber(16)

    content := dh.Public.Text(10) + sessionId.Text(10)
    log.Printf("content %v ", content)

    // block size is always 128 bits (16 bytes), so iv size is 128 bits (16 bytes)
    encryptedContent := EncryptWithDHKey(content)
    log.Printf("encryptedContent %v ", encryptedContent)

    response := LoginResponse {
                            DHServerKey: dh.Public.Text(10),
                            EncryptedContent: encryptedContent}
    json.NewEncoder(w).Encode(response)

    fmt.Fprintf(w, "")
>>>>>>> 3ea98d04f88169b80dce034f6d8929408b18941e
}

func submitHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("submit handler")
	var userRequest SubmitRequest
	json.NewDecoder(r.Body).Decode(&userRequest)

	log.Printf("submit request for: %v", userRequest.VulnDescription)

<<<<<<< HEAD
	fmt.Fprintf(w, "Submit")
}

func showHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Show")
}

func scoreHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Score")
}

func removeUserHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Remove user")
}

func removeSubmissionHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Remove submission")
=======
    fmt.Fprintf(w, "")
}

func showHandler(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "")
}

func scoreHandler(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "")
}

func removeUserHandler(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "")
}

func removeSubmissionHandler(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "")
>>>>>>> 3ea98d04f88169b80dce034f6d8929408b18941e
}

func main() {
	finish := make(chan bool)
	dh = dh_go.New(
		"2",
		"32317006071311007300338913926423828248817941241140239112842009751400741706634354222619689417363569347117901737909704191754605873209195028853758986185622153212175412514901774520270235796078236248884246189477587641105928646099411723245426622522193230540919037680524235519125679715870117001058055877651038861847280257976054903569732561526167081339361799541336476559160368317896729073178384589680639671900977202194168647225871031411336429319536193471636533209717077448227988588565369208645296636077250268955505928362751121174096972998068410554359584866583291642136218231078990999448652468262416972035911852507045361090559")

	mux_http := http.NewServeMux()
	mux_http.HandleFunc("/login", loginHandler)
	mux_http.HandleFunc("/submit", submitHandler)
	mux_http.HandleFunc("/show", showHandler)
	mux_http.HandleFunc("/score", scoreHandler)

	mux_http_tls := http.NewServeMux()
	mux_http_tls.HandleFunc("/register", registerHandler)
	mux_http_tls.HandleFunc("/admin/remove_user", removeUserHandler)
	mux_http_tls.HandleFunc("/admin/remove_submission", removeSubmissionHandler)

	config_tls := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}

	server_http_tls := &http.Server{
		Addr:         ":443",
		Handler:      mux_http_tls,
		TLSConfig:    config_tls,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}

	go func() {
		fmt.Println("Serving HTTP")
		http.ListenAndServe(":80", mux_http)
	}()

	go func() {
		fmt.Println("Serving TLS")
		//log.fatal(server_http_tls.ListenAndServeTLS("../../ssl/server.crt", "../../ssl/server.key"))
		server_http_tls.ListenAndServeTLS("../../ssl/server_tls.crt", "../../ssl/server_tls.key")
	}()

	<-finish
}
