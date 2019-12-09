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
	"os"
	"os/exec"
	"strings"
)

var dh *dh_go.DH

var userKey *rsa.PublicKey
var userKeyString []byte

type VerifyStruct struct {
	Username  string `json:"username"`
	Hmac      string `json:"hmac"`
	Signature string `json:"signature"`
	PublicKey []byte `json:"pub_key"`
}

type RegisterRequest struct {
	Username     string `json:"username"`
	HashedPasswd string `json:"hashedPasswd"`
	PublicKey    string `json:"publicKey"`
}

type RegisterResponse struct {
	Status string `json:"status"`
}

type LoginRequest struct {
	Signature            string `json:"signature"`
	Hmac                 string `json:"hmac"`
	EncryptedCredentials []byte `json:"encryptedCredentials"`
	EncryptedKey         []byte `json:"encryptedKey"`
}

type LoginResponse struct {
	Signature   string `json:"signature"`
	Hmac        string `json:"hmac"`
	DHServerKey string `json:"dhServerKey"`
	// includes non encypted iv (16 bytes) + ks from diffie-hellman () + sessionId (16 bytes)
	EncryptedContent []byte `json:"encryptedContent"`
}

type SubmitRequest struct {
	Signature       string `json:"signature"`
	Hmac            string `json:"hmac"`
	VulnDescription string `json:"vulnDescription"`
	Fingerprint     string `json:"fingerprint"`
}

type SubmitResponse struct {
	Signature string `json:"signature"`
	Hmac      string `json:"hmac"`
	Status    string `json:"status"`
}

type ScoreResponse struct {
	Signature string `json:"signature"`
	Hmac      string `json:"hmac"`
	ScoreList string `json:"scoreList"`
}

func GenerateRandomNumber(length int) *big.Int {
	randInteger, err := rand.Int(rand.Reader, big.NewInt(int64(length)))
	if err != nil {
		log.Fatal(err)
	}
	return randInteger
}

func LoadPrivKeyFromFile(filename string) *rsa.PrivateKey {
	keyString, _ := ioutil.ReadFile(filename)
	block, _ := pem.Decode([]byte(keyString))
	parseResult, _ := x509.ParsePKCS8PrivateKey(block.Bytes)
	privKey := parseResult.(*rsa.PrivateKey)
	return privKey
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
	hash := sha256.New()

	plainText, err := rsa.DecryptOAEP(hash, rand.Reader, privKey, encryptedMessage, nil)
	log.Printf("plainText: %v", string(plainText))
	if err != nil {
		log.Fatal(err)
	}

	return string(plainText)
}

// using symmetric key generated (size = 256 bits)
func EncryptWithDHKey(message string) []byte {
	//cipher, err := aes.NewCipher(dh.Sh_secret.Bytes())
	log.Printf("secret dh key size %v", len(dh.Sh_secret.Bytes()))
	log.Printf("secret dh key size %v", dh.Sh_secret)
	_, key := HashWithSHA256(dh.Sh_secret.Bytes())
	keyBlock, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("message before padding: %v\n size %v\n", message, len(message))

	// message padding to match block size
	paddedMessage := PKCS5Padding([]byte(message), aes.BlockSize)
	log.Printf("message after padding: %v\n size %v\n", paddedMessage, len(paddedMessage))
	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext
	buffer := make([]byte, aes.BlockSize+len(paddedMessage))
	iv := buffer[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		log.Fatal(err)
	}

	log.Printf("BUFFER %v", buffer[aes.BlockSize:])
	log.Printf("TO CYPHER %v", []byte(paddedMessage))
	log.Printf("IV: %v", iv)
	log.Printf("KEYYYY: %v", key)
	mode := cipher.NewCBCEncrypter(keyBlock, iv)
	mode.CryptBlocks(buffer[aes.BlockSize:], []byte(paddedMessage))
	log.Printf("ENCRYPTED CONTENT %v", buffer[aes.BlockSize:])

	return buffer
}

func PKCS5Padding(message []byte, blockSize int) []byte {
	padding := blockSize - len(message)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(message, padtext...)
}

func VerifyClientSignaturePython(username string, hmac []byte, signature []byte) bool {
	// create temp file
	// write json to it with username, hmac and signature
	file, err := ioutil.TempFile("verify", "config_")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(file.Name())

	fmt.Println(file.Name()) // For example "dir/prefix054003078"

	fmt.Println(userKeyString)
	verify_struct := VerifyStruct{username, string(hmac), string(signature), userKeyString}

	data, write_err := json.MarshalIndent(verify_struct, "", " ")

	write_err = ioutil.WriteFile(file.Name(), data, 0644)

	if write_err != nil {
		log.Fatal(write_err)
	}

	cmd := exec.Command("python", "verify.py", file.Name())
	fmt.Println(cmd.Args)
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("OUTPUT: %v", string(out))
	fmt.Printf("OUTPUT: %v", out)

	return strings.TrimSuffix(string(out), "\n") == "True"
}

func HashWithSHA256(textToHash []byte) (crypto.Hash, []byte) {
	newhash := crypto.SHA256
	pssh := newhash.New()
	pssh.Write(textToHash)
	hashed := pssh.Sum(nil)

	return newhash, hashed
}

//func VerifyClientSignature(username string, hashedPasswd []byte, hmac []byte, signature []byte) {
func VerifyClientSignature(hashedPasswd []byte, hmac []byte, signature []byte) {
	// load client's public key from database and parse into key

	//publicKey := LoadClientPubKeyFromDatabase(username)

	//log.Printf("hmac %v", string(hmac));
	//encodedExpectedHmac := hex.EncodeToString(hmac);
	//log.Printf("encodedExpectedHmac %v", encodedExpectedHmac);

	newhash, hashedHmac := HashWithSHA256(hmac)

	log.Printf("hashedhmac %v", hashedHmac[:])
	//verifyErr := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashedHmac[:], signature)
	verifyErr := rsa.VerifyPSS(userKey, newhash, hashedHmac, signature, nil)
	if verifyErr != nil {
		log.Fatal(verifyErr)
	}
	log.Printf("Message signature verified!")
}

func CheckMessageIntegrity(messageHmac []byte, encryptedMessage []byte, hashedPasswd []byte) {
	// does the hmac of the encrypted message content received to check if the hmac's the same in the signature
	encodedExpectedHmac := hmacMaker(encryptedMessage, hashedPasswd)

	integrityChecks := hmac.Equal(messageHmac, []byte(encodedExpectedHmac))
	if integrityChecks == false {
		log.Fatal("Integrity violated!")
	}
	log.Printf("Message integrity checked!")
}

func hmacMaker(encryptedMessage []byte, hashedPasswd []byte) string {
	// does the hmac of the encrypted message content received to check if the hmac's the same in the signature
	hasherHmac := hmac.New(sha256.New, hashedPasswd)
	hasherHmac.Write(encryptedMessage)
	expectedHmac := hasherHmac.Sum(nil)
	return hex.EncodeToString(expectedHmac)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {

	var userRequest RegisterRequest
	json.NewDecoder(r.Body).Decode(&userRequest)

	decodedPublicKey, err := base64.StdEncoding.DecodeString(userRequest.PublicKey)
	if err != nil {
		log.Fatal(err)
	}

	userKeyString = decodedPublicKey

	log.Printf("userkey %v", string(decodedPublicKey))
	userKey = LoadClientPubKeyFromDatabase(decodedPublicKey)

	log.Printf("register request from: %v", userRequest.Username)

	// TODO falta aqui a parte da base de dados: guardar user data
	// CHANGE DATABASE TO KEEP USER PUBLIC KEY????
	//addUser(userRequest.Username, userRequest.HashedPasswd, userRequest.PublicKey)

	// fmt.Fprintf(w, "")
	fmt.Fprintf(w, "Request body: %+v", userRequest.Username)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {

	var userRequest LoginRequest
	json.NewDecoder(r.Body).Decode(&userRequest)

	signatureBytes := []byte(userRequest.Signature)

	hmacBytes := []byte(userRequest.Hmac)
	log.Printf("hmac: %v", userRequest.Hmac)
	log.Printf("hmac bytes: %v", hmacBytes)

	//log.Printf("userRequest.EncryptedCredentials: %v", userRequest.EncryptedCredentials)
	//log.Printf("userRequest.EncryptedKeys: %v", userRequest.EncryptedKey)

	//encryptedKeys := append(userRequest.EncryptedCredentials[len(userRequest.EncryptedCredentials)-60 : len(userRequest.EncryptedCredentials)], userRequest.EncryptedKey...)
	//log.Printf("encryptedKeys: %v", encryptedKeys)

	//encryptedCredentials := userRequest.EncryptedCredentials[0 : len(userRequest.EncryptedCredentials)-60]
	//log.Printf("encryptedCredentials: %v", encryptedCredentials)

	serverPrivateKey := LoadPrivKeyFromFile("../../ssl/server.key")
	//decryptedKeys := DecryptWithPrivateKey(encryptedKeys, serverPrivateKey)
	//log.Printf("decryptedKeys: %v", decryptedKeys)
	//decryptedCredentials := DecryptWithPrivateKey(encryptedCredentials, serverPrivateKey)
	//log.Printf("decryptedCredentials: %v", decryptedCredentials)

	decryptedKey := DecryptWithPrivateKey(userRequest.EncryptedKey, serverPrivateKey)
	log.Printf("decryptedKeys: %v\n", decryptedKey)
	decryptedCredentials := DecryptWithPrivateKey(userRequest.EncryptedCredentials, serverPrivateKey)
	log.Printf("decryptedCredentials: %v\n", decryptedCredentials)

	fields := strings.Split(decryptedCredentials, ",")
	//username := fields[0]
	hashedPasswd := fields[1]
	hashedPasswdBytes := []byte(hashedPasswd)

	//Kc := base64.StdEncoding.EncodeToString([]byte(fields[2] + decryptedKey))
	clientKey := fields[2] + decryptedKey
	//Kc := string(hex.EncodeToString([]byte(fields[2] + decryptedKey)))
	//Kc := fields[2] + decryptedKey
	Kc := new(big.Int)
	Kc.SetBytes([]byte(clientKey))
	log.Printf("Kc %v\n", Kc)
	//log.Printf("Kc byte[] %v\n", []byte(Kc))
	//log.Printf("Kc byte[] encode to string %v\n", base64.StdEncoding.EncodeToString([]byte(Kc)))
	//log.Printf("login request from: %v\n", fields[0])

	CheckMessageIntegrity(hmacBytes, append(userRequest.EncryptedCredentials, userRequest.EncryptedKey...), hashedPasswdBytes)
	//VerifyClientSignature(username, []byte(hashedPasswd),userRequest.Hmac, userRequest.Signature)
	//VerifyClientSignature(hashedPasswdBytes, hmacBytes, signatureBytes)
	authenic := VerifyClientSignaturePython(fields[0], hmacBytes, signatureBytes)
	log.Printf("Authentic message? %v", authenic)

	dh.GenSecret()
	log.Printf("after gensecret")
	dh.CalcPublic()
	log.Printf("after calcpublic")
	dh.CalcSahredSecret(Kc.String())

	log.Printf("after dh")

	log.Printf("k: %v", dh.Sh_secret)

	w.Header().Set("Content-Type", "application/json")

	sessionId := GenerateRandomNumber(16)

	content := dh.Public.Text(10) + "," + sessionId.Text(10)
	log.Printf("content %v ", content)

	// block size is always 128 bits (16 bytes), so iv size is 128 bits (16 bytes)
	encryptedContent := EncryptWithDHKey(content)

	response := LoginResponse{
		Hmac:             hmacMaker(encryptedContent, hashedPasswdBytes),
		DHServerKey:      dh.Public.Text(10),
		EncryptedContent: encryptedContent}
	json.NewEncoder(w).Encode(response)

	fmt.Fprintf(w, "")
}

func submitHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("submit handler")
	var userRequest SubmitRequest
	json.NewDecoder(r.Body).Decode(&userRequest)

	log.Printf("submit request for: %v", userRequest.VulnDescription)

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
}

func main() {
	finish := make(chan bool)
	dh = dh_go.New(
		"2",
		"2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919")

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
