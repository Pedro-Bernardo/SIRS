package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	crypto_rand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"db_func"
	"dh_go"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// var dh *dh_go.DH

var sessions = make(map[string]Session)

type Session struct {
	Username string
	DiffieH  *dh_go.DH
}

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
	ScoreList []byte `json:"scoreList"`
}

type ScoreRequest struct {
	Signature        string `json:"signature"`
	Hmac             string `json:"hmac"`
	EncryptedContent []byte `json:"encryptedContent"`
	SessionID        string `json:"sessionId"`
}

// func GenerateRandomNumber(length int) *big.Int {
// 	randInteger, err := rand.Int(crypto_rand.Reader, big.NewInt(int64(length)))
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	return randInteger
// }

func StringWithCharset(length int) string {
	charset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
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

func SignWithServerKey(data []byte) []byte {
	server_priv_key := LoadPrivKeyFromFile("../../ssl/server.key")
	// signed, err := server_priv_key.SignPSS(data)
	newhash := crypto.SHA256
	pssh := newhash.New()
	pssh.Write(data)
	hashed := pssh.Sum(nil)
	signed, err := rsa.SignPSS(crypto_rand.Reader, server_priv_key, newhash, hashed, nil)

	if err != nil {
		fmt.Errorf("could not sign request: %v", err)
	}
	return signed
}

/*func BytesToPublicKey(username string) *rsa.PublicKey {
    // obtain keytext from database

    parseResult, _ := x509.ParsePKCS8PrivateKey(block.Bytes)
    publicKey := parseResult.(*rsa.PublicKey)
}*/

func BytesToPublicKey(block []byte) *rsa.PublicKey {
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

	plainText, err := rsa.DecryptOAEP(hash, crypto_rand.Reader, privKey, encryptedMessage, nil)
	log.Printf("plainText: %v", string(plainText))
	if err != nil {
		log.Fatal(err)
	}

	return string(plainText)
}

// using symmetric key generated (size = 256 bits)
func EncryptWithAES(message string, key []byte) []byte {
	//cipher, err := aes.NewCipher(dh.Sh_secret.Bytes())
	// log.Printf("secret dh key size %v", len(dh.Sh_secret.Bytes()))
	// log.Printf("secret dh key size %v", dh.Sh_secret)
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
	if _, err := io.ReadFull(crypto_rand.Reader, iv); err != nil {
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

func DecryptWithAES(message []byte, key []byte) []byte {
	keyBlock, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	if len(message) < aes.BlockSize {
		errors.New("Ciphertext block size is too short!")
		return []byte("")
	}

	//IV needs to be unique, but doesn't have to be secure.
	//It's common to put it at the beginning of the ciphertext.
	iv := message[:aes.BlockSize]
	cipherText := message[aes.BlockSize:]
	fmt.Printf("Data to be decrypted: %v\n", cipherText)
	fmt.Printf("IV: %v\n", iv)

	mode := cipher.NewCBCDecrypter(keyBlock, iv)
	// XORKeyStream can work in-place if the two arguments are the same.
	mode.CryptBlocks(cipherText, cipherText)
	fmt.Printf("Decrypted cipherText: %v\n", cipherText)
	fmt.Printf("Decrypted decoded cipherText: %v\n", string(cipherText))
	decrypted_ciphertext := pkcs7Unpad(cipherText, aes.BlockSize)

	return decrypted_ciphertext
}

func PKCS5Padding(message []byte, blockSize int) []byte {
	padding := blockSize - len(message)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(message, padtext...)
}

func PKCS5Trimming(encrypt []byte) []byte {
	padding := encrypt[len(encrypt)-1]
	return encrypt[:len(encrypt)-int(padding)]
}

func pkcs7Unpad(b []byte, blocksize int) []byte {
	if blocksize <= 0 {
		return nil
	}
	if b == nil || len(b) == 0 {
		return nil
	}
	if len(b)%blocksize != 0 {
		return nil
	}
	c := b[len(b)-1]
	n := int(c)
	if n == 0 || n > len(b) {
		return nil
	}
	for i := 0; i < n; i++ {
		if b[len(b)-n+i] != c {
			return nil
		}
	}
	return b[:len(b)-n]
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

	verify_struct := VerifyStruct{username, string(hmac), string(signature), []byte(db_func.GetUserPublicKey(username))}

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
	return strings.TrimSuffix(string(out), "\n") == "True"
}

func HashWithSHA256(textToHash []byte) (crypto.Hash, []byte) {
	newhash := crypto.SHA256
	pssh := newhash.New()
	pssh.Write(textToHash)
	hashed := pssh.Sum(nil)

	return newhash, hashed
}

// //func VerifyClientSignature(username string, hashedPasswd []byte, hmac []byte, signature []byte) {
// func VerifyClientSignature(username string, hashedPasswd []byte, hmac []byte, signature []byte) {
// 	// load client's public key from database and parse into key

// 	//publicKey := BytesToPublicKey(username)

// 	//log.Printf("hmac %v", string(hmac));
// 	//encodedExpectedHmac := hex.EncodeToString(hmac);
// 	//log.Printf("encodedExpectedHmac %v", encodedExpectedHmac);

// 	newhash, hashedHmac := HashWithSHA256(hmac)

// 	userKey := BytesToPublicKey(db_func.GetUserPublicKey(username))
// 	log.Printf("hashedhmac %v", hashedHmac[:])
// 	//verifyErr := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashedHmac[:], signature)
// 	verifyErr := rsa.VerifyPSS(userKey, newhash, hashedHmac, signature, nil)
// 	if verifyErr != nil {
// 		log.Fatal(verifyErr)
// 	}
// 	log.Printf("Message signature verified!")
// }

func CheckMessageIntegrity(messageHmac []byte, encryptedMessage []byte, hashedPasswd []byte) bool {
	// does the hmac of the encrypted message content received to check if the hmac's the same in the signature
	encodedExpectedHmac := hmacMaker(encryptedMessage, hashedPasswd)

	return hmac.Equal(messageHmac, []byte(encodedExpectedHmac))
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

	log.Printf("userkey %v", string(decodedPublicKey))
	// userKey = BytesToPublicKey(decodedPublicKey)

	log.Printf("register request from: %v", userRequest.Username)

	// TODO falta aqui a parte da base de dados: guardar user data
	// CHANGE DATABASE TO KEEP USER PUBLIC KEY????
	db_func.AddUser(userRequest.Username, userRequest.HashedPasswd, string(decodedPublicKey))

	// fmt.Fprintf(w, "")
	fmt.Fprintf(w, "Request body: %+v", userRequest.Username)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {

	var userRequest LoginRequest
	json.NewDecoder(r.Body).Decode(&userRequest)

	signatureBytes := []byte(userRequest.Signature)

	hmacBytes := []byte(userRequest.Hmac)

	serverPrivateKey := LoadPrivKeyFromFile("../../ssl/server.key")

	// decrypt last half of Kc
	decryptedKey := DecryptWithPrivateKey(userRequest.EncryptedKey, serverPrivateKey)

	decryptedCredentials := DecryptWithPrivateKey(userRequest.EncryptedCredentials, serverPrivateKey)

	fields := strings.Split(decryptedCredentials, ",")
	username := fields[0]
	hashedPasswd := fields[1]
	hashedPasswdBytes := []byte(hashedPasswd)
	// TODO: VERIFICAR HASH DA PASSWOOOORD
	// fields[2] == first half of Kc
	clientKey := fields[2] + decryptedKey

	CheckMessageIntegrity(hmacBytes, append(userRequest.EncryptedCredentials, userRequest.EncryptedKey...), hashedPasswdBytes)

	authenic := VerifyClientSignaturePython(username, hmacBytes, signatureBytes)
	log.Printf("Authentic message? %v", authenic)

	sessionId := StringWithCharset(16)

	sessions[sessionId] = Session{
		Username: username,
		DiffieH: dh_go.New("2",
			"2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919")}

	Kc := new(big.Int)
	Kc.SetBytes([]byte(clientKey))
	log.Printf("Kc %v\n", Kc)

	sessions[sessionId].DiffieH.GenSecret()
	sessions[sessionId].DiffieH.CalcPublic()
	sessions[sessionId].DiffieH.CalcSahredSecret(Kc.String())
	log.Printf("after dh")

	log.Printf("k: %v", sessions[sessionId].DiffieH.Sh_secret)

	w.Header().Set("Content-Type", "application/json")

	content := sessions[sessionId].DiffieH.Public.Text(10) + "," + sessionId
	log.Printf("content %v ", content)

	// block size is always 128 bits (16 bytes), so iv size is 128 bits (16 bytes)
	_, block_key := HashWithSHA256(sessions[sessionId].DiffieH.Sh_secret.Bytes())
	encryptedContent := EncryptWithAES(content, block_key)

	hmac_response := hmacMaker(encryptedContent, hashedPasswdBytes)
	log.Printf("hmac %v", hmac_response)
	signature := hex.EncodeToString(SignWithServerKey([]byte(hmac_response)))

	log.Printf("SIGNATURE: %v", signature)
	response := LoginResponse{
		Signature:        signature,
		Hmac:             hmac_response,
		DHServerKey:      sessions[sessionId].DiffieH.Public.Text(10),
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
	fmt.Printf("IN SCOREBOARD HANDLEEEER\n")
	// get the session ID
	var scoreRequest ScoreRequest
	json.NewDecoder(r.Body).Decode(&scoreRequest)
	fmt.Printf("Received: %v\n", scoreRequest)
	fmt.Printf("SESSION ID: %v\n", scoreRequest.SessionID)
	fmt.Printf("ENCRYPTED CONTENT: %v\n", scoreRequest.EncryptedContent)

	// delete session entry when current function is left
	defer delete(sessions, scoreRequest.SessionID)

	encrypted_content := make([]byte, len(scoreRequest.EncryptedContent))
	copy(encrypted_content, scoreRequest.EncryptedContent)

	_, block_key := HashWithSHA256(sessions[scoreRequest.SessionID].DiffieH.Sh_secret.Bytes())
	decrypted := DecryptWithAES(scoreRequest.EncryptedContent, block_key)

	decrypted_sessionID := decrypted[:16]
	decrypted_username := decrypted[16:]

	if bytes.Compare(decrypted_sessionID, []byte(scoreRequest.SessionID)) != 0 {
		log.Println("Session ID's do not match")
		fmt.Fprintf(w, "Session ID's do not match")
		return
	}

	if bytes.Compare(decrypted_username, []byte(sessions[scoreRequest.SessionID].Username)) != 0 {
		log.Println("Usernames do not match")
		fmt.Fprintf(w, "Usernames do not match")
		return
	}
	hmacBytes := []byte(scoreRequest.Hmac)
	// VerifyClientSignaturePython(username string, hmac []byte, signature []byte)
	control := VerifyClientSignaturePython(sessions[scoreRequest.SessionID].Username, hmacBytes, []byte(scoreRequest.Signature))
	// sessionID + sessionID + Username
	if !control {
		log.Println("Failed to verify client signature")
		fmt.Fprintf(w, "Failed to verify client signature")
		return
	}

	hashedPasswdBytes := []byte(db_func.GetUserPasswordHash(sessions[scoreRequest.SessionID].Username))
	original_message := []byte(scoreRequest.SessionID + string(encrypted_content))
	log.Printf("HMAC'D message: %v\n", original_message)
	log.Printf("HMAC'D message (string): %v\n", string(original_message))
	control = CheckMessageIntegrity(hmacBytes, original_message, hashedPasswdBytes)
	if !control {
		log.Println("Failed to verify message integrity")
		fmt.Fprintf(w, "Failed to verify message integrity")
		return
	}

	log.Print("After verifications")

	scoreboard := db_func.GetScoreboard()

	fmt.Printf("Scoreboard: %v\n", scoreboard)
	score_data := ""
	for _, entry := range scoreboard {
		fmt.Printf("entry: %v\n", entry)
		fmt.Printf("username: %v\n", entry.Username)
		fmt.Printf("points: %v\n", strconv.Itoa(entry.Points))
		score_data = score_data + fmt.Sprintf("%s,%s,", entry.Username,
			strconv.Itoa(entry.Points))
	}

	score_data_final := score_data[:len(score_data)-1]

	_, block_key = HashWithSHA256(sessions[scoreRequest.SessionID].DiffieH.Sh_secret.Bytes())
	encryptedContent := EncryptWithAES(score_data_final, block_key)
	fmt.Println("Encrypted score data: %v\n", encryptedContent)
	hmac := hmacMaker(encryptedContent, hashedPasswdBytes)
	signature := hex.EncodeToString(SignWithServerKey([]byte(hmac)))

	response := ScoreResponse{
		Hmac:      hmac,
		Signature: signature,
		ScoreList: encryptedContent}
	json.NewEncoder(w).Encode(response)

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
