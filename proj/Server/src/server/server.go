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
	"regexp"
	"strconv"
	"strings"
	"time"
)

// var dh *dh_go.DH

// map key is session ID
var sessions = make(map[string]Session)

type Session struct {
	Username  string
	DiffieH   *dh_go.DH
	Timestamp time.Time
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
	EncryptedTimestamp   []byte `json:"encryptedTimestamp"`
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
	SessionID       string `json:"sessionId"`
	VulnDescription string `json:"vulnDescription"`
	Fingerprint     string `json:"fingerprint"`
}

type SubmitResponse struct {
	Signature string `json:"signature"`
	Hmac      string `json:"hmac"`
	Status    string `json:"status"`
}

type GenericResponse struct {
	Signature        string `json:"signature"`
	Hmac             string `json:"hmac"`
	EncryptedContent []byte `json:"encryptedContent"`
}

type GenericRequest struct {
	Signature        string `json:"signature"`
	Hmac             string `json:"hmac"`
	EncryptedContent []byte `json:"encryptedContent"`
	SessionID        string `json:"sessionId"`
}

type AdminShowRequest struct {
	Signature string `json:"signature"`
	Username  string `json:"username"`
	SessionID string `json:"sessionId"`
}

type AdminShowResponse struct {
	Submissions string `json:"submissions"`
	Status      string `json:"status"`
}

type RemoveUserRequest struct {
	Signature        string `json:"signature"`
	Username         string `json:"username"`
	UsernameToRemove string `json:"usernameToRemove"`
	SessionID        string `json:"sessionId"`
}

type RemoveUserResponse struct {
	Status string `json:"status"`
}

type RemoveSubmissionRequest struct {
	Signature  string `json:"signature"`
	Username   string `json:"username"`
	IdToRemove int    `json:"idToRemove"`
	SessionID  string `json:"sessionId"`
}

type RemoveSubmissionResponse struct {
	Status string `json:"status"`
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

func BytesToPublicKey(block []byte) (*rsa.PublicKey, string) {
	publicPem, _ := pem.Decode(block)
	if publicPem == nil {
		log.Println("Client's public key is not in pem format")
		return nil, "Client's public key is not in pem format"
	}
	parseResult, parseErr := x509.ParsePKIXPublicKey(publicPem.Bytes)
	if parseErr != nil {
		log.Println(parseErr)
		return nil, "Error parsing key"
	}
	publicKey := parseResult.(*rsa.PublicKey)

	return publicKey, ""
}

func DecryptWithPrivateKey(encryptedMessage []byte, privKey *rsa.PrivateKey) string {
	hash := sha256.New()

	plainText, err := rsa.DecryptOAEP(hash, crypto_rand.Reader, privKey, encryptedMessage, nil)
	if err != nil {
		log.Fatal(err)
	}

	return string(plainText)
}

// using symmetric key generated (size = 256 bits)
func EncryptWithAES(message string, key []byte) []byte {
	keyBlock, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	// message padding to match block size
	paddedMessage := pkcs7Pad([]byte(message), aes.BlockSize)
	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext
	buffer := make([]byte, aes.BlockSize+len(paddedMessage))
	iv := buffer[:aes.BlockSize]
	if _, err := io.ReadFull(crypto_rand.Reader, iv); err != nil {
		log.Fatal(err)
	}

	mode := cipher.NewCBCEncrypter(keyBlock, iv)
	mode.CryptBlocks(buffer[aes.BlockSize:], []byte(paddedMessage))

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
	decrytped_message := make([]byte, len(cipherText))

	mode := cipher.NewCBCDecrypter(keyBlock, iv)
	// XORKeyStream can work in-place if the two arguments are the same.
	mode.CryptBlocks(decrytped_message, cipherText)
	decrypted_ciphertext := pkcs7Unpad(decrytped_message, aes.BlockSize)

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

func pkcs7Pad(b []byte, blocksize int) []byte {
	if blocksize <= 0 {
		return nil
	}
	if b == nil || len(b) == 0 {
		return nil
	}
	n := blocksize - (len(b) % blocksize)
	pb := make([]byte, len(b)+n)
	copy(pb, b)
	copy(pb[len(b):], bytes.Repeat([]byte{byte(n)}, n))
	return pb
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

	if len(userRequest.Username) == 0 {
		log.Printf("invalid username: %v\n", userRequest.Username)
		http.Error(w, "invalid username", http.StatusBadRequest)
		fmt.Fprintf(w, "")
		return
	} else {
		if !regexp.MustCompile(`^[a-zA-Z0-9]+$`).MatchString(userRequest.Username) {
			log.Printf("invalid username: %v\n", userRequest.Username)
			http.Error(w, "invalid username", http.StatusBadRequest)
			fmt.Fprintf(w, "")
			return
		}
	}

	decodedPublicKey, err := base64.StdEncoding.DecodeString(userRequest.PublicKey)
	if err != nil {
		log.Printf("invalid user public key: %v\n", decodedPublicKey)
		http.Error(w, "invalid user public key", http.StatusBadRequest)
		fmt.Fprintf(w, "")
		return
	}

	log.Printf("userkey %v", string(decodedPublicKey))
	// verify if public key is valid
	_, err_string := BytesToPublicKey(decodedPublicKey)
	if err_string != "" {
		log.Printf("invalid user public key: %v\n", decodedPublicKey)
		http.Error(w, "invalid user public key", http.StatusBadRequest)
		fmt.Fprintf(w, "")
		return
	}

	log.Printf("register request from: %v", userRequest.Username)

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
	decryptedTimestamp := DecryptWithPrivateKey(userRequest.EncryptedTimestamp, serverPrivateKey)

	log.Printf("Decrypted timestamp: %v\n", decryptedTimestamp)
	sent_ts, err := strconv.ParseInt(decryptedTimestamp, 10, 64)
	if err != nil {
		log.Println("Invalid timestamp")
		// http.Error(w, err, http.StatusUnauthorized)
		http.Error(w, "Invalid timestamp", http.StatusBadRequest)
		fmt.Fprintf(w, "")
		return
	}

	tm := time.Now().Unix()

	// check if ts is older than 10 seconds
	log.Printf("sent ts: %v\nmy ts: %v\n", strconv.Itoa(int(sent_ts)), strconv.Itoa(int(tm)))
	if (tm - sent_ts) > 10 {
		log.Println("Expired request")
		// http.Error(w, err, http.StatusUnauthorized)
		http.Error(w, "Expired request", http.StatusBadRequest)
		fmt.Fprintf(w, "")
		return
	}
	fmt.Println(tm)

	fields := strings.Split(decryptedCredentials, ",")
	username := fields[0]
	hashedPasswd := fields[1]
	hashedPasswdBytes := []byte(hashedPasswd)
	// TODO: VERIFICAR HASH DA PASSWOOOORD

	realHashedPasswdBytes, err2 := db_func.GetUserPasswordHash(username)
	if !err2 {
		log.Println("Invalid username")
		// http.Error(w, err, http.StatusUnauthorized)
		http.Error(w, "Invalid username", http.StatusUnauthorized)
		fmt.Fprintf(w, "")
		return
	}

	if realHashedPasswdBytes != hashedPasswd {
		log.Printf("Wrong password: %v vs %v\n", realHashedPasswdBytes, hashedPasswd)
		http.Error(w, "Wrong password", http.StatusUnauthorized)
		fmt.Fprintf(w, "")
		return
	}

	clientKey := fields[2] + decryptedKey

	CheckMessageIntegrity(hmacBytes, append(append(userRequest.EncryptedCredentials, userRequest.EncryptedKey...), userRequest.EncryptedTimestamp...), hashedPasswdBytes)

	authenic := VerifyClientSignaturePython(username, hmacBytes, signatureBytes)
	log.Printf("Authentic message? %v", authenic)

	// for _, entry := range sessions {
	// 	if entry.Username == username {
	// 		log.Printf("User already logged in")
	// 		http.Error(w, "User already logged in", http.StatusUnauthorized)
	// 		fmt.Fprintf(w, "")
	// 		return
	// 	}
	// }

	sessionId := StringWithCharset(16)

	for _, ok := sessions[sessionId]; ok; {
		sessionId = StringWithCharset(16)
	}

	sessions[sessionId] = Session{
		Username: username,
		DiffieH: dh_go.New("2",
			"2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919"),
		Timestamp: time.Now()}

	Kc := new(big.Int)
	Kc.SetBytes([]byte(clientKey))

	sessions[sessionId].DiffieH.GenSecret()
	sessions[sessionId].DiffieH.CalcPublic()
	sessions[sessionId].DiffieH.CalcSahredSecret(Kc.String())

	w.Header().Set("Content-Type", "application/json")

	content := sessions[sessionId].DiffieH.Public.Text(10) + "," + sessionId

	// block size is always 128 bits (16 bytes), so iv size is 128 bits (16 bytes)
	_, block_key := HashWithSHA256(sessions[sessionId].DiffieH.Sh_secret.Bytes())
	encryptedContent := EncryptWithAES(content, block_key)

	hmac_response := hmacMaker(append([]byte(sessions[sessionId].DiffieH.Public.Text(10)), encryptedContent...), hashedPasswdBytes)
	signature := hex.EncodeToString(SignWithServerKey([]byte(hmac_response)))

	response := LoginResponse{
		Signature:        signature,
		Hmac:             hmac_response,
		DHServerKey:      sessions[sessionId].DiffieH.Public.Text(10),
		EncryptedContent: encryptedContent}

	json.NewEncoder(w).Encode(response)

	fmt.Fprintf(w, "")
}

func submitHandler(w http.ResponseWriter, r *http.Request) {

	fmt.Printf("IN SUBMIT HANDLEEEER\n")
	// get the session ID
	var submitRequest SubmitRequest
	json.NewDecoder(r.Body).Decode(&submitRequest)

	realHashedPasswdBytes, control := db_func.GetUserPasswordHash(sessions[submitRequest.SessionID].Username)
	if !control {
		log.Println("Invalid username")
		http.Error(w, "Invalid username", http.StatusUnauthorized)
		// http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		fmt.Fprintf(w, "")
		return
	}

	control, err := validateSubmitRequest(submitRequest)
	if !control {
		log.Println("Error validating request data")
		http.Error(w, err, http.StatusBadRequest)
		// http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		fmt.Fprintf(w, "")
		return
	}

	log.Print("After verifications")

	// delete session entry when current function is left
	defer delete(sessions, submitRequest.SessionID)

	decoded_vuln_descriptor, _ := base64.StdEncoding.DecodeString(submitRequest.VulnDescription)
	decoded_fingerprint, _ := base64.StdEncoding.DecodeString(submitRequest.Fingerprint)

	_, block_key := HashWithSHA256(sessions[submitRequest.SessionID].DiffieH.Sh_secret.Bytes())
	decrypted_vuln := string(DecryptWithAES(decoded_vuln_descriptor, block_key))
	decrypted_fp := string(DecryptWithAES(decoded_fingerprint, block_key))

	if !(regexp.MustCompile(`^[a-zA-Z0-9]+$`).MatchString(decrypted_vuln) && regexp.MustCompile(`^[a-f0-9]+$`).MatchString(decrypted_fp)) {
		log.Println("Invalid data: must be alphanumeric")
		http.Error(w, "Invalid data: must be alphanumeric", http.StatusBadRequest)
		// http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		fmt.Fprintf(w, "")
		return
	}

	success := db_func.AddSubmission(sessions[submitRequest.SessionID].Username, decrypted_vuln, decrypted_fp)

	_, block_key = HashWithSHA256(sessions[submitRequest.SessionID].DiffieH.Sh_secret.Bytes())
	var result string
	if success {
		result = "OK"
	} else {
		result = "NOK"
	}

	encryptedContent := EncryptWithAES(result, block_key)
	fmt.Println("Encrypted data: %v\n", encryptedContent)

	hashedPasswdBytes := []byte(realHashedPasswdBytes)
	hmac := hmacMaker(encryptedContent, hashedPasswdBytes)
	signature := hex.EncodeToString(SignWithServerKey([]byte(hmac)))

	response := GenericResponse{
		Hmac:             hmac,
		Signature:        signature,
		EncryptedContent: encryptedContent}
	json.NewEncoder(w).Encode(response)

	fmt.Fprintf(w, "")
}

func validateSubmitRequest(req SubmitRequest) (bool, string) {
	decoded_vuln_descriptor, _ := base64.StdEncoding.DecodeString(req.VulnDescription)
	decoded_fingerprint, _ := base64.StdEncoding.DecodeString(req.Fingerprint)

	if _, ok := sessions[req.SessionID]; !ok {
		return false, "Invalid session"
	}

	hmacBytes := []byte(req.Hmac)
	// VerifyClientSignaturePython(username string, hmac []byte, signature []byte)
	control := VerifyClientSignaturePython(sessions[req.SessionID].Username, hmacBytes, []byte(req.Signature))
	// sessionID + sessionID + Username
	if !control {
		log.Println("Failed to verify client signature")
		return false, "Failed to verify client signature"
	}

	realHashedPasswdBytes, control := db_func.GetUserPasswordHash(sessions[req.SessionID].Username)
	if !control {
		return false, "Invalid username"
	}
	hashedPasswdBytes := []byte(realHashedPasswdBytes)
	original_message := []byte(req.SessionID + string(decoded_fingerprint) + string(decoded_vuln_descriptor))
	control = CheckMessageIntegrity(hmacBytes, original_message, hashedPasswdBytes)
	if !control {
		log.Println("Failed to verify message integrity")
		return false, "Failed to verify message integrity"
	}
	return true, ""
}

func showHandler(w http.ResponseWriter, r *http.Request) {
	// get the session ID
	var showRequest GenericRequest
	json.NewDecoder(r.Body).Decode(&showRequest)

	control, err := validateRequest(showRequest)
	if !control {
		log.Println(err)
		http.Error(w, err, http.StatusBadRequest)
		// http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		fmt.Fprintf(w, "")
		return
	}

	log.Print("After verifications")

	// delete session entry when current function is left
	defer delete(sessions, showRequest.SessionID)

	submissions := db_func.GetUserSubmissions(sessions[showRequest.SessionID].Username)

	fmt.Printf("Submissions: %v\n", submissions)
	var subs_data string
	if len(submissions) != 0 {
		for _, entry := range submissions {
			fmt.Printf("entry: %v\n", entry)
			fmt.Printf("Vulnerability: %v\n", entry.Vuln)
			fmt.Printf("Binary Fingerprint: %v\n", entry.BinFP)
			subs_data = subs_data + fmt.Sprintf("%s,%s,", entry.Vuln, entry.BinFP)
		}

		subs_data = subs_data[:len(subs_data)-1]
	} else {
		subs_data = "No submissions"
	}

	subs_data_final := subs_data[:len(subs_data)-1]

	realHashedPasswdBytes, control := db_func.GetUserPasswordHash(sessions[showRequest.SessionID].Username)
	if !control {
		log.Println("Invalid username")
		http.Error(w, "Invalid username", http.StatusBadRequest)
		http.Error(w, err, http.StatusBadRequest)
		// http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		fmt.Fprintf(w, "")
		return
	}
	hashedPasswdBytes := []byte(realHashedPasswdBytes)
	_, block_key := HashWithSHA256(sessions[showRequest.SessionID].DiffieH.Sh_secret.Bytes())
	encryptedContent := EncryptWithAES(subs_data_final, block_key)
	fmt.Println("Encrypted show data: %v\n", encryptedContent)
	hmac := hmacMaker(encryptedContent, hashedPasswdBytes)
	signature := hex.EncodeToString(SignWithServerKey([]byte(hmac)))

	response := GenericResponse{
		Hmac:             hmac,
		Signature:        signature,
		EncryptedContent: encryptedContent}
	json.NewEncoder(w).Encode(response)

	fmt.Fprintf(w, "")
}

func validateRequest(req GenericRequest) (bool, string) {
	fmt.Printf("Received: %v\n", req)
	fmt.Printf("SESSION ID: %v\n", req.SessionID)
	fmt.Printf("ENCRYPTED CONTENT: %v\n", req.EncryptedContent)

	if _, ok := sessions[req.SessionID]; !ok {
		return false, "Invalid session"
	}

	_, block_key := HashWithSHA256(sessions[req.SessionID].DiffieH.Sh_secret.Bytes())
	decrypted := DecryptWithAES(req.EncryptedContent, block_key)

	decrypted_sessionID := decrypted[:16]
	decrypted_username := decrypted[16:]

	if bytes.Compare(decrypted_sessionID, []byte(req.SessionID)) != 0 {
		log.Println("Session ID's do not match")
		return false, "Session ID's do not match"
	}

	if bytes.Compare(decrypted_username, []byte(sessions[req.SessionID].Username)) != 0 {
		log.Println("Usernames do not match")
		return false, "Usernames do not match"
	}
	hmacBytes := []byte(req.Hmac)
	// VerifyClientSignaturePython(username string, hmac []byte, signature []byte)
	control := VerifyClientSignaturePython(sessions[req.SessionID].Username, hmacBytes, []byte(req.Signature))
	// sessionID + sessionID + Username
	if !control {
		log.Println("Failed to verify client signature")
		return false, "Failed to verify client signature"
	}

	realHashedPasswdBytes, control := db_func.GetUserPasswordHash(sessions[req.SessionID].Username)
	if !control {
		return false, "Invalid username"
	}
	hashedPasswdBytes := []byte(realHashedPasswdBytes)
	original_message := []byte(req.SessionID + string(req.EncryptedContent))
	control = CheckMessageIntegrity(hmacBytes, original_message, hashedPasswdBytes)
	if !control {
		log.Println("Failed to verify message integrity")
		return false, "Failed to verify message integrity"
	}
	return true, ""
}

func scoreHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("IN SCOREBOARD HANDLEEEER\n")
	// get the session ID
	var scoreRequest GenericRequest
	json.NewDecoder(r.Body).Decode(&scoreRequest)

	control, err := validateRequest(scoreRequest)
	if !control {
		log.Println(err)
		http.Error(w, err, http.StatusBadRequest)
		// http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		fmt.Fprintf(w, "")
		return
	}

	log.Print("After verifications")

	// delete session entry when current function is left
	defer delete(sessions, scoreRequest.SessionID)

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

	realHashedPasswdBytes, control := db_func.GetUserPasswordHash(sessions[scoreRequest.SessionID].Username)
	if !control {
		log.Println("Invalid username")
		http.Error(w, "Invalid username", http.StatusBadRequest)
		// http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		fmt.Fprintf(w, "")
		return
	}
	hashedPasswdBytes := []byte(realHashedPasswdBytes)
	_, block_key := HashWithSHA256(sessions[scoreRequest.SessionID].DiffieH.Sh_secret.Bytes())
	encryptedContent := EncryptWithAES(score_data_final, block_key)
	fmt.Println("Encrypted score data: %v\n", encryptedContent)
	hmac := hmacMaker(encryptedContent, hashedPasswdBytes)
	signature := hex.EncodeToString(SignWithServerKey([]byte(hmac)))

	response := GenericResponse{
		Hmac:             hmac,
		Signature:        signature,
		EncryptedContent: encryptedContent}
	json.NewEncoder(w).Encode(response)

	fmt.Fprintf(w, "")
}

// CLEAN SESSION FOR ADMIN
func adminShowHandler(w http.ResponseWriter, r *http.Request) {

	var userRequest AdminShowRequest
	json.NewDecoder(r.Body).Decode(&userRequest)

	if db_func.IsAdmin(userRequest.Username) &&
		VerifyClientSignaturePython(userRequest.Username, []byte(userRequest.Username),
			[]byte(userRequest.Signature)) {

		submissions := db_func.AdminGetAllSubmissions()

		defer delete(sessions, userRequest.SessionID)

		// TODO put vulnerabilities in string
		subs_data := ""
		if len(submissions) != 0 {
			for user, subs := range submissions {
				for _, entry := range subs {
					fmt.Printf("entry: %v\n", entry)
					fmt.Printf("Vulnerability: %v\n", entry.Vuln)
					fmt.Printf("Binary Fingerprint: %v\n", entry.BinFP)
					subs_data = subs_data + fmt.Sprintf("%s,%s,%s,%s,", user, strconv.Itoa(entry.SubID), entry.Vuln, entry.BinFP)
				}
			}
			// remove comma
			subs_data = subs_data[:len(subs_data)-1]

		} else {
			subs_data = "No submissions"
		}

		response := AdminShowResponse{Submissions: subs_data, Status: "OK"}
		json.NewEncoder(w).Encode(response)
		w.WriteHeader(200)
	} else {
		response := AdminShowResponse{Submissions: "", Status: "NOK"}
		json.NewEncoder(w).Encode(response)
		// http.Error(w, , http.StatusBadRequest)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
	}

	fmt.Fprintf(w, "")
}

func removeUserHandler(w http.ResponseWriter, r *http.Request) {

	var userRequest RemoveUserRequest
	json.NewDecoder(r.Body).Decode(&userRequest)

	if db_func.IsAdmin(userRequest.Username) &&
		VerifyClientSignaturePython(userRequest.Username, []byte(userRequest.Username),
			[]byte(userRequest.Signature)) {

		defer delete(sessions, userRequest.SessionID)
		db_func.AdminRemoveUser(userRequest.UsernameToRemove)

		response := RemoveUserResponse{Status: "OK"}
		json.NewEncoder(w).Encode(response)
		w.WriteHeader(200)
	} else {
		response := RemoveUserResponse{Status: "NOK"}
		json.NewEncoder(w).Encode(response)
		// http.Error(w, , http.StatusBadRequest)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
	}

	fmt.Fprintf(w, "")
}

func removeSubmissionHandler(w http.ResponseWriter, r *http.Request) {
	var userRequest RemoveSubmissionRequest
	json.NewDecoder(r.Body).Decode(&userRequest)

	if db_func.IsAdmin(userRequest.Username) &&
		VerifyClientSignaturePython(userRequest.Username, []byte(userRequest.Username),
			[]byte(userRequest.Signature)) {

		defer delete(sessions, userRequest.SessionID)

		fmt.Printf("ID TO REMOVE: %v\n", userRequest.IdToRemove)
		db_func.AdminDeleteSubmission(userRequest.IdToRemove)
		response := RemoveSubmissionResponse{Status: "OK"}
		json.NewEncoder(w).Encode(response)
		w.WriteHeader(200)
	} else {
		response := RemoveSubmissionResponse{Status: "NOK"}

		json.NewEncoder(w).Encode(response)
		// http.Error(w, , http.StatusBadRequest)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
	}

	fmt.Fprintf(w, "")
}

func prune_sessions() {
	var s_ids []string
	for true {
		log.Printf("cleaning sessions")
		for k, v := range sessions {
			// precision of prune is in seconds (good enough)
			if (int(time.Since(v.Timestamp) / time.Second)) >= 60 {
				s_ids = append(s_ids, k)
			}
		}

		for _, id := range s_ids {
			log.Printf("deleting session %v", id)
			delete(sessions, id)
		}
		s_ids = nil
		time.Sleep(10 * time.Second)
	}
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
	mux_http_tls.HandleFunc("/admin/show", adminShowHandler)
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
		prune_sessions()
	}()

	go func() {
		log.Println("Serving HTTP")
		http.ListenAndServe(":80", mux_http)
	}()

	go func() {
		log.Println("Serving TLS")
		//log.fatal(server_http_tls.ListenAndServeTLS("../../ssl/server.crt", "../../ssl/server.key"))
		server_http_tls.ListenAndServeTLS("../../ssl/server_tls.crt", "../../ssl/server_tls.key")
	}()

	<-finish
}
