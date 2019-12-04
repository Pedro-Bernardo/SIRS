package main

import (
    "fmt"
    "log"
    "io/ioutil"
    "io"
    "strings"
    "crypto/rand"
    "math/big"
    "net/http"
    "crypto/tls"
    "crypto/x509"
    "encoding/pem"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/hmac"
    "dh_go"
    "crypto"
    "crypto/cipher"
    "crypto/aes"
    "encoding/hex"
    "encoding/json"
    "encoding/base64"
    "bytes"
)

var dh *dh_go.DH

var userKey *rsa.PublicKey

type RegisterRequest struct {
    Username  string `json:"username"`
    HashedPasswd  string `json:"hashedPasswd"`
    PublicKey  string `json:"publicKey"`
}

type RegisterResponse struct {
    Status string `json:"status"`
}

type LoginRequest struct {
    Signature  string `json:"Signature"` 
    Hmac  string `json:"hmac"`
    EncryptedContent  []byte `json:"encryptedContent"`
}

type LoginResponse struct {
    DHServerKey  string `json:"dhServerKey"`
    Iv  []byte `json:"iv"`
    EncryptedContent  []byte `json:"encryptedContent"`
}

type SubmitRequest struct {
    VulnDescription  string `json:"vulnDescription"`
    Fingerprint  string `json:"fingerprint"`
}

type SubmitResponse struct {
    Status  string `json:"status"`
}

type ScoreResponse struct {
    ScoreList  string `json:"scoreList"`
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
    var cert* x509.Certificate
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
	if err != nil {
		log.Fatal(err)
    }
	return string(plainText)
}

// using symmetric key generated (size = 256 bits)
func EncryptWithDHKey(message string) ([]byte, []byte) {
    //cipher, err := aes.NewCipher(dh.Sh_secret.Bytes())
    keyBlock, err := aes.NewCipher(dh.Sh_secret.Bytes())
    if err != nil {
		log.Fatal(err)
    }
    log.Printf("keyBlock %v", keyBlock);

    log.Printf("block len %v", aes.BlockSize);

    log.Printf("message %v", string(message));
    log.Printf("message len %v", len(message));
    
    // message padding to match block size
    paddedMessage := PKCS5Padding([]byte(message), aes.BlockSize)
    log.Printf("paddedMessage %v", string(paddedMessage));
    log.Printf("paddedMessage len %v", len(paddedMessage));

    // The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext
    buffer := make([]byte, aes.BlockSize + len(message) + 1)
    log.Printf("buffer after make %v", buffer);
    iv := buffer[:aes.BlockSize]
    log.Printf("iv %v", iv);
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		log.Fatal(err)
    }
    log.Printf("buffer after io %v", buffer);

    log.Printf("buffer after %v", buffer);
    log.Printf("buffer len after %v", len(buffer));
    
    mode := cipher.NewCBCEncrypter(keyBlock, iv)
    mode.CryptBlocks(buffer[aes.BlockSize:], []byte(paddedMessage))
    
    log.Printf("buffer after cryptblocks %v", buffer);
    log.Printf("buffer len after cryptblocks %v", len(buffer));


    log.Printf("message in bytes %v", []byte(paddedMessage));

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
}

//func VerifyClientSignature(username string, hashedPasswd []byte, hmac []byte, signature []byte) {
func VerifyClientSignature(hashedPasswd []byte, hmac []byte, signature []byte) {
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
    log.Printf("userkey %v", userKey);
    verifyErr := rsa.VerifyPSS(userKey, newhash, hashedHmac, signature, nil)
    if verifyErr != nil {
        log.Fatal(verifyErr)
    }
    log.Printf("Message signature verified!")
}

func CheckMessageIntegrity(messageHmac []byte, encryptedMessage []byte, hashedPasswd []byte) {
    // does the hmac of the encrypted message content received to check if the hmac's the same in the signature
    hasherHmac := hmac.New(sha256.New, hashedPasswd)
    hasherHmac.Write(encryptedMessage)
    expectedHmac := hasherHmac.Sum(nil)
    encodedExpectedHmac := hex.EncodeToString(expectedHmac)

    integrityChecks := hmac.Equal(messageHmac, []byte(encodedExpectedHmac))
    if (integrityChecks == false) {
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
    
    log.Printf("userkey %v", string(decodedPublicKey));
    userKey = LoadClientPubKeyFromDatabase(decodedPublicKey)

    log.Printf("register request from: %v", userRequest.Username)

    // TODO falta aqui a parte da base de dados: guardar user data
    // CHANGE DATABASE TO KEEP USER PUBLIC KEY????
    //addUser(userRequest.Username, userRequest.HashedPasswd, userRequest.PublicKey)

    //fmt.Fprintf(w, "Request body: %+v", ur.Username)
    fmt.Fprintf(w, "Register")
}

func loginHandler(w http.ResponseWriter, r *http.Request) {

    var userRequest LoginRequest
    json.NewDecoder(r.Body).Decode(&userRequest)

    //signatureBytes := []byte(userRequest.Signature)

    hmacBytes := []byte(userRequest.Hmac)

    decryptedContent := DecryptWithPrivateKey(userRequest.EncryptedContent, LoadPrivKeyFromFile("../../ssl/server_tls.key"))
    
    fields := strings.Split(decryptedContent, ",")
    //username := fields[0]
    hashedPasswd := fields[1]
    hashedPasswdBytes := []byte(hashedPasswd)
    Kc := fields[2]
    log.Printf(Kc)
    log.Printf("login request from: %v", fields[0])

    CheckMessageIntegrity(hmacBytes, userRequest.EncryptedContent, hashedPasswdBytes)
    //VerifyClientSignature(username, []byte(hashedPasswd),userRequest.Hmac, userRequest.Signature)
    //VerifyClientSignature(hashedPasswdBytes, hmacBytes, signatureBytes)

    dh.GenSecret()
    dh.CalcPublic()
    dh.CalcSahredSecret(Kc)

    w.Header().Set("Content-Type", "application/json")

    sessionId := GenerateRandomNumber(8)

    content := dh.Public.Text(10) + "," + sessionId.Text(10)
    log.Printf("content %v ", content)

    // block size is always 128 bits (16 bytes), so iv size is 128 bits (16 bytes)
    encryptedContent, iv := EncryptWithDHKey(content)
    log.Printf("encryptedContent %v ", content)

    response := LoginResponse {
                            DHServerKey: dh.Public.Text(10),
                            Iv: iv,
                            EncryptedContent: encryptedContent}
    json.NewEncoder(w).Encode(response)

    fmt.Fprintf(w, "Login")
}

func submitHandler(w http.ResponseWriter, r *http.Request) {
    log.Printf("submit handler")
    var userRequest SubmitRequest
    json.NewDecoder(r.Body).Decode(&userRequest)

    log.Printf("submit request for: %v", userRequest.VulnDescription)

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
}

func main() {
    finish := make(chan bool)
    dh = dh_go.New(
		"16308619823141802043", 
		"67698572054823323968190430198898140425166346813366120209767078191542539756243")
    
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
