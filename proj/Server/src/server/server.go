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

    //_ "github.com/alexellis/hmac"
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
    Signature  []byte `json:"Signature"` 
    Hmac  []byte `json:"hmac"`
    EncryptedContent  []byte `json:"encryptedContent"`
}

type LoginResponse struct {
    DHServerKey  string `json:"dhServerKey"`
    EncryptedContent  string `json:"encryptedContent"`
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
	if err != nil {
		log.Fatal(err)
    }
	return string(plainText)
}

// using symmetric key generated (size = 256)
func EncryptWithDHKey(message string) string {
    //cipher, err := aes.NewCipher(dh.Sh_secret.Bytes())
    keyBlock, err := aes.NewCipher(dh.Sh_secret.Bytes())
    if err != nil {
		log.Fatal(err)
    }
    // The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext
    buffer := make([]byte, aes.BlockSize + len(message))
    iv := buffer[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		log.Fatal(err)
    }
    
    mode := cipher.NewCBCEncrypter(keyBlock, iv)
	mode.CryptBlocks(buffer[aes.BlockSize:], []byte(message))

    return hex.EncodeToString(buffer)
}

//func VerifyClientSignature(username string, hashedPasswd []byte, hmac []byte, signature []byte) {
func VerifyClientSignature(hashedPasswd []byte, hmac []byte, signature []byte) {
    // load client's public key from database and parse into key

    //publicKey := LoadClientPubKeyFromDatabase(username)

    hashedHmac := sha256.Sum256(hmac)
    //verifyErr := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashedHmac[:], signature)
    verifyErr := rsa.VerifyPKCS1v15(userKey, crypto.SHA256, hashedHmac[:], signature)
    if verifyErr != nil {
        log.Fatal(verifyErr)
    }
}

func CheckMessageIntegrity(messageHmac []byte, encryptedMessage []byte, hashedPasswd []byte) {
    // does the hmac of the encrypted message content received to check if the hmac's the same in the signature
    hasherHmac := hmac.New(sha256.New, hashedPasswd)
    hasherHmac.Write(encryptedMessage)
    expectedHmac := hasherHmac.Sum(nil)

    integrityChecks := hmac.Equal(messageHmac, expectedHmac)
    if (integrityChecks == false) {
        log.Fatal("Integrity violated!")
    }
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
    
    var userRequest RegisterRequest
    json.NewDecoder(r.Body).Decode(&userRequest)

    decodedPublicKey, err := base64.StdEncoding.DecodeString(userRequest.PublicKey)
    if err != nil {
		log.Fatal(err)
	}
    userKey = LoadClientPubKeyFromDatabase(decodedPublicKey)

    log.Printf("register request from: %v", userRequest.Username)

    // TODO falta aqui a parte da base de dados: guardar user data
    // CHANGE DATABASE TO KEEP USER PUBLIC KEY????
    //addUser(userRequest.Username, userRequest.HashedPasswd, userRequest.PublicKey)

    //fmt.Fprintf(w, "Request body: %+v", ur.Username)
    fmt.Fprintf(w, "Register")
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    log.Printf("login handler")
    var userRequest LoginRequest
    json.NewDecoder(r.Body).Decode(&userRequest)

    decryptedContent := DecryptWithPrivateKey(userRequest.EncryptedContent, LoadPrivKeyFromFile("../../ssl/server_tls.key"))
    
    fields := strings.Split(decryptedContent, ",")
    //username := fields[0]
    hashedPasswd := fields[1]
    Kc := fields[2]
    log.Printf(Kc)
    log.Printf("login request from: %v", fields[0])

    CheckMessageIntegrity(userRequest.Hmac, userRequest.EncryptedContent, []byte(hashedPasswd))
    //VerifyClientSignature(username, []byte(hashedPasswd),userRequest.Hmac, userRequest.Signature)
    VerifyClientSignature([]byte(hashedPasswd),userRequest.Hmac, userRequest.Signature)

    dh.GenSecret()
    dh.CalcPublic()
    dh.CalcSahredSecret(Kc)

    w.Header().Set("Content-Type", "application/json")

    sessionId := GenerateRandomNumber(8)

    content := dh.Public.Text(10) + "," + sessionId.Text(10)
    log.Printf(content)

    encryptedContent := EncryptWithDHKey(content)

    response := LoginResponse {
                            DHServerKey: dh.Public.Text(10),
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
