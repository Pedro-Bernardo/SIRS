package main

import (
    "fmt"
    "log"
    "io/ioutil"
    "strings"
    "crypto/rand"
    "math/big"
    "net/http"
    "crypto/tls"
    "crypto/x509"
    "encoding/pem"
    "crypto/rsa"
    "crypto/sha256"
    //"crypto/cipher"
    //"crypto/aes"
    "encoding/json"
    //"encoding/base64"
)

// Diffie-Hellman constants
var G = big.NewInt(23)
var P = big.NewInt(577)

// Diffie-Hellman secret values
var Sc big.Int
var Ss big.Int

// Diffie-Hellman keys
var Ks big.Int
var Kc big.Int
var K big.Int

type RegisterRequest struct {
    Username  string `json:"username"`
    Passwd  string `json:"passwd"`
}

type RegisterResponse struct {
    Status string `json:"status"`
}

type LoginRequest struct {
    EncryptedContent  []byte `json:"encryptedContent"`
}

type LoginResponse struct {
    DHServerKey  string `json:"dhServerKey"`
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

/*func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func GenerateRandomSecret(length int) string {
    bytes, err := GenerateRandomBytes(length)
    if err != nil {
		log.Fatal(err)
    }
	return base64.URLEncoding.EncodeToString(bytes)
}*/

func LoadPrivKeyFromFile(filename string) *rsa.PrivateKey {
    keyString, _ := ioutil.ReadFile(filename)
    block, _ := pem.Decode([]byte(keyString))
    parseResult, _ := x509.ParsePKCS8PrivateKey(block.Bytes)
    privKey := parseResult.(*rsa.PrivateKey)
    return privKey
}

func DecryptWithPrivateKey(encryptedMessage []byte, privKey *rsa.PrivateKey) string {
    hash := sha256.New()
    plainText, err := rsa.DecryptOAEP(hash, rand.Reader, privKey, encryptedMessage, nil)
	if err != nil {
		log.Fatal(err)
    }
	return string(plainText)
}

func EncryptWithServerDHKey() {

}

func GenerateDiffieHellmanSecretServerValue() {
    Ss := GenerateRandomNumber(16)
    log.Printf("%v", Ss)
}

func GenerateDiffieHellmanServerKey() {
    exp := Kc.Exp(G, &Ss, nil)
    Ks :=  K.Mod(exp, P)
    //Ks := int(math.Pow(G, float64(Ss))) % P
    log.Printf("%v", Ks)
}

func GenerateDiffieHellmanSecretKey() {
    exp := Kc.Exp(&Kc, &Ss, nil)
    K :=  K.Mod(exp, P)
    //K := int(math.Pow(float64(Kc), float64(Ss))) % P
    log.Printf("%v", K)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
    
    var userRequest RegisterRequest
    json.NewDecoder(r.Body).Decode(&userRequest)

    log.Printf("register request from: %v", userRequest.Username)

    // TODO falta aqui a parte da base de dados: guardar user data


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
    //passwd := fields[1]
    Kc := fields[2]
    log.Printf(Kc)
    log.Printf("login request from: %v", fields[0])

    // TODO ver se hash guardada e igual a hash(username + passwd)

    GenerateDiffieHellmanSecretServerValue()
    GenerateDiffieHellmanServerKey()
    GenerateDiffieHellmanSecretKey()

    w.Header().Set("Content-Type", "application/json")

    sessionId := GenerateRandomNumber(8)

    content := Ks.Text(10) + "," + sessionId.Text(10)
    log.Printf(content)

    encryptedContent := []byte("ola")

    response := LoginResponse {
                            DHServerKey: Ks.Text(10),
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
