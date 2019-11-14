package main

import (
    "fmt"
    "log"
    "net/http"
    "crypto/tls"
    "crypto/rsa"
    //"crypto/sha256"
    //"crypto/cipher"
    //"crypto/aes"
    "crypto/rand"
    "encoding/json"
    "encoding/base64"
)

type Status int

const (
    OK Status = iota
    NOK
    ADMIN_RESERVED
)

type UserSession struct {
    Username  string
    Key  []byte
    Secret  string
}

// only saves one for now
var clientPubKey *rsa.PublicKey

type RegisterRequest struct {
    Username  string `json:"username"`
    Passwd  string `json:"passwd"`
    ClientPubKey  string `json:"clientPubKey"`
}

type RegisterResponse struct {
    HmacSecret  string `json:"hmacSecret"`
}

type KeygenRequest struct {
    Username  string `json:"username"`
    EncryptedUsername  string `json:"encryptedUsername"`
}

type KeygenResponse struct {
    Key  []byte `json:"key"`
    Secret  string `json:"secret"`
}

type LoginRequest struct {
    Username  string `json:"username"`
    EncryptedPasswd  string `json:"encryptedPasswd"`
}

type SubmitRequest struct {
    VulnDescription  string `json:"vulnDescription"`
    Fingerprint  string `json:"fingerprint"`
}

type StatusResponse struct {
    Status  string `json:"status"`
}

func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func GenerateRandom256bitSecret() (string, error) {
    bytes, err := GenerateRandomBytes(32)
	return base64.URLEncoding.EncodeToString(bytes), err
}

/*func DecryptWithPublicKey(ciphertext []byte, pub *rsa.PublicKey) []byte {

	hash := sha256.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, pub, ciphertext, nil)
	if err != nil {
		log.Error(err)
	}
	return plaintext
} */

func registerHandler(w http.ResponseWriter, r *http.Request) {
    
    var userRequest RegisterRequest
    json.NewDecoder(r.Body).Decode(&userRequest)

    log.Printf("register request from: %v", userRequest.Username)

    // TODO falta aqui a parte da base de dados: guardar user data


    //fmt.Fprintf(w, "Request body: %+v", ur.Username)
    fmt.Fprintf(w, "Register")
}

func keygenHandler(w http.ResponseWriter, r *http.Request) {

    var userRequest KeygenRequest
    json.NewDecoder(r.Body).Decode(&userRequest)

    log.Printf("keygen request from: %v", userRequest.Username)

    decodedUsername, err := base64.StdEncoding.DecodeString(userRequest.EncryptedUsername)
    log.Printf("%v", decodedUsername)
    if err != nil {
        fmt.Println("decode error:", err)
		return
    }

    // TODO falta aqui a parte da base de dados e o que fazer com decodedPasswd
    
    w.Header().Set("Content-Type", "application/json")
    
    key := []byte("AES256Key-32Characters1234567890")
    secret, err := GenerateRandom256bitSecret()
    if err != nil {
        fmt.Println("generate secret error:", err)
		return
    }

    keygenResponse:= KeygenResponse {
                            Key: key,
                            Secret: secret}
    json.NewEncoder(w).Encode(keygenResponse)

    fmt.Fprintf(w, "Keygen")
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    log.Printf("login handler")
    var userRequest LoginRequest
    json.NewDecoder(r.Body).Decode(&userRequest)

    log.Printf("login request from: %v", userRequest.Username)

    // TODO ver se hash guardada e igual a hash(username + passwd)

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
    mux_http_tls.HandleFunc("/keygen", keygenHandler)
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
        server_http_tls.ListenAndServeTLS("../../ssl/server.crt", "../../ssl/server.key")
    }()

    <-finish
}
