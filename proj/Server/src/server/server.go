package main

import (
    "fmt"
    "log"
    "net/http"
    "encoding/json"
)

/*func handler(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "Hi there!")
}*/

type RegisterRequest struct {
    Username  string `json:"username"`
    Passwd  string `json:"passwd"`
  }

func registerHandler(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "Register")

    var ur RegisterRequest
    decoder := json.NewDecoder(r.Body)
    decoder.Decode(&ur)

    log.Printf("username: %v", ur.Username)
    log.Printf("password: %v", ur.Passwd)

    fmt.Fprintf(w, "Request body: %+v", ur.Username)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "Login")
}

func submitHandler(w http.ResponseWriter, r *http.Request) {
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
    //http.HandleFunc("/", handler)
    http.HandleFunc("/register", registerHandler)
    http.HandleFunc("/login", loginHandler)
    http.HandleFunc("/submit", submitHandler)
    http.HandleFunc("/show", showHandler)
    http.HandleFunc("/score", scoreHandler)
    http.HandleFunc("/admin/remove_user", removeUserHandler)
    http.HandleFunc("/admin/remove_submission", removeSubmissionHandler)

    fmt.Println("Serving TLS")

    // http.ListenAndServeTLS(":443", "../../ssl/server.crt", "../../ssl/server.key", nil)
    http.ListenAndServeTLS(":443", "../../ssl/server.crt", "../../ssl/server.key", nil)
}
