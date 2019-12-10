package db_func

import (
	"database/sql"
	"fmt"
	"log"
	"strings"

	_ "github.com/lib/pq"
)

type Submission struct {
	Vuln  string
	BinFP string
}

type SubmissionAdmin struct {
	Vuln  string
	BinFP string
	SubID int
}

type Score struct {
	Username string
	Points   int
}

/*
ERROR FUNCTIONS
*/
func SQLErrorHandling(err error) {
	if err == sql.ErrNoRows {
		log.Println("This username doesn't exist")

	} else if strings.Contains(err.Error(), "violates unique constraint") {
		log.Println("Duplicated parameters !")
	} else {
		log.Fatal("Something is off") //important to not show the error! (if you need to specify new errors, then add them to the else if)
	}
}

//Retrives the users points from the database
func GetUserPoints(username string) int {
	db := connDB()

	queryStmt, err := db.Prepare("	SELECT points FROM accounts WHERE username = $1")

	//since there should only be one element from this table it should be fine to just get the first one
	var points int
	err = queryStmt.QueryRow(username).Scan(&points)

	SQLErrorHandling(err)

	db.Close()
	return points
}

//Creates a new user in the database
func AddUser(username string, hashedPassword string, publicKey string) {
	db := connDB()

	queryStmt, err := db.Prepare("INSERT INTO accounts (username, public_key, pass , points) VALUES ($1,$2,$3,0)")

	log.Printf("Prepared query: %v", queryStmt)
	//the database itself should error if the username already exists
	_, err = queryStmt.Exec(username, publicKey, hashedPassword)

	if err == nil {
		log.Println("Successfully created new user!")
	} else {
		SQLErrorHandling(err)
	}

	db.Close()
}

//Retrives the hashed password for a specific user
func GetUserPasswordHash(username string) string {
	//Connects to the database
	db := connDB()
	//Does the query
	queryStmt, err := db.Prepare("	SELECT pass FROM accounts WHERE username = $1")

	var password string
	err = queryStmt.QueryRow(username).Scan(&password)

	if err != nil {
		SQLErrorHandling(err)
	}

	//Closes the connection to the database
	db.Close()

	return password
}

//
func GetUserPublicKey(username string) string {
	//Connects to the database
	db := connDB()
	//Does the query
	queryStmt, err := db.Prepare("	SELECT public_key FROM accounts WHERE username = $1")

	var publicKey string
	err = queryStmt.QueryRow(username).Scan(&publicKey)

	if err != nil {
		SQLErrorHandling(err)
	}

	//Closes the connection to the database
	db.Close()

	return publicKey
}

//Associates a already created username with the admin privileges
func AddAdmin(username string) {
	db := connDB()

	queryStmt, err := db.Prepare("INSERT INTO admin (user_id) SELECT id FROM accounts WHERE username = $1")

	//the database itself should error if the username already exists
	_, err = queryStmt.Exec(username)

	if err == nil {
		log.Println("Successfully added a new admin!")
	} else {
		SQLErrorHandling(err)
	}

	db.Close()
}

//Checks if the given username is an admin
func IsAdmin(username string) bool {
	//Connects to the database
	db := connDB()
	//Does the query
	queryStmt, err := db.Prepare("SELECT username FROM accounts INNER JOIN admin ON accounts.id= admin.user_id WHERE username = $1")

	//if the username provided is indeed the admin
	//the result should be user = username
	var user string
	err = queryStmt.QueryRow(username).Scan(&user)

	if err != nil {
		SQLErrorHandling(err)
	}

	//Closes the connection to the database
	db.Close()

	//check if the result is null
	if user != "" && user == username {
		return true
	} else {
		return false
	}

}

//FIXME: duplicates
//Creates a new user in the database
func AddSubmission(username string, vuln string, binFP string) bool {
	db := connDB()
	//try to add the binary fingerprint
	queryStmt, err := db.Prepare("INSERT INTO binaries (bin_fp) VALUES ($1)")
	_, err = queryStmt.Exec(binFP)

	if err != nil {
		log.Println("Could not add the binary ...")
	}

	//Add the submission itself
	queryStmt, err = db.Prepare("INSERT INTO submissions (user_id,vuln,bin_id) SELECT accounts.id as user_id, $1, binaries.id as bin_id FROM accounts FULL JOIN binaries ON true WHERE accounts.username = $2 AND binaries.bin_fp = $3")

	res, err := queryStmt.Exec(vuln, username, binFP)

	defer db.Close()
	if err != nil {
		SQLErrorHandling(err)
		return false
	} else {
		count, _ := res.RowsAffected()
		//query happened without errors but there was nothing to insert
		if count == 0 {
			log.Println("Submission not added ...")
			return false
		} else {
			log.Println("Successfully created a new Submission!")
			return true
		}
	}
}

func GetUserSubmissions(username string) []Submission {
	//Connects to the database
	db := connDB()
	//Does the query
	queryStmt, err := db.Prepare("SELECT vuln,bin_fp FROM (SELECT submissions.id,user_id,vuln,bin_fp FROM submissions INNER JOIN binaries ON submissions.bin_id = binaries.id) AS subs INNER JOIN accounts ON accounts.id = subs.user_id WHERE accounts.username = $1")

	rows, err := queryStmt.Query(username)
	defer rows.Close()

	submissions := make([]Submission, 0)
	for rows.Next() {
		var vuln string
		var binFP string
		if err := rows.Scan(&vuln, &binFP); err != nil {
			log.Fatal(err)
		}

		submissions = append(submissions, Submission{Vuln: vuln, BinFP: binFP})
	}
	if err != nil {
		SQLErrorHandling(err)
	}

	//Closes the connection to the database
	db.Close()

	return submissions
}

func GetScoreboard() []Score {
	//Connects to the database
	db := connDB()
	//Does the query
	queryStmt, err := db.Prepare("SELECT username, points FROM accounts")

	rows, err := queryStmt.Query()
	defer rows.Close()

	scoreboard := make([]Score, 0)
	for rows.Next() {
		var username string
		var points int
		if err := rows.Scan(&username, &points); err != nil {
			log.Fatal(err)
		}

		scoreboard = append(scoreboard, Score{Username: username, Points: points})
	}
	if err != nil {
		SQLErrorHandling(err)
	}

	//Closes the connection to the database
	db.Close()

	return scoreboard
}

func AdminGetAllSubmissions() map[string][]SubmissionAdmin {
	//Connects to the database
	db := connDB()
	//Does the query
	queryStmt, err := db.Prepare("SELECT username,vuln,bin_fp,subs.sub_id FROM (SELECT submissions.id AS sub_id, user_id, vuln, bin_fp FROM submissions INNER JOIN binaries ON submissions.bin_id = binaries.id) AS subs INNER JOIN accounts ON accounts.id = subs.user_id")

	rows, err := queryStmt.Query()
	defer rows.Close()

	submissions := make(map[string][]SubmissionAdmin, 0)
	for rows.Next() {
		var username string
		var vuln string
		var binFP string
		var subID int

		if err := rows.Scan(&username, &vuln, &binFP, &subID); err != nil {
			log.Fatal(err)
		}

		//checks if already exists
		if _, ok := submissions[username]; ok {
			submissions[username] = append(submissions[username], SubmissionAdmin{Vuln: vuln, BinFP: binFP, SubID: subID})
		} else {
			submissions[username] = []SubmissionAdmin{SubmissionAdmin{Vuln: vuln, BinFP: binFP, SubID: subID}}
		}

	}

	if err != nil {
		SQLErrorHandling(err)
	}

	//Closes the connection to the database
	db.Close()

	return submissions
}

func AdminDeleteSubmission(username string, vuln string, binFP string) {
	//Connects to the database
	db := connDB()

	//Does the query
	queryStmt, err := db.Prepare("DELETE FROM submissions USING (SELECT subs.id FROM (SELECT submissions.id,user_id,vuln,bin_fp FROM submissions INNER JOIN binaries ON submissions.bin_id = binaries.id) AS subs INNER JOIN accounts ON accounts.id = subs.user_id WHERE accounts.username = $1 AND subs.vuln=$2 AND subs.bin_fp=$3) AS tmp WHERE tmp.id = submissions.id")
	_, err = queryStmt.Exec(username, vuln, binFP)

	if err != nil {
		SQLErrorHandling(err)
	} else {
		log.Println("Successfully deleted user submission!")
	}

	db.Close()
}

//Creates a new user in the database
func AdminRemoveUser(username string) {
	db := connDB()

	queryStmt, err := db.Prepare("DELETE FROM accounts WHERE username = $1")

	//the database itself should error if the username already exists
	_, err = queryStmt.Exec(username)

	if err == nil {
		log.Println("Successfully removed the user!")
	} else {
		SQLErrorHandling(err)
	}

	db.Close()
}

func connDB() *sql.DB {
	//FIXME: maybe import this ?
	var dbHost string = "127.0.0.1"
	// var dbHost string = "172.18.1.11"
	var dbPort string = "5432"
	var username string = "sirs"
	var dbName string = "sirsdb"
	var password string = "sirs"

	dbURI := fmt.Sprintf("host=%s port=%s user=%s dbname=%s sslmode=disable password=%s", dbHost, dbPort, username, dbName, password) //Build connection string

	log.Printf("Establishing connection with database...\n")
	db, err := sql.Open("postgres", dbURI)

	if err != nil {
		log.Println("Connection Failed to Open!\n")
	} else {
		log.Println("Connection Established!\n")
	}
	return db
}

// func main() {
// 	//Example, TODO: delete the main function, this way it works as a library?
// 	addUser("Ze", "aaa")
// 	addSubmission("Ze", "a", "a")
// }

//ALTER SEQUENCE accounts_id_seq RESTART WITH 1;
