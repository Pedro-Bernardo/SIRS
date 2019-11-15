package main

import (
	"database/sql"
	"fmt"
	"log"
	"strings"

	_ "github.com/lib/pq"
)

type submission struct {
	vuln  string
	binFP string
}

type score struct {
	username string
	points   int
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
func getUserPoints(username string) int {
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
func addUser(username string, hashedPassword string) {
	db := connDB()

	queryStmt, err := db.Prepare("INSERT INTO accounts (username, pass , points) VALUES ($1,$2,0)")

	//the database itself should error if the username already exists
	_, err = queryStmt.Exec(username, hashedPassword)

	if err == nil {
		log.Println("Successfully created new user!")
	} else {
		SQLErrorHandling(err)
	}

	db.Close()
}

//Retrives the hashed password for a specific user
func getUserPasswordHash(username string) string {
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

//Creates a new user in the database
func addSession(username string, secret string) {
	db := connDB()

	queryStmt, err := db.Prepare("INSERT INTO sessions (user_id,secret) SELECT id, $1 FROM accounts WHERE username = $2")

	//the database itself should error if the username already exists
	_, err = queryStmt.Exec(secret, username)

	if err == nil {
		log.Println("Successfully created a new session!")
	} else {
		SQLErrorHandling(err)
	}

	db.Close()
}

//Retrives the session secret for the communication server/client
func getSecret(username string) string {
	//Connects to the database
	db := connDB()
	//Does the query
	queryStmt, err := db.Prepare("SELECT secret FROM accounts INNER JOIN sessions ON accounts.id= sessions.user_id WHERE username = $1")

	var secret string
	err = queryStmt.QueryRow(username).Scan(&secret)

	if err != nil {
		SQLErrorHandling(err)
	}

	//Closes the connection to the database
	db.Close()

	return secret
}

//Creates a new user in the database
func setSecret(username string, secret string) {
	db := connDB()

	queryStmt, err := db.Prepare("UPDATE sessions SET secret = $1 FROM accounts WHERE sessions.user_id = accounts.id AND accounts.username = $2")

	//the database itself should error if the username already exists
	_, err = queryStmt.Exec(secret, username)

	if err != nil {
		SQLErrorHandling(err)

	} else {
		log.Println("Successfully updated the users secret!")
	}

	db.Close()
}

//FIXME: duplicates
//Creates a new user in the database
func addSubmission(username string, vuln string, binFP string) {
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

	if err != nil {
		SQLErrorHandling(err)
	} else {
		count, _ := res.RowsAffected()
		//query happened without errors but there was nothing to insert
		if count == 0 {
			log.Println("Submission not added ...")
		} else {
			log.Println("Successfully created a new Submission!")
		}
	}
	db.Close()

}

func getUserSubmissions(username string) []submission {
	//Connects to the database
	db := connDB()
	//Does the query
	queryStmt, err := db.Prepare("SELECT vuln,bin_fp FROM (SELECT submissions.id,user_id,vuln,bin_fp FROM submissions INNER JOIN binaries ON submissions.bin_id = binaries.id) AS subs INNER JOIN accounts ON accounts.id = subs.user_id WHERE accounts.username = $1")

	rows, err := queryStmt.Query(username)
	defer rows.Close()

	submissions := make([]submission, 0)
	for rows.Next() {
		var vuln string
		var binFP string
		if err := rows.Scan(&vuln, &binFP); err != nil {
			log.Fatal(err)
		}

		submissions = append(submissions, submission{vuln: vuln, binFP: binFP})
	}
	if err != nil {
		SQLErrorHandling(err)
	}

	//Closes the connection to the database
	db.Close()

	return submissions
}

func getScoreboard() []score {
	//Connects to the database
	db := connDB()
	//Does the query
	queryStmt, err := db.Prepare("SELECT username, points FROM accounts")

	rows, err := queryStmt.Query()
	defer rows.Close()

	scoreboard := make([]score, 0)
	for rows.Next() {
		var username string
		var points int
		if err := rows.Scan(&username, &points); err != nil {
			log.Fatal(err)
		}

		scoreboard = append(scoreboard, score{username: username, points: points})
	}
	if err != nil {
		SQLErrorHandling(err)
	}

	//Closes the connection to the database
	db.Close()

	return scoreboard
}

func adminGetAllSubmissions() map[string][]submission {
	//Connects to the database
	db := connDB()
	//Does the query
	queryStmt, err := db.Prepare("SELECT username,vuln,bin_fp FROM (SELECT submissions.id,user_id,vuln,bin_fp FROM submissions INNER JOIN binaries ON submissions.bin_id = binaries.id) AS subs INNER JOIN accounts ON accounts.id = subs.user_id")

	rows, err := queryStmt.Query()
	defer rows.Close()

	submissions := make(map[string][]submission, 0)
	for rows.Next() {
		var username string
		var vuln string
		var binFP string

		if err := rows.Scan(&username, &vuln, &binFP); err != nil {
			log.Fatal(err)
		}

		//checks if already exists
		if _, ok := submissions[username]; ok {
			submissions[username] = append(submissions[username], submission{vuln: vuln, binFP: binFP})
		} else {
			submissions[username] = []submission{submission{vuln: vuln, binFP: binFP}}
		}

	}

	if err != nil {
		SQLErrorHandling(err)
	}

	//Closes the connection to the database
	db.Close()

	return submissions
}

func adminDeleteSubmission(username string, vuln string, binFP string) {
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
func adminRemoveUser(username string) {
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

func main() {
	//Example, TODO: delete the main function, this way it works as a library?
	addUser("Ze", "aaa")
	addSubmission("Ze", "a", "a")
}

//ALTER SEQUENCE accounts_id_seq RESTART WITH 1;
