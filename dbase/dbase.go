package dbase

import (
	"database/sql"
	"os"

	//imported
	_ "github.com/go-sql-driver/mysql"
)

//Conn connects to
func Conn() (db *sql.DB) {
	dbDriver := os.Getenv("NETWORKFLOW_DB_DRIVER")
	dbUser := os.Getenv("NETWORKFLOW_DB_USER")
	dbPass := os.Getenv("NETWORKFLOW_DB_PASS")
	dbName := os.Getenv("NETWORKFLOW_DB_NAME")
	db, err := sql.Open(dbDriver, dbUser+":"+dbPass+"@/"+dbName)
	if err != nil {
		panic(err.Error())
	}
	return db
}
