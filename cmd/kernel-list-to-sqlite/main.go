package main

import (
	"database/sql"
	"flag"
	"fmt"
	"os"
	"regexp"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/mattfoster/kcve/pkg/utils"
	_ "modernc.org/sqlite"
)

func initDB(dbPath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("error opening database: %v", err)
	}

	// Create the commits table if it doesn't exist
	createTable := `
	CREATE TABLE IF NOT EXISTS commits (
		hash TEXT PRIMARY KEY,
		cve TEXT,
		author_name TEXT,
		author_email TEXT,
		commit_date DATETIME,
		message TEXT,
		file_content TEXT
	);`

	_, err = db.Exec(createTable)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("error creating table: %v", err)
	}

	return db, nil
}

func main() {
	// Get database path from flag
	dbPath := flag.String("db", "commits.db", "Path to SQLite database file")
	flag.Parse()

	// Initialize the database
	db, err := initDB(*dbPath)
	if err != nil {
		fmt.Printf("Error initializing database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// Prepare the insert statement
	stmt, err := db.Prepare(`
		INSERT OR REPLACE INTO commits (
			hash, cve, author_name, author_email, commit_date, message, file_content
		) VALUES (?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		fmt.Printf("Error preparing statement: %v\n", err)
		os.Exit(1)
	}
	defer stmt.Close()

	// TODO: clone repo into tmp here and use that
	tmpDir, err := os.MkdirTemp("", "kernel-list-to-sqlite")
	if err != nil {
		fmt.Printf("Error creating temp directory: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	repo, err := git.PlainClone(tmpDir, false, &git.CloneOptions{
		URL: "http://lore.kernel.org/linux-cve-announce/0",
	})
	if err != nil {
		fmt.Printf("Error cloning repository: %v\n", err)
		os.Exit(1)
	}

	// Open the repository in the specified directory
	// repo, err := git.PlainOpen(*repoDir)
	// if err != nil {
	// 	fmt.Printf("Error opening repository at %s: %v\n", *repoDir, err)
	// 	os.Exit(1)
	// }

	// Get the HEAD reference
	ref, err := repo.Head()
	if err != nil {
		fmt.Printf("Error getting HEAD: %v\n", err)
		os.Exit(1)
	}

	// Create a log iterator
	logIter, err := repo.Log(&git.LogOptions{
		From: ref.Hash(),
	})
	if err != nil {
		fmt.Printf("Error getting logs: %v\n", err)
		os.Exit(1)
	}

	// Iterate through the commits
	err = logIter.ForEach(func(commit *object.Commit) error {

		// Get the file changes for this commit
		fileTree, err := commit.Tree()
		if err != nil {
			return fmt.Errorf("error getting commit tree: %v", err)
		}

		// Try to find file 'm'
		file, err := fileTree.File("m")
		if err != nil {
			return nil // Skip if file doesn't exist in this commit
		}

		// Get the contents
		contents, err := file.Contents()
		if err != nil {
			return fmt.Errorf("error reading file contents: %v", err)
		}

		// Strip headers and any patterns
		contents = utils.StripHeaders(contents)

		cve := regexp.MustCompile(`CVE-\d{4}-\d{4,7}`).FindString(commit.Message)

		// Store in database
		_, err = stmt.Exec(
			commit.Hash.String(),
			cve,
			commit.Author.Name,
			commit.Author.Email,
			commit.Author.When,
			commit.Message,
			contents,
		)
		if err != nil {
			return fmt.Errorf("error storing commit in database: %v", err)
		}

		return nil
	})
	if err != nil {
		fmt.Printf("Error iterating commits: %v\n", err)
		os.Exit(1)
	}
}
