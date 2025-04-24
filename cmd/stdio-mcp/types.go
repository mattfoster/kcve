package main

import (
	"database/sql"
	"fmt"
	"os"

	mcp_golang "github.com/metoro-io/mcp-golang"
)

type KernelCveArguments struct {
	CVE string `json:"cve"`
}

type KernelCveResponse struct {
	CommitHash    string `json:"commit_hash"`
	CVE           string `json:"cve"`
	CommitAuthor  string `json:"commit_author"`
	CommitEmail   string `json:"commit_email"`
	CommitMessage string `json:"commit_message"`
	CommitDate    string `json:"commit_date"`
	FileContent   string `json:"file_content"`
}

func getKernelCveInfo(db *sql.DB, cve string) (*KernelCveResponse, error) {
	rows, err := db.Query("SELECT * FROM commits WHERE cve = ?", cve)
	if err != nil {
		fmt.Printf("error querying database: %v", err)
		os.Exit(1)
	}
	defer rows.Close()

	for rows.Next() {
		var commit KernelCveResponse
		err = rows.Scan(
			&commit.CommitHash,
			&commit.CVE,
			&commit.CommitAuthor,
			&commit.CommitEmail,
			&commit.CommitDate,
			&commit.CommitMessage,
			&commit.FileContent)
		if err != nil {
			fmt.Printf("error scanning database: %v", err)
			os.Exit(1)
		}
		return &commit, nil
	}
	return nil, fmt.Errorf("no commit found for CVE: %s", cve)
}

func registerKernelCveList(db *sql.DB, server *mcp_golang.Server) error {
	rows, err := db.Query("SELECT DISTINCT cve, hash FROM commits")
	if err != nil {
		fmt.Printf("error querying database: %v", err)
		os.Exit(1)
	}
	defer rows.Close()

	for rows.Next() {
		var cve string
		var commitHash string
		err = rows.Scan(&cve, &commitHash)
		if err != nil {
			fmt.Printf("error scanning database: %v", err)
			os.Exit(1)
		}
		// callback func to register resource
		registerResource(db, cve, commitHash, server)
	}
	return nil
}

func registerResource(db *sql.DB, cve string, commitHash string, server *mcp_golang.Server) {
	err := server.RegisterResource(
		cve,
		fmt.Sprintf("Resource %s", commitHash),
		fmt.Sprintf("Description for resource %s", cve),
		"text/plain",
		func() (*mcp_golang.ResourceResponse, error) {
			return getKernelCveResource(db, cve, commitHash)
		},
	)
	if err != nil {
		fmt.Printf("error registering resource: %v", err)
		os.Exit(1)
	}
}

// getKernelCveResource returns a resource for a given CVE and commit hash
// this includes the commit message, author, date, and file content
func getKernelCveResource(db *sql.DB, cve string, commitHash string) (*mcp_golang.ResourceResponse, error) {
	rows, err := db.Query("SELECT * FROM commits WHERE cve = ? AND hash = ?", cve, commitHash)
	if err != nil {
		return nil, fmt.Errorf("error querying database: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var commit KernelCveResponse
		err = rows.Scan(&commit.CommitHash, &commit.CVE, &commit.CommitAuthor, &commit.CommitEmail, &commit.CommitDate, &commit.CommitMessage, &commit.FileContent)
		if err != nil {
			return nil, fmt.Errorf("error querying database: %v", err)
		}
		return mcp_golang.NewResourceResponse(
			mcp_golang.NewTextEmbeddedResource(
				cve,
				commit.CommitMessage+"\n"+commit.FileContent,
				"text/plain",
			),
		), nil
	}
	return nil, fmt.Errorf("no commit found for CVE: %s, commit hash: %s", cve, commitHash)
}
