package main

import (
	"database/sql"
	"fmt"
	"os"
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
