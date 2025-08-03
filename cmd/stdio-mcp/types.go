package main

import (
	"database/sql"
	"fmt"
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

type KernelCveSearchArguments struct {
	Keyword string `json:"keyword"`
}

type KernelCveSearchResponse struct {
	Count   int                 `json:"count"`
	Results []KernelCveResponse `json:"results"`
}

func getKernelCveInfo(db *sql.DB, cve string) (*KernelCveResponse, error) {
	rows, err := db.Query("SELECT * FROM commits WHERE cve = ?", cve)
	if err != nil {
		return nil, fmt.Errorf("error querying database: %v", err)
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
			return nil, fmt.Errorf("error scanning database: %v", err)
		}
		return &commit, nil
	}
	return nil, fmt.Errorf("no commit found for CVE: %s", cve)
}

func searchKernelCveInfo(db *sql.DB, keyword string) (*KernelCveSearchResponse, error) {
	rows, err := db.Query("SELECT * FROM commits WHERE file_content LIKE ? OR message LIKE ?", "%"+keyword+"%", "%"+keyword+"%")
	if err != nil {
		return nil, fmt.Errorf("error querying database: %v", err)
	}
	defer rows.Close()

	results := []KernelCveResponse{}
	for rows.Next() {
		var commit KernelCveResponse
		err = rows.Scan(
			&commit.CommitHash,
			&commit.CVE,
			&commit.CommitAuthor,
			&commit.CommitEmail,
			&commit.CommitDate,
			&commit.CommitMessage,
			&commit.FileContent,
		)
		commit.FileContent = "" // File content makes the response too large.
		if err != nil {
			return nil, fmt.Errorf("error scanning database: %v", err)
		}
		results = append(results, commit)
	}
	return &KernelCveSearchResponse{Count: len(results), Results: results}, nil
}
