package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	mcp "github.com/metoro-io/mcp-golang"
	"github.com/metoro-io/mcp-golang/transport/stdio"
	_ "modernc.org/sqlite"
)

var dbPath *string

func main() {
	// Get database path from flag
	dbPath = flag.String("db", "commits.db", "Path to SQLite database file")
	flag.Parse()

	db, err := sql.Open("sqlite", *dbPath)
	if err != nil {
		fmt.Printf("error opening database: %v", err)
		os.Exit(1)
	}
	defer db.Close()

	done := make(chan struct{})

	// Create a transport for the server
	serverTransport := stdio.NewStdioServerTransport()

	// Create a new server with the transport
	server := mcp.NewServer(serverTransport)

	err = server.RegisterTool("get_kernel_cve_info", "Get information on a CVE affecting the Linux kernel", func(arguments KernelCveArguments) (*mcp.ToolResponse, error) {
		commit, err := getKernelCveInfo(db, arguments.CVE)
		if err != nil {
			return nil, err
		}
		json, err := json.Marshal(commit)
		if err != nil {
			return nil, err
		}
		return mcp.NewToolResponse(mcp.NewTextContent(string(json))), nil
	})

	if err != nil {
		panic(err)
	}

	err = server.RegisterTool("search_kernel_cve_info", "Search kernel vulnerability information for specific keywords", func(arguments KernelCveSearchArguments) (*mcp.ToolResponse, error) {
		commit, err := searchKernelCveInfo(db, arguments.Keyword)
		if err != nil {
			return nil, err
		}
		json, err := json.Marshal(commit)
		if err != nil {
			return nil, err
		}
		return mcp.NewToolResponse(mcp.NewTextContent(string(json))), nil
	})

	if err != nil {
		panic(err)
	}

	// Start the server
	err = server.Serve()
	if err != nil {
		panic(err)
	}

	<-done
}
