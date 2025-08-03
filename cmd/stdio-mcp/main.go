package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
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

	// Create MCP server
	s := server.NewMCPServer(
		"Kernel CVE Info Server",
		"1.0.0",
		server.WithToolCapabilities(false),
	)

	// Create get_kernel_cve_info tool
	getCveInfoTool := mcp.NewTool("get_kernel_cve_info",
		mcp.WithDescription("Get information on a CVE affecting the Linux kernel, use this to obtain more information about a CVE affecting the kernel."),
		mcp.WithString("cve",
			mcp.Required(),
			mcp.Description("The CVE identifier to look up"),
		),
	)

	s.AddTool(getCveInfoTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		cve, err := request.RequireString("cve")
		if err != nil {
			return mcp.NewToolResultError("cve parameter is required and must be a string"), nil
		}

		commit, err := getKernelCveInfo(db, cve)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		jsonData, err := json.Marshal(commit)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		return mcp.NewToolResultText(string(jsonData)), nil
	})

	// Create search_kernel_cve_info tool
	searchCveInfoTool := mcp.NewTool("search_kernel_cve_info",
		mcp.WithDescription("Search kernel vulnerability information for specific keywords"),
		mcp.WithString("keyword",
			mcp.Required(),
			mcp.Description("The keyword to search for in commit messages and file content"),
		),
	)

	s.AddTool(searchCveInfoTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		keyword, err := request.RequireString("keyword")
		if err != nil {
			return mcp.NewToolResultError("keyword parameter is required and must be a string"), nil
		}

		results, err := searchKernelCveInfo(db, keyword)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		jsonData, err := json.Marshal(results)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		return mcp.NewToolResultText(string(jsonData)), nil
	})

	// Start the server
	if err := server.ServeStdio(s); err != nil {
		fmt.Printf("Server error: %v\n", err)
		os.Exit(1)
	}
}
