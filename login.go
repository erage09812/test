package main

import (
    "fmt"
    "net/http"
    "net/url"
    "io/ioutil"
    "encoding/json"
    "os"
)

const (
    SalesforceLoginURL = "https://login.salesforce.com"
    EnvUsername        = "USERNAME"
    EnvPassword        = "PASSWORD"
    EnvSecurityToken   = "SECURITY_TOKEN"
)

type SalesforceAuthResponse struct {
    AccessToken string `json:"access_token"`
    InstanceURL string `json:"instance_url"`
    TokenType   string `json:"token_type"`
    IssuedAt    string `json:"issued_at"`
    Signature   string `json:"signature"`
}
func main() {
    repository := os.Getenv("GITHUB_REPOSITORY")
    actor := os.Getenv("GITHUB_ACTOR")
    workspace := os.Getenv("GITHUB_WORKSPACE")

    // Print the GitHub Actions environment variables
    fmt.Println("Repository:", repository)
    fmt.Println("Actor:", actor)
    fmt.Println("Workspace:", workspace)
	
    fmt.Println("Environment variable names:")
    fmt.Println("EnvUsername:",  os.Getenv(EnvUsername))
    fmt.Println("EnvPassword:", os.Getenv(EnvPassword))
    fmt.Println("EnvSecurityToken:", os.Getenv(EnvPassword))
    // Retrieve secrets from environment variables
    username := os.Getenv(EnvUsername)
    password := os.Getenv(EnvPassword)
    securityToken := os.Getenv(EnvSecurityToken)

    // Check if environment variables are empty
    if username == "" || password == "" || securityToken == "" {
        fmt.Println("One or more environment variables not found or empty")
        return
    }


    // Prepare the HTTP request to login.salesforce.com
    data := url.Values{}
    data.Set("grant_type", "password")
    data.Set("username", username)
    data.Set("password", password + securityToken) // Append security token to the password

    // Send the HTTP POST request to obtain the access token
    resp, err := http.PostForm(SalesforceLoginURL+"/services/oauth2/token", data)
    if err != nil {
        fmt.Println("Failed to send request:", err)
        return
    }
    defer resp.Body.Close()

    // Read the response body
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        fmt.Println("Failed to read response body:", err)
        return
    }

    // Parse the JSON response
    var authResponse SalesforceAuthResponse
    if err := json.Unmarshal(body, &authResponse); err != nil {
        fmt.Println("Failed to parse JSON response:", err)
        return
    }

    // Print the access token and instance URL
    fmt.Println("Access Token:", authResponse.AccessToken)
    fmt.Println("Instance URL:", authResponse.InstanceURL)
}
