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
)

type SalesforceAuthResponse struct {
    AccessToken string `json:"access_token"`
    InstanceURL string `json:"instance_url"`
    TokenType   string `json:"token_type"`
    IssuedAt    string `json:"issued_at"`
    Signature   string `json:"signature"`
}

func main() {
    // Retrieve secrets from environment variables
    // clientID := os.Getenv("CLIENT_ID")
    // clientSecret := os.Getenv("CLIENT_SECRET")
username, usernameExists :=os.LookupEnv("USERNAME")
password, passwordExists := os.LookupEnv("PASSWORD")
securityToken, securityTokenExists := os.LookupEnv("SECURITY_TOKEN")


    // Prepare the HTTP request to login.salesforce.com
    data := url.Values{}
    data.Set("grant_type", "password")
    // data.Set("client_id", clientID)
    // data.Set("client_secret", clientSecret)
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
    fmt.Println("UserName:",  username )
    fmt.Println("Password:", password )
}

// if !usernameExists || !passwordExists || !securityTokenExists {
//     fmt.Println("One or more environment variables not found")
//     return
// }

