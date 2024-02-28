package main

import (
    "fmt"
    "net/http"
    "net/url"
    "io/ioutil"
    "encoding/json"

)

const (
    SalesforceLoginURL = "https://login.salesforce.com"
    ClientID           = "your_client_id"
    ClientSecret       = "your_client_secret"
    Username           = "your_salesforce_username"
    Password           = "your_salesforce_password"
    SecurityToken      = "your_security_token"
)

type SalesforceAuthResponse struct {
    AccessToken string `json:"access_token"`
    InstanceURL string `json:"instance_url"`
    TokenType   string `json:"token_type"`
    IssuedAt    string `json:"issued_at"`
    Signature   string `json:"signature"`
}

func main() {
    // Prepare the HTTP request to login.salesforce.com
    data := url.Values{}
    data.Set("grant_type", "password")
    data.Set("client_id", ClientID)
    data.Set("client_secret", ClientSecret)
    data.Set("username", Username)
    data.Set("password", Password + SecurityToken) // Append security token to the password

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
