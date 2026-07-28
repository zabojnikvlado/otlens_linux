package management

import "time"

type ReconCredentialRef struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Username string `json:"username,omitempty"`
}

type ReconCredentialSecret struct {
	ID         string `json:"id,omitempty"`
	Name       string `json:"name,omitempty"`
	Type       string `json:"type"`
	Username   string `json:"username,omitempty"`
	Password   string `json:"password,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
}

type ReconCredential struct {
	ReconCredentialRef
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
