package provider

import (
	"context"
	"strings"

	"github.com/supabase/auth/internal/conf"
	"golang.org/x/oauth2"
)

// Amazon
// Reference: https://developer.amazon.com/docs/login-with-amazon/web-docs.html

const (
	defaultAmazonAuthBase = "www.amazon.com"
	defaultAmazonAPIBase  = "api.amazon.com"
)

type amazonProvider struct {
	*oauth2.Config
	APIHost string
}

type amazonUser struct {
	ID        string `json:"user_id"`
	Email     string `json:"email"`
	Name      string `json:"name"`
}

// NewAmazonProvider creates a Amazon account provider.
func NewAmazonProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.ValidateOAuth(); err != nil {
		return nil, err
	}

	authHost := chooseHost(ext.URL, defaultAmazonAuthBase)
	apiHost := chooseHost(ext.URL, defaultAmazonAPIBase)

	oauthScopes := []string{
		"profile",
	}

	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, ",")...)
	}

	return &amazonProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID[0],
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authHost + "/ap/oa",
				TokenURL: apiHost + "/auth/o2/token",
			},
			RedirectURL: ext.RedirectURI,
			Scopes:      oauthScopes,
		},
		APIHost: apiHost,
	}, nil
}

func (p amazonProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return p.Exchange(context.Background(), code)
}

func (p amazonProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var u amazonUser
	if err := makeRequest(ctx, tok, p.Config, p.APIHost+"/user/profile", &u); err != nil {
		return nil, err
	}

	data := &UserProvidedData{}
	if u.Email != "" {
		data.Emails = []Email{{
			Email:    u.Email,
			Verified: true,
			Primary:  true,
		}}
	}

	data.Metadata = &Claims{
		Issuer:        p.APIHost,
		Subject:       u.ID,
		Name:          u.Name,
		Email:         u.Email,
		EmailVerified: true,
	}
	return data, nil
}
