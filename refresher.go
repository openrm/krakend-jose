package jose

import (
	"fmt"
	"errors"
	"net/http"
	"encoding/json"

	"github.com/luraproject/lura/config"
	"github.com/luraproject/lura/logging"
	"gopkg.in/square/go-jose.v2/jwt"
)

var client = &http.Client{}

var (
	ErrNoRefresherCfg = errors.New("JOSE: no refresher config")
)

type RefresherConfig struct {
	RefreshURI               string `json:"refresh_url"`
	RefreshBodyProperty      string `json:"refresh_property"`
	RefreshCookieKey         string `json:"refresh_cookie_key"`
}

func NewRefresher(cfg *config.EndpointConfig) (Refresher, error) {
	tmp, ok := cfg.ExtraConfig[ValidatorNamespace]
	if !ok {
		return nil, ErrNoValidatorCfg
	}
	data, _ := json.Marshal(tmp)
	res := new(RefresherConfig)
	if err := json.Unmarshal(data, res); err != nil {
		return nil, err
	}

	if res.RefreshURI == "" {
		return nil, ErrNoRefresherCfg
	}

	if res.RefreshBodyProperty == "" {
		return nil, fmt.Errorf("JOSE: no backend property specified to get the refresh token for %s", cfg.Endpoint)
	}

	if res.RefreshCookieKey == "" {
		return nil, fmt.Errorf("JOSE: no refresh cookie key set for %s", cfg.Endpoint)
	}

	return &refresher{
		cfg: res,
	}, nil
}

type Refresher interface {
	RefreshToken(r *http.Request, l logging.Logger) (*jwt.JSONWebToken, *http.Cookie, error)
}

type refresher struct {
	cfg *RefresherConfig
}

func (r *refresher) RefreshToken(req *http.Request, logger logging.Logger) (*jwt.JSONWebToken, *http.Cookie, error) {
	cookie, err := req.Cookie(r.cfg.RefreshCookieKey)

	if err != nil {
		logger.Warning("JOSE: refresh token not set when attempting to refresh")
		return nil, nil, err
	}

	_, err = jwt.ParseSigned(cookie.Value)

	if err != nil {
		logger.Warning("JOSE: refresh token signature is invalid")
		return nil, nil, err
	}


	req, _ = http.NewRequest("GET", r.cfg.RefreshURI, nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", cookie.Value))
	resp, err := client.Do(req)

	if err != nil {
		logger.Error("JOSE: backend error when refreshing token")
		return nil, nil, err
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		logger.Error("JOSE: failed to parse response from refresh URL")
		return nil, nil, err
	}

	var tokenStr string
	if v, ok := result[r.cfg.RefreshBodyProperty]; ok {
		if s, ok := v.(string); ok {
			tokenStr = s
		}
	}

	token, err := jwt.ParseSigned(tokenStr)

	if err != nil {
		logger.Warning("JOSE: refreshed token is not parsable")
		return nil, nil, err
	}

	cookie.Value = tokenStr

	return token, cookie, nil
}
