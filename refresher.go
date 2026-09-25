package jose

import (
	"fmt"
	"errors"
	"net/http"
	"encoding/json"

	"github.com/luraproject/lura/v2/config"
	"github.com/luraproject/lura/v2/logging"
	"github.com/go-jose/go-jose/v3/jwt"
)

var client = &http.Client{}

var (
	ErrNoRefresherCfg = errors.New("JOSE: no refresher config")
	ErrNoTokenFound   = errors.New("JOSE: no cookie found in the response")
)

type RefresherConfig struct {
	CookieKey                string `json:"cookie_key"`
	RefreshURI               string `json:"refresh_url"`
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

	cookies := resp.Cookies()

	for i := 0; i < len(cookies); i++ {
		cookie := cookies[i]
		if cookie.Name == r.cfg.CookieKey {
			token, err := jwt.ParseSigned(cookie.Value)

			if err != nil {
				logger.Warning("JOSE: refreshed token is not parsable")
				return nil, nil, err
			}

			return token, cookie, nil
		}
	}

	return nil, nil, ErrNoTokenFound
}
