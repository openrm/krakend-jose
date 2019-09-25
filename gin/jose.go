package gin

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"encoding/json"

	auth0 "github.com/auth0-community/go-auth0"
	krakendjose "github.com/openrm/krakend-jose"
	"github.com/devopsfaith/krakend/config"
	"github.com/devopsfaith/krakend/logging"
	"github.com/devopsfaith/krakend/proxy"
	ginkrakend "github.com/devopsfaith/krakend/router/gin"
	"github.com/gin-gonic/gin"
	"gopkg.in/square/go-jose.v2/jwt"
)

func HandlerFactory(hf ginkrakend.HandlerFactory, logger logging.Logger, rejecterF krakendjose.RejecterFactory) ginkrakend.HandlerFactory {
	return TokenSigner(TokenSignatureValidator(hf, logger, rejecterF), logger)
}

func TokenSigner(hf ginkrakend.HandlerFactory, logger logging.Logger) ginkrakend.HandlerFactory {
	return func(cfg *config.EndpointConfig, prxy proxy.Proxy) gin.HandlerFunc {
		signerCfg, signer, err := krakendjose.NewSigner(cfg, nil)
		if err == krakendjose.ErrNoSignerCfg {
			logger.Info("JOSE: singer disabled for the endpoint", cfg.Endpoint)
			return hf(cfg, prxy)
		}
		if err != nil {
			logger.Error(err.Error(), cfg.Endpoint)
			return hf(cfg, prxy)
		}

		logger.Info("JOSE: singer enabled for the endpoint", cfg.Endpoint)

		return func(c *gin.Context) {
			proxyReq := ginkrakend.NewRequest(cfg.HeadersToPass)(c, cfg.QueryString)
			ctx, cancel := context.WithTimeout(c, cfg.Timeout)
			defer cancel()

			response, err := prxy(ctx, proxyReq)
			if err != nil {
				logger.Error("proxy response error:", err.Error())
				c.AbortWithStatus(http.StatusBadRequest)
				return
			}

			if response == nil {
				c.AbortWithStatus(http.StatusBadRequest)
				return
			}

			if err := krakendjose.SignFields(signerCfg.KeysToSign, signer, response); err != nil {
				logger.Error(err.Error())
				c.AbortWithStatus(http.StatusBadRequest)
				return
			}

			for k, v := range response.Metadata.Headers {
				c.Header(k, v[0])
			}
			c.JSON(response.Metadata.StatusCode, response.Data)
		}
	}
}

func GetRefreshedToken(cfg *krakendjose.SignatureConfig, logger logging.Logger, r *http.Request) (*jwt.JSONWebToken, string, error) {
	cookie, err := r.Cookie(cfg.RefreshCookieKey)

	if err != nil {
		logger.Warning("JOSE: refresh token not set when attempting to refresh")
		return nil, "", jwt.ErrExpired
	}

	_, err = jwt.ParseSigned(cookie.Value)

	if err != nil {
		logger.Warning("JOSE: refresh token signature is invalid")
		return nil, "", err
	}

	client := &http.Client{}
	req, _ := http.NewRequest("GET", cfg.RefreshURI, nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", cookie.Value))
	resp, err := client.Do(req)

    if err != nil {
    	logger.Warning("JOSE: backend error when refreshing token")
    	return nil, "", err
    }

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	refreshedToken, err := jwt.ParseSigned(result[cfg.RefreshBodyProperty].(string))

	if err != nil {
		logger.Warning("JOSE: refreshed token is not parsable")
		return nil, "", err
	}

	return refreshedToken, result[cfg.RefreshBodyProperty].(string), nil
}

func TokenSignatureValidator(hf ginkrakend.HandlerFactory, logger logging.Logger, rejecterF krakendjose.RejecterFactory) ginkrakend.HandlerFactory {
	return func(cfg *config.EndpointConfig, prxy proxy.Proxy) gin.HandlerFunc {
		if rejecterF == nil {
			rejecterF = new(krakendjose.NopRejecterFactory)
		}
		rejecter := rejecterF.New(logger, cfg)

		handler := hf(cfg, prxy)
		scfg, err := krakendjose.GetSignatureConfig(cfg)
		if err == krakendjose.ErrNoValidatorCfg {
			logger.Info("JOSE: validator disabled for the endpoint", cfg.Endpoint)
			return handler
		}
		if err != nil {
			logger.Warning(fmt.Sprintf("JOSE: validator for %s: %s", cfg.Endpoint, err.Error()))
			return handler
		}

		validator, err := krakendjose.NewValidator(scfg, FromCookie)
		if err != nil {
			log.Fatalf("%s: %s", cfg.Endpoint, err.Error())
		}

		logger.Info("JOSE: validator enabled for the endpoint", cfg.Endpoint)

		refreshTokenEnabled := false

        if scfg.RefreshURI != "" {

	        if scfg.RefreshBodyProperty != "" {
	        	logger.Warning("JOSE: no backend property specified to get the refresh token for", cfg.Endpoint)
	        }

	        if scfg.RefreshCookieKey != "" {
	        	logger.Warning("JOSE: no refresh cookie key set for", cfg.Endpoint)
	        }

        	logger.Info("JOSE: refresh token enabled on expiration")
        	refreshTokenEnabled = scfg.RefreshBodyProperty != "" && scfg.RefreshCookieKey != ""

	    }

		return func(c *gin.Context) {
			token, err := validator.ValidateRequest(c.Request)
			if err != nil {

				if err == jwt.ErrExpired && refreshTokenEnabled {
					var tokenString string
					token, tokenString, err = GetRefreshedToken(scfg, logger, c.Request)
					if err != nil {
						c.AbortWithError(http.StatusUnauthorized, err)
						return
					}
					
					newCookie := &http.Cookie{Name: scfg.CookieKey, Value: tokenString, HttpOnly: false, Domain: scfg.RefreshCookieDomain}
					
					http.SetCookie(c.Writer, newCookie)

					logger.Info("JOSE: Token refreshed")

				} else {
					c.AbortWithError(http.StatusUnauthorized, err)
					return
				}
			}

			claims := map[string]interface{}{}
			err = validator.Claims(c.Request, token, &claims)
			if err != nil {
				c.AbortWithError(http.StatusUnauthorized, err)
				return
			}

			if rejecter.Reject(claims) {
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}

			if !krakendjose.CanAccess(scfg.RolesKey, claims, scfg.Roles) {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}

			handler(c)
		}
	}
}

func FromCookie(key string) func(r *http.Request) (*jwt.JSONWebToken, error) {
	if key == "" {
		key = "access_token"
	}
	return func(r *http.Request) (*jwt.JSONWebToken, error) {
		cookie, err := r.Cookie(key)
		if err != nil {
			return nil, auth0.ErrTokenNotFound
		}
		return jwt.ParseSigned(cookie.Value)
	}
}
