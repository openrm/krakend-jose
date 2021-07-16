package gin

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"

	auth0 "github.com/auth0-community/go-auth0"
	krakendjose "github.com/devopsfaith/krakend-jose"
	"github.com/gin-gonic/gin"
	"github.com/luraproject/lura/config"
	"github.com/luraproject/lura/logging"
	"github.com/luraproject/lura/proxy"
	ginlura "github.com/luraproject/lura/router/gin"
	"gopkg.in/square/go-jose.v2/jwt"
)

func HandlerFactory(hf ginlura.HandlerFactory, logger logging.Logger, rejecterF krakendjose.RejecterFactory) ginlura.HandlerFactory {
	return TokenSignatureValidator(TokenSigner(hf, logger), logger, rejecterF)
}

func TokenSigner(hf ginlura.HandlerFactory, logger logging.Logger) ginlura.HandlerFactory {
	return func(cfg *config.EndpointConfig, prxy proxy.Proxy) gin.HandlerFunc {
		signerCfg, signer, err := krakendjose.NewSigner(cfg, nil)
		if err == krakendjose.ErrNoSignerCfg {
			logger.Info("JOSE: signer disabled for the endpoint", cfg.Endpoint)
			return hf(cfg, prxy)
		}
		if err != nil {
			logger.Error("JOSE: unable to create the signer for the endpoint", cfg.Endpoint)
			logger.Error(err.Error())
			return hf(cfg, prxy)
		}

		logger.Info("JOSE: signer enabled for the endpoint", cfg.Endpoint)

		return func(c *gin.Context) {
			proxyReq := ginlura.NewRequest(cfg.HeadersToPass)(c, cfg.QueryString)
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

func TokenSignatureValidator(hf ginlura.HandlerFactory, logger logging.Logger, rejecterF krakendjose.RejecterFactory) ginlura.HandlerFactory {
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

		var aclCheck func(string, map[string]interface{}, []string) bool

		if scfg.RolesKeyIsNested && strings.Contains(scfg.RolesKey, ".") && scfg.RolesKey[:4] != "http" {
			aclCheck = krakendjose.CanAccessNested
		} else {
			aclCheck = krakendjose.CanAccess
		}

		var scopesMatcher func(string, map[string]interface{}, []string) bool

		if len(scfg.Scopes) > 0 && scfg.ScopesKey != "" {
			if scfg.ScopesMatcher == "all" {
				scopesMatcher = krakendjose.ScopesAllMatcher
			} else {
				scopesMatcher = krakendjose.ScopesAnyMatcher
			}
		} else {
			scopesMatcher = krakendjose.ScopesDefaultMatcher
		}

		logger.Info("JOSE: validator enabled for the endpoint", cfg.Endpoint)

		refresher, err := krakendjose.NewRefresher(cfg)
		if err == krakendjose.ErrNoRefresherCfg {
			logger.Info("JOSE: refresher disabled for the endpoint", cfg.Endpoint)
		} else if err != nil {
			logger.Warning(err.Error())
		} else {
			logger.Info("JOSE: refresh token enabled on expiration for", cfg.Endpoint)
		}

		var handleUnauth func(*gin.Context, error)
		if redirectUrl, ok := krakendjose.ExtractRedirectUrl(cfg); ok {
			handleUnauth = func(c *gin.Context, err error) {
				c.Redirect(http.StatusFound, redirectUrl)
			}
		} else {
			logger.Info("JOSE: redirection disabled for the endpoint", cfg.Endpoint)
			handleUnauth = func(c *gin.Context, err error) {
				if err != nil {
					c.AbortWithError(http.StatusUnauthorized, err)
				} else {
					c.AbortWithStatus(http.StatusUnauthorized)
				}
			}
		}

		paramExtractor := extractRequiredJWTClaims(cfg)

		return func(c *gin.Context) {
			token, err := validator.ValidateRequest(c.Request)
			if err != nil {
				if err == jwt.ErrExpired && refresher != nil {
					var cookie *http.Cookie
					if token, cookie, err = refresher.RefreshToken(c.Request, logger); err != nil {
						c.AbortWithError(http.StatusUnauthorized, jwt.ErrExpired)
						return
					}
					http.SetCookie(c.Writer, cookie)
				}
				handleUnauth(c, err)
				return
			}

			claims := map[string]interface{}{}
			err = validator.Claims(c.Request, token, &claims)
			if err != nil {
				handleUnauth(c, err)
				return
			}

			if rejecter.Reject(claims) {
				handleUnauth(c, nil)
				return
			}

			if !aclCheck(scfg.RolesKey, claims, scfg.Roles) {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}

			if !scopesMatcher(scfg.ScopesKey, claims, scfg.Scopes) {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}

			propagateHeaders(cfg, scfg.PropagateClaimsToHeader, claims, c, logger)

			paramExtractor(c, claims)

			handler(c)
		}
	}
}

func propagateHeaders(cfg *config.EndpointConfig, propagationCfg [][]string, claims map[string]interface{}, c *gin.Context, logger logging.Logger) {
	if len(propagationCfg) > 0 {
		headersToPropagate, err := krakendjose.CalculateHeadersToPropagate(propagationCfg, claims)
		if err != nil {
			logger.Warning(fmt.Sprintf("JOSE: header propagations error for %s: %s", cfg.Endpoint, err.Error()))
		}
		for k, v := range headersToPropagate {
			// Set header value - replaces existing one
			c.Request.Header.Set(k, v)
		}
	}
}

var jwtParamsPattern = regexp.MustCompile(`{{\.JWT\.([^}]*)}}`)

func extractRequiredJWTClaims(cfg *config.EndpointConfig) func(*gin.Context, map[string]interface{}) {
	required := []string{}
	for _, backend := range cfg.Backend {
		for _, match := range jwtParamsPattern.FindAllStringSubmatch(backend.URLPattern, -1) {
			if len(match) < 2 {
				continue
			}
			required = append(required, match[1])
		}
	}
	if len(required) == 0 {
		return func(_ *gin.Context, _ map[string]interface{}) {}
	}

	return func(c *gin.Context, claims map[string]interface{}) {
		cl := krakendjose.Claims(claims)
		for _, param := range required {
			// TODO: check for nested claims
			v, ok := cl.Get(param)
			if !ok {
				continue
			}
			params := append(c.Params, gin.Param{Key: "JWT." + param, Value: v})
			c.Params = params
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
