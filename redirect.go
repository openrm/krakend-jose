package jose

import (
	"github.com/luraproject/lura/config"
)

const redirectKey = "redirect_on_unauth_to"

func ExtractRedirectUrl(cfg *config.EndpointConfig) (string, bool) {
	if v, ok := cfg.ExtraConfig[redirectKey]; ok {
		if s, ok := v.(string); ok {
			return s, true
		}
	}
	return "", false
}
